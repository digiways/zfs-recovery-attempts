#pragma once

#include "file.hpp"
#include "zfs_try_decompress.hpp"
#include "zfs_recovery_tools_views.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <stdint.h>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <set>
#include <algorithm>
#include <thread>
#include <unordered_map>
#include <sys/zap_impl.h>
#include <sys/zap_leaf.h>
#include <sys/stat.h>
#include <fcntl.h>

#define private private_non_keyword
#define class class_non_keyword
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/zio_checksum.h>
#include <sys/zio_compress.h>
#include <sys/dnode.h>
#undef class
#undef private


namespace zfs_recover_tools
{
	template<class T>
	const T& get_mem_pod(const uint8_t* ptr, size_t offset, size_t data_length)
	{
		if (offset + sizeof(T) > data_length)
			throw std::runtime_error("out of bounds in get_mem_pod");
		return *reinterpret_cast<const T*>(ptr + offset);
	}

	int highBit(uint64_t some)
	{
	    for (int i = 63; i >= 0; i--)
	    {
	        if (((1L << i) & some) != 0)
	            return i;
	    }
	    throw std::runtime_error("high bit internal error");
	}

	std::vector<uint64_t> ReadPointerTable(const uint8_t* ptr, int length, long startReadOffset, long numberOfBytesToRead)
	{
		std::vector<uint64_t> ret;
		for (long i = 0; i < numberOfBytesToRead; i += sizeof(uint64_t))
		{
			uint64_t val = get_mem_pod<uint64_t>(ptr, startReadOffset + i, length);
			if (val != 0)
			{
				if (val > length)
					return {};
				ret.push_back(val);
			}
		}
		return ret;
	}

	struct IntegerArray
	{
		template<class POD>
		struct pod_type {};

		template<class POD>
		explicit IntegerArray(const pod_type<POD>& type) : element_size_(sizeof(POD)) {}

		explicit IntegerArray(const pod_type<uint8_t>& type, std::vector<uint8_t>&& data) : element_size_(sizeof(uint8_t)), data_(std::move(data)) {}
		explicit IntegerArray(const pod_type<uint16_t>& type, std::vector<uint8_t>&& data) : element_size_(sizeof(uint16_t)), data_(std::move(data)) { byte_swap_all<uint16_t>(); }
		explicit IntegerArray(const pod_type<uint32_t>& type, std::vector<uint8_t>&& data) : element_size_(sizeof(uint32_t)), data_(std::move(data)) { byte_swap_all<uint32_t>(); }
		explicit IntegerArray(const pod_type<uint64_t>& type, std::vector<uint8_t>&& data) : element_size_(sizeof(uint64_t)), data_(std::move(data)) { byte_swap_all<uint64_t>(); }

		size_t size() const { return data_.size() / element_size_; }

		size_t element_size() const { return element_size_; }

		template<class POD>
		const POD* data() const
		{
			if (sizeof(POD) != element_size_)
				throw std::runtime_error("POD Array element size error");
			return reinterpret_cast<const POD*>(data_.data());
		}

	private:
		template<class POD>
		void byte_swap_all()
		{
			if (data_.size() % sizeof(POD) != 0)
				throw std::runtime_error("IntegerArray, invalid data size");
			POD* ptr = reinterpret_cast<POD*>(data_.data());
			for (size_t i = 0, sz = size(); i != sz; ++i)
				byte_swap(ptr[i]);
		}
		static void byte_swap(uint16_t& value) { value = __builtin_bswap16(value); }
		static void byte_swap(uint32_t& value) { value = __builtin_bswap32(value); }
		static void byte_swap(uint64_t& value) { value = __builtin_bswap64(value); }
		std::vector<uint8_t> data_;
		const uint8_t element_size_;
	};

	void GetByteArray(const uint8_t* ptr, long ptrLength, long chunkTableOffset, int chunkEntryNdx, int totalEntries, std::vector<uint8_t>& list)
	{
		static constexpr uint16_t CHAIN_END = 0xffff;

	    if (totalEntries <= 0)
	        throw std::runtime_error("out of range");
	    if (chunkEntryNdx == CHAIN_END)
	    	throw std::runtime_error("out of range");

	    const zap_leaf_chunk_t& chunk = get_mem_pod<zap_leaf_chunk_t>(ptr, chunkTableOffset + sizeof(zap_leaf_chunk_t) * chunkEntryNdx, ptrLength);
	    if (chunk.l_entry.le_type != zap_chunk_type_t::ZAP_CHUNK_ARRAY)
	        throw std::runtime_error("Invalid zap chunk type, not ZAP_CHUNK_ARRAY");
	    const zap_leaf_chunk::zap_leaf_array& array = chunk.l_array;

	    int entriesToRead = ZAP_LEAF_ARRAY_BYTES;
	    if (entriesToRead > totalEntries)
	        entriesToRead = totalEntries;
	    for (int i = 0; i < entriesToRead; i++)
	    {
	        uint8_t item = *(array.la_array + i);
	        list.push_back(item);
	    }
	    totalEntries -= entriesToRead;
	    if (totalEntries != 0)
	    {
	        GetByteArray(ptr, ptrLength, chunkTableOffset, array.la_next, totalEntries, list);
	    }
	}

	template<class POD>
	IntegerArray GetArray(const uint8_t* ptr, long ptrLength, long chunkTableOffset, int chunkEntryNdx, int totalEntries)
	{
	    std::vector<uint8_t> byteArray;
	    constexpr int itemSize = sizeof(POD);
	    GetByteArray(ptr, ptrLength, chunkTableOffset, chunkEntryNdx, totalEntries * itemSize, byteArray);
	    if (sizeof(POD) != 1 && sizeof(POD) != 4 && sizeof(POD) != 2 && sizeof(POD) != 8)
	    	throw std::runtime_error("Not supported POD type in GetArray");
	    return IntegerArray(IntegerArray::pod_type<POD>(), std::move(byteArray));
	}

	IntegerArray GetValueArray(const uint8_t* ptr, long ptrLength, long chunkTableOffset, const zap_leaf_chunk_t::zap_leaf_entry& entry)
	{
	    switch (entry.le_value_intlen)
	    {
	        case 1:
	            return GetArray<uint8_t>(ptr, ptrLength, chunkTableOffset, entry.le_value_chunk, entry.le_value_numints);
	        case 2:
	            return GetArray<uint16_t>(ptr, ptrLength, chunkTableOffset, entry.le_value_chunk, entry.le_value_numints);
	        case 4:
	            return GetArray<uint32_t>(ptr, ptrLength, chunkTableOffset, entry.le_value_chunk, entry.le_value_numints);
	        case 8:
	            return GetArray<uint64_t>(ptr, ptrLength, chunkTableOffset, entry.le_value_chunk, entry.le_value_numints);
	        default:
	            throw std::runtime_error("unknown type");
	    }
	}

	template<class POD, class Adaptor>
	inline void print_integer_array(std::ostream& os, const IntegerArray& ze, const Adaptor& adaptor)
	{
		os << "IntegerArray<" << sizeof(POD) << "bit>{";
		const POD* data = ze.data<POD>();
		for (size_t i = 0; i != ze.size(); ++i)
		{
			if (i != 0)
				os << ',';
			os << adaptor(data[i]) ;
		}
		os << "}";
	}

	template<class Adaptor>
	inline void print_any_integer_array(std::ostream& os, const IntegerArray& ze, const Adaptor& adaptor)
	{
		if (ze.element_size() == sizeof(uint8_t))
			print_integer_array<uint8_t>(os, ze, adaptor);
		else if (ze.element_size() == sizeof(uint16_t))
			print_integer_array<uint16_t>(os, ze, adaptor);
		else if (ze.element_size() == sizeof(uint32_t))
			print_integer_array<uint32_t>(os, ze, adaptor);
		else if (ze.element_size() == sizeof(uint64_t))
			print_integer_array<uint64_t>(os, ze, adaptor);
		else
			throw std::runtime_error("Unexpected IntegerArray element size");
	}

	struct zap_entry
	{
		zap_entry(std::string&& n, IntegerArray&& i) : name(std::move(n)), value(std::move(i)) {}
		std::string name;
		IntegerArray value;
	};

	inline std::ostream& operator << (std::ostream& os, const zap_entry& ze)
	{
		os << "zap_entry{'" << ze.name << "', ";
		print_any_integer_array(os, ze.value, [](auto value) { return (sizeof(value) == 8) ? (value&0xFFFFFFF) : value; });
		os << "}";
		return os;
	}

	std::vector<zap_entry> parse_fat(const uint8_t* ptr, size_t length, uint64_t BlockSizeInBytes)
	{
		const zap_phys_t& header = get_mem_pod<zap_phys_t>(ptr, 0, length);

	    if (header.zap_block_type != ZBT_HEADER)
	        throw std::runtime_error("not a header (zap_block_type is not ZBT_HEADER)");
	    if (header.zap_magic != ZAP_MAGIC)
	        throw std::runtime_error("Wrong magic");
	    if (header.zap_num_entries > 100000)
	    	throw std::runtime_error("Too many entries in directory: " + std::to_string(header.zap_num_entries));

	    std::vector<zap_entry> ret;
	    ret.reserve(header.zap_num_entries);
	    int bs = highBit(BlockSizeInBytes);
	    //printf("bs=%u\n", bs);
	    const uint8_t* end = ptr + length;

	    //--bs;
	    std::vector<uint64_t> blkIds;
	    //printf("header.zap_ptrtbl.zt_numblks=%u\n", int(header.zap_ptrtbl.zt_numblks));
	    while (true)
	    {
	    	if (header.zap_ptrtbl.zt_numblks == 0)
	    	{
	    		//the embedded block table is the second half of the first block
	    		printf("1 << (bs - 1)=%u\n", int(1 << (bs - 1)));
	    		blkIds = ReadPointerTable(ptr, length, 1 << (bs - 1), 1 << (bs - 1));
	    	}
	    	else
	    	{
	    		long startReadOffset = header.zap_ptrtbl.zt_blk << bs;
	    		long numberOfBytesToRead = header.zap_ptrtbl.zt_numblks << bs;
	    		blkIds = ReadPointerTable(ptr, length, startReadOffset, numberOfBytesToRead);
	    	}
	    	if ((ulong)blkIds.size() == 0 && header.zap_num_leafs != 0 && bs > 2)
	    		--bs;
	    	else
	    		break;
	    }

	    //read the leaves
	    std::sort(blkIds.begin(), blkIds.end());
	    blkIds.erase(std::unique(blkIds.begin(), blkIds.end()), blkIds.end());

	    //printf("blkIds.size()=%u\n", int(blkIds.size()));
	    if (blkIds.empty())
	    	throw std::runtime_error("blkIds is empty");

	//    if ((ulong)blkIds.size() != header.zap_num_leafs)
	//        throw std::runtime_error("Not enough leafs, blkIds.size()=" + std::to_string(blkIds.size()) + ", zap_num_leafs=" + std::to_string(header.zap_num_leafs));

	    size_t base_offset = 0;
	    {
	    	// find base offset
	    	for (size_t i = (blkIds[0] << bs); i != length-sizeof(uint32_t)*2; ++i)
	    	{
	    		//printf("%lu[%lu] ", i, length);
	    		if (
	   				get_mem_pod<uint64_t>(ptr, i, length) == uint64_t(ZBT_LEAF)
	    			&& get_mem_pod<uint32_t>(ptr, i+sizeof(uint64_t)*3, length) == uint32_t(ZAP_LEAF_MAGIC)
					)
	    		{
	    			base_offset = i;
	    			break;
	    		}
	    	}
	    	if (base_offset == 0)
	    		throw std::runtime_error("ZAP_LEAF_MAGIC not found");
	    	//printf("base_offset=%lu\n", base_offset);
	    	//printf("blkIds[0]=%u, (blkIds[0] << bs)=%u\n", int(blkIds[0]), int((blkIds[0] << bs)));
	    	base_offset -= (blkIds[0] << bs);
			//printf("base_offset=%lu\n", base_offset);
	    }
	    for (uint64_t blkid : blkIds)
	    {
	    	//printf("blkid=%lu\n", blkid);
	        long offset = base_offset + (blkid << bs);
	        //printf("offset=%lu, base_offset=%lu, blkid=%lu, bs=%u, length=%lu\n", uint64_t(offset), base_offset, uint64_t(blkid), int(bs), length);
	        const zap_leaf_phys_t::zap_leaf_header& leaf = get_mem_pod<zap_leaf_phys_t::zap_leaf_header>(ptr, offset, length);
	        //printf("got leaf, lh_block_type=%lx, nentries=%u\n", leaf.lh_block_type, int(leaf.lh_nentries));
	        if (leaf.lh_magic != ZAP_LEAF_MAGIC)
	            throw std::runtime_error("wrong lh_magic");
	        if (leaf.lh_block_type != ZBT_LEAF)
	        {
	        	std::ostringstream err;
	        	err << "leaf.lh_block_type is not ZBT_LEAF, but " << std::hex << leaf.lh_block_type;
	        	throw std::runtime_error(err.str());
	        }
	        //printf("bs=%u\n", int(bs));
	        int numHashEntries = 1 << (bs - 5);

	        //printf("numHashEntries = %u\n", numHashEntries);

	        std::set<ushort> hashEntries;

	        offset += sizeof(zap_leaf_phys_t::zap_leaf_header);
	        for (int i = 0; i < numHashEntries; i++)
	        {
	            ushort* hashPtr = (ushort*)(ptr + offset);
	            if (reinterpret_cast<uint8_t*>(hashPtr) > end)
	                throw std::runtime_error("hashPtr > end");
	            ushort loc = *hashPtr;
	            if (loc != 0xffff)
	            {
	                if (hashEntries.insert(loc).second == false)
	                    throw std::runtime_error("Duplicate leaf entry?");
	            }
	            offset += 2;
	        }

	        std::vector<ushort> itemsToProcess(hashEntries.begin(), hashEntries.end());
	        for (int i = 0; i < itemsToProcess.size(); i++)
	        {
	            ushort hashLoc = itemsToProcess[i];
	            const zap_leaf_chunk_t& chunk = get_mem_pod<zap_leaf_chunk_t>(ptr, offset + sizeof(zap_leaf_chunk_t) * hashLoc, length);
	            switch (chunk.l_entry.le_type)
	            {
	                case ZAP_CHUNK_ENTRY:
	                {
	                	const zap_leaf_chunk_t::zap_leaf_entry& entry = chunk.l_entry;
	                    IntegerArray nameBytes = GetArray<uint8_t>(ptr, length, offset, entry.le_name_chunk, entry.le_name_numints);
	                    size_t nameLength = nameBytes.size();
	                    if (nameBytes.data<char>()[nameLength - 1] == 0)
	                        nameLength--;
	                    std::string nameStr(nameBytes.data<char>(), nameLength);
	                    IntegerArray valueArray = GetValueArray(ptr, length, offset, entry);
	                    ret.emplace_back(std::move(nameStr), std::move(valueArray));
	                    if (entry.le_next != 0xffff && hashEntries.insert(entry.le_next).second)
	                        itemsToProcess.push_back(entry.le_next);
	                    break;
	                }
	                case ZAP_CHUNK_FREE:
	                case ZAP_CHUNK_ARRAY:
	                default:
	                    throw std::runtime_error("not implemented");
	            }
	        }

	        if (hashEntries.size()!= leaf.lh_nentries)
	            throw std::runtime_error ("Did not find the correct number of entries.");
	    }

	    if (ret.size() != header.zap_num_entries)
	        throw std::runtime_error("Did not read the correct number of entries.");

	    return ret;
	}


	class zfs_config
	{
	public:
		struct device_t
		{
			std::string name;
			unsigned int device_id = 0;
			unsigned int top_level_id = 0;
		};

		explicit zfs_config(const std::string& filename)
		{
			std::ifstream f(filename);
			std::string line;
			while (std::getline(f, line))
			{
				while (!line.empty() && ::isspace(line[0]))
					line.erase(line.begin());
				if (line.empty() || line[0] == '#')
					continue;
				size_t sep_1 = line.find(':');
				size_t sep_2 = line.find(':', sep_1+1);
				if (sep_2 == std::string::npos)
					throw std::runtime_error("Invalid config line '" + line + "'");
				device_t device;
				device.name = line.substr(0, sep_1);
				size_t next_idx = 0;
				std::string devices_id_str = line.substr(sep_1+1, sep_2-sep_1-1);
				device.device_id = std::stoul(devices_id_str, &next_idx);
				if (next_idx != devices_id_str.size())
					throw std::runtime_error("Invalid device id '" + devices_id_str + "' in line '" + line + "'");
				std::string top_level_id_str = line.substr(sep_2+1);
				device.top_level_id = std::stoul(top_level_id_str, &next_idx);
				if (next_idx != top_level_id_str.size())
					throw std::runtime_error("Invalid parent id '" + top_level_id_str + "' in line '" + line + "'");
				devices_.push_back(device);
				devices_by_top_level_id_.resize(device.top_level_id+1);
				devices_by_top_level_id_[device.top_level_id].push_back(device);
			}
		}

		const std::vector<device_t>& devices() const { return devices_; }
		const std::vector<device_t>& devices_with_top_level_id(uint32_t top_level_id) const
		{
			if (top_level_id >= devices_by_top_level_id_.size())
				throw std::runtime_error("Invalid parent id " + std::to_string(top_level_id) + ", max allowed: " + std::to_string(devices_by_top_level_id_.size()));
			return devices_by_top_level_id_[top_level_id];
		}

	private:
		std::vector<device_t> devices_;
		std::vector<std::vector<device_t>> devices_by_top_level_id_;
	};

	inline uint64_t raw_offset_to_physical_offset(uint64_t dva_offset)
	{
		return dva_offset + 0x400000;
	}

	inline uint64_t dva_offset_to_physical_offset(uint64_t dva_offset)
	{
		// dva_offset is in 512b sectors
		return (dva_offset << 9) + 0x400000;
	}

	inline uint64_t physical_offset_to_dva_offset(uint64_t physical_offset)
	{
		// dva_offset is in 512b sectors
		return (physical_offset - 0x400000) >> 9;
	}

	inline uint64_t raw_offset_to_dva_offset(uint64_t raw_offset)
	{
		if (raw_offset % 512 != 0)
			throw std::runtime_error("raw offset is not a multiple of 512 (sector size)");
		return raw_offset >> 9;
	}

	// ZFS Data Virtual Address
	struct zfs_data_address
	{
		uint32_t vdev_id = 0;
		uint64_t offset = 0; // in sectors (512 bytes), starting from ZFS data start, see dva_offset_to_physical_offset function
		uint64_t size = 0; // in bytes

		uint64_t physical_vdev_offset() const { return dva_offset_to_physical_offset(offset); }

		bool operator == (const zfs_data_address& rhs) const
		{
			// we don't compare size on purpose
			return vdev_id == rhs.vdev_id && offset == rhs.offset;
		}
	};

	inline std::ostream& operator << (std::ostream& os, const zfs_data_address& addr)
	{
		os << std::hex << addr.vdev_id << ':' << std::hex << (addr.offset*512) << ':' << std::hex << addr.size << std::dec ;
		return os;
	}

	template<typename UnsignedInt>
	UnsignedInt hex_str_to_int(const char* str, const char* str_end)
	{
		if (str == str_end)
			throw std::runtime_error("Trying to hex parse an empty string");
		UnsignedInt value = 0;
		for (const char* s = str; s != str_end; ++s)
		{
			char ch = *s;
			if ('0' <= ch && ch <= '9')
				value = (value << 4) + uint8_t(ch - '0');
			else if ('A' <= ch && ch <= 'F')
				value = (value << 4) + (uint8_t(ch - 'A') + 10);
			else if ('a' <= ch && ch <= 'f')
				value = (value << 4) + (uint8_t(ch - 'a') + 10);
			else
				throw std::runtime_error("invalid hex string: " + std::string(str, str_end));
		}
		return value;
	}

	zfs_data_address parse_zfs_data_addr_string(const char* str, const char* str_end)
	{
		uint32_t vdev_id = 0xFFFFFFFF;
		uint64_t offset = 0xFFFFFFFFFFFFFFFF;
		uint64_t size = 0xFFFFFFFFFFFFFFFF;
		const char* start = str;
		for (const char* s = str; s != str_end; ++s)
		{
			if (*s == ':')
			{
				if (vdev_id == 0xFFFFFFFF)
					vdev_id = hex_str_to_int<uint32_t>(start, s);
				else if (offset == 0xFFFFFFFFFFFFFFFF)
					offset = hex_str_to_int<uint64_t>(start, s);
				start = s+1;
			}
		}
		if (vdev_id == 0xFFFFFFFF || offset == 0xFFFFFFFFFFFFFFFF)
			throw std::runtime_error("Error parsing ZFS data address: " + std::string(str, str_end));
		if (offset % 512 != 0)
			throw std::runtime_error("Invalid offset in ZFS DVA, must be divisible by 512");
		offset /= 512;
		size = hex_str_to_int<uint64_t>(start, str_end);
		return zfs_data_address{vdev_id, offset, size};
	}

	zfs_data_address parse_zfs_data_addr_string(const std::string& str)
	{
		return parse_zfs_data_addr_string(str.c_str(), str.c_str() + str.size());
	}

	inline bool is_valid(const zfs_data_address& addr) { return addr.size != 0 || addr.offset != 0; }
	inline bool is_zero(const zfs_data_address& addr) { return addr.size == 0 && addr.offset == 0 && addr.vdev_id == 0; }

	zfs_data_address dva_from_raw_offset(uint32_t vdev_id, uint64_t offset, size_t size)
	{
		return zfs_data_address { vdev_id, raw_offset_to_dva_offset(offset), size };
	}

	struct block_pointer_info
	{
		static constexpr size_t ADDR_COUNT = SPA_DVAS_PER_BP;
		zfs_data_address address[SPA_DVAS_PER_BP] = {};
		bool address_gang_flag[SPA_DVAS_PER_BP] = {};
		uint8_t compression_algo_idx = 0;
		uint8_t level = 0;
		uint8_t type = 0;
		uint64_t tgx = 0;
		uint32_t fill_count = 0;
		uint64_t data_size = 0;
	};

	inline bool operator == (const block_pointer_info& lhs, const block_pointer_info& rhs)
	{
		return memcmp(&lhs, &rhs, sizeof(block_pointer_info)) == 0;
	}

	const char* bpi_type_to_string(uint8_t bpi_type)
	{
		if (bpi_type < DMU_OT_NUMTYPES)
			return dmu_ot[bpi_type].ot_name;
		else
			return "INVALID";
	}

	std::ostream& operator << (std::ostream& os, const block_pointer_info& info)
	{
		os << "{" ;
		for (size_t i = 0; i != SPA_DVAS_PER_BP; ++i)
			if (is_valid(info.address[i]))
			{
				if (i != 0)
					os << ", " ;
				os << "dva[" << info.address[i]
					<< ", gang=" << (info.address_gang_flag[i] ? 'Y' : 'N')
					<< "]";
			}
		if (info.compression_algo_idx < ZIO_COMPRESS_FUNCTIONS)
			os << ", compr=" << zio_compress_table[info.compression_algo_idx].ci_name;
		else
			os << ", compr=INVALID[" << (unsigned)info.compression_algo_idx << ']';
		os << ", level=" << (unsigned)info.level;
		if (info.type < DMU_OT_NUMTYPES)
			os << ", type=" << dmu_ot[info.type].ot_name;
		else
			os << ", type=INVALID[" << (unsigned)info.type << ']';
		os << ", tgx=" << std::dec << info.tgx ;
		os << ", fill_count=" << info.fill_count ;
		os << ", data_size=" << info.data_size ;
		os << "}" ;

		return os;
	}

	class zfs_pool
	{
	public:
		explicit zfs_pool(const zfs_config& config) : config_(config)
		{
			for (const zfs_config::device_t& dev : config_.devices())
			{
				if (raw_devices_by_top_level_id_.size() <= dev.top_level_id)
					raw_devices_by_top_level_id_.resize(dev.top_level_id+1);
				Device device(dev.name);
				uint64_t max_valid_device_dva_offset = device.size() / 512; // dva offset is in 512 byte sectors
				if (max_valid_dva_offset_ < max_valid_device_dva_offset)
					max_valid_dva_offset_ = max_valid_device_dva_offset;
				raw_devices_by_top_level_id_[dev.top_level_id].push_back(std::move(device));
			}
		}

		data_view_t get_block(const zfs_data_address& address)
		{
			if (address.vdev_id >= raw_devices_by_top_level_id_.size())
				throw std::runtime_error("Invalid parent id " + std::to_string(address.vdev_id) + ", max allowed: " + std::to_string(raw_devices_by_top_level_id_.size()));
			const std::vector<Device>& devices = raw_devices_by_top_level_id_[address.vdev_id];
			uint64_t physical_offset = dva_offset_to_physical_offset(address.offset);
			if (physical_offset + address.size > devices[0].size())
				throw std::runtime_error("Device " + devices[0].filename() + " size=" + std::to_string(devices[0].size()) + " but trying to read " + std::to_string(address.size) + " from offset " + std::to_string(physical_offset));
			for (size_t d = 1; d != devices.size(); ++d)
			{
				if (physical_offset + address.size > devices[d].size())
					throw std::runtime_error("Device " + devices[d].filename() + " size=" + std::to_string(devices[d].size()) + " but trying to read " + std::to_string(address.size) + " from offset " + std::to_string(physical_offset));
#ifdef ENABLE_ZFS_POOL_READER_MIRROR_MATCHING
				bool match = (memcmp(devices[0].data() + physical_offset, devices[d].data() + physical_offset, address.size) == 0);
				if (!match)
					throw std::runtime_error("Mismatch reading data, " + devices[0].name() + " vs " + devices[d].name());
#endif
			}
			return data_view_t { devices[0].data() + physical_offset, address.size };
		}

		uint64_t max_valid_dva_offset() const { return max_valid_dva_offset_; }

		size_t max_top_level_vdev_id() const { return raw_devices_by_top_level_id_.size()-1; }

		size_t get_device_size_by_top_level_id(uint32_t top_level_id) const
		{
			if (top_level_id >= raw_devices_by_top_level_id_.size())
				throw std::runtime_error("Invalid parent id " + std::to_string(top_level_id) + ", max allowed: " + std::to_string(raw_devices_by_top_level_id_.size()));
			if (raw_devices_by_top_level_id_[top_level_id].empty())
				throw std::runtime_error("Invalid parent id " + std::to_string(top_level_id) + ", max allowed: " + std::to_string(raw_devices_by_top_level_id_.size()));
			return raw_devices_by_top_level_id_[top_level_id][0].size();
		}

		const zfs_config& config() const { return config_; }

	private:
		zfs_config config_;
		uint64_t max_valid_dva_offset_ = 0;
		std::vector<std::vector<Device>> raw_devices_by_top_level_id_;
	};

	bool is_potential_zap_phys_block(const uint8_t* data, size_t size)
	{
		const zap_phys_t& header = get_mem_pod<zap_phys_t>(data, 0, size);
		if (header.zap_block_type != ZBT_HEADER)
			return false;
		if (header.zap_magic != ZAP_MAGIC)
			return false;
		if (header.zap_num_entries > 10000000)
			return false;
		return true;
	}

	void decompress(uint8_t compression_method_idx, const uint8_t* const src, size_t size, std::vector<uint8_t>& out)
	{
		decompression_error error;
		// see zio_compress structure
		if (compression_method_idx == ZIO_COMPRESS_LZJB)
		{
			size_t src_size = lzjb_decompress(src, size, out, error);
			if (src_size == 0)
				throw std::runtime_error("LZJB error: " + error.to_string());
		}
		else if (compression_method_idx == ZIO_COMPRESS_ZLE)
		{
			size_t src_size = zle_decompress(src, size, out, error);
			if (src_size == 0)
				throw std::runtime_error("ZLE error: " + error.to_string());
		}
		else if (compression_method_idx == ZIO_COMPRESS_LZ4)
		{
			size_t src_size = lz4_decompress(src, size, out, error);
			if (src_size == 0)
				throw std::runtime_error("LZ4 error: " + error.to_string());
		}
		else
			throw std::runtime_error("Unsupported compression method " + std::to_string(compression_method_idx));
	}

	bool is_potential_gang_block_pointer(const uint8_t* data, size_t size)
	{
		if (size < 512)
			return false;
		const zio_gbh_phys_t& gbh = get_mem_pod<zio_gbh_phys_t>(data, 0, size);
		if (gbh.zg_tail.zec_magic != ZEC_MAGIC)
			return false;
		return true;
	}

	bool get_zfs_dva_gang_flag(const dva_t& dva)
	{
		return (dva.dva_word[1] & (static_cast<uint64_t>(1)<<63)) != 0;
	}

	uint32_t get_zfs_dva_dev_id(const dva_t& dva)
	{
		return dva.dva_word[0] >> 32;
	}

	uint64_t get_zfs_dva_offset(const dva_t& dva)
	{
		return dva.dva_word[1] & (~(static_cast<uint64_t>(1)<<63));
	}

	// returns original, potentially compressed, raw data
	template<class Receiver, size_t SIZE_COUNT>
	data_view_t read_block(
		zfs_pool& pool,
		const zfs_data_address& dva,
		const std::array<size_t, SIZE_COUNT>& sizes_to_try,
		zfs_decompressed_block_data_storage_t& dest_data,
		const Receiver& receiver
		)
	{
		data_view_t original_raw_data = pool.get_block(dva);
		try_decompress(original_raw_data.data(), sizes_to_try, dest_data);
		for (const auto& block : dest_data.decompressed_blocks)
			receiver(dest_data.decompressed_blocks.size()+1, block.data(), block.size(), block.original_size());
		receiver(dest_data.decompressed_blocks.size()+1, original_raw_data.data(), original_raw_data.size(), original_raw_data.size());
		return original_raw_data;
	}

	bool is_indirect_block_pointer_checksum_valid(const blkptr& block_pointer, const uint8_t* data, size_t data_size)
	{
		size_t checksum_algorithm_idx = BP_GET_CHECKSUM(&block_pointer);
		if (checksum_algorithm_idx >= ZIO_CHECKSUM_FUNCTIONS)
			return false;
		zio_checksum_info_t& checksum_info = zio_checksum_table[checksum_algorithm_idx];
		zio_cksum_t cksum;
		(*checksum_info.ci_func[0])(data, data_size, nullptr, &cksum);
		return ZIO_CHECKSUM_EQUAL(cksum, block_pointer.blk_cksum);
	}

	zio_gbh_phys_t read_gang_block_pointer(zfs_pool& pool, const zfs_data_address& dva)
	{
		data_view_t block = pool.get_block(dva);
		std::ofstream tmp("gbl___.bin");
		tmp.write(reinterpret_cast<const char*>(block.data()), block.size());

		if (is_potential_gang_block_pointer(block.data(), block.size()))
			return get_mem_pod<zio_gbh_phys_t>(block.data(), 0, block.size());
		zfs_decompressed_block_data_storage_t decompressed_data;
		try_decompress(block.data(), std::array<size_t, 1>{block.size()}, decompressed_data);
		for (size_t block_idx = 0; block_idx != decompressed_data.decompressed_blocks.size(); ++block_idx)
		{
			std::cout << "sizeof(blkptr)=" << sizeof(blkptr) << std::endl ;
			std::cout << "SPA_GBH_FILLER=" << SPA_GBH_FILLER << std::endl;
			const auto& data = decompressed_data.decompressed_blocks[block_idx];
			std::ofstream tmp("gbl_" + std::to_string(block_idx) + ".bin");
			tmp.write(reinterpret_cast<const char*>(data.data()), data.size());
			std::cout << data.size() << std::endl ;
			std::cout << is_potential_gang_block_pointer(data.data(), data.size()) << std::endl ;
			std::cout << sizeof(zio_gbh_phys_t) << std::endl ;
		}
	}

	// returns -1 in case of a fatal error
	// returns number of valid DVAs in the block pointer (can be zero)
	int try_parse_block_pointer(zfs_pool* pool, const blkptr_t& ptr, block_pointer_info& info)
	{
		static_assert(sizeof(blkptr_t)%8 == 0, "");
		bool all_zeroes = true;
		for (size_t i = 0; i != (sizeof(blkptr_t)/8); ++i)
			if (reinterpret_cast<const uint64_t*>(&ptr)[i] != 0)
			{
				all_zeroes = false;
				break;
			}
		if (all_zeroes)
			return 0;

		if (BP_GET_CHECKSUM(&ptr) >= ZIO_CHECKSUM_FUNCTIONS
			|| BP_GET_COMPRESS(&ptr) >= ZIO_COMPRESS_FUNCTIONS
			|| BP_GET_TYPE(&ptr) >= DMU_OT_NUMTYPES
			)
		{
			return -1;
		}

		size_t valid_ptr_count = 0;

		info.compression_algo_idx = BP_GET_COMPRESS(&ptr);
		info.level = BP_GET_LEVEL(&ptr);
		info.type = BP_GET_TYPE(&ptr);
		info.tgx = BP_PHYSICAL_BIRTH(&ptr);
		info.fill_count = BP_GET_FILL(&ptr);
		info.data_size = BP_GET_LSIZE(&ptr);

		if (!(BP_IS_HOLE(&ptr)))
		{
			std::array<uint64_t, SPA_DVAS_PER_BP> offsets;
			for (size_t dva_idx = 0; dva_idx != SPA_DVAS_PER_BP; ++dva_idx)
			{
				uint32_t vdev_id = DVA_GET_VDEV(&ptr.blk_dva[dva_idx]);
				uint64_t offset = (DVA_GET_OFFSET(&ptr.blk_dva[dva_idx]) >> SPA_MINBLOCKSHIFT);
				uint64_t size = DVA_GET_ASIZE(&ptr.blk_dva[dva_idx]);
				if (offset < 1024)
					offset = 0;
				offsets[dva_idx] = offset;
				if ((offset != 0 && size == 0) || (pool && (vdev_id > pool->max_top_level_vdev_id() || offset > pool->max_valid_dva_offset())))
				{
					return -1;
				}
				++valid_ptr_count;
				info.address[dva_idx].vdev_id = vdev_id;
				info.address[dva_idx].offset = offset;
				info.address[dva_idx].size = size;
				info.address_gang_flag[dva_idx] = DVA_GET_GANG(&ptr.blk_dva[dva_idx]);
				if (info.address_gang_flag[dva_idx])
				{
					std::cerr << "Gang? " << info.address << std::endl ;
				}
			}
			static_assert(SPA_DVAS_PER_BP == 3, "");
			if ((offsets[0] == 0 && offsets[1] == 0 && offsets[2] == 0) && info.data_size == 0)
			{
				return -1;
			}
		}
		return valid_ptr_count;
	}

	bool try_parse_indirect_block(zfs_pool* pool, const uint8_t* data, size_t data_size, std::vector<block_pointer_info>& results)
	{
		if (data_size < sizeof(blkptr_t))
			return false;

		size_t results_initial_size = results.size();

		size_t valid_ptr_count = 0;
		for (size_t blk_ptr_offset = 0; blk_ptr_offset + sizeof(blkptr_t) <= data_size; blk_ptr_offset += sizeof(blkptr_t))
		{
			const blkptr_t& ptr = get_mem_pod<blkptr_t>(data, blk_ptr_offset, data_size);
			block_pointer_info info;
			int parse_res = try_parse_block_pointer(pool, ptr, info);
			if (parse_res == -1)
			{
				results.resize(results_initial_size);
				return false;
			}
			valid_ptr_count += parse_res;
			if (parse_res != 0 || info.data_size != 0)
				results.push_back(info);
		}

		return true;
	}

	// reusing 'decompressed_block_data_storage' to make sure we don't keep reallocating memory
	// if dva_alt_sizes_to_try is non empty, 'size' from 'dva' is ignored
	// and the bi
	template<size_t SIZE_COUNT>
	size_t read_indirect_blocks(
		zfs_pool& pool,
		const zfs_data_address& dva,
		const std::array<size_t, SIZE_COUNT>& sizes_to_try,
		zfs_decompressed_block_data_storage_t& decompressed_block_data_storage,
		std::vector<block_pointer_info>& results
		)
	{
		results.clear();

		size_t final_original_size = 0;

		read_block(
			pool,
			dva,
			sizes_to_try,
			decompressed_block_data_storage,
			[&dva, &pool, &results, &final_original_size](size_t potential_results_count, const uint8_t* data, size_t data_size, size_t original_size)
			{
				bool success = try_parse_indirect_block(&pool, data, data_size, results);
				if (success)
					final_original_size = original_size;
			}
			);

		return final_original_size;
	}

	std::vector<block_pointer_info> read_all_indirect_blocks(zfs_pool& pool, const zfs_data_address& dva, zfs_decompressed_block_data_storage_t& decompressed_block_data_storage)
	{
		std::vector<block_pointer_info> top_level;
		read_indirect_blocks(pool, dva, std::array<size_t, 1>{dva.size}, decompressed_block_data_storage, top_level);
		for (const block_pointer_info& bpi : top_level)
			std::cout << bpi << std::endl ;
		size_t top_level_size = top_level.size();
		for (size_t i = 0; i != top_level_size; ++i)
		{
			const block_pointer_info& bpi = top_level[i];
			if (bpi.level != 0)
			{
				std::vector<block_pointer_info> children = read_all_indirect_blocks(pool, bpi.address[0], decompressed_block_data_storage);
				top_level.insert(top_level.end(), children.begin(), children.end());
			}
		}
		return top_level;
	}

	struct __attribute__((packed)) serialized_zfs_data_address
	{
		serialized_zfs_data_address() = default;
		serialized_zfs_data_address(const zfs_data_address& addr)
			: vdev_id_and_offset((static_cast<uint64_t>(addr.vdev_id) << 56) + addr.offset)
			, size(addr.size)
		{}
		uint64_t vdev_id_and_offset = 0; // (vdev_id << 56) + (size in 512 byte sectors)
		uint64_t size = 0;

		void unserialize_into(zfs_data_address& dest) const
		{
			dest.vdev_id = vdev_id_and_offset >> 56;
			dest.offset = vdev_id_and_offset & 0xFFFFFFFFFFFFFF;
			dest.size = size;
		}
	};

	struct __attribute__((packed)) serialized_bpi_array_header
	{
		uint32_t data_size = 0; // including this header
		uint32_t bpi_count = 0;
		serialized_zfs_data_address addr;
	};

	struct __attribute__((packed)) serialized_bpi
	{
		serialized_bpi() = default;
		serialized_bpi(const block_pointer_info& bpi)
			: address{bpi.address[0], bpi.address[1], bpi.address[2] }
			, tgx(bpi.tgx)
			, address_gang_mask((bpi.address_gang_flag[0] ? 1 : 0) | (bpi.address_gang_flag[1] ? (1<<1) : 0) | (bpi.address_gang_flag[2] ? (1<<2) : 0))
			, compression_algo_idx(bpi.compression_algo_idx)
			, level(bpi.level)
			, type(bpi.type)
		{
			static_assert(SPA_DVAS_PER_BP == 3, "");
		}
		serialized_zfs_data_address address[SPA_DVAS_PER_BP] = {};
		uint64_t tgx = 0;
		uint8_t address_gang_mask = 0;
		uint8_t compression_algo_idx = 0;
		uint8_t level = 0xFF;
		uint8_t type = 0xFF;

		void unserialize_into(block_pointer_info& dest) const
		{
			dest.tgx = tgx;
			dest.compression_algo_idx = compression_algo_idx;
			address[0].unserialize_into(dest.address[0]);
			address[1].unserialize_into(dest.address[1]);
			address[2].unserialize_into(dest.address[2]);
			dest.address_gang_flag[0] = address_gang_mask & 1;
			dest.address_gang_flag[1] = address_gang_mask & (1 << 1);
			dest.address_gang_flag[2] = address_gang_mask & (1 << 2);
			dest.level = level;
			dest.type = type;
		}
	};

	// Next step - find all potential indirect block pointers


	void serialize_block_pointers(RWFile& out, const zfs_data_address& addr, const std::vector<block_pointer_info>& block_pointers)
	{
		serialized_bpi_array_header header
			{
				static_cast<uint32_t>(sizeof(serialized_bpi_array_header) + sizeof(serialized_bpi)*block_pointers.size()),
				static_cast<uint32_t>(block_pointers.size()),
				addr
			};
		out.write(&header, sizeof(header));
		for (const block_pointer_info& bpi : block_pointers)
		{
			serialized_bpi sbpi(bpi);
			out.write(&sbpi, sizeof(sbpi));
		}
	}

	template<class Handler>
	void read_serialized_block_pointers(ROFile& in, Handler&& handler)
	{
		size_t size = in.size();
		size_t position = in.get_position();
		size_t remaining_size = size - position;

		serialized_bpi_array_header header;

		std::vector<serialized_bpi> serialized_block_pointers;

		zfs_data_address addr_for_handler;
		std::vector<block_pointer_info> block_pointers_for_handler;

		while (remaining_size >= sizeof(serialized_bpi_array_header))
		{
			size_t pos_in_file = in.get_position();
			in.read(&header, sizeof(header));
			if (header.data_size != sizeof(serialized_bpi_array_header) + sizeof(serialized_bpi)*header.bpi_count)
				throw std::runtime_error("Invalid input format while reading serialized block pointers from '" + in.filename() + "'");
			serialized_block_pointers.resize(header.bpi_count);
			for (serialized_bpi& bpi : serialized_block_pointers)
				in.read(&bpi, sizeof(bpi));
			header.addr.unserialize_into(addr_for_handler);
			block_pointers_for_handler.resize(serialized_block_pointers.size());
			for (size_t i = 0; i != block_pointers_for_handler.size(); ++i)
				serialized_block_pointers[i].unserialize_into(block_pointers_for_handler[i]);

			size_t pos_in_file_before_handler = in.get_position();
			bool continue_reading = handler(pos_in_file, addr_for_handler, block_pointers_for_handler);
			// in case handler resets the position
			in.set_position(pos_in_file_before_handler);
			if (!continue_reading)
				break;
			remaining_size -= header.data_size;
		}
	}

	void read_serialized_block_pointer(ROFile& in, size_t pos_in_file, zfs_data_address& addr, std::vector<block_pointer_info>& bpis)
	{
		in.set_position(pos_in_file);
		serialized_bpi_array_header header;
		in.read(&header, sizeof(header));
		if (header.data_size != sizeof(serialized_bpi_array_header) + sizeof(serialized_bpi)*header.bpi_count)
			throw std::runtime_error("Invalid input format while reading serialized block pointers from '" + in.filename() + "'");
		std::vector<serialized_bpi> serialized_block_pointers;
		serialized_block_pointers.resize(header.bpi_count);
		for (serialized_bpi& bpi : serialized_block_pointers)
			in.read(&bpi, sizeof(bpi));
		header.addr.unserialize_into(addr);
		bpis.resize(serialized_block_pointers.size());
		for (size_t i = 0; i != bpis.size(); ++i)
			serialized_block_pointers[i].unserialize_into(bpis[i]);
	}

	void scan_device_for_potential_indirect_block_pointers(zfs_pool& pool, uint32_t vdev_id, RWFile& in_out, RWFile& state_file)
	{
		size_t vdev_size = pool.get_device_size_by_top_level_id(vdev_id);
		// offset in 512 byte sectors
		uint64_t start_offset = 0;
		uint64_t max_offset = vdev_size / 512 - 1;

		struct __attribute__((packed)) State
		{
			uint64_t offset;
		};

		size_t initial_state_size = state_file.size();
		if (initial_state_size < sizeof(State))
			state_file.resize(sizeof(State));

		MMRWFileView state_file_view(state_file);
		::memset(state_file_view.data() + initial_state_size, 0, state_file_view.size() - initial_state_size);
		State& state = *reinterpret_cast<State*>(state_file_view.data());

		printf("Read previous state.offset=%lu\n", state.offset);

		if (in_out.size() != 0)
		{
			size_t record_count = 0;
			read_serialized_block_pointers(
				in_out,
				[&start_offset, &record_count, vdev_id](size_t pos_in_file, const zfs_data_address& addr, const std::vector<block_pointer_info>& bpis)
				{
					if (addr.vdev_id == vdev_id)
					{
						start_offset = addr.offset+1;
						++record_count;
					}
					return true;
				}
				);

			in_out.resize(in_out.get_position());
			in_out.set_position(in_out.size());

			printf("Loaded %lu records for vdev %u from file %s, next offset is %lu\n", record_count, vdev_id, in_out.filename().c_str(), start_offset);
			printf("File size=%lu, pos=%lu\n", in_out.size(), in_out.get_position());
		}

		if (state.offset > start_offset)
			start_offset = state.offset;

		zfs_decompressed_block_data_storage_t decompressed_block_data_storage;

		std::vector<block_pointer_info> block_pointers;

		for (uint64_t offset = start_offset; offset != max_offset; ++offset)
		{
			if ((offset % (max_offset/100)) == 0)
			{
				printf("[vdev=%u]->%u %% complete\n", unsigned(vdev_id), unsigned(100*offset/max_offset));
			}
			zfs_data_address addr{vdev_id, offset, 0};
			block_pointers.clear();
			size_t final_original_size = read_indirect_blocks(pool, addr, std::array<size_t, 3>{0x1000, 0x2000, 0x4000}, decompressed_block_data_storage, block_pointers);
			addr.size = final_original_size;
			if (!block_pointers.empty())
				serialize_block_pointers(in_out, addr, block_pointers);
			state.offset = offset;
		}
	}

	void scan_top_level_devices_for_potential_indirect_block_pointers(zfs_pool& pool, const std::string& filename_prefix, std::vector<uint32_t> vdev_ids = {})
	{
		std::vector<std::thread> threads;
		for (uint32_t vdev_id = 0; vdev_id != pool.max_top_level_vdev_id()+1; ++vdev_id)
		{
			if (vdev_ids.size() == 0 || std::find(vdev_ids.begin(), vdev_ids.end(), vdev_id) != vdev_ids.end())
			{
				threads.emplace_back(
					[&pool, filename_prefix, vdev_id]()
					{
						RWFile in_out(filename_prefix + "_" + std::to_string(vdev_id), RWFile::CREATE_IF_NOT_EXISTS);
						RWFile state_file(filename_prefix + "_" + std::to_string(vdev_id) + ".state", RWFile::CREATE_IF_NOT_EXISTS);
						printf("[vdev=%u]->%s\n", unsigned(vdev_id), in_out.filename().c_str());
						scan_device_for_potential_indirect_block_pointers(pool, vdev_id, in_out, state_file);
					}
					);
			}
		}
		for (std::thread& t : threads)
			t.join();
	}


	std::vector<zfs_data_address> load_zfs_data_addresses_from_file(const zfs_config* zfs_config, const std::string& filename)
	{
		std::string line;
		std::ifstream f(filename);
		std::unordered_map<std::string, uint32_t> device_id_by_name;
		if (zfs_config)
			for (const zfs_config::device_t& dev : zfs_config->devices())
				device_id_by_name[dev.name] = dev.top_level_id;

		std::vector<zfs_data_address> addresses;

		while (std::getline(f, line))
		{
			if (!line.empty())
			{
				if (line[0] == '=')
				{
					if (!zfs_config)
						throw std::runtime_error("Can't parse device name syntax without zfs pool being passed");
					size_t coma_pos = line.find(',', 1);
					std::string device_name = line.substr(1, coma_pos-1);
					size_t offset = std::stoul(line.substr(coma_pos+1));
					if (offset == 0)
						throw std::runtime_error("Invalid syntax in file " + filename);
					auto it = device_id_by_name.find(device_name);
					if (it == device_id_by_name.end())
						throw std::runtime_error("Invalid device name '" + device_name + "' in file " + filename);

					zfs_data_address addr;
					addr.vdev_id = it->second;
					addr.size = 4096;
					addr.offset = physical_offset_to_dva_offset(offset);
					if (std::find(addresses.begin(), addresses.end(), addr) == addresses.end())
						addresses.push_back(addr);
				}
				else
				{
					addresses.push_back(parse_zfs_data_addr_string(line.data(), line.data() + line.size()));
				}
			}
		}
		return addresses;
	}

	void try_read_direntry(zfs_pool& pool, const std::vector<block_pointer_info>& bpis)
	{
		std::vector<std::vector<uint8_t>> data;
		std::vector<uint8_t> bpi_data;
		for (const block_pointer_info& bpi : bpis)
		{
			std::vector<std::vector<uint8_t>> new_data;
			for (const zfs_data_address& addr : bpi.address)
			{
				if (is_valid(addr))
				{
					try
					{
						data_view_t block = pool.get_block(addr);
						bpi_data.clear();
						decompress(bpi.compression_algo_idx, block.data(), block.size(), bpi_data);
						if (!data.empty())
						{
							for (std::vector<uint8_t>& v : data)
							{
								std::vector<uint8_t> tmp(v);
								tmp.insert(tmp.end(), bpi_data.begin(), bpi_data.end());
								new_data.push_back(std::move(tmp));
							}
						}
						else
							new_data.push_back(std::move(bpi_data));
					}
					catch(const std::exception& e)
					{
						std::cout << "decompression attempt error: " << e.what() << std::endl ;
					}
					bpi_data.clear();
				}
			}
			data = std::move(new_data);
		}
		size_t idx = 0;
		std::sort(data.begin(), data.end());
		data.erase(std::unique(data.begin(), data.end()), data.end());
		for (std::vector<uint8_t>& v : data)
		{
			if (false){
				std::ofstream FF("__TMP_" + std::to_string(idx) + ".bin");
				FF.write(reinterpret_cast<const char*>(v.data()), v.size());
				++idx;
			}
			try
			{
				std::vector<zap_entry> entries = parse_fat(v.data(), v.size(), v.size());
				for (const zap_entry& entry : entries)
				{
					std::cout << "Entry: " << entry << std::endl ;
				}
			}
			catch(const std::exception& e)
			{
				std::cout << "err: " << e.what() << std::endl ;
			}
		}
	}

	void try_read_direntry(zfs_pool& pool, std::vector<zfs_data_address> addresses)
	{
		std::vector<uint8_t> data;
		for (size_t addr_idx = 0; addr_idx != addresses.size(); ++addr_idx)
		{
			const zfs_data_address& addr = *(addresses.begin() + addr_idx);
			data_view_t block = pool.get_block(addr);
			zfs_decompressed_block_data_storage_t decompressed_data;
			try_decompress(block.data(), std::array<size_t, 1>{block.size()}, decompressed_data);
			std::vector<decompressed_data_view_t> views;
			for (const decompressed_data_view_t& v : decompressed_data.decompressed_blocks)
				if (addr_idx == 0 || is_potential_zap_phys_block(v.data(), v.size()))
					views.push_back(v);
			if (views.size() > 1)
			{
				for (const auto& b : views)
					printf("sz=%lu\n", b.size());
				throw std::runtime_error("Multiple decompression methods succeeded");
			}

			if (views.size() == 0)
			{
				printf("failed to decompress for addr_idx=%lu\n", addr_idx);
				data.insert(data.end(), block.data(), block.data() + block.size());
			}
			else
			{
				std::ofstream tmp("tt_" + std::to_string(addr_idx) + ".bin");
				tmp.write(reinterpret_cast<const char*>(views[0].data()), views[0].size());

				data.insert(data.end(), views[0].data(), views[0].data() + views[0].size());
			}
		}
		std::vector<zap_entry> entries = parse_fat(data.data(), data.size(), data.size());
		for (const zap_entry& entry : entries)
		{
			std::cout << "Entry: " << entry << std::endl ;
		}
	}

	template<class Receiver>
	bool read_data_from_block_pointer(zfs_pool& pool, const block_pointer_info& bpi, const Receiver& receiver)
	{
		std::vector<uint8_t> decompressed;
		std::cout << "Reading from bpi: " << bpi << std::endl ;
		if (is_zero(bpi.address[0]) && is_zero(bpi.address[1]) && is_zero(bpi.address[2]) && bpi.data_size != 0)
		{
			decompressed.resize(bpi.data_size);
		}
		else
		{
			for (size_t addr_idx = 0; addr_idx != block_pointer_info::ADDR_COUNT; ++addr_idx)
				if (is_valid(bpi.address[addr_idx]))
				{
					decompressed.clear();
					data_view_t block = pool.get_block(bpi.address[addr_idx]);
					try
					{
						decompress(bpi.compression_algo_idx, block.data(), block.size(), decompressed);
						break;
					}
					catch(const std::exception& e)
					{
						if (addr_idx == block_pointer_info::ADDR_COUNT-1)
						{
							std::ostringstream err;
							err << "Error decompressing data at " << bpi << ", block size = " << block.size() ;
							throw std::runtime_error(err.str());
						}
					}
				}
		}

		bool continue_reading;
		if (bpi.level == 0)
		{
			continue_reading = receiver(decompressed.data(), decompressed.size(), bpi);
		}
		else
		{
			continue_reading = receiver(0, 0, bpi);
			if (!continue_reading)
				return false;
			std::vector<block_pointer_info> child_bpis;
			if (!try_parse_indirect_block(&pool, decompressed.data(), decompressed.size(), child_bpis))
				throw std::runtime_error("Error parsing indirect block");
			for (const block_pointer_info& child_bpi : child_bpis)
			{
				continue_reading = read_data_from_block_pointer(pool, child_bpi, receiver);
				if (!continue_reading)
					return false;
			}
		}
		return continue_reading;
	}

	template<class Receiver>
	void read_data_from_block_pointers(zfs_pool& pool, const std::vector<block_pointer_info>& bpis, const Receiver& receiver)
	{
		for (const block_pointer_info& bpi : bpis)
		{
			bool continue_reading = read_data_from_block_pointer(pool, bpi, receiver);
			if (!continue_reading)
				return;
		}
	}

	std::ostream& operator << (std::ostream& os, const dnode_phys_t& dnode)
	{
		os << "dnode_phys_t{type: " << dmu_ot[dnode.dn_type].ot_name
			<< ", dn_extra_slots=" << (int)dnode.dn_extra_slots
			<< ", bonustype=" << (int)dnode.dn_bonustype
			<< ", dn_indblkshift=" << (int)dnode.dn_indblkshift
			<< ", dn_datablkszsec=" << (int)dnode.dn_datablkszsec
			<< ", flags=" << (int)dnode.dn_flags
			<< "}";


		if (dnode.dn_nblkptr != 0)
		{
			for (size_t i = 0; i!= dnode.dn_nblkptr; ++i)
			{
				block_pointer_info info;
				int parse_res = try_parse_block_pointer(nullptr, dnode.dn_blkptr[i], info);
				if (parse_res > 0)
				{
					for (const zfs_data_address& addr : info.address)
						if (is_valid(addr))
							std::cout << "{" << addr << "}";
				}
			}
		}

		return os;
	}

	void try_parse_data_as_dmu_block(zfs_pool* pool, const uint8_t* data, size_t size, size_t start_idx, size_t& unallocated_count, size_t& allocated_count, std::vector<dnode_phys_t>& out)
	{
		static_assert(sizeof(dnode_phys_t) == 512, "");
		size_t count = size/512;
		for (size_t i = 0; i != count; ++i)
		{
			const dnode_phys_t& node = get_mem_pod<dnode_phys_t>(data, i * 512, size);
			out.push_back(node);
			if (node.dn_type == DMU_OT_NONE)
				++unallocated_count;
			else
				++allocated_count;
		}
	}

	bool try_read_dmu_dnode(zfs_pool& pool, const zfs_data_address& dmu_root_addr, uint64_t obj_id, dnode_phys_t& result)
	{
		data_view_t dmu_root_data = pool.get_block(dmu_root_addr);
		zfs_decompressed_block_data_storage_t decompressed_data;
		try_decompress(dmu_root_data.data(), std::array<size_t, 1>{dmu_root_data.size()}, decompressed_data, &std::cout);

		size_t count = decompressed_data.decompressed_blocks.size();
		const std::vector<decompressed_data_view_t>& decompressed_views = decompressed_data.decompressed_blocks;
		if (count == 0)
			throw std::runtime_error("All decompression attempts failed");

		std::vector<block_pointer_info> results;

		for (size_t attempt = 0; attempt != count; ++attempt)
		{
			results.clear();
			decompressed_data_view_t data = decompressed_views[attempt];
			bool success = try_parse_indirect_block(&pool, data.data(), data.size(), results);
			if (success)
				break;
		}
		if (results.empty())
			throw std::runtime_error("Error parsing root dmu dnode indirect block pointer");

		size_t dmu_block_idx = 0;

		size_t level1_fill_count = 0;
		size_t level0_unallocated_count = 0;
		size_t level0_allocated_count = 0;
		size_t level1_total_size = 0;
		size_t level1_total_size_from_bpi = 0;
		size_t level0_bpi_count = 0;
		size_t level0_fill_count = 0;
		size_t expected_obj_id_at_level1_start = 0;
		std::vector<dnode_phys_t> dnodes;
		bool found_result = false;
		read_data_from_block_pointers(
			pool,
			results,
			[&](const uint8_t* data, size_t size, const block_pointer_info& bpi) -> bool
			{
				if (bpi.level == 0)
				{
					level1_total_size_from_bpi += bpi.data_size;
					level0_fill_count += bpi.fill_count;
					level1_total_size += size;
					++level0_bpi_count;
					dnodes.clear();
					try_parse_data_as_dmu_block(&pool, data, size, dmu_block_idx, level0_unallocated_count, level0_allocated_count, dnodes);
					for (size_t i = 0; i != dnodes.size(); ++i)
					{
						uint64_t idx = dmu_block_idx + i;
						std::cout << "idx=" << idx << ", " << dnodes[i] << std::endl ;
						if (idx == obj_id)
						{
							result = dnodes[i];
							found_result = true;
							std::cout << "Found result: " << result << std::endl ;
							return false;
						}
					}
					size_t count = dnodes.size();
					size_t count2 = size/512;
					dmu_block_idx += count;
					if (count != count2)
						fprintf(stderr, "count=%lu, count2=%lu\n", count, (size_t)count2);
					//if (count != bpi.fill_count)
//										throw std::runtime_error("foobar");
					//dmu_block_idx += bpi.fill_count;
				}
				else if (bpi.level == 1)
				{
					if (expected_obj_id_at_level1_start != dmu_block_idx)
					{
						dmu_block_idx = expected_obj_id_at_level1_start;
						printf("expected_obj_id_at_level1_start=%lu, dmu_block_idx=%lu\n", expected_obj_id_at_level1_start, dmu_block_idx);
						//throw std::runtime_error("foobar");
					}
					printf(
						"level0_unallocated_count=%lu, level1_fill_count=%lu, sum=%lu, level0_allocated_count=%lu, level1_total_size=%lu, level1_total_size_from_bpi=%lu, level0_bpi_count=%lu, level0_fill_count=%lu\n",
						level0_unallocated_count,
						level1_fill_count,
						level1_fill_count+level0_unallocated_count,
						level0_allocated_count,
						level1_total_size,
						level1_total_size_from_bpi,
						level0_bpi_count,
						level0_fill_count
						);

					level0_unallocated_count = 0;
					level0_allocated_count = 0;
					level1_fill_count = bpi.fill_count;
					level1_total_size = 0;
					level1_total_size_from_bpi = 0;
					level0_bpi_count = 0;
					level0_fill_count = 0;
					expected_obj_id_at_level1_start += (bpi.data_size / sizeof(blkptr_t)) * (bpi.data_size / sizeof(dnode_phys_t));
				}
				return true;
			}
			);
		return found_result;
	}

	void extract_filesystem_entry(zfs_pool& pool, const zfs_data_address& dmu_root, uint64_t obj_id)
	{
	}

}
