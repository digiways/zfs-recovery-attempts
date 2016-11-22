#include "device.hpp"
#include "zfs_try_decompress.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <stdint.h>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <set>
#include <algorithm>
#include <sys/zap_impl.h>
#include <sys/zap_leaf.h>

#define private private_non_keyword
#define class class_non_keyword
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/zio_checksum.h>
#include <sys/zio_compress.h>
#undef class
#undef private

//#include "zfs_standard_structures.hpp"

int highBit(uint64_t some)
{
    for (int i = 63; i >= 0; i--)
    {
        if (((1L << i) & some) != 0)
            return i;
    }
    throw std::runtime_error("high bit internal error");
}

template<class T>
const T& get_mem_pod(const uint8_t* ptr, size_t offset, size_t data_length)
{
	if (offset + sizeof(T) > data_length)
		throw std::runtime_error("out of bounds in get_mem_pod");
	return *reinterpret_cast<const T*>(ptr + offset);
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

struct zap_entry
{
	zap_entry(std::string&& n, IntegerArray&& i) : name(std::move(n)), value(std::move(i)) {}
	std::string name;
	IntegerArray value;
};

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
    printf("bs=%u\n", bs);
    const uint8_t* end = ptr + length;

    //--bs;
    std::vector<uint64_t> blkIds;
    printf("header.zap_ptrtbl.zt_numblks=%u\n", int(header.zap_ptrtbl.zt_numblks));
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

    printf("blkIds.size()=%u\n", int(blkIds.size()));

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
    	printf("base_offset=%lu\n", base_offset);
    	printf("blkIds[0]=%u, (blkIds[0] << bs)=%u\n", int(blkIds[0]), int((blkIds[0] << bs)));
    	base_offset -= (blkIds[0] << bs);
		printf("base_offset=%lu\n", base_offset);
    }
    for (uint64_t blkid : blkIds)
    {
    	printf("blkid=%lu\n", blkid);
        long offset = base_offset + (blkid << bs);
        printf("offset=%lu, base_offset=%lu, blkid=%lu, bs=%u, length=%lu\n", uint64_t(offset), base_offset, uint64_t(blkid), int(bs), length);
        const zap_leaf_phys_t::zap_leaf_header& leaf = get_mem_pod<zap_leaf_phys_t::zap_leaf_header>(ptr, offset, length);
        printf("got leaf, lh_block_type=%lx, nentries=%u\n", leaf.lh_block_type, int(leaf.lh_nentries));
        if (leaf.lh_magic != ZAP_LEAF_MAGIC)
            throw std::runtime_error("wrong lh_magic");
        if (leaf.lh_block_type != ZBT_LEAF)
        {
        	std::ostringstream err;
        	err << "leaf.lh_block_type is not ZBT_LEAF, but " << std::hex << leaf.lh_block_type;
        	throw std::runtime_error(err.str());
        }
        printf("bs=%u\n", int(bs));
        int numHashEntries = 1 << (bs - 5);

        printf("numHashEntries = %u\n", numHashEntries);

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

namespace zfs_recover_tools
{
	class zfs_config
	{
	public:
		struct device_t
		{
			std::string name;
			unsigned int device_id = 0;
			unsigned int parent_id = 0;
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
				std::string parent_id_str = line.substr(sep_2+1);
				device.parent_id = std::stoul(parent_id_str, &next_idx);
				if (next_idx != parent_id_str.size())
					throw std::runtime_error("Invalid parent id '" + parent_id_str + "' in line '" + line + "'");
				devices_.push_back(device);
				devices_by_parent_id_.resize(device.parent_id+1);
				devices_by_parent_id_[device.parent_id].push_back(device);
			}
		}

		const std::vector<device_t>& devices() const { return devices_; }
		const std::vector<device_t>& devices_with_parent_id(uint32_t parent_id) const
		{
			if (parent_id >= devices_by_parent_id_.size())
				throw std::runtime_error("Invalid parent id " + std::to_string(parent_id) + ", max allowed: " + std::to_string(devices_by_parent_id_.size()));
			return devices_by_parent_id_[parent_id];
		}

	private:
		std::vector<device_t> devices_;
		std::vector<std::vector<device_t>> devices_by_parent_id_;
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
		uint64_t offset = 0; // in sectors (512 bytes)
		uint64_t size = 0; // in bytes
	};

	inline bool is_valid(const zfs_data_address& addr) { return addr.size != 0 || addr.offset != 0; }

	zfs_data_address dva_from_raw_offset(uint32_t vdev_id, uint64_t offset, size_t size)
	{
		return zfs_data_address { vdev_id, raw_offset_to_dva_offset(offset), size };
	}

	class data_view_t
	{
	public:
		data_view_t(const uint8_t* data, size_t size) : data_(data), size_(size) {}
		const uint8_t* data() const { return data_; }
		size_t size() const { return size_; }
		uint8_t operator[](size_t pos)
		{
			if (pos >= size_)
				throw std::runtime_error("out of bounds data_view access");
			return data_[pos];
		}
	private:
		const uint8_t* const data_;
		const size_t size_;
	};

	class zfs_pool
	{
	public:
		explicit zfs_pool(const zfs_config& config) : config_(config)
		{
			for (const zfs_config::device_t& dev : config_.devices())
			{
				if (raw_devices_by_parent_id_.size() <= dev.parent_id)
					raw_devices_by_parent_id_.resize(dev.parent_id+1);
				Device device(dev.name);
				uint64_t max_valid_device_dva_offset = device.size() / 512; // dva offset is in 512 byte sectors
				if (max_valid_dva_offset_ < max_valid_device_dva_offset)
					max_valid_dva_offset_ = max_valid_device_dva_offset;
				raw_devices_by_parent_id_[dev.parent_id].push_back(std::move(device));
			}
		}

		data_view_t get_block(const zfs_data_address& address)
		{
			if (address.vdev_id >= raw_devices_by_parent_id_.size())
				throw std::runtime_error("Invalid parent id " + std::to_string(address.vdev_id) + ", max allowed: " + std::to_string(raw_devices_by_parent_id_.size()));
			const std::vector<Device>& devices = raw_devices_by_parent_id_[address.vdev_id];
			uint64_t physical_offset = dva_offset_to_physical_offset(address.offset);
			if (physical_offset + address.size > devices[0].size())
				throw std::runtime_error("Device " + devices[0].name() + " size=" + std::to_string(devices[0].size()) + " but trying to read " + std::to_string(address.size) + " from offset " + std::to_string(physical_offset));
			for (size_t d = 1; d != devices.size(); ++d)
			{
				if (physical_offset + address.size > devices[d].size())
					throw std::runtime_error("Device " + devices[d].name() + " size=" + std::to_string(devices[d].size()) + " but trying to read " + std::to_string(address.size) + " from offset " + std::to_string(physical_offset));
				bool match = (memcmp(devices[0].data() + physical_offset, devices[d].data() + physical_offset, address.size) == 0);
				if (!match)
					throw std::runtime_error("Mismatch reading data, " + devices[0].name() + " vs " + devices[d].name());
			}
			return data_view_t { devices[0].data() + physical_offset, address.size };
		}

		uint64_t max_valid_dva_offset() const { return max_valid_dva_offset_; }

		size_t max_parent_vdev_id() const { return raw_devices_by_parent_id_.size()-1; }

	private:
		zfs_config config_;
		uint64_t max_valid_dva_offset_ = 0;
		std::vector<std::vector<Device>> raw_devices_by_parent_id_;
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


	void try_read_direntry(zfs_pool& pool, std::initializer_list<zfs_data_address> addresses)
	{
		std::vector<uint8_t> data;
		for (size_t addr_idx = 0; addr_idx != addresses.size(); ++addr_idx)
		{
			const zfs_data_address& addr = *(addresses.begin() + addr_idx);
			data_view_t block = pool.get_block(addr);
			std::vector<std::vector<uint8_t>> decompressed_block = try_decompress(block.data(), block.size());
			if (addr_idx == 0)
			{
				decompressed_block.erase(
						std::remove_if(
								decompressed_block.begin(),
								decompressed_block.end(),
								[](const std::vector<uint8_t>& data) { return !is_potential_zap_phys_block(data.data(), data.size()); }
						),
						decompressed_block.end()
					);
			}
			if (decompressed_block.size() > 1)
			{
				for (const std::vector<uint8_t>& b : decompressed_block)
					printf("sz=%lu\n", b.size());
				throw std::runtime_error("Multiple decompression methods succeeded");
			}

			if (decompressed_block.size() == 0)
			{
				printf("failed to decompress for addr_idx=%lu\n", addr_idx);
				data.insert(data.end(), block.data(), block.data() + block.size());
			}
			else
			{
				std::ofstream tmp("tt_" + std::to_string(addr_idx) + ".bin");
				tmp.write(reinterpret_cast<const char*>(decompressed_block[0].data()), decompressed_block[0].size());

				data.insert(data.end(), decompressed_block[0].data(), decompressed_block[0].data() + decompressed_block[0].size());
			}
		}
		std::vector<zap_entry> entries = parse_fat(data.data(), data.size(), data.size());
		for (const zap_entry& entry : entries)
		{
			std::cout << "Entry: " << entry << std::endl ;
		}
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

	bool is_potential_indirect_block_pointer(zfs_pool& pool, const uint8_t* data, size_t size)
	{
		if (size < sizeof(blkptr))
			return false;

		size_t valid_ptr_count = 0;
		for (size_t blk_ptr_offset = 0; blk_ptr_offset + sizeof(blkptr) <= size; blk_ptr_offset += sizeof(blkptr))
		{
			const blkptr& ptr = get_mem_pod<blkptr>(data, blk_ptr_offset, size);

			if (BP_GET_CHECKSUM(&ptr) >= ZIO_CHECKSUM_FUNCTIONS)
				return false;

			if (BP_GET_COMPRESS(&ptr) >= ZIO_COMPRESS_FUNCTIONS)
				return false;

			if (BP_GET_TYPE(&ptr) >= DMU_OT_NUMTYPES)
				return false;

			for (size_t dva_idx = 0; dva_idx != SPA_DVAS_PER_BP; ++dva_idx)
			{
				uint32_t vdev_id = DVA_GET_VDEV(&ptr.blk_dva[dva_idx]);
				uint64_t offset = (DVA_GET_OFFSET(&ptr.blk_dva[dva_idx]) >> SPA_MINBLOCKSHIFT);
				if (vdev_id > pool.max_parent_vdev_id())
					return false;
				if (offset > pool.max_valid_dva_offset())
					return false;
				if (offset != 0)
					++valid_ptr_count;
			}
		}
		if (valid_ptr_count == 0)
			return false;
		return true;
	}

	std::vector<data_view_t> make_data_views(const std::vector<std::vector<uint8_t>>& blocks)
	{
		std::vector<data_view_t> views;
		views.reserve(blocks.size());
		for (const std::vector<uint8_t>& block : blocks)
			views.emplace_back(block.data(), block.size());
		return views;
	}

	struct data_block_views_t
	{
		data_view_t original_data;
		std::vector<std::vector<uint8_t>> decompressed_blocks;
		std::vector<data_view_t> all_views;

		data_block_views_t(const data_view_t& original) : original_data(original) {}
		data_block_views_t(const data_block_views_t&) = delete;
		data_block_views_t& operator=(const data_block_views_t&) = delete;
		data_block_views_t(data_block_views_t&&) = default;
		data_block_views_t& operator=(data_block_views_t&&) = default;
	};

	template<class Filter>
	data_block_views_t read_block(zfs_pool& pool, const zfs_data_address& dva, const Filter& filter)
	{
		data_block_views_t views(pool.get_block(dva));
		views.decompressed_blocks = try_decompress(views.original_data.data(), views.original_data.size());
		views.all_views.reserve(views.decompressed_blocks.size());
		for (const std::vector<uint8_t>& block : views.decompressed_blocks)
			if (filter(block.data(), block.size()))
				views.all_views.emplace_back(block.data(), block.size());
		if (filter(views.original_data.data(), views.original_data.size()))
			views.all_views.push_back(views.original_data);
		return views;
	}

	bool is_indirect_block_pointer_checksum_valid(const blkptr& block_pointer, const uint8_t* data, size_t data_size)
	{
		size_t checksum_algorithm_idx = BP_GET_CHECKSUM(&block_pointer);
		if (checksum_algorithm_idx >= ZIO_CHECKSUM_FUNCTIONS)
			return false;
		zio_checksum_info_t& checksum_info = zio_checksum_table[checksum_algorithm_idx];
		zio_cksum_t cksum;
		checksum_info.ci_func[0](data, data_size, &cksum);
		return ZIO_CHECKSUM_EQUAL(cksum, block_pointer.blk_cksum);
	}

	zio_gbh_phys_t read_gang_block_pointer(zfs_pool& pool, const zfs_data_address& dva)
	{
		data_view_t block = pool.get_block(dva);
		std::ofstream tmp("gbl___.bin");
		tmp.write(reinterpret_cast<const char*>(block.data()), block.size());

		if (is_potential_gang_block_pointer(block.data(), block.size()))
			return get_mem_pod<zio_gbh_phys_t>(block.data(), 0, block.size());
		std::vector<std::vector<uint8_t>> decompressed_block = try_decompress(block.data(), block.size());
		for (size_t block_idx = 0; block_idx != decompressed_block.size(); ++block_idx)
		{
			std::cout << "sizeof(blkptr)=" << sizeof(blkptr) << std::endl ;
			std::cout << "SPA_GBH_FILLER=" << SPA_GBH_FILLER << std::endl;
			const std::vector<uint8_t>& data = decompressed_block[block_idx];
			std::ofstream tmp("gbl_" + std::to_string(block_idx) + ".bin");
			tmp.write(reinterpret_cast<const char*>(data.data()), data.size());
			std::cout << data.size() << std::endl ;
			std::cout << is_potential_gang_block_pointer(data.data(), data.size()) << std::endl ;
			std::cout << sizeof(zio_gbh_phys_t) << std::endl ;
		}
	}

	struct block_pointer_info
	{
		zfs_data_address address[SPA_DVAS_PER_BP] = {};
		bool address_gang_flag[SPA_DVAS_PER_BP] = {};
		uint8_t compression_algo_idx = 0;
		uint8_t level = 0xFF;
		uint8_t type = 0xFF;
		uint64_t tgx = 0;
	};

	std::ostream& operator << (std::ostream& os, const block_pointer_info& info)
	{
		os << "{" ;
		for (size_t i = 0; i != SPA_DVAS_PER_BP; ++i)
			if (is_valid(info.address[i]))
			{
				if (i != 0)
					os << ", " ;
				os << "dva[dev=" << info.address[i].vdev_id
					<< ", offset=" << std::hex << info.address[i].offset << std::dec
					<< ", size=" << info.address[i].size
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
		os << ", tgx=" << info.tgx ;
		os << "}" ;

		return os;
	}

	std::vector<block_pointer_info> read_indirect_blocks(zfs_pool& pool, const zfs_data_address& dva)
	{
		data_block_views_t data_views = read_block(
			pool,
			dva,
			[&pool](const uint8_t* data, size_t sz)
			{
				return is_potential_indirect_block_pointer(pool, data, sz);
			}
			);
		if (data_views.all_views.size() == 0)
			throw std::runtime_error("no data views");
		if (data_views.all_views.size() != 1)
			throw std::runtime_error("more than 1 view");

		data_view_t data = data_views.all_views[0];

		std::vector<block_pointer_info> results;
		results.reserve(data.size() / sizeof(blkptr) + 1);

		for (size_t blk_ptr_offset = 0; blk_ptr_offset + sizeof(blkptr) <= data.size(); blk_ptr_offset += sizeof(blkptr))
		{
			const blkptr& ptr = get_mem_pod<blkptr>(data.data(), blk_ptr_offset, data.size());
			if (!(BP_IS_HOLE(&ptr)))
			{
				block_pointer_info info;
				for (size_t dva_idx = 0; dva_idx != SPA_DVAS_PER_BP; ++dva_idx)
				{
					uint32_t vdev_id = DVA_GET_VDEV(&ptr.blk_dva[dva_idx]);
					uint64_t offset = (DVA_GET_OFFSET(&ptr.blk_dva[dva_idx]) >> SPA_MINBLOCKSHIFT);
					if (offset != 0 || vdev_id != 0)
					{
						info.address[dva_idx].vdev_id = vdev_id;
						info.address[dva_idx].offset = offset;
						info.address[dva_idx].size = DVA_GET_ASIZE(&ptr.blk_dva[dva_idx]);
						info.address_gang_flag[dva_idx] = DVA_GET_GANG(&ptr.blk_dva[dva_idx]);
					}
				}
				info.compression_algo_idx = BP_GET_COMPRESS(&ptr);
				info.level = BP_GET_LEVEL(&ptr);
				info.type = BP_GET_TYPE(&ptr);
				info.tgx = BP_PHYSICAL_BIRTH(&ptr);
				results.push_back(info);
			}
		}

		return results;
	}

	std::vector<block_pointer_info> read_all_indirect_blocks(zfs_pool& pool, const zfs_data_address& dva)
	{
		std::vector<block_pointer_info> top_level = read_indirect_blocks(pool, dva);
		for (const block_pointer_info& bpi : top_level)
			std::cout << bpi << std::endl ;
		size_t top_level_size = top_level.size();
		for (size_t i = 0; i != top_level_size; ++i)
		{
			const block_pointer_info& bpi = top_level[i];
			if (bpi.level != 0)
			{
				std::vector<block_pointer_info> children = read_all_indirect_blocks(pool, bpi.address[0]);
				top_level.insert(top_level.end(), children.begin(), children.end());
			}
		}
		return top_level;
	}


}

int main()
{
	try
	{
		using namespace zfs_recover_tools;
		zfs_config config("zfs-raid.config");
		for (const zfs_config::device_t& device : config.devices())
			printf("Config: Device %s id=%u parent_id=%u\n", device.name.c_str(), unsigned(device.device_id), unsigned(device.parent_id));

		zfs_pool pool(config);
		try_read_direntry(pool, {dva_from_raw_offset(1, 0xd0bd22e000, 0x1000), dva_from_raw_offset(1, 0xd0bd22f000, 0x2000) });

		zfs_data_address test_dva = dva_from_raw_offset(1, 0xd0bd22e000, 0x1000);
		printf("dva.offset = %lx\n", test_dva.offset);
		test_dva = dva_from_raw_offset(1, 0xd0bd22f000, 0x2000);
		printf("dva.offset = %lx\n", test_dva.offset);

		//read_gang_block_pointer(pool, dva_from_raw_offset(1, 0xd0bd231000, 0x1000));
		std::vector<block_pointer_info> info = read_indirect_blocks(pool, dva_from_raw_offset(2, 0x1398734e000, 0x1000));//1, 0xd0bd231000, 0x1000));
		for (const block_pointer_info& bpi : info)
			std::cout << bpi << std::endl ;

		read_all_indirect_blocks(pool, dva_from_raw_offset(2, 0x1398734e000, 0x1000));//1, 0xd0bd231000, 0x1000));

		//return 0;
		data_view_t block = pool.get_block(dva_from_raw_offset(1, 0xd0bd231000, 0x1000));
		std::vector<std::vector<uint8_t>> decompressed_block = try_decompress(block.data(), block.size());
		for (size_t i = 0; i != decompressed_block.size(); ++i)
		{
			std::ofstream tmp("data_block_" + std::to_string(i) + ".bin");
			tmp.write(reinterpret_cast<const char*>(decompressed_block[i].data()), decompressed_block[i].size());
		}

		std::cout << block.size() << std::endl ;
		std::cout << decompressed_block.size() << std::endl ;
		return 0;
		Device data("data");
		uint64_t BlockSizeInBytes = data.size();
		printf("data size=%lu\n", BlockSizeInBytes);
		std::vector<zap_entry> entries = parse_fat(data.data(), data.size(), BlockSizeInBytes);
		for (const zap_entry& entry : entries)
		{
			std::cout << "Entry, name='" << entry.name << "'" << std::endl ;
		}
	}
	catch(const std::exception& e)
	{
		std::cerr << "Fatal error: " << e.what() << std::endl ;
	}
}
