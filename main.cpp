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

std::vector<long> ReadPointerTable(const uint8_t* ptr, int length, long startReadOffset, long numberOfBytesToRead)
{
	std::vector<long> ret;
	for (long i = 0; i < numberOfBytesToRead; i += 8)
	{
		long val = get_mem_pod<long>(ptr, startReadOffset + i, length);
		if (val != 0)
			ret.push_back(val);
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

	size_t size() { return data_.size() / element_size_; }

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

    std::vector<long> blkIds;
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

    if ((ulong)blkIds.size() != header.zap_num_leafs)
        throw std::runtime_error("Not enough leafs, blkIds.size()=" + std::to_string(blkIds.size()) + ", zap_num_leafs=" + std::to_string(header.zap_num_leafs));

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
    for (long blkid : blkIds)
    {
        long offset = base_offset + (blkid << bs);
        printf("offset=%lu, base_offset=%lu, blkid=%lu, bs=%u, length=%lu\n", uint64_t(offset), base_offset, uint64_t(blkid), int(bs), length);
        const zap_leaf_phys_t::zap_leaf_header& leaf = get_mem_pod<zap_leaf_phys_t::zap_leaf_header>(ptr, offset, length);
        printf("got leaf, lh_block_type=%lu, nentries=%u\n", leaf.lh_block_type, int(leaf.lh_nentries));
        if (leaf.lh_magic != ZAP_LEAF_MAGIC)
            throw std::runtime_error("wrong lh_magic");
        if (leaf.lh_block_type != ZBT_LEAF)
        {
        	std::ostringstream err;
        	err << "leaf.lh_block_type is not ZBT_LEAF, but " << std::hex << leaf.lh_block_type;
        	throw std::runtime_error(err.str());
        }
        int numHashEntries = 1 << (bs - 5);

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
            	printf("Got hash entry: %u\n", int(loc));
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

std::vector<uint8_t> read_file(const std::string& filename)
{
    std::streampos fsize = 0;
    std::ifstream file(filename, std::ios::binary );
    file.seekg( 0, std::ios::end );
    size_t sz = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(sz);
    file.read(reinterpret_cast<char*>(data.data()), sz);
    return data;
}

int main()
{
	try
	{
		std::vector<uint8_t> data = read_file("data");
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
