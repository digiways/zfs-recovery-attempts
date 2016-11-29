#include "file.hpp"
#include "zfs_try_decompress.hpp"
#include "zfs_recovery_tools.hpp"

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
#include <sys/zap_impl.h>
#include <sys/zap_leaf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unordered_map>
#include <algorithm>

#define private private_non_keyword
#define class class_non_keyword
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/zio_checksum.h>
#include <sys/zio_compress.h>
#undef class
#undef private

using namespace zfs_recover_tools;

void test1()
{
	zfs_config config("zfs-raid.config");
	for (const zfs_config::device_t& device : config.devices())
		printf("Config: Device %s id=%u top_level_id=%u\n", device.name.c_str(), unsigned(device.device_id), unsigned(device.top_level_id));

	zfs_pool pool(config);

	try_read_direntry(pool, {dva_from_raw_offset(1, 0xd0bd22e000, 0x1000), dva_from_raw_offset(1, 0xd0bd22f000, 0x2000) });

	zfs_data_address test_dva = dva_from_raw_offset(1, 0xd0bd22e000, 0x1000);
	printf("dva.offset = %lx\n", test_dva.offset);
	test_dva = dva_from_raw_offset(1, 0xd0bd22f000, 0x2000);
	printf("dva.offset = %lx\n", test_dva.offset);

#if 0
	//read_gang_block_pointer(pool, dva_from_raw_offset(1, 0xd0bd231000, 0x1000));
	std::vector<block_pointer_info> info = read_indirect_blocks(pool, dva_from_raw_offset(2, 0x1398734e000, 0x1000));//1, 0xd0bd231000, 0x1000));
	for (const block_pointer_info& bpi : info)
		std::cout << bpi << std::endl ;

	read_all_indirect_blocks(pool, dva_from_raw_offset(2, 0x1398734e000, 0x1000));//1, 0xd0bd231000, 0x1000));

	std::vector<zfs_data_address> addresses = load_missing_filename_search_data_file(pool, "missing_filename_search.txt");
	addresses.push_back(dva_from_raw_offset(1, 0xd0bd22e000, 0x1000));
	addresses.push_back(dva_from_raw_offset(1, 0xd0bd22f000, 0x2000));
	//addresses.push_back(dva_from_raw_offset(2, 0x1398734d000 / 512, 0x1000)); // expected to find: 2:1398734e000:1000
	addresses.push_back(dva_from_raw_offset(2, 0x9CC39A68, 0x1000)); // expected to find: 2:1398734e000:1000
	//0x9CC39A68
	//0x17235991
	return 0;
#endif

	data_view_t block = pool.get_block(dva_from_raw_offset(1, 0xd0bd231000, 0x1000));
	zfs_decompressed_block_data_storage_t decompressed_data;
	try_decompress(block.data(), std::array<size_t, 1>{block.size()}, decompressed_data);
	for (size_t i = 0; i != decompressed_data.decompressed_blocks.size(); ++i)
	{
		std::ofstream tmp("data_block_" + std::to_string(i) + ".bin");
		tmp.write(reinterpret_cast<const char*>(decompressed_data.decompressed_blocks[i].data()), decompressed_data.decompressed_blocks[i].size());
	}

	std::cout << block.size() << std::endl ;
	std::cout << decompressed_data.decompressed_blocks.size() << std::endl ;
}

void try_parse_fat_test()
{
	using namespace zfs_recover_tools;
	ROFile data_file_1("MATCH/1_d0bcdea000_1000-decompressed-maybe-1.bin");
	std::vector<uint8_t> data_1 = data_file_1.read();
	ROFile data_file_2("MATCH/1_d0bcdeb000_2000-decompressed.bin");
	std::vector<uint8_t> data_2 = data_file_2.read();
	std::vector<uint8_t> data(data_1);
	data.insert(data.end(), data_2.begin(), data_2.end());

	uint64_t BlockSizeInBytes = data.size();
	printf("data size=%lu\n", BlockSizeInBytes);
	std::vector<zap_entry> entries = parse_fat(data.data(), data.size(), BlockSizeInBytes);
	for (const zap_entry& entry : entries)
	{
		std::cout << "Entry, name='" << entry.name << "'" << std::endl ;
	}
}

int main()
{
	try
	{
		try_parse_fat_test();
	}
	catch(const std::exception& e)
	{
		std::cerr << "Fatal error: " << e.what() << std::endl ;
	}
}
