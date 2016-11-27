#include "device.hpp"
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

std::vector<zfs_data_address> load_missing_filename_search_data_file(zfs_pool& pool, const std::string& filename)
{
	std::string line;
	std::ifstream f(filename);
	std::unordered_map<std::string, uint32_t> device_id_by_name;
	for (const zfs_config::device_t& dev : pool.config().devices())
		device_id_by_name[dev.name] = dev.top_level_id;

	std::vector<zfs_data_address> addresses;

	while (std::getline(f, line))
	{
		if (!line.empty() && line[0] == '=')
		{
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
			addr.offset = offset / 512;
			if (std::find(addresses.begin(), addresses.end(), addr) == addresses.end())
				addresses.push_back(addr);
		}
	}
	return addresses;
}

void try_find(const std::vector<zfs_data_address>& addresses_to_find, const std::vector<std::string>& serialized_block_pointers_files)
{
	size_t bpi_count = 0;
	size_t addr_count = 0;
	for (const std::string& filename : serialized_block_pointers_files)
	{
		File file(filename, O_RDONLY);
		read_serialized_block_pointers(
			file,
			[&](const zfs_data_address& addr, const std::vector<block_pointer_info>& bpis)
			{
				for (const block_pointer_info& bpi : bpis)
				{
					for (size_t bpi_addr_idx = 0; bpi_addr_idx != block_pointer_info::ADDR_COUNT; ++bpi_addr_idx)
					{
						const zfs_data_address& bpi_addr = bpi.address[bpi_addr_idx];
						if (is_valid(bpi_addr))
						{
							++addr_count;
							for (const zfs_data_address& address_to_find : addresses_to_find)
							{
								if (//bpi_addr.vdev_id == address_to_find.vdev_id
									//&&
									bpi_addr.offset <= address_to_find.offset
									&& bpi_addr.offset >= address_to_find.offset - 16000)
								{
									std::cout << "Potential match, looking for " << address_to_find << ", found " << bpi_addr << std::endl ;
								}
							}
						}
					}
				}
				++bpi_count;
			}
			);
	}
	std::cout << "Tried " << bpi_count << " bpis with " << addr_count << " addresses" << std::endl ;
}

int main()
{
	try
	{
		using namespace zfs_recover_tools;
		zfs_config config("zfs-raid.config");
		for (const zfs_config::device_t& device : config.devices())
			printf("Config: Device %s id=%u top_level_id=%u\n", device.name.c_str(), unsigned(device.device_id), unsigned(device.top_level_id));

		zfs_pool pool(config);
#if 0
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
#endif

		std::vector<zfs_data_address> addresses = load_missing_filename_search_data_file(pool, "missing_filename_search.txt");
		addresses.push_back(dva_from_raw_offset(1, 0xd0bd22e000, 0x1000));
		addresses.push_back(dva_from_raw_offset(1, 0xd0bd22f000, 0x2000));
		//addresses.push_back(dva_from_raw_offset(2, 0x1398734d000 / 512, 0x1000)); // expected to find: 2:1398734e000:1000
		addresses.push_back(dva_from_raw_offset(2, 0x9CC39A68, 0x1000)); // expected to find: 2:1398734e000:1000
		//0x9CC39A68
		//0x17235991

		// TODO: Don't try to decompress same address (with bigger size) if decompression with smaller size has failed already
		try_find(addresses, {"backup/bpi_serialized_0", "backup/bpi_serialized_1", "backup/bpi_serialized_2", "backup/bpi_serialized_3"});
		return 0;
		for (const zfs_data_address& addr : addresses)
			std::cout << addr << std::endl ;


		return 0;
		data_view_t block = pool.get_block(dva_from_raw_offset(1, 0xd0bd231000, 0x1000));
		std::vector<std::vector<uint8_t>> decompressed_block;
		size_t decompressed_block_count = try_decompress(block.data(), std::array<size_t, 1>{block.size()}, decompressed_block);
		decompressed_block.resize(decompressed_block_count);
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
