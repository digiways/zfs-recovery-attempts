#include "zfs_recovery_tools.hpp"

#include <boost/program_options.hpp>


#include <stdio.h>
#include <stdexcept>
#include <iostream>
#include <stdint.h>

#include <stdint.h>
#include <array>
#include <memory>
#include <functional>

namespace zfs_recover_tools
{
	class block_pointer_tree
	{
	public:
		void add_node(const zfs_data_address& parent_addr, const std::vector<block_pointer_info>& bpis)
		{
			uint64_t parent_id = make_id(parent_addr);
			for (const block_pointer_info& bpi : bpis)
			{
				for (const zfs_data_address& child_addr : bpi.address)
				{
					if (is_valid(child_addr))
						set_dependency(parent_id, make_id(child_addr));
				}
			}
		}
	private:
		static uint64_t make_id(const zfs_data_address& addr) { return (static_cast<uint64_t>(addr.vdev_id) << 56) + addr.offset; }
		static uint64_t make_id_hash(uint64_t x)
		{
			x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
			x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
			x = x ^ (x >> 31);
			return x % BUCKET_COUNT;
		}
		void set_dependency(uint64_t parent_id, uint64_t child_id)
		{
			uint64_t child_id_hash = make_id_hash(child_id);
			std::unique_ptr<bucket_t>* b = &buckets_[child_id_hash];
			while (true)
			{
				if (!*b)
					b->reset(new bucket_t);
				for (size_t i = 0; i != (*b)->data_size; ++i)
				{
					node_t& node = (*b)->data[i];
					if (node.bpi_id == child_id)
					{
						if (node.parent_ids[1] == 0)
						{
							node.parent_ids[1] = parent_id;
							return;
						}
					}
				}
				if ((*b)->data_size < BUCKET_SIZE)
				{
					node_t& node = (*b)->data[(*b)->data_size];
					node.bpi_id = child_id;
					node.parent_ids[0] = parent_id;
					node.parent_ids[1] = 0;
					++(*b)->data_size;
					return;
				}
				b = &(*b)->next;
			}

		}
		struct node_t
		{
			uint64_t bpi_id; // vdev_id<<56 + offset
			uint64_t bpi_offset_in_file;
			uint64_t parent_ids[2];
		};
		static constexpr size_t BUCKET_COUNT = 256;
		static constexpr size_t BUCKET_SIZE = 1024*1024 / sizeof(node_t);
		struct bucket_t
		{
			std::array<node_t, BUCKET_SIZE> data;
			std::unique_ptr<bucket_t> next;
			size_t data_size = 0;
		};
		std::array<std::unique_ptr<bucket_t>, BUCKET_COUNT> buckets_;
	};
}

int main(int argc, const char** argv)
{
	try
	{
		namespace po = boost::program_options;
		using namespace zfs_recover_tools;

		po::positional_options_description p;

		std::string zfs_config_filename;
		std::string dest_filename_base;
		std::string read_block_pointers_from;
		size_t max_block_pointers_to_read = 0;
		std::vector<uint32_t> vdev_ids;
		bool construct_block_pointer_tree = false;

		po::options_description desc("Allowed options");
		desc.add_options()
	    	("help", "produce help message")
			("dest-filename", po::value(&dest_filename_base), "file name base to store found block pointers")
			("read-block-pointers-from", po::value(&read_block_pointers_from), "read, parse and print block pointers from this file")
			("max-block-pointers-to-read", po::value(&max_block_pointers_to_read), "maximum number of block pointers to read from --read-block-pointers-from")
			("zfs-cfg", po::value(&zfs_config_filename), "file with zfs configuration")
			("vdev-ids", po::value(&vdev_ids)->multitoken(), "only scan specified vdevs")
			("construct-block-pointer-tree", po::value(&construct_block_pointer_tree)->implicit_value(true)->zero_tokens(), "construct block pointer tree")
			;

		po::variables_map vm;
		po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
		po::notify(vm);

		if (vm.count("help"))
		{
			std::cout << desc << "\n";
			return 1;
		}

		if (!read_block_pointers_from.empty())
		{
			File file(read_block_pointers_from, O_RDONLY);
			size_t read_count = 0;
			block_pointer_tree bp_tree;
			read_serialized_block_pointers(
				file,
				[&bp_tree, &read_count, max_block_pointers_to_read,construct_block_pointer_tree](size_t pos_in_file, const zfs_data_address& addr, const std::vector<block_pointer_info>& bpis)
				{
					if (construct_block_pointer_tree)
					{
						bp_tree.add_node(addr, bpis);
					}
					else
					{
						std::cout << "addr=" << addr << std::endl ;
						for (const block_pointer_info& bpi : bpis)
							std::cout << "\t\t" << bpi << std::endl ;
					}
					++read_count;
					return (max_block_pointers_to_read == 0 || read_count < max_block_pointers_to_read);
				});
			std::cout << read_count << " records read from " << file.filename() << std::endl ;
		}
		else if (!dest_filename_base.empty())
		{
			if (zfs_config_filename.empty())
				throw std::runtime_error("--zfs-cfg is missing");

			zfs_config config(zfs_config_filename);
			for (const zfs_config::device_t& device : config.devices())
				printf("Config: Device %s id=%u top_level_id=%u\n", device.name.c_str(), unsigned(device.device_id), unsigned(device.top_level_id));

			zfs_pool pool(config);
			scan_top_level_devices_for_potential_indirect_block_pointers(pool, dest_filename_base, vdev_ids);
		}
		return 0;
	}
	catch(const std::exception& e)
	{
		std::cerr << "Fatal error: " << e.what() << std::endl ;
		return 1;
	}
}
