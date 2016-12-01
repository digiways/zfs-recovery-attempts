#include "zfs_recovery_tools.hpp"

#include <sparsehash/sparse_hash_map>
#include <sparsehash/sparse_hash_set>
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
		void add_node(const zfs_data_address& parent_addr, const std::vector<block_pointer_info>& bpis, uint64_t user_id)
		{
			for (const block_pointer_info& bpi : bpis)
			{
				for (const zfs_data_address& child_addr : bpi.address)
				{
					if (is_valid(child_addr))
					{
						set_dependency(user_id, parent_addr, make_id(child_addr));
					}
				}
			}
		}

		void find_parents(const zfs_data_address& addr, std::vector<uint64_t>& parent_user_ids)
		{
			auto it = tree_.find(make_id(addr));
			if (it == tree_.end())
				return;
			for (parent_t parent : it->second.parents)
				if (parent.user_id)
					parent_user_ids.push_back(parent.user_id);

			more_parents_t* more = it->second.more;
			while (more != nullptr)
			{
				for (size_t i = 0; i != more->size; ++i)
					parent_user_ids.push_back(more->parents[i].user_id);
				more = more->more;
			}
			std::sort(parent_user_ids.begin(), parent_user_ids.end());
			parent_user_ids.erase(std::unique(parent_user_ids.begin(), parent_user_ids.end()), parent_user_ids.end());
		}

		// removes duplicates
		/*
		void compact()
		{
			for (const auto& item : tree_)
			{
				parents_t& value = item.second;
				if (value.more == nullptr)
				{
					static_assert(value.parents.size() == 2, "");
					if (value.parents[0].user_id == value.parents[1].user_id)
						value.parents[1].user_id = 0;
				}
				else
				{
					size_t required_size = value.parents.size();
					more_parents_t* more = value.more;
					while (more != nullptr)
					{
						required_size += more->size;
						more = more->more;
					}
				}

			}
		}
		*/

		block_pointer_tree() = default;
		block_pointer_tree(const block_pointer_tree&) = delete;
		block_pointer_tree& operator=(const block_pointer_tree&) = delete;
		~block_pointer_tree()
		{
			for (const auto& item : tree_)
				free_parents(item.second.more);
		}
	private:
		struct parent_t
		{
			uint64_t user_id = 0;
		};
		struct more_parents_t
		{
			uint32_t size;
			uint32_t allocated_size;
			more_parents_t* more;
			parent_t parents[0];
		};

		static more_parents_t* make_more_parents(size_t size)
		{
			more_parents_t* ptr = (more_parents_t*)malloc(sizeof(more_parents_t) + sizeof(parent_t)*size);
			ptr->size = 0;
			ptr->allocated_size = size;
			ptr->more = nullptr;
			return ptr;
		}
		static void free_parents(more_parents_t* ptr)
		{
			if (ptr)
			{
				if (ptr->more)
					free_parents(ptr->more);
				::free(ptr);
			}
		}

		struct parents_t
		{
			std::array<parent_t, 2> parents{};
			more_parents_t* more = nullptr;
		};
		google::sparse_hash_map<uint64_t, parents_t> tree_;

		void set_dependency(uint64_t user_id, const zfs_data_address& parent_addr, uint64_t child_id)
		{
			parents_t& data = tree_[child_id];
			for (size_t i = 0; i != data.parents.size(); ++i)
				if (data.parents[i].user_id == user_id)
					return;
			if (data.more == nullptr)
			{
				for (size_t i = 0; i != data.parents.size(); ++i)
				{
					if (data.parents[i].user_id == 0)
					{
						data.parents[i] = parent_t{user_id};
						return;
					}
				}
				data.more = make_more_parents(4);
			}
			more_parents_t* more = data.more;
			while (true)
			{
//				for (size_t i = 0; i != more->size; ++i)
					//if (more->parents[i].user_id == user_id)
//						return;
				if (more->allocated_size > more->size)
				{
					more->parents[more->size] = parent_t{user_id};
					++more->size;
					return;
				}
				else if (more->more == nullptr)
					more = more->more = make_more_parents(more->size*2);
				else
					more = more->more;
			}

			throw std::runtime_error("full");
		}

		static uint64_t make_id(const zfs_data_address& addr) { return (static_cast<uint64_t>(addr.vdev_id) << 56) + addr.offset; }
	};

	class block_pointer_tree_state_t
	{
	public:
		explicit block_pointer_tree_state_t(const std::vector<std::string>& serialized_block_pointer_filenames)
		{
			for (const std::string& filename : serialized_block_pointer_filenames)
				block_pointer_files_.push_back(ROFile(filename));
		}
		template<class Handler>
		void scan_all(size_t max_block_pointers_to_read, bool update_tree, const Handler& handler)
		{
			for (size_t file_idx = 0; file_idx != block_pointer_files_.size(); ++file_idx)
			{
				size_t read_count = 0;
				zfs_data_address last_addr;
				read_serialized_block_pointers(
					block_pointer_files_[file_idx],
					[&last_addr, file_idx, this, &read_count, max_block_pointers_to_read, update_tree, &handler]
					 	 (size_t pos_in_file, const zfs_data_address& addr, const std::vector<block_pointer_info>& bpis)
					{
						last_addr = addr;
						if (update_tree)
						{
							bp_tree_.add_node(addr, bpis, (static_cast<uint64_t>(file_idx) << 56) + pos_in_file);
						}
						handler(file_idx, pos_in_file, addr, bpis);
						++read_count;
						return (max_block_pointers_to_read == 0 || read_count < max_block_pointers_to_read);
					});
				std::cout << read_count << " records read from " << block_pointer_files_[file_idx].filename() << ", last address: " << last_addr << std::endl ;
			}
		}

		void update_tree()
		{
			scan_all(0, true, [](size_t file_idx, size_t file_pos, const zfs_data_address& addr, const std::vector<block_pointer_info>& bpis) {});
		}

		void scan_dnodes(zfs_pool& pool, const std::vector<zfs_data_address>& to_find)
		{
			std::vector<uint8_t> decompressed;
			uint64_t update_count = 0;
			scan_all(
				0,
				true,
				[&](size_t file_idx, size_t file_pos, const zfs_data_address& addr, const std::vector<block_pointer_info>& bpis)
				{
					++update_count;
					if (update_count % 10000 == 0)
					{
						std::cout << "Scanning at file " << file_idx << ", pos " << file_pos << ", addr " << addr << std::endl ;
					}
					for (const block_pointer_info& bpi : bpis)
					{
						if (bpi.type == DMU_OT_DNODE && bpi.level == 0)
						{
							data_view_t block = pool.get_block(bpi.address[0]);
							try
							{
								decompress(bpi.compression_algo_idx, block.data(), block.size(), decompressed);
							}
							catch(const std::exception& e)
							{
								continue;
							}
							static_assert(sizeof(dnode_phys_t) == 512, "");
							if (decompressed.size() % 512 != 0)
							{
								// TODO: Check why we get so many nodes with invalid sizes, maybe that's expected
								//std::cout << "Skipping DNode block with invalid size " << bpi << ", size: " << decompressed.size() << std::endl ;
								continue;
							}
							size_t count = decompressed.size() / 512;
							for (size_t i = 0; i != count; ++i)
							{
								const dnode_phys_t& node = get_mem_pod<dnode_phys_t>(decompressed.data(), i * 512, decompressed.size());
								if (node.dn_nblkptr != 0)
								{
									//printf("dnode got %u block pointers\n", uint32_t(node.dn_nblkptr));
									for (size_t i = 0; i!= node.dn_nblkptr; ++i)
									{
										block_pointer_info info;
										int parse_res = try_parse_block_pointer(&pool, node.dn_blkptr[i], info);
										if (parse_res > 0)
										{
											for (const zfs_data_address& addr : info.address)
												if (is_valid(addr))
												{
													if (std::find(to_find.begin(), to_find.end(), addr) != to_find.end())
													{
														std::cout << "Found !! bpi: " << info << " in " << bpi << std::endl ;
													}
												}
										}
									}
								}

							}
						}
					}
				});
		}

		struct Parent
		{
			zfs_data_address addr;
			std::vector<block_pointer_info> bpis;
		};
		void get_parents(const zfs_data_address& addr_to_find, std::vector<Parent>& parent_bpis, size_t max_left_offset_in_sectors = 0, size_t max_right_offset_in_sectors = 0)
		{
			parent_bpis.clear();
			std::vector<uint64_t> direct_parents;
			std::vector<uint64_t> all_considered_direct_parents;
			for (int64_t addr_offset = -static_cast<int64_t>(max_left_offset_in_sectors); addr_offset != max_right_offset_in_sectors+1; ++addr_offset)
			{
				direct_parents.clear();
				bp_tree_.find_parents(zfs_data_address{addr_to_find.vdev_id, addr_to_find.offset + addr_offset, addr_to_find.size}, direct_parents);
				for (uint64_t direct_parent_user_id : direct_parents)
				{
					if (std::find(all_considered_direct_parents.begin(), all_considered_direct_parents.end(), direct_parent_user_id) != all_considered_direct_parents.end())
						continue;
					uint8_t file_id = direct_parent_user_id >> 56;
					uint64_t pos_in_file = direct_parent_user_id & 0xFFFFFFFFFFFFFFLLU;
					zfs_data_address parent_addr;
					Parent parent;
					read_serialized_block_pointer(block_pointer_files_[file_id], pos_in_file, parent.addr, parent.bpis);
					parent_bpis.push_back(std::move(parent));
				}
				all_considered_direct_parents.insert(all_considered_direct_parents.end(), direct_parents.begin(), direct_parents.end());
			}
		}
	private:
		block_pointer_tree bp_tree_;
		std::vector<ROFile> block_pointer_files_;
	};

	void print_parent_tree(block_pointer_tree_state_t& state, const zfs_data_address& addr, size_t left_offset = 0)
	{
		if (left_offset >= 40)
		{
			std::cout << std::string(left_offset, ' ') << "***" << std::endl ;
			return;
		}
		std::vector<block_pointer_tree_state_t::Parent> parents;
		state.get_parents(addr, parents);
		for (const block_pointer_tree_state_t::Parent& parent : parents)
		{
			std::cout << std::string(left_offset, ' ') << "-> " << parent.addr << std::endl ;
			print_parent_tree(state, parent.addr, left_offset + 4);
		}
	}
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
		std::vector<std::string> read_block_pointers_from;
		size_t max_block_pointers_to_read = 0;
		std::vector<uint32_t> vdev_ids;
		bool construct_block_pointer_tree = false;
		std::string dva_str_to_find_references_for;
		std::string filename_to_find_references_for;
		bool try_read_direntries = false;
		size_t find_address_references_max_left_offset_in_sectors = 32;
		size_t find_address_references_max_right_offset_in_sectors = 32;
		bool scan_dnodes = false;

		po::options_description desc("Allowed options");
		desc.add_options()
	    	("help", "produce help message")
			("dest-filename", po::value(&dest_filename_base), "file name base to store found block pointers")
			("read-block-pointers-from", po::value(&read_block_pointers_from)->multitoken(), "read, parse and print block pointers from this file")
			("max-block-pointers-to-read", po::value(&max_block_pointers_to_read), "maximum number of block pointers to read from --read-block-pointers-from")
			("zfs-cfg", po::value(&zfs_config_filename), "file with zfs configuration")
			("vdev-ids", po::value(&vdev_ids)->multitoken(), "only scan specified vdevs")
			("construct-block-pointer-tree", po::value(&construct_block_pointer_tree)->implicit_value(true)->zero_tokens(), "construct block pointer tree")
			("find-address-references", po::value(&dva_str_to_find_references_for), "find references for address in form vdev_id:offset::size, size is ignored, this option enables construction of the block pointer tree")
			("find-address-references-from-file", po::value(&filename_to_find_references_for), "filename that cotains references for address in form vdev_id:offset::size, size is ignored (or alternative syntax with device names), this option enables construction of the block pointer tree")
			("try-read-direntries", po::value(&try_read_direntries)->implicit_value(true)->zero_tokens(), "try to parse matched parent data as directory entries")
			("find-address-references-max-left-offset-in-sectors", po::value(&find_address_references_max_left_offset_in_sectors)->default_value(32), "max offset in sectors when trying to find references to an offset")
			("find-address-references-max-right-offset-in-sectors", po::value(&find_address_references_max_right_offset_in_sectors)->default_value(0), "max offset in sectors when trying to find references to an offset")
			("scan-dnodes", po::value(&scan_dnodes)->implicit_value(true)->zero_tokens(), "scan dnodes")
			;

		po::variables_map vm;
		po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
		po::notify(vm);

		if (vm.count("help"))
		{
			std::cout << desc << "\n";
			return 1;
		}

		std::unique_ptr<zfs_pool> pool;
		std::unique_ptr<zfs_config> pool_config;
		if (!zfs_config_filename.empty())
		{
			pool_config.reset(new zfs_config(zfs_config_filename));
		}

		std::vector<zfs_data_address> dva_to_find_references_for;

		if (!dva_str_to_find_references_for.empty())
		{
			construct_block_pointer_tree = true;
			dva_to_find_references_for.push_back(parse_zfs_data_addr_string(dva_str_to_find_references_for));
		}
		if (!filename_to_find_references_for.empty())
		{
			std::vector<zfs_data_address> addresses = load_zfs_data_addresses_from_file(pool_config.get(), filename_to_find_references_for);
			std::cout << "Loaded " << addresses.size() << " addresses from " << filename_to_find_references_for << std::endl ;
			dva_to_find_references_for.insert(dva_to_find_references_for.end(), addresses.begin(), addresses.end());
		}

		if (try_read_direntries || scan_dnodes)
		{
			if (!pool_config)
				throw std::runtime_error("--zfs-cfg is missing but required to read direntries");
			pool.reset(new zfs_pool(*pool_config));
		}


		if (!read_block_pointers_from.empty())
		{
			block_pointer_tree_state_t bptree_state(read_block_pointers_from);
			if (scan_dnodes)
			{
				bptree_state.scan_dnodes(*pool, dva_to_find_references_for);
				return 0;
			}
			if (construct_block_pointer_tree)
				bptree_state.update_tree();
			else
			{
				bptree_state.scan_all(
					max_block_pointers_to_read,
					false,
					[](size_t file_idx, size_t file_pos, const zfs_data_address& addr, const std::vector<block_pointer_info>& bpis)
					{
						std::cout << "addr=" << addr << std::endl ;
						for (const block_pointer_info& bpi : bpis)
							std::cout << "\t\t" << bpi << std::endl ;
					});
			}

			for (const auto& addr_to_find : dva_to_find_references_for)
			{
				std::vector<block_pointer_tree_state_t::Parent> parents;
				std::cout << "Searching for parents of " << addr_to_find << std::endl ;
				bptree_state.get_parents(addr_to_find, parents, find_address_references_max_left_offset_in_sectors, find_address_references_max_right_offset_in_sectors);
				for (const block_pointer_tree_state_t::Parent& parent : parents)
				{
					bool is_object_directory = true;
					bool is_object_dnode = true;
					for (const block_pointer_info& bpi : parent.bpis)
					{
						if (bpi.type != DMU_OT_OBJECT_DIRECTORY && bpi.type != DMU_OT_DIRECTORY_CONTENTS)
							is_object_directory = false;
						if (bpi.type != DMU_OT_DNODE)
							is_object_dnode = false;
					}
					if (is_object_directory || is_object_dnode)
					{
						std::cout << "parent dva: " << parent.addr << ", child dva: " << addr_to_find << std::endl ;
						for (const block_pointer_info& bpi : parent.bpis)
							std::cout << "\t" << bpi << std::endl ;
						if (is_object_directory)
							print_parent_tree(bptree_state, parent.addr);
					}
					if (is_object_directory && try_read_direntries)
					{
						try_read_direntry(*pool, parent.bpis);
					}
				}
			}
		}
		else if (!dest_filename_base.empty())
		{
			if (!pool_config)
				throw std::runtime_error("--zfs-cfg is missing");
			pool.reset(new zfs_pool(*pool_config));
			scan_top_level_devices_for_potential_indirect_block_pointers(*pool, dest_filename_base, vdev_ids);
		}
		return 0;
	}
	catch(const std::exception& e)
	{
		std::cerr << "Fatal error: " << e.what() << std::endl ;
		return 1;
	}
}
