#include "file.hpp"
#include "zfs_try_decompress.hpp"
#include "zfs_recovery_tools.hpp"

#include <boost/program_options.hpp>

#include <stdint.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <string>
#include <iostream>

using namespace zfs_recover_tools;

void try_decompress(
	zfs_pool* pool,
	const uint8_t* data,
	size_t data_size,
	const std::string& output_filename,
	bool store_all,
	bool try_parse_as_indirect_block,
	bool try_parse_as_dmu_block,
	bool try_parse_as_direntry,
	RWFile* store_all_indirect_block_data
	)
{
	zfs_decompressed_block_data_storage_t decompressed_data;
	try_decompress(data, std::array<size_t, 1>{data_size}, decompressed_data, &std::cout);
	size_t count = decompressed_data.decompressed_blocks.size();
	const std::vector<decompressed_data_view_t>& decompressed_views = decompressed_data.decompressed_blocks;
	if (count == 0)
		throw std::runtime_error("All decompression attempts failed");
	else if (count != 1)
		printf("More than one decompression attempt succeeded\n");

	size_t dmu_block_idx = 0;

	for (size_t attempt = 0; attempt != count; ++attempt)
	{
		decompressed_data_view_t data = decompressed_views[attempt];
		if (store_all)
		{
			std::ofstream f(output_filename + ((count!= 1) ? ("-decompressed-maybe-" + std::to_string(attempt) + ".bin") : "-decompressed.bin"));
			f.write(reinterpret_cast<const char*>(data.data()), data.size());
		}

		if (try_parse_as_indirect_block)
		{
			std::vector<block_pointer_info> results;
			bool success = try_parse_indirect_block(pool, data.data(), data.size(), results);
			if (success)
			{
				std::cout << "Parsed decompression attempt " << attempt << " as indirect block [decompressed size " << data.size() << "]" << std::endl ;
				for (const auto& result : results)
					std::cout << "\t\t" << result << std::endl ;

				if (store_all_indirect_block_data != nullptr || try_parse_as_dmu_block)
				{
					size_t level1_fill_count = 0;
					size_t level0_unallocated_count = 0;
					size_t level0_allocated_count = 0;
					size_t level1_total_size = 0;
					size_t level1_total_size_from_bpi = 0;
					size_t level0_bpi_count = 0;
					size_t level0_fill_count = 0;
					size_t expected_obj_id_at_level1_start = 0;
					read_data_from_block_pointers(
						*pool,
						results,
						[&](const uint8_t* data, size_t size, const block_pointer_info& bpi)
						{
							if (bpi.level == 0)
							{
								level1_total_size_from_bpi += bpi.data_size;
								level0_fill_count += bpi.fill_count;
								level1_total_size += size;
								++level0_bpi_count;
								if (try_parse_as_dmu_block)
								{
									std::vector<dnode_phys_t> dnodes;
									try_parse_data_as_dmu_block(pool, data, size, dmu_block_idx, level0_unallocated_count, level0_allocated_count, dnodes);
									for (size_t i = 0; i != dnodes.size(); ++i)
									{
										uint64_t idx = dmu_block_idx + i;
										std::cout << "idx=" << idx << ", " << dnodes[i] << std::endl ;
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

								if (store_all_indirect_block_data)
									store_all_indirect_block_data->write(data, size);
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
				}

				if (try_parse_as_direntry)
					try_read_direntry(*pool, results);
			}
			else
				std::cout << "Failed to parse decompression attempt " << attempt << " as indirect block" << std::endl ;
		}
		size_t level0_unallocated_count = 0;
		size_t level0_allocated_count = 0;
	}
}

int main(int argc, const char** argv)
{
	using namespace zfs_recover_tools;

	namespace po = boost::program_options;

	try
	{
		po::positional_options_description p;
		p.add("source", -1);

		bool try_parse_as_indirect_block = false;
		bool try_parse_as_dmu_block = false;
		bool try_parse_as_direntry = false;
		bool store_all = false;
		std::string store_all_indirect_block_data_filename;

		po::options_description desc("Allowed options");
		desc.add_options()
	    	("help", "produce help message")
			("source", po::value<std::string>(), "file to try to decompress or ZFS DVA 'dev_id:OFFSET(hex, in bytes):SIZE(hex)'")
			("zfs-cfg", po::value<std::string>(), "file with zfs configuration")
			("store-all", po::value(&store_all)->implicit_value(true)->zero_tokens(), "store all raw and decompressed results")
			("try-parse-as-indirect-block", po::value(&try_parse_as_indirect_block)->implicit_value(true)->zero_tokens(), "try parse as an indirect block")
			("try-parse-as-dmu-block", po::value(&try_parse_as_dmu_block)->implicit_value(true)->zero_tokens(), "try parse as DMU block")
			("try-parse-as-direntry", po::value(&try_parse_as_direntry)->implicit_value(true)->zero_tokens(), "try parse as direntry")
			("store-all-indirect-block-data", po::value(&store_all_indirect_block_data_filename), "Filename to store data")
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
		if (vm.count("zfs-cfg"))
		{
			zfs_config config(vm["zfs-cfg"].as<std::string>());
			pool.reset(new zfs_pool(config));
		}

		if (vm.count("source"))
		{
			std::string source = vm["source"].as<std::string>();
			std::unique_ptr<RWFile> out_file;
			if (!store_all_indirect_block_data_filename.empty())
				out_file.reset(new RWFile(store_all_indirect_block_data_filename, RWFile::ALWAYS_CREATE_EMPTY_NEW));
			if (source.find(':') == std::string::npos)
			{
				ROFile source_file(source);
				std::vector<uint8_t> data = source_file.read();
				try_decompress(pool.get(), data.data(), data.size(), source, store_all, try_parse_as_indirect_block, try_parse_as_dmu_block, try_parse_as_direntry, out_file.get());
			}
			else
			{
				zfs_data_address addr = parse_zfs_data_addr_string(source);

				std::cout << "Reading from: " << addr << std::endl ;
				if (pool == nullptr)
					throw std::runtime_error("zfs-cfg option is required when ZFS DVA is used");


				std::string output_file_name = source;
				for (auto& ch : output_file_name)
					if (ch == ':')
						ch = '_';

				data_view_t view = pool->get_block(addr);

				if (store_all)
				{
					std::ofstream f(output_file_name + "-original-raw.bin");
					f.write(reinterpret_cast<const char*>(view.data()), view.size());
				}

				try_decompress(pool.get(), view.data(), view.size(), output_file_name, store_all, try_parse_as_indirect_block, try_parse_as_dmu_block, try_parse_as_direntry, out_file.get());
			}
		}
		return 0;
	}
	catch(const std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl ;
		return 1;
	}

}
