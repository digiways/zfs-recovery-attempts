#include "device.hpp"
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

void try_decompress(zfs_pool* pool, const uint8_t* data, size_t data_size, const std::string& output_filename, bool try_parse_as_indirect_block)
{
	zfs_decompressed_block_data_storage_t decompressed_data;
	try_decompress(data, std::array<size_t, 1>{data_size}, decompressed_data, &std::cout);
	size_t count = decompressed_data.decompressed_blocks.size();
	const auto& decompressed_views = decompressed_data.decompressed_blocks;
	if (count == 0)
		throw std::runtime_error("All decompression attempts failed");
	else if (count != 1)
		printf("More than one decompression attempt succeeded\n");

	for (size_t attempt = 0; attempt != count; ++attempt)
	{
		std::ofstream f(output_filename + ((count!= 1) ? ("-decompressed-maybe-" + std::to_string(attempt) + ".bin") : "-decompressed.bin"));
		f.write(reinterpret_cast<const char*>(decompressed_views[attempt].data()), decompressed_views[attempt].size());

		if (try_parse_as_indirect_block)
		{
			std::vector<block_pointer_info> results;
			bool success = try_parse_indirect_block(pool, decompressed_views[attempt].data(), decompressed_views[attempt].size(), results);
			if (success)
			{
				std::cout << "Parsed decompression attempt " << attempt << " as a direct block [decompressed size " << decompressed_views[attempt].size() << "]" << std::endl ;
				for (const auto& result : results)
					std::cout << "\t\t" << result << std::endl ;
			}
			else
				std::cout << "Failed to parse decompression attempt " << attempt << " as a direct block" << std::endl ;
		}
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

		po::options_description desc("Allowed options");
		desc.add_options()
	    	("help", "produce help message")
			("source", po::value<std::string>(), "file to try to decompress or ZFS DVA 'dev_id:OFFSET(hex, in bytes):SIZE(hex)'")
			("zfs-cfg", po::value<std::string>(), "file with zfs configuration")
			("try-parse-as-indirect-block", po::value<bool>(&try_parse_as_indirect_block)->implicit_value(true)->zero_tokens(), "try parse as an indirect block")
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
			if (source.find(':') == std::string::npos)
			{
				Device device(source);
				try_decompress(pool.get(), device.data(), device.size(), source, try_parse_as_indirect_block);
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
				std::ofstream f(output_file_name + "-original-raw.bin");
				f.write(reinterpret_cast<const char*>(view.data()), view.size());

				try_decompress(pool.get(), view.data(), view.size(), output_file_name, try_parse_as_indirect_block);
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
