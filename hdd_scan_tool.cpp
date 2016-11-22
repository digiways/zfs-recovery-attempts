#include "device.hpp"

#include <stdexcept>
#include <string.h>
#include <thread>
#include <vector>

using namespace zfs_recover_tools;

void search(const std::string& name, const uint8_t* data, size_t data_size, const std::vector<std::string>& tokens, size_t max_distance)
{
	printf("Starting searching '%s'\n", name.c_str());
	static constexpr size_t positions_size = 8; // number of bits in uint8_t, can do 16, storing uint16_t in potential_bytes
	uint8_t positions[positions_size] = {}; // zero initialized
	size_t last_found_pos[positions_size] = {}; // zero initialized
	for (size_t i = 0; i != positions_size; ++i)
		last_found_pos[i] = size_t(-1)/2;
	uint8_t potential_bytes[256] = {}; // zero initialized
	uint8_t min_token_len = 0xFF;
	for (size_t token_idx = 0; token_idx != tokens.size(); ++token_idx)
	{
		const std::string& token = tokens[token_idx];
		for (char c : token)
			potential_bytes[static_cast<uint8_t>(c)] = 1;//|= (1 << token_idx);
		if (token.size() < min_token_len)
			min_token_len = token.size();
	}
	size_t token_count = tokens.size();
	if (positions_size < token_count)
		throw std::runtime_error("too many tokens");
	for (size_t i = 0; i < data_size; ++i)
	{
		uint8_t ch = data[i];
		if (uint8_t flag = potential_bytes[ch])
		{
			for (size_t token_idx = 0; token_idx != tokens.size(); ++token_idx)
			{
				const std::string& token = tokens[token_idx];
				if (static_cast<uint8_t>(token[positions[token_idx]]) == ch)
				{
					++positions[token_idx];
					if (positions[token_idx] == token.size())
					{
						// found token
						positions[token_idx] = 0;
						bool match = true;
						for (size_t last_found_pos_idx = 0; last_found_pos_idx != tokens.size(); ++last_found_pos_idx)
						{
							if (last_found_pos_idx != token_idx && (i - token.size()) - last_found_pos[last_found_pos_idx] > max_distance)
							{
								match = false;
								break;
							}
						}
						last_found_pos[token_idx] = i;
						if (match)
						{
							printf("=%s,%lu\n", name.c_str(), i);
						}
					}
				}
			}
		}
		else
		{
			for (size_t pp = 0; pp != positions_size; ++pp)
				positions[pp] = 0;
		}
	}
	printf("Done searching '%s'\n", name.c_str());
}

void search(const std::string& filename, const std::vector<std::string>& tokens, size_t max_distance)
{
	try
	{
		Device device(filename);
		search(filename, device.data(), device.size(), tokens, max_distance);
	}
	catch(const std::exception& e)
	{
		printf("Error with [%s]: %s\n", filename.c_str(), e.what());
	}
}

void search(const std::vector<std::string>& filenames, const std::vector<std::string>& tokens, size_t max_distance)
{
	std::vector<std::thread> threads;
	for (const std::string& filename : filenames)
	{
		threads.emplace_back([=] { search(filename, tokens, max_distance); });
	}
	for (std::thread& thread : threads)
		thread.join();
}

int main()
{
	std::vector<std::string> filenames
	{
		"/dev/disk/by-id/ata-WDC_WD30EFRX-68AX9N0_WD-WMC1T3219459-part1",
		"/dev/disk/by-id/ata-WDC_WD30EFRX-68AX9N0_WD-WMC1T3235264-part1",
		"/dev/disk/by-id/ata-WDC_WD30EFRX-68AX9N0_WD-WMC1T3293520-part1",
		"/dev/disk/by-id/ata-WDC_WD30EFRX-68EUZN0_WD-WMC4N0569379-part1",
		"/dev/disk/by-id/ata-WDC_WD30EFRX-68EUZN0_WD-WMC4N0586006-part1",
		"/dev/disk/by-id/ata-WDC_WD30EFRX-68EUZN0_WD-WMC4N0586517-part1",
		"/dev/disk/by-id/ata-WDC_WD30EFRX-68EUZN0_WD-WMC4N1453028-part1",
		"/dev/disk/by-id/ata-WDC_WD30EFRX-68EUZN0_WD-WMC4N2245578-part1"
	};
	std::vector<std::string> tokens
	{
		"Restless",
		"reebok.jpg",
		"Ryanair.pdf",
		"Avantasia",
		"HELLOWEEN",
		"docs"
	};
	size_t max_distance = 8192;
	search(filenames, tokens, max_distance);
}
