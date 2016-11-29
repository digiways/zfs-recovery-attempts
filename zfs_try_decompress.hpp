#pragma once

#include "zfs_recovery_tools_views.hpp"

#include <stdint.h>
#include <vector>
#include <string>
#include <sys/param.h>
#include <iostream>
#include <sstream>
#include <array>

namespace zfs_recover_tools
{

	struct decompression_error
	{
		const char* msg = nullptr;
		size_t src_pos = 0;
		size_t dest_pos = 0;
		size_t offset = 0;
		size_t length = 0;
		std::string to_string() const
		{
			std::ostringstream s;
			s << msg << ", src_pos=" << src_pos << ", dest_pos=" << dest_pos << ", offset=" << offset << ", length=" << length;
			return s.str();
		}
	};

// returns size of input data used
template<size_t SIZE_COUNT>
size_t lzjb_decompress(const uint8_t* const src, const std::array<size_t, SIZE_COUNT>& try_sizes, std::vector<uint8_t>& out, decompression_error& error)
{
	static_assert(SIZE_COUNT >= 1, "");

	static constexpr int MATCH_BITS = 6;
	static constexpr int OFFSET_MASK = ((1 << (16 - MATCH_BITS)) - 1);
	static constexpr int MATCH_MIN = 3;
	static constexpr int bits_in_a_byte = 8;

	uint8_t copymap = 0;

	uint8_t copymask = 1 << (bits_in_a_byte - 1);

	out.reserve(out.size() + try_sizes[SIZE_COUNT-1]*2);

	std::array<bool, SIZE_COUNT> success_at_size_flag;
	std::array<size_t, SIZE_COUNT> out_size_at_try_size;
	size_t next_try_sizes_idx = 0;

	static constexpr size_t MAX_SIZE_COUNT_IDX = SIZE_COUNT-1;

	for (size_t src_pos = 0; next_try_sizes_idx != SIZE_COUNT; )//src_pos != src_size; ++src_pos)
	{
		copymask <<= 1;
		if (copymask == 0)
		{
			copymask = 1;
			copymap = src[src_pos];
			++src_pos;
			while (src_pos == try_sizes[next_try_sizes_idx])
			{
				success_at_size_flag[next_try_sizes_idx] = false;
				out_size_at_try_size[next_try_sizes_idx] = 0;
				++next_try_sizes_idx;
				if (next_try_sizes_idx == SIZE_COUNT)
				{
					error.msg = "src_pos == src_size on copymask==0";
					error.src_pos = src_pos;
					break;
				}
			}
		}
		if (copymap & copymask)
		{
			while (src_pos+1 == try_sizes[next_try_sizes_idx])
			{
				success_at_size_flag[next_try_sizes_idx] = false;
				out_size_at_try_size[next_try_sizes_idx] = 0;
				++next_try_sizes_idx;
				if (next_try_sizes_idx == SIZE_COUNT)
				{
					error.msg = "src_pos+1 == src_size on (copymap&copymask)";
					error.src_pos = src_pos;
					break;
				}
			}
			uint8_t mlen = (src[src_pos] >> (bits_in_a_byte - MATCH_BITS)) + MATCH_MIN;
			uint16_t offset = (uint16_t(src[src_pos] << bits_in_a_byte) | uint16_t(src[src_pos+1])) & OFFSET_MASK;
			++src_pos;
			if (offset == 0 || offset > out.size()) // should be out.size() - out_starting_size
			{
				if (next_try_sizes_idx == 0)
				{
					error.msg = "offset > out.size() or offset is zero";
					error.src_pos = src_pos;
					error.dest_pos = out.size();
					error.offset = offset;
					return 0;
				}
				else
				{
					break;
				}
			}
			size_t cpy_from_offset = out.size() - offset;
			for (uint8_t i = 0; i != mlen; ++i)
				out.push_back(out[cpy_from_offset++]);
		}
		else
		{
			out.push_back(src[src_pos]);
		}
		if (src_pos == try_sizes[next_try_sizes_idx])
		{
			success_at_size_flag[next_try_sizes_idx] = true;
			out_size_at_try_size[next_try_sizes_idx] = out.size();
			++next_try_sizes_idx;
			if (next_try_sizes_idx == SIZE_COUNT)
				return try_sizes[SIZE_COUNT-1];
		}
	}
	for (size_t try_sizes_idx = next_try_sizes_idx; try_sizes_idx != 0; --try_sizes_idx)
	{
		if (success_at_size_flag[try_sizes_idx-1])
		{
			out.resize(out_size_at_try_size[try_sizes_idx-1]);
			return try_sizes[try_sizes_idx-1];
		}
	}
	return 0;
}

// returns size of input data used
size_t lzjb_decompress(const uint8_t* const src, size_t size, std::vector<uint8_t>& out, decompression_error& error)
{
	return lzjb_decompress(src, std::array<size_t, 1>{size}, out, error);
}


// returns size of input data used
template<size_t SIZE_COUNT>
size_t zle_decompress(const uint8_t* const src, const std::array<size_t, SIZE_COUNT>& try_sizes, std::vector<uint8_t>& out, decompression_error& error)
{
	static_assert(SIZE_COUNT >= 1, "");

	static constexpr size_t level = 64;

	std::array<bool, SIZE_COUNT> success_at_size_flag;
	std::array<size_t, SIZE_COUNT> out_size_at_try_size;
	size_t next_try_sizes_idx = 0;

	for (size_t src_pos = 0; next_try_sizes_idx != SIZE_COUNT; )//src_pos != src_size;)
	{
		uint32_t len = uint32_t(1) + src[src_pos];
		if (len <= level)
		{
			++src_pos;

			while (src_pos + len > try_sizes[next_try_sizes_idx])
			{
				success_at_size_flag[next_try_sizes_idx] = false;
				out_size_at_try_size[next_try_sizes_idx] = 0;
				++next_try_sizes_idx;
				if (next_try_sizes_idx == SIZE_COUNT)
				{
					error.msg = "src_pos == src_size";
					error.src_pos = src_pos;
					return 0;
				}
			}
			out.insert(out.end(), src + src_pos, src + src_pos + len);
			src_pos += len;
		}
		else
		{
			len -= level;
			size_t out_pos = out.size();
			out.resize(out_pos + len);
			::memset(out.data() + out_pos, 0, len);
			++src_pos;
		}
		if (src_pos == try_sizes[next_try_sizes_idx])
		{
			success_at_size_flag[next_try_sizes_idx] = true;
			out_size_at_try_size[next_try_sizes_idx] = out.size();
			++next_try_sizes_idx;
		}
	}
	for (size_t try_sizes_idx = SIZE_COUNT; try_sizes_idx != 0; --try_sizes_idx)
	{
		if (success_at_size_flag[try_sizes_idx-1])
		{
			out.resize(out_size_at_try_size[try_sizes_idx-1]);
			return try_sizes[try_sizes_idx-1];
		}
	}

	return 0;
}

// returns size of input data used
size_t zle_decompress(const uint8_t* const src, size_t size, std::vector<uint8_t>& out, decompression_error& error)
{
	return zle_decompress(src, std::array<size_t, 1>{size}, out, error);
}


// returns size of input data used
template<size_t SIZE_COUNT>
size_t lz4_decompress(const uint8_t* const src, const std::array<size_t, SIZE_COUNT>& try_sizes, std::vector<uint8_t>& out, decompression_error& error)
{
	// https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md

	static_assert(SIZE_COUNT >= 1, "");

	static constexpr int ML_BITS = 4;
	static constexpr int ML_MASK = ((1U<<ML_BITS)-1);
	static constexpr int RUN_BITS = (8-ML_BITS);
	static constexpr int RUN_MASK = ((1U<<RUN_BITS)-1);


	if (try_sizes[SIZE_COUNT-1] < sizeof(uint32_t))
	{
		error.msg = "src_size < sizeof(uint32_t)";
		return 0;
	}
	const size_t input_size = __builtin_bswap32(*reinterpret_cast<const uint32_t*>(src));

	if (try_sizes[SIZE_COUNT-1] < sizeof(uint32_t) + input_size)
	{
		error.msg = "src_size < sizeof(uint32_t) + input_size";
		error.offset = input_size;
		return 0;
	}

	const uint8_t* ip = src + sizeof(uint32_t);
	const uint8_t* const iend = ip + input_size;

	const size_t out_initial_size = out.size();

	while (ip < iend)
	{
		// get runlength
		unsigned int token = *ip;
		++ip;
		size_t length = (token >> ML_BITS);
		static_assert(RUN_MASK == 0xF, "");
		if (length == RUN_MASK)
		{
			while (ip < iend)
			{
				uint8_t s = *ip++;
				length += s;
				if (s != 0xFF)
					break;
			}
		}
		if (length > 1024*1024)
		{
			error.msg = "cpy waf overflowed, length too big";
			error.src_pos = ip - src;
			error.offset = length;
			return 0;
		}
		if (ip + length > iend - 4)
		{
			if (ip + length != iend)
			{
				error.msg = "LZ4 format requires to consume all input at this stage";
				error.src_pos = ip - src;
				return 0;
			}
			out.insert(out.end(), ip, ip+length);
			break;
		}

		out.insert(out.end(), ip, ip + length);
		ip += length;

		// get offset - read little endian 16
		uint16_t ref_offset = *reinterpret_cast<const uint16_t*>(ip);
		if (ref_offset == 0 || ref_offset > (out.size() - out_initial_size))
		{
			error.msg = "ref_offset is invalid";
			error.dest_pos = out.size() - out_initial_size;
			error.offset = ref_offset;
			error.src_pos = ip - src;
			return 0;
		}
		size_t ref_idx = out.size() - ref_offset;
		ip += 2;

		// get matchlength
		static_assert(ML_MASK == 0xF, "");
		size_t ref_length = token & ML_MASK;
		if (ref_length == ML_MASK)
		{
			while (ip < iend)
			{
				uint8_t s = *ip++;
				ref_length += s;
				if (s != 255)
					break;
			}
		}
		ref_length += 4; // minimum length is t, so value of 0 means - 4 bytes to copy
		out.reserve(out.size() + ref_length);
		for (size_t i = 0; i != ref_length; ++i)
			out.push_back(out[out.size() - ref_offset]);
	}

	for (size_t idx = 0; idx != SIZE_COUNT; ++idx)
		if (try_sizes[idx] >= input_size + sizeof(uint32_t))
			return try_sizes[idx];

	throw std::runtime_error("can't happen");
}

// returns size of input data used
size_t lz4_decompress(const uint8_t* const src, size_t size, std::vector<uint8_t>& out, decompression_error& error)
{
	return lz4_decompress(src, std::array<size_t, 1>{size}, out, error);
}

struct zfs_decompressed_block_data_storage_t
{
	std::vector<uint8_t> decompressed_blocks_data[3];
	std::vector<decompressed_data_view_t> decompressed_blocks;

	void clear()
	{
		decompressed_blocks_data[0].clear();
		decompressed_blocks_data[1].clear();
		decompressed_blocks_data[2].clear();
		decompressed_blocks.clear();
	}

	zfs_decompressed_block_data_storage_t() { decompressed_blocks.reserve(3); };
	zfs_decompressed_block_data_storage_t(const zfs_decompressed_block_data_storage_t&) = delete;
	zfs_decompressed_block_data_storage_t& operator=(const zfs_decompressed_block_data_storage_t&) = delete;
	zfs_decompressed_block_data_storage_t(zfs_decompressed_block_data_storage_t&&) = delete;
	zfs_decompressed_block_data_storage_t& operator=(zfs_decompressed_block_data_storage_t&&) = delete;
};

// try_sizes must be in increasing order
template<size_t SIZE_COUNT>
void try_decompress(const uint8_t* data, const std::array<size_t, SIZE_COUNT>& try_sizes, zfs_decompressed_block_data_storage_t& out, std::ostream* error_log = nullptr)
{
	static_assert(SIZE_COUNT >= 1, "");
	for (size_t i = 1; i != SIZE_COUNT; ++i)
		if (try_sizes[i-1] >= try_sizes[i])
			throw std::runtime_error("Invalid input data, try_sizes passed to try_decompress must be in a strictly increasing order");
	out.clear();
	decompression_error error;
	size_t lzjb_res = lzjb_decompress(data, try_sizes, out.decompressed_blocks_data[0], error);
	if (lzjb_res != 0)
		out.decompressed_blocks.emplace_back(out.decompressed_blocks_data[0].data(), out.decompressed_blocks_data[0].size(), lzjb_res);
	else if (error_log)
		*error_log << "LZJB error: " << error.to_string() << std::endl ;

	error = decompression_error();
	size_t zle_res = zle_decompress(data, try_sizes, out.decompressed_blocks_data[1], error);
	if (zle_res != 0)
		out.decompressed_blocks.emplace_back(out.decompressed_blocks_data[1].data(), out.decompressed_blocks_data[1].size(), zle_res);
	else if (error_log)
		*error_log << "LZE error: " << error.to_string() << std::endl ;

	error = decompression_error();
	size_t lz4_res = lz4_decompress(data, try_sizes, out.decompressed_blocks_data[2], error);
	if (lz4_res != 0)
		out.decompressed_blocks.emplace_back(out.decompressed_blocks_data[2].data(), out.decompressed_blocks_data[2].size(), lz4_res);
	else if (error_log)
		*error_log << "LZ4 error: " << error.to_string() << std::endl ;
}

} // namespace zfs_recover_tools
