#pragma once

#include <stdint.h>
#include <vector>
#include <string>
#include <sys/param.h>
#include <iostream>
#include <sstream>

namespace zfs_recover
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

bool lzjb_decompress(const uint8_t* const src, size_t src_size, std::vector<uint8_t>& out, decompression_error& error)
{
	static constexpr int MATCH_BITS = 6;
	static constexpr int OFFSET_MASK = ((1 << (16 - MATCH_BITS)) - 1);
	static constexpr int MATCH_MIN = 3;
	static constexpr int bits_in_a_byte = 8;

	uint8_t copymap = 0;

	uint8_t copymask = 1 << (bits_in_a_byte - 1);

	out.reserve(out.size() + src_size*2);

	for (size_t src_pos = 0; src_pos != src_size; ++src_pos)
	{
		copymask <<= 1;
		if (copymask == 0)
		{
			copymask = 1;
			copymap = src[src_pos];
			++src_pos;
			if (src_pos == src_size)
			{
				error.msg = "src_pos == src_size on copymask==0";
				error.src_pos = src_pos;
				return false;
			}
		}
		if (copymap & copymask)
		{
			if (src_pos+1 == src_size)
			{
				error.msg = "src_pos+1 == src_size on (copymap&copymask)";
				error.src_pos = src_pos;
				return false;
			}
			uint8_t mlen = (src[src_pos] >> (bits_in_a_byte - MATCH_BITS)) + MATCH_MIN;
			uint16_t offset = (uint16_t(src[src_pos] << bits_in_a_byte) | uint16_t(src[src_pos+1])) & OFFSET_MASK;
			++src_pos;
			if (offset > out.size())
			{
				error.msg = "offset > out.size()";
				error.src_pos = src_pos;
				error.dest_pos = out.size();
				error.offset = offset;
				return false;
			}
			size_t cpy_from_offset = out.size() - offset;
			for (uint8_t i = 0; i != mlen; ++i)
				out.push_back(out[cpy_from_offset++]);
		}
		else
		{
			out.push_back(src[src_pos]);
		}
	}
	return true;
}

bool zle_decompress(const uint8_t* const src, size_t src_size, std::vector<uint8_t>& out, decompression_error& error)
{
	static constexpr size_t level = 64;
	for (size_t src_pos = 0; src_pos != src_size;)
	{
		uint32_t len = uint32_t(1) + src[src_pos];
		if (len <= level)
		{
			++src_pos;
			for (size_t i = 0; i != len; ++i)
			{
				if (src_pos == src_size)
				{
					error.msg = "src_pos == src_size";
					error.src_pos = src_pos;
					return false;
				}
				out.push_back(src[src_pos]);
				++src_pos;
			}
		}
		else
		{
			len -= level;
			for (size_t i = 0; i != len; ++i)
				out.push_back(0);
			++src_pos;
		}
	}
	return true;
}

bool lz4_decompress(const uint8_t* const src, size_t src_size, std::vector<uint8_t>& out, decompression_error& error)
{
	// https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md

	static constexpr int ML_BITS = 4;
	static constexpr int ML_MASK = ((1U<<ML_BITS)-1);
	static constexpr int RUN_BITS = (8-ML_BITS);
	static constexpr int RUN_MASK = ((1U<<RUN_BITS)-1);

	if (src_size < sizeof(uint32_t))
	{
		error.msg = "src_size < sizeof(uint32_t)";
		return false;
	}
	size_t input_size = __builtin_bswap32(*reinterpret_cast<const uint32_t*>(src));

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
			return false;
		}
		if (ip + length > iend - 4)
		{
			if (ip + length != iend)
			{
				error.msg = "LZ4 format requires to consume all input at this stage";
				error.src_pos = ip - src;
				return false;
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
			return false;
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

	return true;
}

std::vector<std::vector<uint8_t>> try_decompress(const uint8_t* data, size_t size, std::ostream* error_log = nullptr)
{
	std::vector<std::vector<uint8_t>> all;

	std::vector<uint8_t> ret;
	decompression_error error;
	bool lzjb_res = lzjb_decompress(data, size, ret, error);
	if (lzjb_res)
		all.push_back(std::move(ret));
	else if (error_log)
		*error_log << "LZJB error: " << error.to_string() << std::endl ;

	error = decompression_error();
	ret.clear();
	bool zle_res = zle_decompress(data, size, ret, error);
	if (zle_res)
		all.push_back(std::move(ret));
	else if (error_log)
		*error_log << "LZE error: " << error.to_string() << std::endl ;

	error = decompression_error();
	ret.clear();
	bool lz4_res = lz4_decompress(data, size, ret, error);
	if (lz4_res)
		all.push_back(std::move(ret));
	else if (error_log)
		*error_log << "LZ4 error: " << error.to_string() << std::endl ;

	return all;
}

} // namespace zfs_recover
