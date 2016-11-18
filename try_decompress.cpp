#include <stdint.h>
#include <vector>
#include <string>
#include <fstream>
#include <sys/param.h>
#include <iostream>
#include <iomanip>
#include "device.hpp"

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

/*
 * Note: The decoding functions real_LZ4_uncompress() and
 *	LZ4_uncompress_unknownOutputSize() are safe against "buffer overflow"
 *	attack type. They will never write nor read outside of the provided
 *	output buffers. LZ4_uncompress_unknownOutputSize() also insures that
 *	it will never read outside of the input buffer. A corrupted input
 *	will produce an error result, a negative int, indicating the position
 *	of the error within input stream.
 *
 * Note[2]: real_LZ4_uncompress(), referred to above, is not used in ZFS so
 *	its code is not present here.
 */

void LZ4_SECURECOPY(uint8_t* dest, size_t& ref_idx, size_t& op_idx, size_t cpy_idx)
{
	if (op_idx < cpy_idx)
	{
		do
		{
			*reinterpret_cast<uint64_t*>(dest + op_idx) = *reinterpret_cast<const uint64_t*>(dest + ref_idx);
			op_idx += 8;
			ref_idx += 8;
		} while (op_idx < cpy_idx);
	}
}

size_t LZ4_uncompress_unknownOutputSize(const uint8_t* source, int isize, std::vector<uint8_t>& out, decompression_error& error)
{
	// https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md

	static constexpr int ML_BITS = 4;
	static constexpr int ML_MASK ((1U<<ML_BITS)-1);
	static constexpr int RUN_BITS (8-ML_BITS);
	static constexpr int RUN_MASK ((1U<<RUN_BITS)-1);

	/* Local Variables */
	const uint8_t* ip = (const uint8_t *) source;
	const uint8_t* const iend = ip + isize;

	const size_t out_initial_size = out.size();

	while (ip < iend)
	{
		/* get runlength */
		unsigned int token = *ip;
		printf("token=%u\n", token);
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
		printf("length = %lu\n", length);
		if (length > 1024*1024)
		{
			error.msg = "cpy waf overflowed, length too big";
			error.src_pos = ip - source;
			error.offset = length;
			return 0;
		}
		if (ip + length > iend - 4)
		{
			if (ip + length != iend)
			{
				error.msg = "LZ4 format requires to consume all input at this stage";
				error.src_pos = ip - source;
				return 0;
			}
			out.insert(out.end(), ip, ip+length);
			break;
		}

		out.insert(out.end(), ip, ip + length);
		ip += length;

		// get offset - read little endian 16
		uint16_t ref_offset = *reinterpret_cast<const uint16_t*>(ip);
		printf("ref_offset=%u\n", int(ref_offset));
		if (ref_offset == 0 || ref_offset > (out.size() - out_initial_size))
		{
			error.msg = "ref_offset is invalid";
			error.dest_pos = out.size() - out_initial_size;
			error.offset = ref_offset;
			error.src_pos = ip - source;
			return 0;
		}
		size_t ref_idx = out.size() - ref_offset;
		ip += 2;

		/* get matchlength */
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
		printf("ref_length = %lu\n", ref_length);
		ref_length += 4; // minimum length is t, so value of 0 means - 4 bytes to copy
		if (ref_idx + ref_length > out.size())
		{
			error.msg = "ref length is invalid";
			error.dest_pos = out.size() - out_initial_size;
			error.offset = ref_offset;
			error.length = ref_length;
			error.src_pos = ip - source;
			return false;
		}
		out.reserve(out.size() + ref_length);
		out.insert(out.end(), out.data() + ref_idx, out.data() + ref_idx + ref_length);
	}

	/* end of decoding */
	return out.size();
}

bool lz4_decompress(const uint8_t* const src, size_t src_size, std::vector<uint8_t>& out, decompression_error& error)
{
	if (src_size < sizeof(uint32_t))
	{
		error.msg = "src_size < sizeof(uint32_t)";
		return false;
	}
	size_t input_size = __builtin_bswap32(*reinterpret_cast<const uint32_t*>(src));
	bool res = (LZ4_uncompress_unknownOutputSize(src + sizeof(uint32_t), input_size, out, error) != 0);
	return res;
}

std::vector<uint8_t> try_decompress(const uint8_t* data, size_t size)
{
	std::vector<uint8_t> ret;
	decompression_error error;
	bool lzjb_res = lzjb_decompress(data, size, ret, error);
	if (lzjb_res)
		return ret;
	error = decompression_error();
	bool zle_res = zle_decompress(data, size, ret, error);
	if (zle_res)
		return ret;

	bool lz4_res = lz4_decompress(data, size, ret, error);
	if (!lz4_res)
		throw std::runtime_error("LZ4 decompression error: " + error.to_string() + ", size=" + std::to_string(size));

//	if (!zle_res)
//		throw std::runtime_error("ZLE decompression error: " + error.to_string() + ", size=" + std::to_string(size));

//	if (!lzjb_res)
//		throw std::runtime_error("JZLB decompression error: " + error.to_string());
	return ret;
}

int main()
{
	Device device("data1-compressed.bin");
	std::vector<uint8_t> data = try_decompress(device.data(), device.size());
	std::ofstream f("data1-compressed-decompressed.bin");
	f.write(reinterpret_cast<const char*>(data.data()), data.size());
	std::cout << (uint8_t(0) == uint8_t(1 << 8)) << std::endl ;
	std::cout << std::hex << (1 << 7) << std::endl ;
}
