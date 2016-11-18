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
	std::string to_string() const
	{
		std::ostringstream s;
		s << msg << ", src_pos=" << src_pos << ", dest_pos=" << dest_pos << ", offset=" << offset;
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

size_t LZ4_uncompress_unknownOutputSize(const uint8_t* source, uint8_t* dest, int isize, int maxOutputSize, std::vector<uint8_t>& out, decompression_error& error)
{
	static constexpr int ML_BITS = 4;
	static constexpr int ML_MASK ((1U<<ML_BITS)-1);
	static constexpr int RUN_BITS (8-ML_BITS);
	static constexpr int RUN_MASK ((1U<<RUN_BITS)-1);

	static constexpr int STEPSIZE = 8;
	static constexpr int COPYLENGTH = 8;
	/* Local Variables */
	const uint8_t* ip = (const uint8_t *) source;
	const uint8_t* const iend = ip + isize;

//	const uint8_t* ref;
	//size_t ref_idx;

	size_t op_idx = 0;
//	uint8_t* op = (uint8_t*) dest;
	size_t oend_idx = maxOutputSize;
//	uint8_t* const oend = op + maxOutputSize;
//	size_t cpy_idx;
//	uint8_t* cpy;

	static constexpr size_t dec32table[] = {0, 3, 2, 3, 0, 0, 0, 0};
	static constexpr size_t dec64table[] = {0, 0, 0, (size_t)-1, 0, 1, 2, 3};

	/* Main Loop */
	while (ip < iend)
	{
		unsigned token;
		size_t length;

		/* get runlength */
		token = *ip++;
		if ((length = (token >> ML_BITS)) == RUN_MASK)
		{
			int s = 255;
			while ((ip < iend) && (s == 255))
			{
				s = *ip++;
				length += s;
			}
		}
		/* copy literals */
		size_t cpy_idx = op_idx + length;
		/* CORNER-CASE: cpy might overflow. */
		if (cpy_idx < op_idx)
		{
			error.msg = "cpy waf overflowed";
			error.src_pos = ip - source;
			return 0;
		}
		if ((cpy_idx > oend_idx - COPYLENGTH) || (ip + length > iend - COPYLENGTH))
		{
			if (cpy_idx > oend_idx)
			{
				error.msg = "writes beyond output buffer";
				error.src_pos = ip - source;
				return 0;
			}
			if (ip + length != iend)
			{
				error.msg = "LZ4 format requires to consume all input at this stage";
				error.src_pos = ip - source;
				return 0;
			}
			(void) memcpy(dest + op_idx, ip, length);
			op_idx += length;
			/* Necessarily EOF, due to parsing restrictions */
			break;
		}

		do
		{
			*reinterpret_cast<uint64_t*>(dest + op_idx) = *reinterpret_cast<const uint64_t*>(ip);
			op_idx += 8;
			ip += 8;
		} while (op_idx < cpy_idx);

		ip -= (op_idx - cpy_idx);
		op_idx = cpy_idx;

		/* get offset */
		// read little endian 16
		size_t ref_idx = cpy_idx - *reinterpret_cast<const uint16_t*>(ip);
		if (cpy_idx < *reinterpret_cast<const uint16_t*>(ip))
		{
			error.msg = "offset creates reference outside of destination buffer";
			error.src_pos = ip - source;
			return 0;
		}

		ip += 2;

		/* get matchlength */
		if ((length = (token & ML_MASK)) == ML_MASK)
		{
			while (ip < iend)
			{
				int s = *ip++;
				length += s;
				if (s == 255)
					continue;
				break;
			}
		}
		/* copy repeated sequence */
		if (op_idx - ref_idx < STEPSIZE)
		{
			size_t dec64 = dec64table[op_idx-ref_idx];
			dest[op_idx+0] = dest[ref_idx+0];
			dest[op_idx+1] = dest[ref_idx+1];
			dest[op_idx+2] = dest[ref_idx+2];
			dest[op_idx+3] = dest[ref_idx+3];
			op_idx += 4;
			ref_idx += 4;
			ref_idx -= dec32table[op_idx-ref_idx];
			*reinterpret_cast<uint32_t*>(dest + op_idx) = *reinterpret_cast<const uint32_t*>(dest + ref_idx);
			op_idx += STEPSIZE - 4;
			ref_idx -= dec64;
		}
		else
		{
			*reinterpret_cast<uint64_t*>(dest + op_idx) = *reinterpret_cast<const uint64_t*>(dest + ref_idx);
			op_idx += sizeof(uint64_t);
			ref_idx += sizeof(uint64_t);
		}
		cpy_idx = op_idx + length - (STEPSIZE - 4);
		if (cpy_idx > oend_idx - COPYLENGTH)
		{
			if (cpy_idx > oend_idx)
			{
				error.msg = "request to write outside of destination buffer";
				error.src_pos = ip - source;
				return 0;
			}
			LZ4_SECURECOPY(dest, ref_idx, op_idx, (oend_idx - COPYLENGTH));
			while (op_idx < cpy_idx)
			{
				dest[op_idx] = dest[ref_idx];
				++op_idx;
				++ref_idx;
			}
			op_idx = cpy_idx;
			if (op_idx == oend_idx)
			{
				error.msg = "Check EOF (should never happen, since last 5 bytes are supposed to be literals)";
				error.src_pos = ip - source;
				return 0;
			}
			continue;
		}
		LZ4_SECURECOPY(dest, ref_idx, op_idx, cpy_idx);
		op_idx = cpy_idx;	/* correction */
	}

	/* end of decoding */
	return op_idx;
}

bool lz4_decompress(const uint8_t* const src, size_t src_size, std::vector<uint8_t>& out, decompression_error& error)
{
	if (src_size < sizeof(uint32_t))
	{
		error.msg = "src_size < sizeof(uint32_t)";
		return false;
	}
	size_t input_size = __builtin_bswap32(*reinterpret_cast<const uint32_t*>(src));
	out.resize(999999);
	bool res = (LZ4_uncompress_unknownOutputSize(src + sizeof(uint32_t), out.data(), input_size, out.size(), out, error) != 0);
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
