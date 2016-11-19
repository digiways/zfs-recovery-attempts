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

void LZ4_COPYSTEP(const uint8_t*& ip, uint8_t*& op)
{
	*reinterpret_cast<uint64_t*>(op) = *reinterpret_cast<const uint64_t*>(ip);
	op += 8;
	ip += 8;
}

void LZ4_WILDCOPY(const uint8_t*& ip, uint8_t*& op, uint8_t* cpy)
{
	do
	{
		LZ4_COPYSTEP(ip, op);
	} while (op < cpy);
}

void LZ4_SECURECOPY(const uint8_t*& ref, uint8_t*& op, uint8_t* cpy)
{
	if (op < cpy)
	{
		LZ4_WILDCOPY(ref, op, cpy);
	}
}

int LZ4_uncompress_unknownOutputSize(const char *source, char *dest, int isize, int maxOutputSize)
{
	static constexpr int ML_BITS = 4;
	static constexpr int ML_MASK ((1U<<ML_BITS)-1);
	static constexpr int RUN_BITS (8-ML_BITS);
	static constexpr int RUN_MASK ((1U<<RUN_BITS)-1);

	static constexpr int STEPSIZE = 8;
	static constexpr int COPYLENGTH = 8;
	/* Local Variables */
	const uint8_t * ip = (const uint8_t *) source;
	const uint8_t *const iend = ip + isize;
	const uint8_t *ref;

	uint8_t *op = (uint8_t *) dest;
	uint8_t *const oend = op + maxOutputSize;
	uint8_t *cpy;

	size_t dec32table[] = {0, 3, 2, 3, 0, 0, 0, 0};
	size_t dec64table[] = {0, 0, 0, (size_t)-1, 0, 1, 2, 3};

	/* Main Loop */
	while (ip < iend)
	{
		unsigned token;
		size_t length;

		/* get runlength */
		token = *ip++;
		if ((length = (token >> ML_BITS)) == RUN_MASK) {
			int s = 255;
			while ((ip < iend) && (s == 255)) {
				s = *ip++;
				length += s;
			}
		}
		/* copy literals */
		cpy = op + length;
		/* CORNER-CASE: cpy might overflow. */
		if (cpy < op)
			goto _output_error;	/* cpy was overflowed, bail! */
		if ((cpy > oend - COPYLENGTH) ||
		    (ip + length > iend - COPYLENGTH)) {
			if (cpy > oend)
				/* Error: writes beyond output buffer */
				goto _output_error;
			if (ip + length != iend)
				/*
				 * Error: LZ4 format requires to consume all
				 * input at this stage
				 */
				goto _output_error;
			(void) memcpy(op, ip, length);
			op += length;
			/* Necessarily EOF, due to parsing restrictions */
			break;
		}
		LZ4_WILDCOPY(ip, op, cpy);
		ip -= (op - cpy);
		op = cpy;

		/* get offset */
		// read little endian 16
		ref = cpy - *reinterpret_cast<const uint16_t*>(ip);

		ip += 2;
		if (ref < (uint8_t * const) dest)
			/*
			 * Error: offset creates reference outside of
			 * destination buffer
			 */
			goto _output_error;

		/* get matchlength */
		if ((length = (token & ML_MASK)) == ML_MASK) {
			while (ip < iend) {
				int s = *ip++;
				length += s;
				if (s == 255)
					continue;
				break;
			}
		}
		/* copy repeated sequence */
		if (op - ref < STEPSIZE) {
			size_t dec64 = dec64table[op-ref];
			op[0] = ref[0];
			op[1] = ref[1];
			op[2] = ref[2];
			op[3] = ref[3];
			op += 4;
			ref += 4;
			ref -= dec32table[op-ref];
			*reinterpret_cast<uint32_t*>(op) = *reinterpret_cast<const uint32_t*>(ref);
			op += STEPSIZE - 4;
			ref -= dec64;
		} else {
			LZ4_COPYSTEP(ref, op);
		}
		cpy = op + length - (STEPSIZE - 4);
		if (cpy > oend - COPYLENGTH) {
			if (cpy > oend)
				/*
				 * Error: request to write outside of
				 * destination buffer
				 */
				goto _output_error;
			LZ4_SECURECOPY(ref, op, (oend - COPYLENGTH));
			while (op < cpy)
				*op++ = *ref++;
			op = cpy;
			if (op == oend)
				/*
				 * Check EOF (should never happen, since
				 * last 5 bytes are supposed to be literals)
				 */
				goto _output_error;
			continue;
		}
		LZ4_SECURECOPY(ref, op, cpy);
		op = cpy;	/* correction */
	}

	/* end of decoding */
	return (int)(((char *)op) - dest);

	/* write overflow error detected */
	_output_error:
	return (int)(-(((char *)ip) - source));
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
	bool res = (LZ4_uncompress_unknownOutputSize(reinterpret_cast<char*>(const_cast<uint8_t*>(src + sizeof(uint32_t))), reinterpret_cast<char*>(out.data()), input_size, out.size()) >= 0);
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