#include <stdint.h>
#include <vector>
#include <string>
#include <fstream>
#include <sys/param.h>
#include "device.hpp"

int lzjb_decompress(const uint8_t *s_start, uint8_t *d_start, size_t s_len, size_t d_len, int n)
{
	static constexpr int MATCH_BITS = 6;
	static constexpr int OFFSET_MASK = ((1 << (16 - MATCH_BITS)) - 1);
	static constexpr int MATCH_MIN = 3;

	const uint8_t *src = s_start;
	uint8_t *dst = d_start;
	uint8_t *d_end = (uint8_t *)d_start + d_len;
	uint8_t *cpy;
	uint8_t copymap = 0;
	int copymask = 1 << (NBBY - 1);

	while (dst < d_end) {
		if ((copymask <<= 1) == (1 << NBBY)) {
			copymask = 1;
			copymap = *src++;
		}
		if (copymap & copymask) {
			int mlen = (src[0] >> (NBBY - MATCH_BITS)) + MATCH_MIN;
			int offset = ((src[0] << NBBY) | src[1]) & OFFSET_MASK;
			src += 2;
			if ((cpy = dst - offset) < (uint8_t *)d_start)
				return (-1);
			while (--mlen >= 0 && dst < d_end)
				*dst++ = *cpy++;
		} else {
			*dst++ = *src++;
		}
	}
	return (0);
}

std::vector<uint8_t> try_decompress(const uint8_t* data, size_t size)
{
	std::vector<uint8_t> ret;
	return ret;
}

int main()
{
	Device device("data1-compressed.bin");
	std::vector<uint8_t> data = try_decompress(device.data(), device.size());
	std::ofstream f("data1-compressed-decompressed.bin");
	f.write(reinterpret_cast<const char*>(data.data()), data.size());
}
