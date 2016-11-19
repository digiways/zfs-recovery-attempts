#include "device.hpp"
#include "zfs_try_decompress.hpp"

#include <stdint.h>
#include <stdio.h>
#include <vector>
#include <fstream>

int main()
{
	using namespace zfs_recover;

	Device device("data1-compressed.bin");
	std::vector<std::vector<uint8_t>> data = try_decompress(device.data(), device.size());
	if (data.size() == 0)
	{
		printf("All decompression attempts failed");
		return 1;
	}
	if (data.size() != 1)
	{
		printf("More than one decompression attempt succeeded");
		return 1;
	}
	std::ofstream f("data1-compressed-decompressed.bin");
	f.write(reinterpret_cast<const char*>(data[0].data()), data[0].size());
}
