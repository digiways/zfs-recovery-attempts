#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdexcept>
#include <string.h>
#include <thread>
#include <vector>

class Device
{
public:
	explicit Device(const std::string& filename)
		: name_(filename)
	{
		file_ = ::open(filename.c_str(), O_RDONLY);
		if (file_ == -1)
		{
			int err_code = errno;
			throw std::runtime_error("Error opening '" + filename + "' for reading " + " : " + strerror(err_code));
		}
		struct stat st;
		int res = ::fstat(file_, &st);
		if (res != 0)
			throw std::runtime_error("Error calling fstat on " + filename);
		size_ = st.st_size;

		mapping_addr_ = static_cast<uint8_t*>(::mmap(0, size_, PROT_READ, MAP_SHARED, file_, 0));
		if (mapping_addr_ == MAP_FAILED)
		{
			::close(file_);
			throw std::runtime_error("mmap failed with: " + filename);
		}

		::madvise(mapping_addr_, size_, MADV_SEQUENTIAL);
	}

	~Device()
	{
		::munmap(mapping_addr_, size_);
		::close(file_);
	}

	Device(const Device&) = delete;
	Device& operator=(const Device&) = delete;

	const std::string& name() const { return name_; }
	size_t size() const { return size_; }
	const uint8_t* data() const { return mapping_addr_; }

private:
	std::string name_;
	int file_;
	uint8_t* mapping_addr_;
	size_t size_;
};

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
	Device device(filename);
	search(filename, device.data(), device.size(), tokens, max_distance);
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
	std::vector<std::string> filenames { "data1", "data2", "data3" };
	std::vector<std::string> tokens { "ABC", "DEF" };
	size_t max_distance = 8*60;
	search(filenames, tokens, max_distance);
}
