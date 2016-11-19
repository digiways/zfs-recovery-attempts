#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdexcept>
#include <string.h>
#include <linux/fs.h>

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

		if (size_ == 0)
		{
			::ioctl(file_, BLKGETSIZE64, &size_);
		}

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
