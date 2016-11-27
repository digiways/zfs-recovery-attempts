#pragma once

#include <string>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdexcept>
#include <sys/types.h>
#include <unistd.h>

namespace zfs_recover_tools
{

	class File
	{
	public:
		File() = default;
		File(const std::string& filename, int flags) : filename_(filename)
		{
			handle_ = ::open(filename.c_str(), flags,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
			if (handle_ == -1)
				throw std::runtime_error("Error opening file " + filename);
			pos_ = 0;
		}
		File(const File&) = delete;
		File& operator=(const File&) = delete;
		File(File&& rhs) : handle_(rhs.handle_), pos_(rhs.pos_), filename_(std::move(rhs.filename_)) { rhs.handle_ = 0; }
		~File() { if (handle_ != -1) ::close(handle_); }

		size_t size()
		{
			struct stat st;
			int res = ::fstat(handle_, &st);
			if (res != 0)
				throw std::runtime_error("Error calling fstat on " + filename_);
			return st.st_size;
		}

		void set_position(size_t pos)
		{
			off64_t ret = ::lseek64(handle_, pos, SEEK_SET);
			if (ret == -1)
				throw std::runtime_error("Error setting file '" + filename_ + "' position to " + std::to_string(pos));
			pos_ = pos;
		}

		size_t get_position()
		{
			return pos_;
		}

		void read(void* dest, size_t size)
		{
			int res = ::read(handle_, dest, size);
			if (res != size)
				throw std::runtime_error("Error reading " + std::to_string(size) + " bytes from file '" + filename_ + "'");
			pos_ += size;
		}

		void write(const void* src, size_t size)
		{
			int res = ::write(handle_, src, size);
			if (res != size)
				throw std::runtime_error("Error writing " + std::to_string(size) + " bytes to file '" + filename_ + "'");
			pos_ += size;
		}

		void resize(size_t size)
		{
			int res = ::ftruncate(handle_, size);
			if (res == -1)
				throw std::runtime_error("Error resizing file '" + filename_ + "' to " + std::to_string(size) + " bytes");
		}

		const std::string& filename() const { return filename_; }

	private:
		int handle_ = -1;
		size_t pos_ = 0;
		std::string filename_;
	};

} // namespace zfs_recover_tools
