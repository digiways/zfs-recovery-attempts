#pragma once

#include <vector>
#include <string>
#include <stdexcept>

//#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

namespace zfs_recover_tools
{

	class ROFile
	{
	public:
		explicit ROFile(const std::string& filename) : ROFile(filename, O_RDONLY) {}
		ROFile() = default;
		ROFile(const ROFile&) = delete;
		ROFile& operator=(const ROFile&) = delete;
		ROFile(ROFile&& rhs) : handle_(rhs.handle_), pos_(rhs.pos_), filename_(std::move(rhs.filename_)) { rhs.handle_ = -1; }
		~ROFile() { if (handle_ != -1) ::close(handle_); }

		size_t size() const
		{
			struct stat st;
			int res = ::fstat(handle_, &st);
			if (res != 0)
				throw std::runtime_error("Error calling fstat on " + filename_);

			size_t size = st.st_size;
			if (size == 0)
			{
				::ioctl(handle_, BLKGETSIZE64, &size);
			}

			return size;
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

		std::vector<uint8_t> read()
		{
			std::vector<uint8_t> v(size());
			read(v.data(), v.size());
			return v;
		}

		const std::string& filename() const { return filename_; }

	protected:
		explicit ROFile(const std::string& filename, int flags) : filename_(filename)
		{
			handle_ = ::open(filename.c_str(), flags,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
			if (handle_ == -1)
				throw std::runtime_error("Error opening file " + filename);
			pos_ = 0;
		}

		int handle_ = -1;
		size_t pos_ = 0;
		std::string filename_;
		friend class MMROFileView;
	};

	class RWFile : public ROFile
	{
	public:
		enum flags_t { DEFAULT = 0, CREATE_IF_NOT_EXISTS = 1, ALWAYS_CREATE_EMPTY_NEW = 2 };
		RWFile(const std::string& filename, flags_t flags)
			: ROFile(
				filename,
				(
					O_RDWR
					| (flags==flags_t::CREATE_IF_NOT_EXISTS ? O_CREAT : 0)
					| (flags==flags_t::ALWAYS_CREATE_EMPTY_NEW ? (O_CREAT | O_TRUNC) : 0)
				))
		{
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
	};

	class MMROFileView
	{
	public:
		explicit MMROFileView(const ROFile& file)
			: MMROFileView(file, PROT_READ)
		{
		}
		~MMROFileView()
		{
			if (mapping_addr_)
				::munmap(mapping_addr_, size_);
		}

		MMROFileView(const MMROFileView&) = delete;
		MMROFileView& operator=(const MMROFileView&) = delete;
		MMROFileView(MMROFileView&& rhs) : file_(std::move(rhs.file_)), mapping_addr_(rhs.mapping_addr_), size_(rhs.size_)
		{
			rhs.mapping_addr_ = nullptr;
			rhs.size_ = 0;
		}

		size_t size() const { return size_; }
		const uint8_t* data() const { return mapping_addr_; }

	protected:
		explicit MMROFileView(const ROFile& file, int mmap_flags)
			: file_(&file)
		{
			size_ = file_->size();
			mapping_addr_ = static_cast<uint8_t*>(::mmap(0, size_, mmap_flags, MAP_SHARED, file_->handle_, 0));
			if (mapping_addr_ == MAP_FAILED)
				throw std::runtime_error("mmap failed with: " + file_->filename());

			::madvise(mapping_addr_, size_, MADV_SEQUENTIAL);
		}
		uint8_t* mapping_addr_;
	private:
		const ROFile* file_;
		size_t size_;
	};

	class MMRWFileView : public MMROFileView
	{
	public:
		MMRWFileView(const RWFile& file)
			: MMROFileView(file, PROT_READ | PROT_WRITE)
		{
		}
		uint8_t* data() const { return mapping_addr_; }
	};

	class DeviceImpl { protected: ROFile file; DeviceImpl(const std::string& filename) : file(filename) {} };
	class Device : private DeviceImpl, public MMROFileView
	{
	public:
		explicit Device(const std::string& filename)
			: DeviceImpl(filename), MMROFileView(file)
		{
		}
		const std::string& filename() const { return file.filename(); }
	private:
	};

} // namespace zfs_recover_tools
