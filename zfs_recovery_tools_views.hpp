#pragma once

#include <stdint.h>
#include <stdexcept>

namespace zfs_recover_tools
{

	class data_view_t
	{
	public:
		data_view_t(const uint8_t* data, size_t size) : data_(data), size_(size) {}
		data_view_t(const data_view_t&) = default;
		data_view_t& operator=(const data_view_t&) = default;

		const uint8_t* data() const { return data_; }
		size_t size() const { return size_; }
		uint8_t operator[](size_t pos)
		{
			if (pos >= size_)
				throw std::runtime_error("out of bounds data_view access");
			return data_[pos];
		}
	private:
		const uint8_t* const data_;
		const size_t size_;
	};

	class decompressed_data_view_t : public data_view_t
	{
	public:
		decompressed_data_view_t(const uint8_t* data, size_t size, size_t original_size) : data_view_t(data, size), original_size_(original_size) {}
		decompressed_data_view_t(const decompressed_data_view_t&) = default;
		decompressed_data_view_t& operator=(const decompressed_data_view_t&) = default;

		size_t original_size() const { return original_size_; }

	private:
		size_t original_size_;
	};

	class device_view_t : public data_view_t
	{
	public:
		device_view_t(const uint8_t* data, size_t size, const char* name, uint64_t top_level_id) : data_view_t(data, size), name_(name), top_level_id_(top_level_id) {}

		const char* name() const { return name_; }
		uint64_t top_level_id() const { return top_level_id_; }

	private:
		const char* name_;
		uint64_t top_level_id_;
	};
} // namespace zfs_recover_tools
