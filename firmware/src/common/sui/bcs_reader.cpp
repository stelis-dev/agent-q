#include "bcs_reader.h"

#include <string.h>

namespace signing {

SuiBcsReader::SuiBcsReader(const uint8_t* data, size_t size)
    : data_(data), size_(size), offset_(0), error_(SuiBcsReaderError::ok)
{
    if (data == nullptr && size != 0) {
        error_ = SuiBcsReaderError::malformed;
    }
}

bool SuiBcsReader::require(size_t len)
{
    if (!ok()) {
        return false;
    }
    if (len > remaining()) {
        set_error(SuiBcsReaderError::malformed);
        return false;
    }
    return true;
}

bool SuiBcsReader::read_u8(uint8_t* out)
{
    if (out == nullptr || !require(1)) {
        return false;
    }
    *out = data_[offset_];
    offset_ += 1;
    return true;
}

bool SuiBcsReader::read_u16_le(uint16_t* out)
{
    if (out == nullptr || !require(2)) {
        return false;
    }
    *out = static_cast<uint16_t>(data_[offset_]) |
           static_cast<uint16_t>(static_cast<uint16_t>(data_[offset_ + 1]) << 8);
    offset_ += 2;
    return true;
}

bool SuiBcsReader::read_u32_le(uint32_t* out)
{
    if (out == nullptr || !require(4)) {
        return false;
    }
    *out = static_cast<uint32_t>(data_[offset_]) |
           (static_cast<uint32_t>(data_[offset_ + 1]) << 8) |
           (static_cast<uint32_t>(data_[offset_ + 2]) << 16) |
           (static_cast<uint32_t>(data_[offset_ + 3]) << 24);
    offset_ += 4;
    return true;
}

bool SuiBcsReader::read_u64_le(uint64_t* out)
{
    if (out == nullptr || !require(8)) {
        return false;
    }
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value |= static_cast<uint64_t>(data_[offset_ + index]) << (index * 8);
    }
    *out = value;
    offset_ += 8;
    return true;
}

bool SuiBcsReader::read_uleb128_u32(uint32_t* out)
{
    if (out == nullptr || !ok()) {
        return false;
    }

    uint32_t value = 0;
    for (uint32_t index = 0; index < 5; ++index) {
        uint8_t byte = 0;
        if (!read_u8(&byte)) {
            return false;
        }

        const uint32_t payload = static_cast<uint32_t>(byte & 0x7F);
        if (index == 4 && payload > 0x0F) {
            set_error(SuiBcsReaderError::malformed);
            return false;
        }
        value |= payload << (index * 7);

        if ((byte & 0x80) == 0) {
            *out = value;
            return true;
        }
    }

    set_error(SuiBcsReaderError::malformed);
    return false;
}

bool SuiBcsReader::read_fixed_bytes(uint8_t* out, size_t len)
{
    if ((out == nullptr && len != 0) || !require(len)) {
        return false;
    }
    if (len != 0) {
        memcpy(out, data_ + offset_, len);
    }
    offset_ += len;
    return true;
}

bool SuiBcsReader::skip_bytes(size_t len)
{
    if (!require(len)) {
        return false;
    }
    offset_ += len;
    return true;
}

bool SuiBcsReader::read_vector_length(uint32_t max_len, uint32_t* out)
{
    uint32_t len = 0;
    if (!read_uleb128_u32(&len)) {
        return false;
    }
    if (len > max_len) {
        set_error(SuiBcsReaderError::length_out_of_bounds);
        return false;
    }
    if (out != nullptr) {
        *out = len;
    }
    return true;
}

bool SuiBcsReader::expect_eof()
{
    if (!ok()) {
        return false;
    }
    if (remaining() != 0) {
        set_error(SuiBcsReaderError::trailing_bytes);
        return false;
    }
    return true;
}

size_t SuiBcsReader::remaining() const
{
    return offset_ <= size_ ? size_ - offset_ : 0;
}

size_t SuiBcsReader::consumed() const
{
    return offset_;
}

bool SuiBcsReader::ok() const
{
    return error_ == SuiBcsReaderError::ok;
}

SuiBcsReaderError SuiBcsReader::error() const
{
    return error_;
}

void SuiBcsReader::set_error(SuiBcsReaderError error)
{
    if (error_ == SuiBcsReaderError::ok) {
        error_ = error;
    }
}

}  // namespace signing
