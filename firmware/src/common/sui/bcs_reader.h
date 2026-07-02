#pragma once

#include <stddef.h>
#include <stdint.h>

namespace signing {

enum class SuiBcsReaderError {
    ok,
    malformed,
    length_out_of_bounds,
    trailing_bytes,
};

class SuiBcsReader {
public:
    SuiBcsReader(const uint8_t* data, size_t size);

    bool read_u8(uint8_t* out);
    bool read_u16_le(uint16_t* out);
    bool read_u32_le(uint32_t* out);
    bool read_u64_le(uint64_t* out);
    bool read_uleb128_u32(uint32_t* out);
    bool read_fixed_bytes(uint8_t* out, size_t len);
    bool skip_bytes(size_t len);
    bool read_vector_length(uint32_t max_len, uint32_t* out);
    bool expect_eof();

    size_t remaining() const;
    size_t consumed() const;
    bool ok() const;
    SuiBcsReaderError error() const;
    void set_error(SuiBcsReaderError error);

private:
    bool require(size_t len);

    const uint8_t* data_;
    size_t size_;
    size_t offset_;
    SuiBcsReaderError error_;
};

}  // namespace signing
