#include "protocol/base64.h"
#include "protocol_input_encoding.h"

#include <string.h>

extern "C" {
#include "byte_conversions.h"
}

namespace stopwatch_target {

bool decode_canonical_base64_input(
    const char* value,
    size_t max_chars,
    uint8_t* output,
    size_t output_size,
    size_t* decoded_size)
{
    size_t size = 0;
    if (!signing::validate_canonical_base64_syntax(value, max_chars, &size) ||
        output == nullptr ||
        size > output_size ||
        base64_to_bytes(value, strlen(value), output, output_size) != 0) {
        if (decoded_size != nullptr) {
            *decoded_size = 0;
        }
        return false;
    }
    if (decoded_size != nullptr) {
        *decoded_size = size;
    }
    return true;
}

}  // namespace stopwatch_target
