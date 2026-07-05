#pragma once

#include <stddef.h>
#include <stdint.h>

namespace stopwatch_target {

bool decode_canonical_base64_input(
    const char* value,
    size_t max_chars,
    uint8_t* output,
    size_t output_size,
    size_t* decoded_size);

}  // namespace stopwatch_target
