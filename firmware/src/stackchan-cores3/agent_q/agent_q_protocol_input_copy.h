#pragma once

#include <stddef.h>

namespace agent_q {

// Bounded copy of a non-empty C string into a fixed-size buffer. Returns false
// (and empties output) when input is null/empty, output is null/zero-size, or
// input does not fit in output_size including its terminator. Shared by the
// protocol input paths (connect approval, protocol PIN approval, and the
// sign-transaction / sign-personal-message ingress and validation steps) that
// each copy a bounded request field and fail closed on overflow.
inline bool copy_nonempty_c_string(const char* input, char* output, size_t output_size)
{
    if (input == nullptr || input[0] == '\0' || output == nullptr || output_size == 0) {
        return false;
    }
    size_t index = 0;
    while (input[index] != '\0' && index + 1 < output_size) {
        output[index] = input[index];
        ++index;
    }
    if (input[index] != '\0') {
        output[0] = '\0';
        return false;
    }
    output[index] = '\0';
    return true;
}

}  // namespace agent_q
