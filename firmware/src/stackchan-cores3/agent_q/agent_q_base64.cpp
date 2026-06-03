#include "agent_q_base64.h"

#include <string.h>

namespace agent_q {
namespace {

int base64_value(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return 26 + c - 'a';
    }
    if (c >= '0' && c <= '9') {
        return 52 + c - '0';
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

bool bounded_c_string_length(const char* value, size_t max_size, size_t* output)
{
    if (value == nullptr || output == nullptr) {
        return false;
    }
    for (size_t index = 0; index <= max_size; ++index) {
        if (value[index] == '\0') {
            *output = index;
            return true;
        }
    }
    return false;
}

}  // namespace

bool validate_canonical_base64(
    const char* value,
    size_t max_base64_size,
    size_t max_decoded_size,
    size_t* decoded_size)
{
    if (decoded_size != nullptr) {
        *decoded_size = 0;
    }
    if (value == nullptr) {
        return false;
    }

    size_t length = 0;
    if (!bounded_c_string_length(value, max_base64_size, &length)) {
        return false;
    }
    if (length == 0 || length > max_base64_size || (length % 4) != 0) {
        return false;
    }

    size_t padding = 0;
    if (value[length - 1] == '=') {
        padding++;
    }
    if (length >= 2 && value[length - 2] == '=') {
        padding++;
    }

    for (size_t index = 0; index < length; ++index) {
        const char c = value[index];
        const bool in_padding = index >= length - padding;
        if (in_padding) {
            if (c != '=') {
                return false;
            }
            continue;
        }
        if (c == '=' || base64_value(c) < 0) {
            return false;
        }
    }

    if (padding == 1) {
        const int third = base64_value(value[length - 2]);
        if (third < 0 || (third & 0x03) != 0) {
            return false;
        }
    } else if (padding == 2) {
        const int second = base64_value(value[length - 3]);
        if (second < 0 || (second & 0x0F) != 0) {
            return false;
        }
    } else if (padding > 2) {
        return false;
    }

    const size_t output_size = ((length / 4) * 3) - padding;
    if (output_size == 0 || output_size > max_decoded_size) {
        return false;
    }
    if (decoded_size != nullptr) {
        *decoded_size = output_size;
    }
    return true;
}

}  // namespace agent_q
