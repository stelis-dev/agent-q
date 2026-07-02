#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace signing {

constexpr size_t kU64DecimalMaxDigits = 20;
constexpr size_t kU64DecimalBufferBytes = kU64DecimalMaxDigits + 1;
constexpr const char* kU64DecimalMaxString = "18446744073709551615";

inline bool is_u64_decimal_string(const char* value)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }

    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
        ++length;
        if (length > kU64DecimalMaxDigits) {
            return false;
        }
    }
    if (length == kU64DecimalMaxDigits &&
        strcmp(value, kU64DecimalMaxString) > 0) {
        return false;
    }
    return true;
}

inline bool is_canonical_u64_decimal_string(const char* value)
{
    if (!is_u64_decimal_string(value)) {
        return false;
    }
    return value[0] != '0' || value[1] == '\0';
}

inline bool parse_u64_decimal_string(const char* value, uint64_t* output)
{
    if (output == nullptr) {
        return false;
    }
    *output = 0;
    if (!is_u64_decimal_string(value)) {
        return false;
    }

    uint64_t parsed = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        parsed = (parsed * 10) + static_cast<uint64_t>(*cursor - '0');
    }
    *output = parsed;
    return true;
}

inline bool parse_canonical_u64_decimal_string(const char* value, uint64_t* output)
{
    if (!is_canonical_u64_decimal_string(value)) {
        if (output != nullptr) {
            *output = 0;
        }
        return false;
    }
    return parse_u64_decimal_string(value, output);
}

inline const char* skip_u64_decimal_leading_zeroes(const char* value)
{
    while (value[0] == '0' && value[1] != '\0') {
        ++value;
    }
    return value;
}

inline int compare_u64_decimal_strings(const char* left, const char* right)
{
    const char* normalized_left = skip_u64_decimal_leading_zeroes(left);
    const char* normalized_right = skip_u64_decimal_leading_zeroes(right);
    const size_t left_len = strlen(normalized_left);
    const size_t right_len = strlen(normalized_right);
    if (left_len < right_len) {
        return -1;
    }
    if (left_len > right_len) {
        return 1;
    }
    const int cmp = strcmp(normalized_left, normalized_right);
    if (cmp < 0) {
        return -1;
    }
    if (cmp > 0) {
        return 1;
    }
    return 0;
}

inline bool format_u64_decimal(uint64_t value, char* output, size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return false;
    }

    char scratch[kU64DecimalBufferBytes] = {};
    size_t position = sizeof(scratch) - 1;
    scratch[position] = '\0';

    do {
        if (position == 0) {
            return false;
        }
        scratch[--position] = static_cast<char>('0' + (value % 10));
        value /= 10;
    } while (value != 0);

    const size_t byte_count = sizeof(scratch) - position;
    if (byte_count > output_size) {
        return false;
    }
    memcpy(output, &scratch[position], byte_count);
    return true;
}

}  // namespace signing
