#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

namespace signing {

constexpr uint32_t kSessionAdvertisedTtlMs = 0xffffffffu;
constexpr size_t kSessionIdPrefixSize = 8;
constexpr size_t kSessionIdGeneratedHexSize = 16;
constexpr size_t kSessionIdMaxHexSize = 17;
constexpr size_t kSessionIdGeneratedSize = kSessionIdPrefixSize + kSessionIdGeneratedHexSize + 1;
constexpr size_t kSessionIdSize = kSessionIdPrefixSize + kSessionIdMaxHexSize + 1;

enum class SessionStartResult {
    ok,
    rng_error,
};

enum class SessionValidationResult {
    ok,
    invalid_format,
    missing,
    mismatch,
};

using SessionRandomFn = bool (*)(void* output, size_t size, void* context);

inline void session_id_wipe_bytes(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

inline bool session_id_format_from_random(
    SessionRandomFn random_fn,
    void* random_context,
    char* output,
    size_t output_size)
{
    if (random_fn == nullptr || output == nullptr || output_size < kSessionIdGeneratedSize) {
        return false;
    }

    uint8_t bytes[8] = {};
    if (!random_fn(bytes, sizeof(bytes), random_context)) {
        session_id_wipe_bytes(bytes, sizeof(bytes));
        return false;
    }

    const int written = snprintf(
        output,
        output_size,
        "session_%02x%02x%02x%02x%02x%02x%02x%02x",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7]);
    session_id_wipe_bytes(bytes, sizeof(bytes));
    return written > 0 && static_cast<size_t>(written) + 1 <= output_size;
}

inline bool session_id_format_valid(const char* value)
{
    if (value == nullptr) {
        return false;
    }
    constexpr const char* kExpectedPrefix = "session_";
    for (size_t index = 0; index < kSessionIdPrefixSize; ++index) {
        if (value[index] != kExpectedPrefix[index]) {
            return false;
        }
    }
    size_t suffix_length = 0;
    for (const char* cursor = value + kSessionIdPrefixSize; *cursor != '\0'; ++cursor) {
        if (++suffix_length > kSessionIdMaxHexSize) {
            return false;
        }
        const char c = *cursor;
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) {
            return false;
        }
    }
    return suffix_length > 0;
}

}  // namespace signing
