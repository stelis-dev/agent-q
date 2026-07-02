#pragma once

#include <stddef.h>
#include <stdint.h>

namespace signing {

constexpr uint32_t kSessionAdvertisedTtlMs = 0xffffffffu;
constexpr size_t kSessionIdSize = 26;

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

void session_init();
bool session_active();
const char* session_id();
void session_clear();
SessionStartResult session_replace(
    SessionRandomFn random_fn,
    void* random_context);
bool session_id_format_valid(const char* session_id);
SessionValidationResult session_validate(const char* session_id);

}  // namespace signing
