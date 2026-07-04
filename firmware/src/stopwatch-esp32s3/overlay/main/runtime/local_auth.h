#pragma once

#include <stddef.h>
#include <stdint.h>

namespace stopwatch_target {

constexpr size_t kLocalAuthMinDigits = 1;
constexpr size_t kLocalAuthMaxDigits = 4;
constexpr size_t kLocalAuthInputBufferSize = kLocalAuthMaxDigits + 1;
constexpr uint32_t kLocalAuthInputTimeoutMs = 30000;

enum class LocalAuthStoreStatus {
    active,
    missing,
    invalid,
    storage_error,
};

enum class LocalAuthVerifyResult {
    verified,
    rejected,
    locked,
    missing,
    invalid,
    storage_error,
};

struct LocalAuthSnapshot {
    LocalAuthStoreStatus status;
    uint8_t code_length;
    uint32_t failed_attempts;
    uint8_t lock_tier;
    bool locked;
    uint64_t lock_remaining_ms;
};

void local_auth_init(uint64_t now_ms);
bool local_auth_code_shape_valid(const char* code, size_t length);
bool local_auth_store_new_code(const char* code, size_t length);
LocalAuthVerifyResult local_auth_verify_code(const char* code, size_t length, uint64_t now_ms);
LocalAuthSnapshot local_auth_snapshot(uint64_t now_ms);
bool local_auth_clear();
void wipe_sensitive_buffer(void* data, size_t size);

#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
void local_auth_test_reset_store();
void local_auth_test_corrupt_record();
bool local_auth_test_record_contains(const char* text);
void local_auth_test_set_write_failure(bool enabled);
#endif

}  // namespace stopwatch_target
