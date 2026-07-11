#pragma once

#include <stddef.h>
#include <stdint.h>

#include "keystore/encrypted_keystore.h"
#include "pin_policy.h"

namespace stopwatch_target {

constexpr size_t kLocalAuthInputBufferSize = signing::kKeystorePinBufferBytes;
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
    uint32_t failed_attempts;
    uint8_t lock_tier;
    bool locked;
    uint64_t lock_remaining_ms;
};

void local_auth_init(uint64_t now_ms);
inline bool local_auth_code_shape_valid(const char* code, size_t length)
{
    size_t validated_length = 0;
    return signing::keystore_pin_valid(
               code,
               kLocalAuthMinDigits,
               kLocalAuthMaxDigits,
               &validated_length) &&
           validated_length == length;
}
bool local_auth_store_initial_metadata();
LocalAuthVerifyResult local_auth_record_keystore_result(
    signing::KeystoreOperationStatus result,
    uint64_t now_ms);
LocalAuthSnapshot local_auth_snapshot(uint64_t now_ms);
bool local_auth_clear();

#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
void local_auth_test_reset_store();
void local_auth_test_corrupt_record();
void local_auth_test_set_write_failure(bool enabled);
void local_auth_test_reset_io_counters();
uint32_t local_auth_test_read_count();
uint32_t local_auth_test_write_count();
uint32_t local_auth_test_erase_count();
#endif

}  // namespace stopwatch_target
