#pragma once

#include <stddef.h>
#include <stdint.h>

namespace signing {

constexpr size_t kLocalPinDigits = 6;
constexpr size_t kLocalPinBufferSize = kLocalPinDigits + 1;
constexpr size_t kLocalAuthPreparedRecordBytes = 100;

enum class LocalAuthStatus {
    active,
    missing,
    invalid,
    storage_error,
};

struct LocalAuthPreparedRecord {
    uint8_t bytes[kLocalAuthPreparedRecordBytes];
};

bool is_valid_local_pin(const char* pin);
bool prepare_local_pin_verifier_record(const char* pin, LocalAuthPreparedRecord* out);
bool store_prepared_local_pin_verifier(const LocalAuthPreparedRecord* prepared);
void wipe_local_pin_verifier_record(LocalAuthPreparedRecord* prepared);
bool verify_local_pin(const char* pin, bool* verified);
bool wipe_local_auth();
LocalAuthStatus local_auth_status();

}  // namespace signing
