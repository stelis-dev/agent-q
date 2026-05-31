#pragma once

#include <stddef.h>
#include <stdint.h>

namespace agent_q {

constexpr size_t kLocalPinDigits = 6;
constexpr size_t kLocalPinBufferSize = kLocalPinDigits + 1;
constexpr size_t kLocalAuthPreparedRecordBytes = 100;

enum class AgentQLocalAuthStatus {
    active,
    missing,
    invalid,
    storage_error,
};

struct AgentQLocalAuthPreparedRecord {
    uint8_t bytes[kLocalAuthPreparedRecordBytes];
};

bool is_valid_local_pin(const char* pin);
bool prepare_local_pin_verifier_record(const char* pin, AgentQLocalAuthPreparedRecord* out);
bool store_prepared_local_pin_verifier(const AgentQLocalAuthPreparedRecord* prepared);
void wipe_local_pin_verifier_record(AgentQLocalAuthPreparedRecord* prepared);
bool store_local_pin_verifier(const char* pin);
bool verify_local_pin(const char* pin, bool* verified);
bool wipe_local_auth();
AgentQLocalAuthStatus local_auth_status();

}  // namespace agent_q
