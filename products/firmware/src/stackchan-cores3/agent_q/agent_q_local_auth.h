#pragma once

#include <stddef.h>

namespace agent_q {

constexpr size_t kLocalPinDigits = 6;
constexpr size_t kLocalPinBufferSize = kLocalPinDigits + 1;

enum class AgentQLocalAuthStatus {
    active,
    missing,
    invalid,
    storage_error,
};

bool is_valid_local_pin(const char* pin);
bool store_local_pin_verifier(const char* pin);
bool verify_local_pin(const char* pin, bool* verified);
bool wipe_local_auth();
AgentQLocalAuthStatus local_auth_status();

}  // namespace agent_q
