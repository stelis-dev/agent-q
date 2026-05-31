#pragma once

#include <stddef.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"

namespace agent_q {

constexpr uint32_t kAgentQSessionTtlMs = 1800000;
constexpr uint32_t kAgentQSessionExpiryCheckMs = 5000;
constexpr size_t kAgentQSessionIdSize = 26;

enum class AgentQSessionStartResult {
    ok,
    rng_error,
};

enum class AgentQSessionValidationResult {
    ok,
    invalid_format,
    missing,
    expired,
    mismatch,
};

using AgentQSessionRandomFn = bool (*)(void* output, size_t size, void* context);

void session_init();
bool session_active();
const char* session_id();
void session_clear();
AgentQSessionStartResult session_replace(
    TickType_t now,
    AgentQSessionRandomFn random_fn,
    void* random_context);
AgentQSessionValidationResult session_validate(const char* session_id, TickType_t now);
bool session_expire_if_needed(TickType_t now);

}  // namespace agent_q
