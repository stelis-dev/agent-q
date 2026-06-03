#pragma once

#include <stddef.h>
#include <stdint.h>

namespace agent_q {

constexpr uint32_t kAgentQSessionAdvertisedTtlMs = 0xffffffffu;
constexpr size_t kAgentQSessionIdSize = 26;

enum class AgentQSessionStartResult {
    ok,
    rng_error,
};

enum class AgentQSessionValidationResult {
    ok,
    invalid_format,
    missing,
    mismatch,
};

using AgentQSessionRandomFn = bool (*)(void* output, size_t size, void* context);

void session_init();
bool session_active();
const char* session_id();
void session_clear();
AgentQSessionStartResult session_replace(
    AgentQSessionRandomFn random_fn,
    void* random_context);
bool session_id_format_valid(const char* session_id);
AgentQSessionValidationResult session_validate(const char* session_id);

}  // namespace agent_q
