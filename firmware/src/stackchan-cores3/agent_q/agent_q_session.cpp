#include "agent_q_session.h"

#include <stdio.h>
#include <string.h>

#include "agent_q_bip39.h"

namespace agent_q {
namespace {

struct AgentQSessionState {
    char id[kAgentQSessionIdSize] = {};

    bool active() const
    {
        return id[0] != '\0';
    }
};

AgentQSessionState g_session;

bool format_session_id(
    AgentQSessionRandomFn random_fn,
    void* random_context,
    char* output,
    size_t output_size)
{
    if (random_fn == nullptr || output == nullptr || output_size < kAgentQSessionIdSize) {
        return false;
    }

    uint8_t bytes[8] = {};
    if (!random_fn(bytes, sizeof(bytes), random_context)) {
        return false;
    }
    snprintf(output,
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
    wipe_sensitive_buffer(bytes, sizeof(bytes));
    return true;
}

}  // namespace

void session_init()
{
    session_clear();
}

bool session_active()
{
    return g_session.active();
}

const char* session_id()
{
    return g_session.id;
}

void session_clear()
{
    g_session.id[0] = '\0';
}

AgentQSessionStartResult session_replace(
    AgentQSessionRandomFn random_fn,
    void* random_context)
{
    char next_id[kAgentQSessionIdSize] = {};
    if (!format_session_id(random_fn, random_context, next_id, sizeof(next_id))) {
        return AgentQSessionStartResult::rng_error;
    }
    snprintf(g_session.id, sizeof(g_session.id), "%s", next_id);
    return AgentQSessionStartResult::ok;
}

bool session_id_format_valid(const char* value)
{
    if (value == nullptr) {
        return false;
    }
    constexpr const char* kExpectedPrefix = "session_";
    constexpr size_t kPrefixLength = 8;
    for (size_t index = 0; index < kPrefixLength; ++index) {
        if (value[index] != kExpectedPrefix[index]) {
            return false;
        }
    }
    size_t length = kPrefixLength;
    for (const char* cursor = value + kPrefixLength; *cursor != '\0'; ++cursor) {
        if (++length >= kAgentQSessionIdSize) {
            return false;
        }
        const char c = *cursor;
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) {
            return false;
        }
    }
    return length > kPrefixLength;
}

AgentQSessionValidationResult session_validate(const char* requested_session_id)
{
    if (!session_id_format_valid(requested_session_id)) {
        return AgentQSessionValidationResult::invalid_format;
    }
    if (!g_session.active()) {
        session_clear();
        return AgentQSessionValidationResult::missing;
    }
    if (strcmp(requested_session_id, g_session.id) != 0) {
        return AgentQSessionValidationResult::mismatch;
    }
    return AgentQSessionValidationResult::ok;
}

}  // namespace agent_q
