#pragma once

#include <stddef.h>

namespace agent_q {

enum class AgentQDeviceSessionRule {
    forbidden,
    required,
    optional,
};

enum class AgentQDevicePayloadRule {
    forbidden,
    required,
    optional,
};

struct AgentQDeviceMethodRow {
    const char* method;
    AgentQDeviceSessionRule session_rule;
    AgentQDevicePayloadRule payload_rule;
    const char* payload_schema_owner;
    const char* result_schema_owner;
    const char* firmware_gate;
};

struct AgentQDeviceErrorRow {
    const char* code;
    bool retryable;
    const char* message;
    const char* meaning;
};

const AgentQDeviceMethodRow* device_method_row(const char* method);
const AgentQDeviceErrorRow* device_error_row(const char* code);

const AgentQDeviceMethodRow* device_method_rows(size_t* count);
const AgentQDeviceErrorRow* device_error_rows(size_t* count);
const char* const* device_response_success_fields(size_t* count);
const char* const* device_response_failure_fields(size_t* count);
const char* const* device_response_error_fields(size_t* count);

const char* device_session_rule_name(AgentQDeviceSessionRule rule);
const char* device_payload_rule_name(AgentQDevicePayloadRule rule);

}  // namespace agent_q
