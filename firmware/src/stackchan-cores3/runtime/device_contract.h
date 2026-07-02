#pragma once

#include <stddef.h>

namespace signing {

enum class DeviceSessionRule {
    forbidden,
    required,
    optional,
};

enum class DevicePayloadRule {
    forbidden,
    required,
    optional,
};

struct DeviceMethodRow {
    const char* method;
    DeviceSessionRule session_rule;
    DevicePayloadRule payload_rule;
    const char* payload_schema_owner;
    const char* result_schema_owner;
    const char* firmware_gate;
};

struct DeviceErrorRow {
    const char* code;
    bool retryable;
    const char* message;
    const char* meaning;
};

const DeviceMethodRow* device_method_row(const char* method);
const DeviceErrorRow* device_error_row(const char* code);

const DeviceMethodRow* device_method_rows(size_t* count);
const DeviceErrorRow* device_error_rows(size_t* count);
const char* const* device_response_success_fields(size_t* count);
const char* const* device_response_failure_fields(size_t* count);
const char* const* device_response_error_fields(size_t* count);

const char* device_session_rule_name(DeviceSessionRule rule);
const char* device_payload_rule_name(DevicePayloadRule rule);

}  // namespace signing
