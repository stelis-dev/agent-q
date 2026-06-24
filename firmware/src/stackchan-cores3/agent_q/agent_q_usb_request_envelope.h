#pragma once

#include <ArduinoJson.h>

#include "agent_q_device_contract.h"
#include "agent_q_usb_operation_type.h"

namespace agent_q {

enum class AgentQUsbRequestEnvelopeParseStatus {
    ok,
    invalid_json,
    invalid_id,
    invalid_request,
    invalid_params,
    invalid_session,
    unsupported_version,
    unsupported_method,
};

struct AgentQUsbRequestEnvelope {
    const char* id = nullptr;
    const char* method = nullptr;
    AgentQUsbOperationType operation_type = AgentQUsbOperationType::unsupported;
};

AgentQUsbRequestEnvelopeParseStatus parse_usb_request_envelope(
    const char* line,
    JsonDocument& request,
    AgentQUsbRequestEnvelope* output);

const char* usb_request_envelope_error_code(AgentQUsbRequestEnvelopeParseStatus status);

}  // namespace agent_q
