#include "agent_q_usb_request_envelope.h"

#include <ArduinoJson.h>

#include "agent_q_json_input.h"
#include "agent_q_protocol_constants.h"
#include "agent_q_request_id.h"

namespace agent_q {
namespace {

constexpr uint8_t kUsbRequestJsonNestingLimit = 16;

}  // namespace

AgentQUsbRequestEnvelopeParseStatus parse_usb_request_envelope(
    const char* line,
    JsonDocument& request,
    AgentQUsbRequestEnvelope* output)
{
    if (output == nullptr) {
        return AgentQUsbRequestEnvelopeParseStatus::invalid_json;
    }
    output->id = nullptr;
    output->operation_type = AgentQUsbOperationType::unsupported;

    if (!agent_q_json_line_is_single_object(line)) {
        return AgentQUsbRequestEnvelopeParseStatus::invalid_json;
    }

    const DeserializationError error =
        deserializeJson(request, line, DeserializationOption::NestingLimit(kUsbRequestJsonNestingLimit));
    if (error) {
        return AgentQUsbRequestEnvelopeParseStatus::invalid_json;
    }

    const char* id = nullptr;
    if (!agent_q_json_value_c_string(request["id"], &id)) {
        return AgentQUsbRequestEnvelopeParseStatus::invalid_id;
    }
    if (!request_id_format_valid(id)) {
        return AgentQUsbRequestEnvelopeParseStatus::invalid_id;
    }
    output->id = id;

    const int version = request["version"] | 0;
    if (version != kAgentQProtocolVersion) {
        return AgentQUsbRequestEnvelopeParseStatus::unsupported_version;
    }

    const char* type = nullptr;
    if (!agent_q_json_optional_c_string(request["type"], "", &type)) {
        return AgentQUsbRequestEnvelopeParseStatus::unsupported_type;
    }
    output->operation_type = classify_usb_operation_type(type);
    return AgentQUsbRequestEnvelopeParseStatus::ok;
}

const char* usb_request_envelope_error_code(AgentQUsbRequestEnvelopeParseStatus status)
{
    switch (status) {
        case AgentQUsbRequestEnvelopeParseStatus::invalid_json:
            return "invalid_json";
        case AgentQUsbRequestEnvelopeParseStatus::invalid_id:
            return "invalid_id";
        case AgentQUsbRequestEnvelopeParseStatus::unsupported_version:
            return "unsupported_version";
        case AgentQUsbRequestEnvelopeParseStatus::unsupported_type:
            return "unsupported_type";
        case AgentQUsbRequestEnvelopeParseStatus::ok:
            return nullptr;
    }
    return nullptr;
}

const char* usb_request_envelope_error_message(AgentQUsbRequestEnvelopeParseStatus status)
{
    switch (status) {
        case AgentQUsbRequestEnvelopeParseStatus::invalid_json:
            return "Invalid JSON.";
        case AgentQUsbRequestEnvelopeParseStatus::invalid_id:
            return "Invalid request id.";
        case AgentQUsbRequestEnvelopeParseStatus::unsupported_version:
            return "Unsupported protocol version.";
        case AgentQUsbRequestEnvelopeParseStatus::unsupported_type:
            return "Unsupported request type.";
        case AgentQUsbRequestEnvelopeParseStatus::ok:
            return nullptr;
    }
    return nullptr;
}

}  // namespace agent_q
