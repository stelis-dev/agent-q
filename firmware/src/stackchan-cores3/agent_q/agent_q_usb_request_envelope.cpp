#include "agent_q_usb_request_envelope.h"

#include <ArduinoJson.h>

#include "agent_q_device_contract.h"
#include "agent_q_json_input.h"
#include "agent_q_protocol_constants.h"
#include "agent_q_request_id.h"
#include "agent_q_session.h"

namespace agent_q {
namespace {

constexpr uint8_t kUsbRequestJsonNestingLimit = 16;

bool object_has_key(JsonObjectConst object, const char* key)
{
    if (key == nullptr) {
        return false;
    }
    for (JsonPairConst pair : object) {
        if (agent_q_json_string_equals(pair.key(), key)) {
            return true;
        }
    }
    return false;
}

AgentQUsbOperationType payload_transfer_action_operation(const char* action)
{
    if (action == nullptr) {
        return AgentQUsbOperationType::unsupported;
    }
    if (strcmp(action, "begin") == 0) {
        return AgentQUsbOperationType::payload_transfer_begin;
    }
    if (strcmp(action, "chunk") == 0) {
        return AgentQUsbOperationType::payload_transfer_chunk;
    }
    if (strcmp(action, "finish") == 0) {
        return AgentQUsbOperationType::payload_transfer_finish;
    }
    if (strcmp(action, "abort") == 0) {
        return AgentQUsbOperationType::payload_transfer_abort;
    }
    return AgentQUsbOperationType::unsupported;
}

AgentQUsbRequestEnvelopeParseStatus validate_session_rule(
    const AgentQDeviceMethodRow& row,
    JsonObjectConst object)
{
    const bool has_session_id = object_has_key(object, "sessionId");
    if (row.session_rule == AgentQDeviceSessionRule::forbidden) {
        return has_session_id
                   ? AgentQUsbRequestEnvelopeParseStatus::invalid_request
                   : AgentQUsbRequestEnvelopeParseStatus::ok;
    }
    if (!has_session_id) {
        return row.session_rule == AgentQDeviceSessionRule::required
                   ? AgentQUsbRequestEnvelopeParseStatus::invalid_session
                   : AgentQUsbRequestEnvelopeParseStatus::ok;
    }
    const char* session_id = nullptr;
    if (!agent_q_json_value_c_string(object["sessionId"], &session_id) ||
        !session_id_format_valid(session_id)) {
        return AgentQUsbRequestEnvelopeParseStatus::invalid_session;
    }
    return AgentQUsbRequestEnvelopeParseStatus::ok;
}

AgentQUsbRequestEnvelopeParseStatus validate_payload_rule(
    const AgentQDeviceMethodRow& row,
    JsonObjectConst object)
{
    const bool has_payload = object_has_key(object, "payload");
    if (row.payload_rule == AgentQDevicePayloadRule::forbidden && has_payload) {
        return AgentQUsbRequestEnvelopeParseStatus::invalid_request;
    }
    if (row.payload_rule == AgentQDevicePayloadRule::required && !has_payload) {
        return AgentQUsbRequestEnvelopeParseStatus::invalid_params;
    }
    return AgentQUsbRequestEnvelopeParseStatus::ok;
}

AgentQUsbRequestEnvelopeParseStatus parse_payload_transfer_envelope(
    JsonObjectConst object,
    AgentQUsbRequestEnvelope* output)
{
    const char* const action_fields[] = {
        "id", "version", "type", "action", "sessionId",
        "totalBytes", "payloadDigest", "transferId", "offsetBytes", "chunk",
    };
    if (!agent_q_json_object_fields_supported(object, action_fields, 10)) {
        return AgentQUsbRequestEnvelopeParseStatus::invalid_request;
    }
    const char* action = nullptr;
    if (!agent_q_json_value_c_string(object["action"], &action)) {
        return AgentQUsbRequestEnvelopeParseStatus::unsupported_method;
    }
    const AgentQUsbOperationType operation = payload_transfer_action_operation(action);
    if (operation == AgentQUsbOperationType::unsupported) {
        return AgentQUsbRequestEnvelopeParseStatus::unsupported_method;
    }

    const char* const begin_fields[] = {
        "id", "version", "type", "action", "sessionId", "totalBytes", "payloadDigest",
    };
    const char* const chunk_fields[] = {
        "id", "version", "type", "action", "sessionId", "transferId", "offsetBytes", "chunk",
    };
    const char* const finish_fields[] = {
        "id", "version", "type", "action", "sessionId", "transferId",
    };
    const char* const abort_fields[] = {
        "id", "version", "type", "action", "sessionId", "transferId",
    };
    switch (operation) {
        case AgentQUsbOperationType::payload_transfer_begin:
            if (!agent_q_json_object_fields_supported(object, begin_fields, 7)) {
                return AgentQUsbRequestEnvelopeParseStatus::invalid_request;
            }
            break;
        case AgentQUsbOperationType::payload_transfer_chunk:
            if (!agent_q_json_object_fields_supported(object, chunk_fields, 8)) {
                return AgentQUsbRequestEnvelopeParseStatus::invalid_request;
            }
            break;
        case AgentQUsbOperationType::payload_transfer_finish:
            if (!agent_q_json_object_fields_supported(object, finish_fields, 6)) {
                return AgentQUsbRequestEnvelopeParseStatus::invalid_request;
            }
            break;
        case AgentQUsbOperationType::payload_transfer_abort:
            if (!agent_q_json_object_fields_supported(object, abort_fields, 6)) {
                return AgentQUsbRequestEnvelopeParseStatus::invalid_request;
            }
            break;
        default:
            return AgentQUsbRequestEnvelopeParseStatus::unsupported_method;
    }
    const char* session_id = nullptr;
    if (!agent_q_json_value_c_string(object["sessionId"], &session_id) ||
        !session_id_format_valid(session_id)) {
        return AgentQUsbRequestEnvelopeParseStatus::invalid_session;
    }
    output->operation_type = operation;
    return AgentQUsbRequestEnvelopeParseStatus::ok;
}

AgentQUsbRequestEnvelopeParseStatus parse_device_method_envelope(
    JsonObjectConst object,
    AgentQUsbRequestEnvelope* output)
{
    const char* const allowed_fields[] = {"id", "version", "sessionId", "method", "payload"};
    if (!agent_q_json_object_fields_supported(object, allowed_fields, 5)) {
        return AgentQUsbRequestEnvelopeParseStatus::invalid_request;
    }
    const char* method = nullptr;
    if (!agent_q_json_value_c_string(object["method"], &method)) {
        return AgentQUsbRequestEnvelopeParseStatus::unsupported_method;
    }
    const AgentQDeviceMethodRow* method_row = device_method_row(method);
    if (method_row == nullptr) {
        return AgentQUsbRequestEnvelopeParseStatus::unsupported_method;
    }
    output->method = method;
    const AgentQUsbRequestEnvelopeParseStatus session_status =
        validate_session_rule(*method_row, object);
    if (session_status != AgentQUsbRequestEnvelopeParseStatus::ok) {
        return session_status;
    }
    const AgentQUsbRequestEnvelopeParseStatus payload_status =
        validate_payload_rule(*method_row, object);
    if (payload_status != AgentQUsbRequestEnvelopeParseStatus::ok) {
        return payload_status;
    }
    output->operation_type = classify_usb_operation_type(method);
    return output->operation_type == AgentQUsbOperationType::unsupported
               ? AgentQUsbRequestEnvelopeParseStatus::unsupported_method
               : AgentQUsbRequestEnvelopeParseStatus::ok;
}

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
    output->method = nullptr;
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
        return AgentQUsbRequestEnvelopeParseStatus::invalid_request;
    }
    JsonObjectConst object = request.as<JsonObjectConst>();
    if (type != nullptr && type[0] != '\0') {
        if (strcmp(type, "payload_transfer") != 0) {
            return AgentQUsbRequestEnvelopeParseStatus::unsupported_method;
        }
        return parse_payload_transfer_envelope(object, output);
    }
    return parse_device_method_envelope(object, output);
}

const char* usb_request_envelope_error_code(AgentQUsbRequestEnvelopeParseStatus status)
{
    switch (status) {
        case AgentQUsbRequestEnvelopeParseStatus::invalid_json:
        case AgentQUsbRequestEnvelopeParseStatus::invalid_id:
        case AgentQUsbRequestEnvelopeParseStatus::invalid_request:
            return "invalid_request";
        case AgentQUsbRequestEnvelopeParseStatus::invalid_params:
            return "invalid_params";
        case AgentQUsbRequestEnvelopeParseStatus::invalid_session:
            return "invalid_session";
        case AgentQUsbRequestEnvelopeParseStatus::unsupported_version:
            return "unsupported_version";
        case AgentQUsbRequestEnvelopeParseStatus::unsupported_method:
            return "unsupported_method";
        case AgentQUsbRequestEnvelopeParseStatus::ok:
            return nullptr;
    }
    return nullptr;
}

}  // namespace agent_q
