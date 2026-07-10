#include "protocol/request_envelope.h"

#include <ArduinoJson.h>

#include "protocol/device_contract.h"
#include "protocol/json_input.h"
#include "protocol/protocol_constants.h"
#include "protocol/request_id.h"
#include "protocol/session_state.h"

namespace signing {
namespace {

bool object_has_key(JsonObjectConst object, const char* key)
{
    if (key == nullptr) {
        return false;
    }
    for (JsonPairConst pair : object) {
        if (json_string_equals(pair.key(), key)) {
            return true;
        }
    }
    return false;
}

OperationType payload_transfer_action_operation(const char* action)
{
    if (action == nullptr) {
        return OperationType::unsupported;
    }
    if (strcmp(action, "begin") == 0) {
        return OperationType::payload_transfer_begin;
    }
    if (strcmp(action, "chunk") == 0) {
        return OperationType::payload_transfer_chunk;
    }
    if (strcmp(action, "finish") == 0) {
        return OperationType::payload_transfer_finish;
    }
    if (strcmp(action, "abort") == 0) {
        return OperationType::payload_transfer_abort;
    }
    return OperationType::unsupported;
}

RequestEnvelopeParseStatus validate_session_rule(
    const DeviceMethodRow& row,
    JsonObjectConst object)
{
    const bool has_session_id = object_has_key(object, "sessionId");
    if (row.session_rule == DeviceSessionRule::forbidden) {
        return has_session_id
                   ? RequestEnvelopeParseStatus::invalid_request
                   : RequestEnvelopeParseStatus::ok;
    }
    if (!has_session_id) {
        return row.session_rule == DeviceSessionRule::required
                   ? RequestEnvelopeParseStatus::invalid_session
                   : RequestEnvelopeParseStatus::ok;
    }
    const char* session_id = nullptr;
    if (!json_value_c_string(object["sessionId"], &session_id) ||
        !session_id_format_valid(session_id)) {
        return RequestEnvelopeParseStatus::invalid_session;
    }
    return RequestEnvelopeParseStatus::ok;
}

RequestEnvelopeParseStatus validate_payload_rule(
    const DeviceMethodRow& row,
    JsonObjectConst object)
{
    const bool has_payload = object_has_key(object, "payload");
    if (row.payload_rule == DevicePayloadRule::forbidden && has_payload) {
        return RequestEnvelopeParseStatus::invalid_request;
    }
    if (row.payload_rule == DevicePayloadRule::required && !has_payload) {
        return RequestEnvelopeParseStatus::invalid_params;
    }
    return RequestEnvelopeParseStatus::ok;
}

RequestEnvelopeParseStatus parse_payload_transfer_envelope(
    JsonObjectConst object,
    RequestEnvelope* output)
{
    const char* const action_fields[] = {
        "id", "version", "type", "action", "sessionId",
        "totalBytes", "payloadDigest", "transferId", "payloadRef", "offsetBytes", "chunk",
    };
    if (!json_object_fields_supported(object, action_fields, 11)) {
        return RequestEnvelopeParseStatus::invalid_request;
    }
    const char* action = nullptr;
    if (!json_value_c_string(object["action"], &action)) {
        return RequestEnvelopeParseStatus::unsupported_method;
    }
    const OperationType operation = payload_transfer_action_operation(action);
    if (operation == OperationType::unsupported) {
        return RequestEnvelopeParseStatus::unsupported_method;
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
    const char* const abort_finalized_fields[] = {
        "id", "version", "type", "action", "sessionId", "payloadRef",
    };
    switch (operation) {
        case OperationType::payload_transfer_begin:
            if (!json_object_fields_supported(object, begin_fields, 7)) {
                return RequestEnvelopeParseStatus::invalid_request;
            }
            break;
        case OperationType::payload_transfer_chunk:
            if (!json_object_fields_supported(object, chunk_fields, 8)) {
                return RequestEnvelopeParseStatus::invalid_request;
            }
            break;
        case OperationType::payload_transfer_finish:
            if (!json_object_fields_supported(object, finish_fields, 6)) {
                return RequestEnvelopeParseStatus::invalid_request;
            }
            break;
        case OperationType::payload_transfer_abort: {
            const bool has_transfer_id = object_has_key(object, "transferId");
            const bool has_payload_ref = object_has_key(object, "payloadRef");
            if (has_transfer_id == has_payload_ref) {
                return RequestEnvelopeParseStatus::invalid_request;
            }
            if (has_transfer_id) {
                if (!json_object_fields_supported(object, abort_fields, 6)) {
                    return RequestEnvelopeParseStatus::invalid_request;
                }
            } else if (!json_object_fields_supported(object, abort_finalized_fields, 6)) {
                return RequestEnvelopeParseStatus::invalid_request;
            }
            break;
        }
        default:
            return RequestEnvelopeParseStatus::unsupported_method;
    }
    const char* session_id = nullptr;
    if (!json_value_c_string(object["sessionId"], &session_id) ||
        !session_id_format_valid(session_id)) {
        return RequestEnvelopeParseStatus::invalid_session;
    }
    output->operation_type = operation;
    return RequestEnvelopeParseStatus::ok;
}

RequestEnvelopeParseStatus parse_device_method_envelope(
    JsonObjectConst object,
    RequestEnvelope* output)
{
    const char* const allowed_fields[] = {"id", "version", "sessionId", "method", "payload"};
    if (!json_object_fields_supported(object, allowed_fields, 5)) {
        return RequestEnvelopeParseStatus::invalid_request;
    }
    const char* method = nullptr;
    if (!json_value_c_string(object["method"], &method)) {
        return RequestEnvelopeParseStatus::invalid_request;
    }
    const DeviceMethodRow* method_row = device_method_row(method);
    if (method_row == nullptr) {
        return RequestEnvelopeParseStatus::unsupported_method;
    }
    output->method = method;
    const RequestEnvelopeParseStatus session_status =
        validate_session_rule(*method_row, object);
    if (session_status != RequestEnvelopeParseStatus::ok) {
        return session_status;
    }
    const RequestEnvelopeParseStatus payload_status =
        validate_payload_rule(*method_row, object);
    if (payload_status != RequestEnvelopeParseStatus::ok) {
        return payload_status;
    }
    output->operation_type = classify_operation_type(method);
    return output->operation_type == OperationType::unsupported
               ? RequestEnvelopeParseStatus::unsupported_method
               : RequestEnvelopeParseStatus::ok;
}

}  // namespace

RequestEnvelopeParseStatus parse_request_envelope(
    const char* line,
    JsonDocument& request,
    RequestEnvelope* output)
{
    if (output == nullptr) {
        return RequestEnvelopeParseStatus::invalid_json;
    }
    output->id = nullptr;
    output->method = nullptr;
    output->operation_type = OperationType::unsupported;

    if (!json_line_is_single_object(line)) {
        return RequestEnvelopeParseStatus::invalid_json;
    }

    const DeserializationError error =
        deserializeJson(request, line, DeserializationOption::NestingLimit(kRequestJsonNestingLimit));
    if (error) {
        return RequestEnvelopeParseStatus::invalid_json;
    }

    const char* id = nullptr;
    if (!json_value_c_string(request["id"], &id)) {
        return RequestEnvelopeParseStatus::invalid_id;
    }
    if (!request_id_format_valid(id)) {
        return RequestEnvelopeParseStatus::invalid_id;
    }
    output->id = id;

    JsonVariantConst version_value = request["version"];
    if (!version_value.is<int>()) {
        return RequestEnvelopeParseStatus::invalid_request;
    }
    const int version = version_value.as<int>();
    if (version != kProtocolVersion) {
        return RequestEnvelopeParseStatus::unsupported_version;
    }

    const char* type = nullptr;
    if (!json_optional_c_string(request["type"], "", &type)) {
        return RequestEnvelopeParseStatus::invalid_request;
    }
    JsonObjectConst object = request.as<JsonObjectConst>();
    if (type != nullptr && type[0] != '\0') {
        if (strcmp(type, "payload_transfer") != 0) {
            return RequestEnvelopeParseStatus::unsupported_method;
        }
        return parse_payload_transfer_envelope(object, output);
    }
    return parse_device_method_envelope(object, output);
}

const char* request_envelope_error_code(RequestEnvelopeParseStatus status)
{
    switch (status) {
        case RequestEnvelopeParseStatus::invalid_json:
        case RequestEnvelopeParseStatus::invalid_id:
        case RequestEnvelopeParseStatus::invalid_request:
            return "invalid_request";
        case RequestEnvelopeParseStatus::invalid_params:
            return "invalid_params";
        case RequestEnvelopeParseStatus::invalid_session:
            return "invalid_session";
        case RequestEnvelopeParseStatus::unsupported_version:
            return "unsupported_version";
        case RequestEnvelopeParseStatus::unsupported_method:
            return "unsupported_method";
        case RequestEnvelopeParseStatus::ok:
            return nullptr;
    }
    return nullptr;
}

}  // namespace signing
