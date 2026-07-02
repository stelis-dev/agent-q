#include "usb_request_envelope.h"

#include <ArduinoJson.h>

#include "device_contract.h"
#include "json_input.h"
#include "protocol_constants.h"
#include "request_id.h"
#include "session.h"

namespace signing {
namespace {

constexpr uint8_t kUsbRequestJsonNestingLimit = 16;

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

UsbOperationType payload_transfer_action_operation(const char* action)
{
    if (action == nullptr) {
        return UsbOperationType::unsupported;
    }
    if (strcmp(action, "begin") == 0) {
        return UsbOperationType::payload_transfer_begin;
    }
    if (strcmp(action, "chunk") == 0) {
        return UsbOperationType::payload_transfer_chunk;
    }
    if (strcmp(action, "finish") == 0) {
        return UsbOperationType::payload_transfer_finish;
    }
    if (strcmp(action, "abort") == 0) {
        return UsbOperationType::payload_transfer_abort;
    }
    return UsbOperationType::unsupported;
}

UsbRequestEnvelopeParseStatus validate_session_rule(
    const DeviceMethodRow& row,
    JsonObjectConst object)
{
    const bool has_session_id = object_has_key(object, "sessionId");
    if (row.session_rule == DeviceSessionRule::forbidden) {
        return has_session_id
                   ? UsbRequestEnvelopeParseStatus::invalid_request
                   : UsbRequestEnvelopeParseStatus::ok;
    }
    if (!has_session_id) {
        return row.session_rule == DeviceSessionRule::required
                   ? UsbRequestEnvelopeParseStatus::invalid_session
                   : UsbRequestEnvelopeParseStatus::ok;
    }
    const char* session_id = nullptr;
    if (!json_value_c_string(object["sessionId"], &session_id) ||
        !session_id_format_valid(session_id)) {
        return UsbRequestEnvelopeParseStatus::invalid_session;
    }
    return UsbRequestEnvelopeParseStatus::ok;
}

UsbRequestEnvelopeParseStatus validate_payload_rule(
    const DeviceMethodRow& row,
    JsonObjectConst object)
{
    const bool has_payload = object_has_key(object, "payload");
    if (row.payload_rule == DevicePayloadRule::forbidden && has_payload) {
        return UsbRequestEnvelopeParseStatus::invalid_request;
    }
    if (row.payload_rule == DevicePayloadRule::required && !has_payload) {
        return UsbRequestEnvelopeParseStatus::invalid_params;
    }
    return UsbRequestEnvelopeParseStatus::ok;
}

UsbRequestEnvelopeParseStatus parse_payload_transfer_envelope(
    JsonObjectConst object,
    UsbRequestEnvelope* output)
{
    const char* const action_fields[] = {
        "id", "version", "type", "action", "sessionId",
        "totalBytes", "payloadDigest", "transferId", "offsetBytes", "chunk",
    };
    if (!json_object_fields_supported(object, action_fields, 10)) {
        return UsbRequestEnvelopeParseStatus::invalid_request;
    }
    const char* action = nullptr;
    if (!json_value_c_string(object["action"], &action)) {
        return UsbRequestEnvelopeParseStatus::unsupported_method;
    }
    const UsbOperationType operation = payload_transfer_action_operation(action);
    if (operation == UsbOperationType::unsupported) {
        return UsbRequestEnvelopeParseStatus::unsupported_method;
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
        case UsbOperationType::payload_transfer_begin:
            if (!json_object_fields_supported(object, begin_fields, 7)) {
                return UsbRequestEnvelopeParseStatus::invalid_request;
            }
            break;
        case UsbOperationType::payload_transfer_chunk:
            if (!json_object_fields_supported(object, chunk_fields, 8)) {
                return UsbRequestEnvelopeParseStatus::invalid_request;
            }
            break;
        case UsbOperationType::payload_transfer_finish:
            if (!json_object_fields_supported(object, finish_fields, 6)) {
                return UsbRequestEnvelopeParseStatus::invalid_request;
            }
            break;
        case UsbOperationType::payload_transfer_abort:
            if (!json_object_fields_supported(object, abort_fields, 6)) {
                return UsbRequestEnvelopeParseStatus::invalid_request;
            }
            break;
        default:
            return UsbRequestEnvelopeParseStatus::unsupported_method;
    }
    const char* session_id = nullptr;
    if (!json_value_c_string(object["sessionId"], &session_id) ||
        !session_id_format_valid(session_id)) {
        return UsbRequestEnvelopeParseStatus::invalid_session;
    }
    output->operation_type = operation;
    return UsbRequestEnvelopeParseStatus::ok;
}

UsbRequestEnvelopeParseStatus parse_device_method_envelope(
    JsonObjectConst object,
    UsbRequestEnvelope* output)
{
    const char* const allowed_fields[] = {"id", "version", "sessionId", "method", "payload"};
    if (!json_object_fields_supported(object, allowed_fields, 5)) {
        return UsbRequestEnvelopeParseStatus::invalid_request;
    }
    const char* method = nullptr;
    if (!json_value_c_string(object["method"], &method)) {
        return UsbRequestEnvelopeParseStatus::unsupported_method;
    }
    const DeviceMethodRow* method_row = device_method_row(method);
    if (method_row == nullptr) {
        return UsbRequestEnvelopeParseStatus::unsupported_method;
    }
    output->method = method;
    const UsbRequestEnvelopeParseStatus session_status =
        validate_session_rule(*method_row, object);
    if (session_status != UsbRequestEnvelopeParseStatus::ok) {
        return session_status;
    }
    const UsbRequestEnvelopeParseStatus payload_status =
        validate_payload_rule(*method_row, object);
    if (payload_status != UsbRequestEnvelopeParseStatus::ok) {
        return payload_status;
    }
    output->operation_type = classify_usb_operation_type(method);
    return output->operation_type == UsbOperationType::unsupported
               ? UsbRequestEnvelopeParseStatus::unsupported_method
               : UsbRequestEnvelopeParseStatus::ok;
}

}  // namespace

UsbRequestEnvelopeParseStatus parse_usb_request_envelope(
    const char* line,
    JsonDocument& request,
    UsbRequestEnvelope* output)
{
    if (output == nullptr) {
        return UsbRequestEnvelopeParseStatus::invalid_json;
    }
    output->id = nullptr;
    output->method = nullptr;
    output->operation_type = UsbOperationType::unsupported;

    if (!json_line_is_single_object(line)) {
        return UsbRequestEnvelopeParseStatus::invalid_json;
    }

    const DeserializationError error =
        deserializeJson(request, line, DeserializationOption::NestingLimit(kUsbRequestJsonNestingLimit));
    if (error) {
        return UsbRequestEnvelopeParseStatus::invalid_json;
    }

    const char* id = nullptr;
    if (!json_value_c_string(request["id"], &id)) {
        return UsbRequestEnvelopeParseStatus::invalid_id;
    }
    if (!request_id_format_valid(id)) {
        return UsbRequestEnvelopeParseStatus::invalid_id;
    }
    output->id = id;

    const int version = request["version"] | 0;
    if (version != kProtocolVersion) {
        return UsbRequestEnvelopeParseStatus::unsupported_version;
    }

    const char* type = nullptr;
    if (!json_optional_c_string(request["type"], "", &type)) {
        return UsbRequestEnvelopeParseStatus::invalid_request;
    }
    JsonObjectConst object = request.as<JsonObjectConst>();
    if (type != nullptr && type[0] != '\0') {
        if (strcmp(type, "payload_transfer") != 0) {
            return UsbRequestEnvelopeParseStatus::unsupported_method;
        }
        return parse_payload_transfer_envelope(object, output);
    }
    return parse_device_method_envelope(object, output);
}

const char* usb_request_envelope_error_code(UsbRequestEnvelopeParseStatus status)
{
    switch (status) {
        case UsbRequestEnvelopeParseStatus::invalid_json:
        case UsbRequestEnvelopeParseStatus::invalid_id:
        case UsbRequestEnvelopeParseStatus::invalid_request:
            return "invalid_request";
        case UsbRequestEnvelopeParseStatus::invalid_params:
            return "invalid_params";
        case UsbRequestEnvelopeParseStatus::invalid_session:
            return "invalid_session";
        case UsbRequestEnvelopeParseStatus::unsupported_version:
            return "unsupported_version";
        case UsbRequestEnvelopeParseStatus::unsupported_method:
            return "unsupported_method";
        case UsbRequestEnvelopeParseStatus::ok:
            return nullptr;
    }
    return nullptr;
}

}  // namespace signing
