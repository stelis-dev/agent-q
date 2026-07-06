#include "sign_personal_message_user_validation.h"

#include <string.h>

#include "protocol_input_copy.h"

#include "protocol/json_input.h"
#include "protocol/protocol_constants.h"
#include "protocol/request_id.h"
#include "sui/signing_payload.h"

namespace signing {
namespace {

bool request_top_level_fields_supported(JsonObjectConst request)
{
    for (JsonPairConst pair : request) {
        if (!json_string_equals(pair.key(), "id") &&
            !json_string_equals(pair.key(), "version") &&
            !json_string_equals(pair.key(), "method") &&
            !json_string_equals(pair.key(), "sessionId") &&
            !json_string_equals(pair.key(), "payload")) {
            return false;
        }
    }
    return true;
}

SignPersonalMessageUserValidationResult map_signing_payload_result(
    SuiSigningPayloadParseResult result)
{
    switch (result) {
        case SuiSigningPayloadParseResult::ok:
            return SignPersonalMessageUserValidationResult::ok;
        case SuiSigningPayloadParseResult::unsupported_field:
            return SignPersonalMessageUserValidationResult::unsupported_field;
        case SuiSigningPayloadParseResult::unsupported_method:
            return SignPersonalMessageUserValidationResult::unsupported_method;
        case SuiSigningPayloadParseResult::invalid_network:
            return SignPersonalMessageUserValidationResult::invalid_network;
        case SuiSigningPayloadParseResult::payload_too_large:
            return SignPersonalMessageUserValidationResult::message_too_large;
        case SuiSigningPayloadParseResult::invalid_payload:
            return SignPersonalMessageUserValidationResult::invalid_message;
        case SuiSigningPayloadParseResult::invalid_argument:
        default:
            return SignPersonalMessageUserValidationResult::invalid_params_shape;
    }
}

}  // namespace

SignPersonalMessageUserValidationResult
validate_sign_personal_message_user_envelope(
    JsonDocument& request,
    SignPersonalMessageUserEnvelope* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return SignPersonalMessageUserValidationResult::invalid_request_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return SignPersonalMessageUserValidationResult::invalid_request_shape;
    }
    if (!request_top_level_fields_supported(request_object)) {
        return SignPersonalMessageUserValidationResult::unsupported_field;
    }

    const char* request_id = nullptr;
    if (!json_value_c_string(request_object["id"], &request_id) ||
        !request_id_format_valid(request_id) ||
        !copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id))) {
        memset(output, 0, sizeof(*output));
        return SignPersonalMessageUserValidationResult::invalid_request_shape;
    }

    JsonVariantConst version = request_object["version"];
    if (!version.is<uint32_t>() ||
        version.as<uint32_t>() != kProtocolVersion) {
        memset(output, 0, sizeof(*output));
        return SignPersonalMessageUserValidationResult::unsupported_version;
    }

    const char* method = nullptr;
    if (!json_value_c_string(request_object["method"], &method) ||
        strcmp(method, "sign_personal_message") != 0) {
        memset(output, 0, sizeof(*output));
        return SignPersonalMessageUserValidationResult::unsupported_method;
    }

    return SignPersonalMessageUserValidationResult::ok;
}

SignPersonalMessageUserValidationResult
validate_sign_personal_message_user_session_format(
    JsonDocument& request,
    SignPersonalMessageUserSessionRef* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return SignPersonalMessageUserValidationResult::invalid_session;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return SignPersonalMessageUserValidationResult::invalid_session;
    }

    const char* session_id = nullptr;
    if (!json_value_c_string(request_object["sessionId"], &session_id) ||
        !session_id_format_valid(session_id) ||
        !copy_nonempty_c_string(session_id, output->session_id, sizeof(output->session_id))) {
        memset(output, 0, sizeof(*output));
        return SignPersonalMessageUserValidationResult::invalid_session;
    }

    return SignPersonalMessageUserValidationResult::ok;
}

SignPersonalMessageUserValidationResult
validate_sign_personal_message_user_params(
    JsonDocument& request,
    SupportedSignRoute route,
    SignPersonalMessageUserParams* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return SignPersonalMessageUserValidationResult::invalid_params_shape;
    }

    SuiSigningPayload parsed = {};
    const SuiSigningPayloadParseResult parse_result =
        parse_sui_signing_payload(request, route, &parsed);
    if (parse_result != SuiSigningPayloadParseResult::ok) {
        memset(output, 0, sizeof(*output));
        return map_signing_payload_result(parse_result);
    }
    if (!copy_nonempty_c_string(parsed.network, output->network, sizeof(output->network))) {
        memset(output, 0, sizeof(*output));
        return SignPersonalMessageUserValidationResult::invalid_network;
    }
    output->message_base64 = parsed.payload_base64;
    output->message_decoded_size = parsed.decoded_size;

    return SignPersonalMessageUserValidationResult::ok;
}

const char* sign_personal_message_user_validation_result_name(
    SignPersonalMessageUserValidationResult result)
{
    switch (result) {
        case SignPersonalMessageUserValidationResult::ok:
            return "ok";
        case SignPersonalMessageUserValidationResult::invalid_request_shape:
            return "invalid_request_shape";
        case SignPersonalMessageUserValidationResult::unsupported_version:
            return "unsupported_version";
        case SignPersonalMessageUserValidationResult::invalid_session:
            return "invalid_session";
        case SignPersonalMessageUserValidationResult::invalid_params_shape:
            return "invalid_params_shape";
        case SignPersonalMessageUserValidationResult::unsupported_field:
            return "unsupported_field";
        case SignPersonalMessageUserValidationResult::unsupported_method:
            return "unsupported_method";
        case SignPersonalMessageUserValidationResult::invalid_network:
            return "invalid_network";
        case SignPersonalMessageUserValidationResult::invalid_message:
            return "invalid_message";
        case SignPersonalMessageUserValidationResult::message_too_large:
            return "message_too_large";
    }
    return "unknown";
}

}  // namespace signing
