#include "sign_transaction_user_validation.h"

#include <stdint.h>
#include <string.h>

#include "protocol_input_copy.h"

#include "protocol/approval_history.h"
#include "protocol/json_input.h"
#include "protocol/protocol_constants.h"
#include "protocol/request_id.h"
#include "sui/signing_payload.h"
#include "numeric/u64_decimal.h"

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

SignTransactionUserValidationResult map_signing_payload_result(
    SuiSigningPayloadParseResult result)
{
    switch (result) {
        case SuiSigningPayloadParseResult::ok:
            return SignTransactionUserValidationResult::ok;
        case SuiSigningPayloadParseResult::unsupported_field:
            return SignTransactionUserValidationResult::unsupported_field;
        case SuiSigningPayloadParseResult::unsupported_method:
            return SignTransactionUserValidationResult::unsupported_method;
        case SuiSigningPayloadParseResult::invalid_network:
            return SignTransactionUserValidationResult::invalid_network;
        case SuiSigningPayloadParseResult::invalid_payload:
        case SuiSigningPayloadParseResult::payload_too_large:
            return SignTransactionUserValidationResult::invalid_tx_bytes;
        case SuiSigningPayloadParseResult::invalid_argument:
        default:
            return SignTransactionUserValidationResult::invalid_params_shape;
    }
}

}  // namespace

SignTransactionUserValidationResult validate_sign_transaction_user_envelope(
    JsonDocument& request,
    SignTransactionUserEnvelope* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return SignTransactionUserValidationResult::invalid_request_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return SignTransactionUserValidationResult::invalid_request_shape;
    }
    if (!request_top_level_fields_supported(request_object)) {
        return SignTransactionUserValidationResult::unsupported_field;
    }

    const char* request_id = nullptr;
    if (!json_value_c_string(request_object["id"], &request_id) ||
        !request_id_format_valid(request_id) ||
        !copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id))) {
        memset(output, 0, sizeof(*output));
        return SignTransactionUserValidationResult::invalid_request_shape;
    }

    JsonVariantConst version = request_object["version"];
    if (!version.is<uint32_t>() ||
        version.as<uint32_t>() != kProtocolVersion) {
        memset(output, 0, sizeof(*output));
        return SignTransactionUserValidationResult::unsupported_version;
    }

    const char* method = nullptr;
    if (!json_value_c_string(request_object["method"], &method) ||
        strcmp(method, "sign_transaction") != 0) {
        memset(output, 0, sizeof(*output));
        return SignTransactionUserValidationResult::unsupported_method;
    }

    return SignTransactionUserValidationResult::ok;
}

SignTransactionUserValidationResult validate_sign_transaction_user_session_format(
    JsonDocument& request,
    SignTransactionUserSessionRef* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return SignTransactionUserValidationResult::invalid_session;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return SignTransactionUserValidationResult::invalid_session;
    }

    const char* session_id = nullptr;
    if (!json_value_c_string(request_object["sessionId"], &session_id) ||
        !session_id_format_valid(session_id) ||
        !copy_nonempty_c_string(session_id, output->session_id, sizeof(output->session_id))) {
        memset(output, 0, sizeof(*output));
        return SignTransactionUserValidationResult::invalid_session;
    }

    return SignTransactionUserValidationResult::ok;
}

SignTransactionUserValidationResult validate_sign_transaction_user_params(
    JsonDocument& request,
    SupportedSignRoute route,
    SignTransactionUserParams* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return SignTransactionUserValidationResult::invalid_params_shape;
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
        return SignTransactionUserValidationResult::invalid_network;
    }
    output->tx_bytes_base64 = parsed.payload_base64;
    output->tx_bytes_decoded_size = parsed.decoded_size;

    return SignTransactionUserValidationResult::ok;
}

const char* sign_transaction_user_validation_result_name(
    SignTransactionUserValidationResult result)
{
    switch (result) {
        case SignTransactionUserValidationResult::ok:
            return "ok";
        case SignTransactionUserValidationResult::invalid_request_shape:
            return "invalid_request_shape";
        case SignTransactionUserValidationResult::unsupported_version:
            return "unsupported_version";
        case SignTransactionUserValidationResult::invalid_session:
            return "invalid_session";
        case SignTransactionUserValidationResult::invalid_params_shape:
            return "invalid_params_shape";
        case SignTransactionUserValidationResult::unsupported_field:
            return "unsupported_field";
        case SignTransactionUserValidationResult::unsupported_method:
            return "unsupported_method";
        case SignTransactionUserValidationResult::invalid_network:
            return "invalid_network";
        case SignTransactionUserValidationResult::invalid_tx_bytes:
            return "invalid_tx_bytes";
    }
    return "unknown";
}

}  // namespace signing
