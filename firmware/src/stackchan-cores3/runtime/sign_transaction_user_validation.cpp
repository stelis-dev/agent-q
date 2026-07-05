#include "sign_transaction_user_validation.h"

#include <stdint.h>
#include <string.h>

#include "protocol_input_copy.h"

#include "approval_history.h"
#include "protocol/base64.h"
#include "protocol/json_input.h"
#include "protocol/protocol_constants.h"
#include "protocol/request_id.h"
#include "sui_network.h"
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

bool request_params_fields_supported(JsonObjectConst params)
{
    for (JsonPairConst pair : params) {
        if (!json_string_equals(pair.key(), "network") &&
            !json_string_equals(pair.key(), "chain") &&
            !json_string_equals(pair.key(), "txBytes")) {
            return false;
        }
    }
    return true;
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

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return SignTransactionUserValidationResult::invalid_params_shape;
    }

    JsonVariantConst params_value = request_object["payload"];
    JsonObjectConst params = params_value.as<JsonObjectConst>();
    if (params.isNull()) {
        memset(output, 0, sizeof(*output));
        return SignTransactionUserValidationResult::invalid_params_shape;
    }
    if (!request_params_fields_supported(params)) {
        memset(output, 0, sizeof(*output));
        return SignTransactionUserValidationResult::unsupported_field;
    }

    // Helper boundary assertion: USB preflight classifies the route first, but
    // direct callers must still fail closed before method-parameter decoding.
    if (route != SupportedSignRoute::sui_sign_transaction) {
        memset(output, 0, sizeof(*output));
        return SignTransactionUserValidationResult::unsupported_method;
    }

    const char* network = nullptr;
    if (!json_value_c_string(params["network"], &network) ||
        !copy_nonempty_c_string(network, output->network, sizeof(output->network)) ||
        !sui_network_supported(output->network)) {
        memset(output, 0, sizeof(*output));
        return SignTransactionUserValidationResult::invalid_network;
    }

    const char* tx_bytes_base64 = nullptr;
    if (!json_value_c_string(params["txBytes"], &tx_bytes_base64) ||
        !validate_canonical_base64_syntax(
            tx_bytes_base64,
            kSuiSignTransactionTxBytesMaxBase64Size,
            &output->tx_bytes_decoded_size)) {
        memset(output, 0, sizeof(*output));
        return SignTransactionUserValidationResult::invalid_tx_bytes;
    }
    output->tx_bytes_base64 = tx_bytes_base64;

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
