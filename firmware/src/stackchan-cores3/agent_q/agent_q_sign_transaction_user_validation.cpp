#include "agent_q_sign_transaction_user_validation.h"

#include <stdint.h>
#include <string.h>

#include "agent_q_protocol_input_copy.h"

#include "agent_q_approval_history.h"
#include "agent_q_base64.h"
#include "agent_q_json_input.h"
#include "agent_q_protocol_constants.h"
#include "agent_q_request_id.h"
#include "agent_q_sui_network.h"
#include "agent_q_u64_decimal.h"

namespace agent_q {
namespace {

bool request_top_level_fields_supported(JsonObjectConst request)
{
    for (JsonPairConst pair : request) {
        if (!agent_q_json_string_equals(pair.key(), "id") &&
            !agent_q_json_string_equals(pair.key(), "version") &&
            !agent_q_json_string_equals(pair.key(), "method") &&
            !agent_q_json_string_equals(pair.key(), "sessionId") &&
            !agent_q_json_string_equals(pair.key(), "payload")) {
            return false;
        }
    }
    return true;
}

bool request_params_fields_supported(JsonObjectConst params)
{
    for (JsonPairConst pair : params) {
        if (!agent_q_json_string_equals(pair.key(), "network") &&
            !agent_q_json_string_equals(pair.key(), "chain") &&
            !agent_q_json_string_equals(pair.key(), "txBytes") &&
            !agent_q_json_string_equals(pair.key(), "payloadRef")) {
            return false;
        }
    }
    return true;
}

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

}  // namespace

AgentQSignTransactionUserValidationResult validate_sign_transaction_user_envelope(
    JsonDocument& request,
    AgentQSignTransactionUserEnvelope* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignTransactionUserValidationResult::invalid_request_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignTransactionUserValidationResult::invalid_request_shape;
    }
    if (!request_top_level_fields_supported(request_object)) {
        return AgentQSignTransactionUserValidationResult::unsupported_field;
    }

    const char* request_id = nullptr;
    if (!agent_q_json_value_c_string(request_object["id"], &request_id) ||
        !request_id_format_valid(request_id) ||
        !copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id))) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::invalid_request_shape;
    }

    JsonVariantConst version = request_object["version"];
    if (!version.is<uint32_t>() ||
        version.as<uint32_t>() != kAgentQProtocolVersion) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::unsupported_version;
    }

    const char* method = nullptr;
    if (!agent_q_json_value_c_string(request_object["method"], &method) ||
        strcmp(method, "sign_transaction") != 0) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::unsupported_method;
    }

    return AgentQSignTransactionUserValidationResult::ok;
}

AgentQSignTransactionUserValidationResult validate_sign_transaction_user_session_format(
    JsonDocument& request,
    AgentQSignTransactionUserSessionRef* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignTransactionUserValidationResult::invalid_session;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignTransactionUserValidationResult::invalid_session;
    }

    const char* session_id = nullptr;
    if (!agent_q_json_value_c_string(request_object["sessionId"], &session_id) ||
        !session_id_format_valid(session_id) ||
        !copy_nonempty_c_string(session_id, output->session_id, sizeof(output->session_id))) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::invalid_session;
    }

    return AgentQSignTransactionUserValidationResult::ok;
}

AgentQSignTransactionUserValidationResult validate_sign_transaction_user_params(
    JsonDocument& request,
    AgentQSupportedSignRoute route,
    AgentQSignTransactionUserParams* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignTransactionUserValidationResult::invalid_params_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignTransactionUserValidationResult::invalid_params_shape;
    }

    JsonVariantConst params_value = request_object["payload"];
    JsonObjectConst params = params_value.as<JsonObjectConst>();
    if (params.isNull()) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::invalid_params_shape;
    }
    if (!request_params_fields_supported(params)) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::unsupported_field;
    }

    // Helper boundary assertion: USB preflight classifies the route first, but
    // direct callers must still fail closed before method-parameter decoding.
    if (route != AgentQSupportedSignRoute::sui_sign_transaction) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::unsupported_method;
    }

    const char* network = nullptr;
    if (!agent_q_json_value_c_string(params["network"], &network) ||
        !copy_nonempty_c_string(network, output->network, sizeof(output->network)) ||
        !sui_network_supported(output->network)) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::invalid_network;
    }

    const bool has_tx_bytes = object_has_key(params, "txBytes");
    const bool has_payload_ref = object_has_key(params, "payloadRef");
    if (has_tx_bytes == has_payload_ref) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::invalid_params_shape;
    }

    if (has_tx_bytes) {
        const char* tx_bytes_base64 = nullptr;
        if (!agent_q_json_value_c_string(params["txBytes"], &tx_bytes_base64) ||
            !validate_canonical_base64_syntax(
                tx_bytes_base64,
                kAgentQSignRequestBase64MaxSize,
                &output->tx_bytes_decoded_size)) {
            memset(output, 0, sizeof(*output));
            return AgentQSignTransactionUserValidationResult::invalid_tx_bytes;
        }
        output->payload_form = AgentQSignTransactionPayloadForm::inline_tx_bytes;
        output->tx_bytes_base64 = tx_bytes_base64;
        return AgentQSignTransactionUserValidationResult::ok;
    }

    const char* payload_ref = nullptr;
    if (!agent_q_json_value_c_string(params["payloadRef"], &payload_ref) ||
        !payload_delivery_payload_ref_format_valid(payload_ref) ||
        !copy_nonempty_c_string(
            payload_ref,
            output->payload_ref,
            sizeof(output->payload_ref))) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::invalid_payload_descriptor;
    }
    output->payload_form = AgentQSignTransactionPayloadForm::staged_payload_ref;

    return AgentQSignTransactionUserValidationResult::ok;
}

const char* sign_transaction_user_validation_result_name(
    AgentQSignTransactionUserValidationResult result)
{
    switch (result) {
        case AgentQSignTransactionUserValidationResult::ok:
            return "ok";
        case AgentQSignTransactionUserValidationResult::invalid_request_shape:
            return "invalid_request_shape";
        case AgentQSignTransactionUserValidationResult::unsupported_version:
            return "unsupported_version";
        case AgentQSignTransactionUserValidationResult::invalid_session:
            return "invalid_session";
        case AgentQSignTransactionUserValidationResult::invalid_params_shape:
            return "invalid_params_shape";
        case AgentQSignTransactionUserValidationResult::unsupported_field:
            return "unsupported_field";
        case AgentQSignTransactionUserValidationResult::unsupported_method:
            return "unsupported_method";
        case AgentQSignTransactionUserValidationResult::invalid_network:
            return "invalid_network";
        case AgentQSignTransactionUserValidationResult::invalid_tx_bytes:
            return "invalid_tx_bytes";
        case AgentQSignTransactionUserValidationResult::invalid_payload_ref:
            return "invalid_payload_ref";
        case AgentQSignTransactionUserValidationResult::invalid_payload_descriptor:
            return "invalid_payload_descriptor";
    }
    return "unknown";
}

}  // namespace agent_q
