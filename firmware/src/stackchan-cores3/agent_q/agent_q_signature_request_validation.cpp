#include "agent_q_signature_request_validation.h"

#include <string.h>

#include "agent_q_base64.h"
#include "agent_q_json_input.h"
#include "agent_q_request_id.h"

namespace agent_q {
namespace {

bool json_object_has_key(JsonObjectConst object, const char* key)
{
    if (key == nullptr || object.isNull()) {
        return false;
    }
    for (JsonPairConst pair : object) {
        if (agent_q_json_string_equals(pair.key(), key)) {
            return true;
        }
    }
    return false;
}

bool copy_nonempty_c_string(const char* input, char* output, size_t output_size)
{
    if (input == nullptr || input[0] == '\0' || output == nullptr || output_size == 0) {
        return false;
    }
    size_t index = 0;
    while (input[index] != '\0' && index + 1 < output_size) {
        output[index] = input[index];
        ++index;
    }
    if (input[index] != '\0') {
        output[0] = '\0';
        return false;
    }
    output[index] = '\0';
    return true;
}

bool supported_network(const char* network)
{
    return network != nullptr &&
           (strcmp(network, "mainnet") == 0 ||
            strcmp(network, "testnet") == 0 ||
            strcmp(network, "devnet") == 0 ||
            strcmp(network, "localnet") == 0);
}

bool request_top_level_fields_supported(JsonObjectConst request)
{
    for (JsonPairConst pair : request) {
        if (!agent_q_json_string_equals(pair.key(), "id") &&
            !agent_q_json_string_equals(pair.key(), "version") &&
            !agent_q_json_string_equals(pair.key(), "type") &&
            !agent_q_json_string_equals(pair.key(), "sessionId") &&
            !agent_q_json_string_equals(pair.key(), "params")) {
            return false;
        }
    }
    return true;
}

bool request_params_fields_supported(JsonObjectConst params)
{
    for (JsonPairConst pair : params) {
        if (!agent_q_json_string_equals(pair.key(), "chain") &&
            !agent_q_json_string_equals(pair.key(), "method") &&
            !agent_q_json_string_equals(pair.key(), "network") &&
            !agent_q_json_string_equals(pair.key(), "txBytes") &&
            !agent_q_json_string_equals(pair.key(), "approvalTimeoutMs")) {
            return false;
        }
    }
    return true;
}

AgentQSignatureRequestValidationResult parse_timeout(
    JsonVariantConst params,
    uint32_t* output)
{
    if (output == nullptr) {
        return AgentQSignatureRequestValidationResult::invalid_timeout;
    }
    *output = kAgentQSignatureRequestApprovalTimeoutDefaultMs;
    if (!json_object_has_key(params.as<JsonObjectConst>(), "approvalTimeoutMs")) {
        return AgentQSignatureRequestValidationResult::ok;
    }
    JsonVariantConst value = params["approvalTimeoutMs"];
    if (!value.is<uint32_t>()) {
        return AgentQSignatureRequestValidationResult::invalid_timeout;
    }
    const uint32_t timeout_ms = value.as<uint32_t>();
    if (timeout_ms == 0 || timeout_ms > kAgentQSignatureRequestApprovalTimeoutMaxMs) {
        return AgentQSignatureRequestValidationResult::invalid_timeout;
    }
    *output = timeout_ms;
    return AgentQSignatureRequestValidationResult::ok;
}

}  // namespace

AgentQSignatureRequestValidationResult validate_signature_request_envelope(
    JsonDocument& request,
    AgentQSignatureRequestEnvelope* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignatureRequestValidationResult::invalid_request_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignatureRequestValidationResult::invalid_request_shape;
    }
    if (!request_top_level_fields_supported(request_object)) {
        return AgentQSignatureRequestValidationResult::unsupported_field;
    }

    const char* request_id = nullptr;
    if (!agent_q_json_value_c_string(request_object["id"], &request_id) ||
        !request_id_format_valid(request_id) ||
        !copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id))) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestValidationResult::invalid_request_shape;
    }

    JsonVariantConst version = request_object["version"];
    if (!version.is<uint32_t>() || version.as<uint32_t>() != 1) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestValidationResult::unsupported_version;
    }

    const char* request_type = nullptr;
    if (!agent_q_json_value_c_string(request_object["type"], &request_type) ||
        strcmp(request_type, "request_signature") != 0) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestValidationResult::unsupported_type;
    }

    return AgentQSignatureRequestValidationResult::ok;
}

AgentQSignatureRequestValidationResult validate_signature_request_session_format(
    JsonDocument& request,
    AgentQSignatureRequestSessionRef* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignatureRequestValidationResult::invalid_session;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignatureRequestValidationResult::invalid_session;
    }

    const char* session_id = nullptr;
    if (!agent_q_json_value_c_string(request_object["sessionId"], &session_id) ||
        !session_id_format_valid(session_id) ||
        !copy_nonempty_c_string(session_id, output->session_id, sizeof(output->session_id))) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestValidationResult::invalid_session;
    }

    return AgentQSignatureRequestValidationResult::ok;
}

AgentQSignatureRequestValidationResult validate_signature_request_params(
    JsonDocument& request,
    AgentQSignatureRequestParams* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignatureRequestValidationResult::invalid_params_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignatureRequestValidationResult::invalid_params_shape;
    }

    JsonVariantConst params_value = request_object["params"];
    JsonObjectConst params = params_value.as<JsonObjectConst>();
    if (params.isNull()) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestValidationResult::invalid_params_shape;
    }
    if (!request_params_fields_supported(params)) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestValidationResult::unsupported_field;
    }

    const char* chain = nullptr;
    const char* method = nullptr;
    if (!agent_q_json_value_c_string(params["chain"], &chain) ||
        !agent_q_json_value_c_string(params["method"], &method) ||
        !copy_nonempty_c_string(chain, output->chain, sizeof(output->chain)) ||
        !copy_nonempty_c_string(method, output->method, sizeof(output->method)) ||
        strcmp(output->chain, "sui") != 0 ||
        strcmp(output->method, "sign_transaction") != 0) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestValidationResult::unsupported_method;
    }

    const char* network = nullptr;
    if (!agent_q_json_value_c_string(params["network"], &network) ||
        !copy_nonempty_c_string(network, output->network, sizeof(output->network)) ||
        !supported_network(output->network)) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestValidationResult::invalid_network;
    }

    const char* tx_bytes_base64 = nullptr;
    if (!agent_q_json_value_c_string(params["txBytes"], &tx_bytes_base64) ||
        !copy_nonempty_c_string(
            tx_bytes_base64,
            output->tx_bytes_base64,
            sizeof(output->tx_bytes_base64)) ||
        !validate_canonical_base64(
            output->tx_bytes_base64,
            kAgentQSuiSignTransactionTxBytesMaxBase64Size,
            kAgentQSuiSignTransactionTxBytesMaxBytes,
            &output->tx_bytes_decoded_size)) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestValidationResult::invalid_tx_bytes;
    }

    const AgentQSignatureRequestValidationResult timeout_result =
        parse_timeout(params_value, &output->approval_timeout_ms);
    if (timeout_result != AgentQSignatureRequestValidationResult::ok) {
        memset(output, 0, sizeof(*output));
        return timeout_result;
    }

    return AgentQSignatureRequestValidationResult::ok;
}

const char* signature_request_validation_result_name(
    AgentQSignatureRequestValidationResult result)
{
    switch (result) {
        case AgentQSignatureRequestValidationResult::ok:
            return "ok";
        case AgentQSignatureRequestValidationResult::invalid_request_shape:
            return "invalid_request_shape";
        case AgentQSignatureRequestValidationResult::unsupported_version:
            return "unsupported_version";
        case AgentQSignatureRequestValidationResult::unsupported_type:
            return "unsupported_type";
        case AgentQSignatureRequestValidationResult::invalid_session:
            return "invalid_session";
        case AgentQSignatureRequestValidationResult::invalid_params_shape:
            return "invalid_params_shape";
        case AgentQSignatureRequestValidationResult::unsupported_field:
            return "unsupported_field";
        case AgentQSignatureRequestValidationResult::unsupported_method:
            return "unsupported_method";
        case AgentQSignatureRequestValidationResult::invalid_network:
            return "invalid_network";
        case AgentQSignatureRequestValidationResult::invalid_tx_bytes:
            return "invalid_tx_bytes";
        case AgentQSignatureRequestValidationResult::invalid_timeout:
            return "invalid_timeout";
    }
    return "unknown";
}

}  // namespace agent_q
