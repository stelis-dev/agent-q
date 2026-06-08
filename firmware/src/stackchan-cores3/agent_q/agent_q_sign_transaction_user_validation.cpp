#include "agent_q_sign_transaction_user_validation.h"

#include <string.h>

#include "agent_q_protocol_input_copy.h"

#include "agent_q_base64.h"
#include "agent_q_json_input.h"
#include "agent_q_request_id.h"

namespace agent_q {
namespace {

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
            !agent_q_json_string_equals(pair.key(), "chain") &&
            !agent_q_json_string_equals(pair.key(), "method") &&
            !agent_q_json_string_equals(pair.key(), "params")) {
            return false;
        }
    }
    return true;
}

bool request_params_fields_supported(JsonObjectConst params)
{
    for (JsonPairConst pair : params) {
        if (!agent_q_json_string_equals(pair.key(), "network") &&
            !agent_q_json_string_equals(pair.key(), "txBytes")) {
            return false;
        }
    }
    return true;
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
    if (!version.is<uint32_t>() || version.as<uint32_t>() != 1) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::unsupported_version;
    }

    const char* request_type = nullptr;
    if (!agent_q_json_value_c_string(request_object["type"], &request_type) ||
        strcmp(request_type, "sign_transaction") != 0) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::unsupported_type;
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

    JsonVariantConst params_value = request_object["params"];
    JsonObjectConst params = params_value.as<JsonObjectConst>();
    if (params.isNull()) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::invalid_params_shape;
    }
    if (!request_params_fields_supported(params)) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::unsupported_field;
    }

    const char* chain = nullptr;
    const char* method = nullptr;
    if (!agent_q_json_value_c_string(request_object["chain"], &chain) ||
        !agent_q_json_value_c_string(request_object["method"], &method) ||
        !copy_nonempty_c_string(chain, output->chain, sizeof(output->chain)) ||
        !copy_nonempty_c_string(method, output->method, sizeof(output->method)) ||
        strcmp(output->chain, "sui") != 0 ||
        strcmp(output->method, "sign_transaction") != 0) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::unsupported_method;
    }

    const char* network = nullptr;
    if (!agent_q_json_value_c_string(params["network"], &network) ||
        !copy_nonempty_c_string(network, output->network, sizeof(output->network)) ||
        !supported_network(output->network)) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::invalid_network;
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
        return AgentQSignTransactionUserValidationResult::invalid_tx_bytes;
    }

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
        case AgentQSignTransactionUserValidationResult::unsupported_type:
            return "unsupported_type";
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
    }
    return "unknown";
}

}  // namespace agent_q
