#include "agent_q_call_method_validation.h"

#include <string.h>

#include "agent_q_base64.h"
#include "agent_q_json_input.h"

namespace agent_q {
namespace {

const char* json_string_or_null(JsonVariantConst value)
{
    const char* output = nullptr;
    if (!agent_q_json_value_c_string(value, &output)) {
        return nullptr;
    }
    return output;
}

bool is_supported_sui_network(const char* network)
{
    return network != nullptr &&
           (strcmp(network, "mainnet") == 0 ||
            strcmp(network, "testnet") == 0 ||
            strcmp(network, "devnet") == 0 ||
            strcmp(network, "localnet") == 0);
}

bool json_object_has_key(JsonDocument& request, const char* key)
{
    if (key == nullptr) {
        return false;
    }
    JsonObjectConst object = request.as<JsonObjectConst>();
    if (object.isNull()) {
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

bool is_call_method_identifier(const char* value, size_t max_length)
{
    if (value == nullptr || max_length == 0) {
        return false;
    }

    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (length >= max_length) {
            return false;
        }
        const char c = *cursor;
        const bool is_lower = c >= 'a' && c <= 'z';
        const bool is_digit = c >= '0' && c <= '9';
        const bool is_separator = c == '_' || c == '.' || c == '-';
        if (length == 0) {
            if (!is_lower) {
                return false;
            }
        } else if (!is_lower && !is_digit && !is_separator) {
            return false;
        }
        length++;
    }
    return length > 0;
}

CallMethodNamespaceValidation classify_call_method_namespace(JsonDocument& request)
{
    const bool has_chain = json_object_has_key(request, "chain");
    const bool has_method_namespace = json_object_has_key(request, "methodNamespace");
    if (has_chain == has_method_namespace) {
        return CallMethodNamespaceValidation::invalid_namespace;
    }
    return has_method_namespace ?
        CallMethodNamespaceValidation::admin_scoped :
        CallMethodNamespaceValidation::chain_scoped;
}

CallMethodFieldValidation validate_call_method_request_fields(JsonDocument& request)
{
    if (classify_call_method_namespace(request) != CallMethodNamespaceValidation::chain_scoped) {
        return CallMethodFieldValidation::invalid_method;
    }

    const char* chain = json_string_or_null(request["chain"]);
    const char* method = json_string_or_null(request["method"]);
    if (!is_call_method_identifier(chain, kCallMethodChainMaxLength) ||
        !is_call_method_identifier(method, kCallMethodNameMaxLength)) {
        return CallMethodFieldValidation::invalid_method;
    }

    JsonVariant params = request["params"];
    if (!params.is<JsonObject>()) {
        return CallMethodFieldValidation::invalid_params_shape;
    }
    if (measureJson(params) > kCallMethodParamsJsonMaxBytes) {
        return CallMethodFieldValidation::invalid_params_size;
    }
    return CallMethodFieldValidation::valid;
}

bool validate_sui_sign_transaction_params(JsonVariant params, size_t* decoded_tx_size)
{
    if (decoded_tx_size != nullptr) {
        *decoded_tx_size = 0;
    }
    if (!params.is<JsonObject>()) {
        return false;
    }

    JsonObject params_object = params.as<JsonObject>();
    for (JsonPair item : params_object) {
        if (!agent_q_json_string_equals(item.key(), "network") &&
            !agent_q_json_string_equals(item.key(), "txBytes")) {
            return false;
        }
    }

    const char* network = json_string_or_null(params["network"]);
    const char* tx_bytes_base64 = json_string_or_null(params["txBytes"]);
    return is_supported_sui_network(network) &&
           validate_canonical_base64(
               tx_bytes_base64,
               kSuiSignTransactionTxBytesMaxBase64Size,
               kSuiSignTransactionTxBytesMaxBytes,
               decoded_tx_size);
}

}  // namespace agent_q
