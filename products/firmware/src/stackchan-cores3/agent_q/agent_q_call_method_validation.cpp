#include "agent_q_call_method_validation.h"

#include <string.h>

namespace agent_q {
namespace {

const char* json_string_or_null(JsonVariantConst value)
{
    if (!value.is<const char*>()) {
        return nullptr;
    }
    return value.as<const char*>();
}

int base64_value(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return 26 + c - 'a';
    }
    if (c >= '0' && c <= '9') {
        return 52 + c - '0';
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

bool validate_canonical_base64(
    const char* value,
    size_t max_base64_size,
    size_t max_decoded_size,
    size_t* decoded_size)
{
    if (decoded_size != nullptr) {
        *decoded_size = 0;
    }
    if (value == nullptr) {
        return false;
    }

    const size_t length = strlen(value);
    if (length == 0 || length > max_base64_size || (length % 4) != 0) {
        return false;
    }

    size_t padding = 0;
    if (value[length - 1] == '=') {
        padding++;
    }
    if (length >= 2 && value[length - 2] == '=') {
        padding++;
    }

    for (size_t index = 0; index < length; ++index) {
        const char c = value[index];
        const bool in_padding = index >= length - padding;
        if (in_padding) {
            if (c != '=') {
                return false;
            }
            continue;
        }
        if (c == '=' || base64_value(c) < 0) {
            return false;
        }
    }

    if (padding == 1) {
        const int third = base64_value(value[length - 2]);
        if (third < 0 || (third & 0x03) != 0) {
            return false;
        }
    } else if (padding == 2) {
        const int second = base64_value(value[length - 3]);
        if (second < 0 || (second & 0x0F) != 0) {
            return false;
        }
    } else if (padding > 2) {
        return false;
    }

    const size_t output_size = ((length / 4) * 3) - padding;
    if (output_size == 0 || output_size > max_decoded_size) {
        return false;
    }
    if (decoded_size != nullptr) {
        *decoded_size = output_size;
    }
    return true;
}

bool is_supported_sui_network(const char* network)
{
    return network != nullptr &&
           (strcmp(network, "mainnet") == 0 ||
            strcmp(network, "testnet") == 0 ||
            strcmp(network, "devnet") == 0 ||
            strcmp(network, "localnet") == 0);
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

CallMethodFieldValidation validate_call_method_request_fields(JsonDocument& request)
{
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
        const char* key = item.key().c_str();
        if (strcmp(key, "network") != 0 && strcmp(key, "txBytes") != 0) {
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
