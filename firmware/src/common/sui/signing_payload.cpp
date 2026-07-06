#include "sui/signing_payload.h"

#include <string.h>

#include "protocol/base64.h"
#include "protocol/json_input.h"

namespace signing {
namespace {

void clear_output(SuiSigningPayload* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
}

}  // namespace

SuiSigningPayloadParseResult parse_sui_signing_payload(
    JsonDocument& request,
    SupportedSignRoute route,
    SuiSigningPayload* output)
{
    clear_output(output);
    if (output == nullptr) {
        return SuiSigningPayloadParseResult::invalid_argument;
    }

    JsonObjectConst payload = request["payload"].as<JsonObjectConst>();
    if (payload.isNull()) {
        return SuiSigningPayloadParseResult::invalid_argument;
    }

    const char* payload_field = nullptr;
    size_t max_base64_size = 0;
    size_t max_decoded_size = 0;
    if (route == SupportedSignRoute::sui_sign_personal_message) {
        constexpr const char* kFields[] = {"chain", "network", "message"};
        if (!json_object_fields_supported(payload, kFields, 3)) {
            return SuiSigningPayloadParseResult::unsupported_field;
        }
        payload_field = "message";
        max_base64_size = kSuiSignPersonalMessageMaxBase64Size;
        max_decoded_size = kSuiSignPersonalMessageMaxBytes;
    } else if (route == SupportedSignRoute::sui_sign_transaction) {
        constexpr const char* kFields[] = {"chain", "network", "txBytes"};
        if (!json_object_fields_supported(payload, kFields, 3)) {
            return SuiSigningPayloadParseResult::unsupported_field;
        }
        payload_field = "txBytes";
        max_base64_size = kSuiSignTransactionTxBytesMaxBase64Size;
        max_decoded_size = kSuiSignTransactionTxBytesMaxBytes;
    } else {
        return SuiSigningPayloadParseResult::unsupported_method;
    }

    const char* network = nullptr;
    if (!json_value_c_string(request["payload"]["network"], &network) ||
        !sui_network_supported(network) ||
        strlcpy(output->network, network, sizeof(output->network)) >=
            sizeof(output->network)) {
        clear_output(output);
        return SuiSigningPayloadParseResult::invalid_network;
    }

    const char* payload_base64 = nullptr;
    if (!json_value_c_string(request["payload"][payload_field], &payload_base64)) {
        clear_output(output);
        return SuiSigningPayloadParseResult::invalid_payload;
    }
    if (strlen(payload_base64) > max_base64_size) {
        clear_output(output);
        return SuiSigningPayloadParseResult::payload_too_large;
    }
    if (!validate_canonical_base64_syntax(
            payload_base64,
            max_base64_size,
            &output->decoded_size)) {
        clear_output(output);
        return SuiSigningPayloadParseResult::invalid_payload;
    }
    if (output->decoded_size == 0 || output->decoded_size > max_decoded_size) {
        clear_output(output);
        return SuiSigningPayloadParseResult::payload_too_large;
    }
    output->payload_base64 = payload_base64;
    return SuiSigningPayloadParseResult::ok;
}

}  // namespace signing
