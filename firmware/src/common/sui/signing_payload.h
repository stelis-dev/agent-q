#pragma once

#include <ArduinoJson.h>

#include "protocol/sign_route.h"
#include "sui/network.h"
#include "sui/signing_limits.h"

namespace signing {

enum class SuiSigningPayloadParseResult {
    ok,
    invalid_argument,
    unsupported_field,
    unsupported_method,
    invalid_network,
    invalid_payload,
    payload_too_large,
};

struct SuiSigningPayload {
    char network[kSuiNetworkBufferSize];
    const char* payload_base64;
    size_t decoded_size;
};

SuiSigningPayloadParseResult parse_sui_signing_payload(
    JsonDocument& request,
    SupportedSignRoute route,
    SuiSigningPayload* output);

}  // namespace signing
