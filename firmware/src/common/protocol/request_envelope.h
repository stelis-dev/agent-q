#pragma once

#include <ArduinoJson.h>

#include "protocol/device_contract.h"
#include "protocol/operation_type.h"

namespace signing {

enum class RequestEnvelopeParseStatus {
    ok,
    invalid_json,
    invalid_id,
    invalid_request,
    invalid_params,
    invalid_session,
    unsupported_version,
    unsupported_method,
};

struct RequestEnvelope {
    const char* id = nullptr;
    const char* method = nullptr;
    OperationType operation_type = OperationType::unsupported;
};

RequestEnvelopeParseStatus parse_request_envelope(
    const char* line,
    JsonDocument& request,
    RequestEnvelope* output);

const char* request_envelope_error_code(RequestEnvelopeParseStatus status);

}  // namespace signing
