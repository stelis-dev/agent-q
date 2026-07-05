#pragma once

#include <ArduinoJson.h>

namespace stopwatch_target {

enum class PayloadTransferRequestAction {
    begin,
    chunk,
    finish,
    abort,
};

enum class PayloadTransferRequestParseStatus {
    ok,
    invalid_envelope,
    invalid_request,
    invalid_session,
    unsupported_version,
    unsupported_method,
};

struct PayloadTransferRequestEnvelope {
    const char* id;
    const char* session_id;
    PayloadTransferRequestAction action;
};

PayloadTransferRequestParseStatus payload_transfer_request_parse(
    JsonDocument& request,
    PayloadTransferRequestEnvelope* output);
const char* payload_transfer_request_error_code(PayloadTransferRequestParseStatus status);

}  // namespace stopwatch_target
