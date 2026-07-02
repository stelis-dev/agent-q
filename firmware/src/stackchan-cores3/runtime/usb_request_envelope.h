#pragma once

#include <ArduinoJson.h>

#include "device_contract.h"
#include "usb_operation_type.h"

namespace signing {

enum class UsbRequestEnvelopeParseStatus {
    ok,
    invalid_json,
    invalid_id,
    invalid_request,
    invalid_params,
    invalid_session,
    unsupported_version,
    unsupported_method,
};

struct UsbRequestEnvelope {
    const char* id = nullptr;
    const char* method = nullptr;
    UsbOperationType operation_type = UsbOperationType::unsupported;
};

UsbRequestEnvelopeParseStatus parse_usb_request_envelope(
    const char* line,
    JsonDocument& request,
    UsbRequestEnvelope* output);

const char* usb_request_envelope_error_code(UsbRequestEnvelopeParseStatus status);

}  // namespace signing
