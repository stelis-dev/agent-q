#pragma once

#include <ArduinoJson.h>

#include "transport/payload_delivery_primitives.h"
#include "transport/timeout_window.h"
#include "protocol/usb_operation_response_writer.h"
#include "protocol/usb_request_envelope.h"

namespace signing {

bool payload_delivery_payload_ref_wrapper(JsonDocument& request, const char** payload_ref);
const char* payload_delivery_resolve_error_code(PayloadDeliveryResult result);
bool payload_delivery_resolve_request_payload_ref(
    JsonDocument& request,
    JsonDocument& resolved_payload,
    TimeoutTick now_tick,
    const UsbRequestEnvelope& envelope,
    const UsbOperationResponseWriter& writer);

}  // namespace signing
