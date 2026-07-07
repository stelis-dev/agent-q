#pragma once

#include <ArduinoJson.h>

#include "transport/timeout_window.h"
#include "protocol/usb_request_envelope.h"
#include "protocol/usb_operation_dispatch.h"
#include "protocol/usb_operation_response_writer.h"

namespace signing {

using UsbPayloadRefResolver = bool (*)(
    JsonDocument& request,
    JsonDocument& resolved_payload,
    TimeoutTick now_tick,
    const UsbRequestEnvelope& envelope,
    const UsbOperationResponseWriter& writer);

void handle_usb_request_line(
    const char* line,
    TimeoutTick now_tick,
    const UsbOperationResponseWriter& response_writer,
    const UsbOperationHandlers& handlers,
    UsbPayloadRefResolver resolve_payload_ref = nullptr);

}  // namespace signing
