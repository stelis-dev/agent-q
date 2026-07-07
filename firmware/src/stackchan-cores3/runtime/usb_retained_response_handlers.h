#pragma once

#include <ArduinoJson.h>

#include "usb_operation_type.h"
#include "protocol/usb_operation_response_writer.h"

namespace signing {

struct UsbRetainedResponseHandlerOps {
    bool (*material_ready)();
    bool (*write_payload_delivery_retained_response_admission_error)(
        const char* id,
        UsbOperationType operation,
        const UsbOperationResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const UsbOperationResponseWriter& writer);
};

void handle_usb_get_result_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbRetainedResponseHandlerOps& ops);

void handle_usb_ack_result_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbRetainedResponseHandlerOps& ops);

}  // namespace signing
