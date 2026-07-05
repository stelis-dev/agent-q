#pragma once

#include <stdint.h>

#include <ArduinoJson.h>

#include "transport/timeout_window.h"
#include "usb_operation_response_writer.h"

namespace signing {

struct UsbPayloadTransferHandlerOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(
        const char* id,
        const UsbOperationResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const UsbOperationResponseWriter& writer);
    TimeoutTick (*current_tick)();
    TimeoutWindow (*timeout_window_for_size)(size_t size_bytes);
};

void handle_usb_payload_transfer_begin_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbPayloadTransferHandlerOps& ops);
void handle_usb_payload_transfer_chunk_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbPayloadTransferHandlerOps& ops);
void handle_usb_payload_transfer_finish_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbPayloadTransferHandlerOps& ops);
void handle_usb_payload_transfer_abort_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbPayloadTransferHandlerOps& ops);

}  // namespace signing
