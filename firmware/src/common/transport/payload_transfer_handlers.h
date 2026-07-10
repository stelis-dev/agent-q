#pragma once

#include <stdint.h>

#include <ArduinoJson.h>

#include "transport/timeout_window.h"
#include "protocol/response_writer.h"

namespace signing {

struct PayloadTransferHandlerOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(
        const char* id,
        const ResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const ResponseWriter& writer);
    TimeoutTick (*current_tick)();
    TimeoutWindow (*timeout_window_for_size)(size_t size_bytes);
};

void handle_protocol_payload_transfer_begin_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PayloadTransferHandlerOps& ops);
void handle_protocol_payload_transfer_chunk_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PayloadTransferHandlerOps& ops);
void handle_protocol_payload_transfer_finish_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PayloadTransferHandlerOps& ops);
void handle_protocol_payload_transfer_abort_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PayloadTransferHandlerOps& ops);

}  // namespace signing
