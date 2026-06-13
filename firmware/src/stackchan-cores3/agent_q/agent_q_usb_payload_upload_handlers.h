#pragma once

#include <stdint.h>

#include <ArduinoJson.h>

#include "agent_q_timeout_window.h"
#include "agent_q_usb_operation_response_writer.h"

namespace agent_q {

struct AgentQUsbPayloadUploadHandlerOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(const char* id);
    bool (*require_active_matching_session)(const char* id, const char* session_id);
    AgentQTimeoutTick (*current_tick)();
    AgentQTimeoutWindow (*timeout_window_for_size)(size_t size_bytes);
};

void handle_usb_payload_upload_begin_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadUploadHandlerOps& ops);
void handle_usb_payload_upload_chunk_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadUploadHandlerOps& ops);
void handle_usb_payload_upload_finish_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadUploadHandlerOps& ops);
void handle_usb_payload_upload_abort_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPayloadUploadHandlerOps& ops);

}  // namespace agent_q
