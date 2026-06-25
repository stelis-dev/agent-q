#pragma once

#include <ArduinoJson.h>

#include "agent_q_usb_operation_type.h"
#include "agent_q_usb_operation_response_writer.h"

namespace agent_q {

struct AgentQUsbRetainedResponseHandlerOps {
    bool (*material_ready)();
    bool (*write_payload_delivery_retained_response_admission_error)(
        const char* id,
        AgentQUsbOperationType operation,
        const AgentQUsbOperationResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const AgentQUsbOperationResponseWriter& writer);
};

void handle_usb_get_result_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbRetainedResponseHandlerOps& ops);

void handle_usb_ack_result_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbRetainedResponseHandlerOps& ops);

}  // namespace agent_q
