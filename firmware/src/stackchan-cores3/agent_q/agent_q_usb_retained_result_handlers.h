#pragma once

#include <ArduinoJson.h>

#include "agent_q_usb_operation_response_writer.h"

namespace agent_q {

struct AgentQUsbRetainedResultHandlerOps {
    bool (*material_ready)();
    bool (*require_active_matching_session)(const char* id, const char* session_id);
};

void handle_usb_get_result_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbRetainedResultHandlerOps& ops);

void handle_usb_ack_result_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbRetainedResultHandlerOps& ops);

}  // namespace agent_q
