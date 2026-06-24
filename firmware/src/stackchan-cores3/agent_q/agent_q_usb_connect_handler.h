#pragma once

#include <ArduinoJson.h>

#include "agent_q_timeout_window.h"
#include "agent_q_usb_operation_response_writer.h"

namespace agent_q {

struct AgentQUsbConnectHandlerOps {
    bool (*material_ready)();
    bool (*write_connect_admission_error)(
        const char* id,
        const AgentQUsbOperationResponseWriter& writer);
    AgentQTimeoutTick (*current_tick)();
    AgentQTimeoutWindow (*make_approval_window)(AgentQTimeoutTick now);
    bool (*begin_connect_approval)(
        const char* request_id,
        const char* client_name,
        AgentQTimeoutTick now,
        AgentQTimeoutWindow approval_window);
    void (*show_connect_unavailable)();
    void (*reset_review_choice_queue)();
    void (*show_connect_review)();
    void (*record_review_waiting)(const char* id, const char* client_name);
};

void handle_usb_connect_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbConnectHandlerOps& ops);

}  // namespace agent_q
