#pragma once

#include <ArduinoJson.h>

#include "agent_q_policy_update_flow.h"
#include "agent_q_timeout_window.h"
#include "agent_q_usb_operation_response_writer.h"

namespace agent_q {

struct AgentQUsbPolicyProposeHandlerOps {
    bool (*material_ready)();
    bool (*write_policy_propose_admission_error)(
        const char* id,
        const AgentQUsbOperationResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const AgentQUsbOperationResponseWriter& writer);
    AgentQTimeoutTick (*current_tick)();
    AgentQTimeoutWindow (*make_review_window)(AgentQTimeoutTick now);
    AgentQPolicyUpdateFlowBeginResult (*begin_policy_update)(
        JsonVariantConst policy,
        const char* request_id,
        const char* session_id,
        TickType_t now,
        AgentQTimeoutWindow review_window);
    const char* (*begin_result_reason)(AgentQPolicyUpdateFlowBeginResult result);
    bool (*show_policy_update_review)();
    AgentQPolicyUpdateFlowTerminalResult (*record_ui_error)();
    void (*finish_policy_update_terminal)(const char* id, AgentQPolicyUpdateFlowTerminalResult result);
    void (*record_review_waiting)(const char* id);
};

void handle_usb_policy_propose_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPolicyProposeHandlerOps& ops);

}  // namespace agent_q
