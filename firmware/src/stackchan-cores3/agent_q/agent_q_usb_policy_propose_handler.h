#pragma once

#include <ArduinoJson.h>

#include "agent_q_policy_update_flow.h"
#include "agent_q_timeout_window.h"
#include "agent_q_usb_operation_response_writer.h"

namespace agent_q {

struct AgentQUsbPolicyProposeHandlerOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(const char* id);
    bool (*require_active_matching_session)(const char* id, const char* session_id);
    AgentQTimeoutWindow (*make_review_window)();
    AgentQPolicyUpdateFlowBeginResult (*begin_policy_update)(
        JsonVariantConst policy,
        const char* request_id,
        const char* session_id,
        AgentQTimeoutWindow review_window);
    const char* (*begin_result_reason)(AgentQPolicyUpdateFlowBeginResult result);
    bool (*write_policy_propose_result_response)(
        const char* id,
        const char* status,
        const char* reason,
        bool applied);
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
