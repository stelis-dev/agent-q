#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "agent_q_policy_update_marker.h"
#include "agent_q_request_id.h"
#include "agent_q_session.h"
#include "agent_q_timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQPolicyUpdateFlowBeginResult {
    ok,
    invalid_argument,
    too_large,
    invalid_policy,
    unsupported_method,
    unsupported_field,
    encode_error,
};

enum class AgentQPolicyUpdateFlowTerminalResult {
    applied,
    rejected,
    timed_out,
    ui_error,
    storage_error,
    consistency_error,
    history_error,
    invalid_state,
};

enum class AgentQPolicyUpdateFlowStage {
    idle,
    reviewing,
    pin_entry,
    pin_verifying,
    committing,
};

enum class AgentQPolicyUpdateFlowTransitionResult {
    ok,
    inactive,
    wrong_stage,
    timed_out,
    invalid_argument,
    invalid_deadline,
};

struct AgentQPolicyUpdateFlowSnapshot {
    bool active;
    AgentQPolicyUpdateFlowStage stage;
    const char* request_id;
    const char* session_id;
    AgentQTimeoutWindow review_window;
    const char* policy_hash;
    size_t rule_count;
    const char* highest_action;
    const char* default_action;
    const char* method_summary;
    const char* review_summary;
};

bool policy_update_flow_active();
void policy_update_flow_clear();
AgentQPolicyUpdateFlowSnapshot policy_update_flow_snapshot();

AgentQPolicyUpdateFlowBeginResult policy_update_flow_begin(
    JsonVariantConst policy,
    const char* request_id,
    const char* session_id,
    AgentQTimeoutWindow review_window);
AgentQPolicyUpdateFlowTransitionResult policy_update_flow_continue_to_pin(TickType_t now);
AgentQPolicyUpdateFlowTransitionResult policy_update_flow_return_to_review(
    AgentQTimeoutWindow review_window);
AgentQPolicyUpdateFlowTransitionResult policy_update_flow_return_to_pin_entry();
AgentQPolicyUpdateFlowTransitionResult policy_update_flow_mark_pin_verifying();
bool policy_update_flow_review_deadline_reached(TickType_t now);
AgentQPolicyUpdateFlowTerminalResult policy_update_flow_record_rejected(uint64_t uptime_ms);
AgentQPolicyUpdateFlowTerminalResult policy_update_flow_record_timed_out(uint64_t uptime_ms);
AgentQPolicyUpdateFlowTerminalResult policy_update_flow_record_ui_error();
AgentQPolicyUpdateFlowTerminalResult policy_update_flow_commit(uint64_t uptime_ms);

const char* policy_update_flow_begin_result_reason(AgentQPolicyUpdateFlowBeginResult result);
const char* policy_update_flow_terminal_status(AgentQPolicyUpdateFlowTerminalResult result);
const char* policy_update_flow_terminal_reason(AgentQPolicyUpdateFlowTerminalResult result);

}  // namespace agent_q
