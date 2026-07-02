#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "policy_update_marker.h"
#include "request_id.h"
#include "session.h"
#include "timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace signing {

enum class PolicyUpdateFlowBeginResult {
    ok,
    invalid_argument,
    too_large,
    invalid_policy,
    unsupported_field,
    encode_error,
};

enum class PolicyUpdateFlowTerminalResult {
    applied,
    rejected,
    timed_out,
    ui_error,
    storage_error,
    consistency_error,
    history_error,
    invalid_state,
};

enum class PolicyUpdateFlowStage {
    idle,
    reviewing,
    pin_entry,
    pin_verifying,
    committing,
};

enum class PolicyUpdateFlowTransitionResult {
    ok,
    inactive,
    wrong_stage,
    timed_out,
    invalid_argument,
    invalid_deadline,
};

struct PolicyUpdateFlowSnapshot {
    bool active;
    PolicyUpdateFlowStage stage;
    const char* request_id;
    const char* session_id;
    TimeoutWindow review_window;
    const char* policy_hash;
    size_t blockchain_count;
    size_t network_count;
    size_t policy_count;
    size_t condition_count;
    const char* highest_action;
    const char* default_action;
    const char* scope_summary;
    const char* review_summary;
};

bool policy_update_flow_active();
void policy_update_flow_clear();
PolicyUpdateFlowSnapshot policy_update_flow_snapshot();

PolicyUpdateFlowBeginResult policy_update_flow_begin(
    JsonVariantConst policy,
    const char* request_id,
    const char* session_id,
    TickType_t now,
    TimeoutWindow review_window);
PolicyUpdateFlowTransitionResult policy_update_flow_continue_to_pin(TickType_t now);
PolicyUpdateFlowTransitionResult policy_update_flow_return_to_review(
    TickType_t now,
    TimeoutWindow review_window);
PolicyUpdateFlowTransitionResult policy_update_flow_return_to_pin_entry();
PolicyUpdateFlowTransitionResult policy_update_flow_mark_pin_verifying();
bool policy_update_flow_review_deadline_reached(TickType_t now);
PolicyUpdateFlowTerminalResult policy_update_flow_record_rejected(uint64_t uptime_ms);
PolicyUpdateFlowTerminalResult policy_update_flow_record_timed_out(uint64_t uptime_ms);
PolicyUpdateFlowTerminalResult policy_update_flow_record_ui_error();
PolicyUpdateFlowTerminalResult policy_update_flow_commit(uint64_t uptime_ms);

const char* policy_update_flow_begin_result_reason(PolicyUpdateFlowBeginResult result);
const char* policy_update_flow_terminal_status(PolicyUpdateFlowTerminalResult result);
const char* policy_update_flow_terminal_reason(PolicyUpdateFlowTerminalResult result);

}  // namespace signing
