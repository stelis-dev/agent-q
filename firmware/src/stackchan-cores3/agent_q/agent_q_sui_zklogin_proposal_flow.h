#pragma once

#include <ArduinoJson.h>

#include "agent_q_request_id.h"
#include "agent_q_session.h"
#include "agent_q_sui_zklogin_proof_store.h"
#include "agent_q_timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQSuiZkLoginProposalBeginResult {
    ok,
    invalid_argument,
    invalid_proof,
    encode_error,
};

enum class AgentQSuiZkLoginProposalTerminalResult {
    activated,
    rejected,
    timed_out,
    invalid_proof,
    ui_error,
    storage_error,
    consistency_error,
    invalid_state,
};

enum class AgentQSuiZkLoginProposalStage {
    idle,
    reviewing,
    pin_entry,
    pin_verifying,
    committing,
};

enum class AgentQSuiZkLoginProposalTransitionResult {
    ok,
    inactive,
    wrong_stage,
    timed_out,
    invalid_argument,
};

struct AgentQSuiZkLoginProposalSnapshot {
    bool active;
    AgentQSuiZkLoginProposalStage stage;
    const char* request_id;
    const char* session_id;
    AgentQTimeoutWindow request_window;
    const char* address;
    const char* network;
    const char* issuer;
    const char* max_epoch;
    const char* proof_hash;
};

bool sui_zklogin_proposal_flow_active();
void sui_zklogin_proposal_flow_clear();
AgentQSuiZkLoginProposalSnapshot sui_zklogin_proposal_flow_snapshot();

AgentQSuiZkLoginProposalBeginResult sui_zklogin_proposal_flow_begin(
    JsonVariantConst params,
    const char* request_id,
    const char* session_id,
    TickType_t now,
    AgentQTimeoutWindow request_window);
AgentQSuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_continue_to_pin(
    TickType_t now);
AgentQSuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_return_to_review(
    TickType_t now);
AgentQSuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_mark_pin_verifying();
AgentQSuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_return_to_pin_entry();
bool sui_zklogin_proposal_flow_deadline_reached(TickType_t now);
AgentQSuiZkLoginProposalTerminalResult sui_zklogin_proposal_flow_record_rejected();
AgentQSuiZkLoginProposalTerminalResult sui_zklogin_proposal_flow_record_timed_out();
AgentQSuiZkLoginProposalTerminalResult sui_zklogin_proposal_flow_record_ui_error();
AgentQSuiZkLoginProposalTerminalResult sui_zklogin_proposal_flow_commit();

const char* sui_zklogin_proposal_begin_result_reason(
    AgentQSuiZkLoginProposalBeginResult result);
const char* sui_zklogin_proposal_terminal_status(
    AgentQSuiZkLoginProposalTerminalResult result);
const char* sui_zklogin_proposal_terminal_reason(
    AgentQSuiZkLoginProposalTerminalResult result);

}  // namespace agent_q
