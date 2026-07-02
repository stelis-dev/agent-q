#pragma once

#include <ArduinoJson.h>

#include "protocol/request_id.h"
#include "session.h"
#include "sui_zklogin_proof_store.h"
#include "timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace signing {

enum class SuiZkLoginProposalBeginResult {
    ok,
    invalid_argument,
    invalid_proof,
    encode_error,
};

enum class SuiZkLoginProposalTerminalResult {
    activated,
    rejected,
    timed_out,
    invalid_proof,
    ui_error,
    storage_error,
    consistency_error,
    invalid_state,
};

enum class SuiZkLoginProposalStage {
    idle,
    reviewing,
    pin_entry,
    pin_verifying,
    committing,
};

enum class SuiZkLoginProposalTransitionResult {
    ok,
    inactive,
    wrong_stage,
    timed_out,
    invalid_argument,
};

struct SuiZkLoginProposalSnapshot {
    bool active;
    SuiZkLoginProposalStage stage;
    const char* request_id;
    const char* session_id;
    TimeoutWindow request_window;
    const char* address;
    const char* network;
    const char* issuer;
    const char* max_epoch;
    const char* proof_hash;
};

bool sui_zklogin_proposal_flow_active();
void sui_zklogin_proposal_flow_clear();
SuiZkLoginProposalSnapshot sui_zklogin_proposal_flow_snapshot();

SuiZkLoginProposalBeginResult sui_zklogin_proposal_flow_begin(
    JsonVariantConst params,
    const char* request_id,
    const char* session_id,
    TickType_t now,
    TimeoutWindow request_window);
SuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_continue_to_pin(
    TickType_t now);
SuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_return_to_review(
    TickType_t now);
SuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_mark_pin_verifying();
SuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_return_to_pin_entry();
bool sui_zklogin_proposal_flow_deadline_reached(TickType_t now);
SuiZkLoginProposalTerminalResult sui_zklogin_proposal_flow_record_rejected();
SuiZkLoginProposalTerminalResult sui_zklogin_proposal_flow_record_timed_out();
SuiZkLoginProposalTerminalResult sui_zklogin_proposal_flow_record_ui_error();
SuiZkLoginProposalTerminalResult sui_zklogin_proposal_flow_commit();

const char* sui_zklogin_proposal_begin_result_reason(
    SuiZkLoginProposalBeginResult result);
const char* sui_zklogin_proposal_terminal_status(
    SuiZkLoginProposalTerminalResult result);
const char* sui_zklogin_proposal_terminal_reason(
    SuiZkLoginProposalTerminalResult result);

}  // namespace signing
