#pragma once

#include <ArduinoJson.h>
#include <stdint.h>

#include "protocol/request_id.h"
#include "session_state.h"
#include "sui/zklogin_credential_outcome.h"
#include "sui_zklogin_credential_store.h"
#include "transport/timeout_window.h"

namespace stopwatch_target {

constexpr uint32_t kSuiZkLoginProposalWindowMs = 30000;

enum class SuiZkLoginProposalBeginResult {
    ok,
    invalid_argument,
    invalid_proof,
    encode_error,
};

using signing::SuiZkLoginProposalTerminalResult;
using signing::sui_zklogin_proposal_terminal_ends_session;
using signing::sui_zklogin_proposal_terminal_reason;
using signing::sui_zklogin_proposal_terminal_status;

enum class SuiZkLoginProposalStage {
    idle,
    reviewing,
    auth_entry,
    auth_verifying,
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
    signing::TimeoutWindow request_window;
    const char* address;
    const char* network;
    const char* issuer;
    const char* max_epoch;
    const char* proof_hash;
};

void sui_zklogin_proposal_state_init();
bool sui_zklogin_proposal_state_active();
void sui_zklogin_proposal_state_clear();
SuiZkLoginProposalSnapshot sui_zklogin_proposal_state_snapshot();

SuiZkLoginProposalBeginResult sui_zklogin_proposal_state_begin(
    JsonVariantConst params,
    const char* request_id,
    const char* session_id,
    uint32_t now_ms,
    signing::TimeoutWindow request_window,
    const uint8_t prepared_seed[kSuiEd25519SeedBytes]);
SuiZkLoginProposalTransitionResult sui_zklogin_proposal_continue_to_auth(
    uint32_t now_ms);
SuiZkLoginProposalTransitionResult sui_zklogin_proposal_return_to_review(
    uint32_t now_ms);
SuiZkLoginProposalTransitionResult sui_zklogin_proposal_mark_auth_verifying();
SuiZkLoginProposalTransitionResult sui_zklogin_proposal_return_to_auth_entry();
bool sui_zklogin_proposal_deadline_reached(uint32_t now_ms);
SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_rejected();
SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_timed_out();
SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_ui_error();
SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_consistency_error();
SuiZkLoginProposalTerminalResult sui_zklogin_proposal_commit();

}  // namespace stopwatch_target
