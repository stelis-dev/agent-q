#include "sui_zklogin_proposal_state.h"

#include <string.h>

#include "sensitive_memory.h"
#include "sui/zklogin_proof_payload.h"

namespace stopwatch_target {
namespace {

struct SuiZkLoginProposalState {
    bool active = false;
    SuiZkLoginProposalStage stage = SuiZkLoginProposalStage::idle;
    char request_id[signing::kRequestIdSize] = {};
    char session_id[signing::kSessionIdSize] = {};
    signing::TimeoutWindow request_window = signing::kTimeoutWindowNone;
    SuiZkLoginCredentialRecord record = {};

    void clear()
    {
        wipe_sensitive_buffer(&record, sizeof(record));
        memset(this, 0, sizeof(*this));
        stage = SuiZkLoginProposalStage::idle;
    }
};

SuiZkLoginProposalState g_state;
SuiZkLoginCredentialRecord g_begin_record = {};

void clear_credential_record(SuiZkLoginCredentialRecord* record)
{
    if (record != nullptr) {
        wipe_sensitive_buffer(record, sizeof(*record));
    }
}

SuiZkLoginProposalBeginResult map_parse_result(
    signing::SuiZkLoginProofPayloadParseResult result)
{
    switch (result) {
        case signing::SuiZkLoginProofPayloadParseResult::ok:
            return SuiZkLoginProposalBeginResult::ok;
        case signing::SuiZkLoginProofPayloadParseResult::invalid_argument:
            return SuiZkLoginProposalBeginResult::invalid_argument;
        case signing::SuiZkLoginProofPayloadParseResult::encode_error:
            return SuiZkLoginProposalBeginResult::encode_error;
        case signing::SuiZkLoginProofPayloadParseResult::invalid_proof:
        default:
            return SuiZkLoginProposalBeginResult::invalid_proof;
    }
}

bool valid_request_and_session(const char* request_id, const char* session_id)
{
    return request_id != nullptr &&
           signing::request_id_format_valid(request_id) &&
           signing::session_id_format_valid(session_id);
}

}  // namespace

void sui_zklogin_proposal_state_init()
{
    sui_zklogin_proposal_state_clear();
}

bool sui_zklogin_proposal_state_active()
{
    return g_state.active;
}

void sui_zklogin_proposal_state_clear()
{
    g_state.clear();
}

SuiZkLoginProposalSnapshot sui_zklogin_proposal_state_snapshot()
{
    return SuiZkLoginProposalSnapshot{
        g_state.active,
        g_state.stage,
        g_state.request_id,
        g_state.session_id,
        g_state.request_window,
        g_state.record.proof.address,
        g_state.record.proof.network,
        g_state.record.proof.issuer,
        g_state.record.proof.max_epoch,
        g_state.record.proof.proof_hash,
    };
}

SuiZkLoginProposalBeginResult sui_zklogin_proposal_state_begin(
    JsonVariantConst params,
    const char* request_id,
    const char* session_id,
    uint32_t now_ms,
    signing::TimeoutWindow request_window,
    const uint8_t prepared_seed[kSuiEd25519SeedBytes])
{
    g_state.clear();
    if (!valid_request_and_session(request_id, session_id) ||
        prepared_seed == nullptr) {
        return SuiZkLoginProposalBeginResult::invalid_argument;
    }
    if (!signing::timeout_window_valid_and_open_at(request_window, now_ms)) {
        return SuiZkLoginProposalBeginResult::invalid_argument;
    }
    clear_credential_record(&g_begin_record);
    memcpy(g_begin_record.prepared_seed, prepared_seed, kSuiEd25519SeedBytes);
    const SuiZkLoginProposalBeginResult parse_result =
        map_parse_result(signing::parse_sui_zklogin_proof_payload(
            params,
            &g_begin_record.proof));
    if (parse_result != SuiZkLoginProposalBeginResult::ok) {
        clear_credential_record(&g_begin_record);
        return parse_result;
    }
    if (!validate_sui_zklogin_credential_record(&g_begin_record)) {
        clear_credential_record(&g_begin_record);
        return SuiZkLoginProposalBeginResult::invalid_proof;
    }

    memcpy(&g_state.record, &g_begin_record, sizeof(g_state.record));
    clear_credential_record(&g_begin_record);
    strlcpy(g_state.request_id, request_id, sizeof(g_state.request_id));
    strlcpy(g_state.session_id, session_id, sizeof(g_state.session_id));
    g_state.request_window = request_window;
    g_state.stage = SuiZkLoginProposalStage::reviewing;
    g_state.active = true;
    return SuiZkLoginProposalBeginResult::ok;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_continue_to_auth(
    uint32_t now_ms)
{
    if (!g_state.active) {
        return SuiZkLoginProposalTransitionResult::inactive;
    }
    if (g_state.stage != SuiZkLoginProposalStage::reviewing) {
        return SuiZkLoginProposalTransitionResult::wrong_stage;
    }
    if (signing::timeout_window_reached(g_state.request_window, now_ms)) {
        return SuiZkLoginProposalTransitionResult::timed_out;
    }
    g_state.stage = SuiZkLoginProposalStage::auth_entry;
    return SuiZkLoginProposalTransitionResult::ok;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_return_to_review(
    uint32_t now_ms)
{
    if (!g_state.active) {
        return SuiZkLoginProposalTransitionResult::inactive;
    }
    if (g_state.stage != SuiZkLoginProposalStage::auth_entry) {
        return SuiZkLoginProposalTransitionResult::wrong_stage;
    }
    if (signing::timeout_window_reached(g_state.request_window, now_ms)) {
        return SuiZkLoginProposalTransitionResult::timed_out;
    }
    g_state.stage = SuiZkLoginProposalStage::reviewing;
    return SuiZkLoginProposalTransitionResult::ok;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_mark_auth_verifying()
{
    if (!g_state.active) {
        return SuiZkLoginProposalTransitionResult::inactive;
    }
    if (g_state.stage != SuiZkLoginProposalStage::auth_entry) {
        return SuiZkLoginProposalTransitionResult::wrong_stage;
    }
    g_state.stage = SuiZkLoginProposalStage::auth_verifying;
    return SuiZkLoginProposalTransitionResult::ok;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_return_to_auth_entry()
{
    if (!g_state.active) {
        return SuiZkLoginProposalTransitionResult::inactive;
    }
    if (g_state.stage != SuiZkLoginProposalStage::auth_verifying) {
        return SuiZkLoginProposalTransitionResult::wrong_stage;
    }
    g_state.stage = SuiZkLoginProposalStage::auth_entry;
    return SuiZkLoginProposalTransitionResult::ok;
}

bool sui_zklogin_proposal_deadline_reached(uint32_t now_ms)
{
    return g_state.active &&
           signing::timeout_window_reached(g_state.request_window, now_ms);
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_rejected()
{
    return g_state.active
               ? SuiZkLoginProposalTerminalResult::rejected
               : SuiZkLoginProposalTerminalResult::invalid_state;
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_timed_out()
{
    return g_state.active
               ? SuiZkLoginProposalTerminalResult::timed_out
               : SuiZkLoginProposalTerminalResult::invalid_state;
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_ui_error()
{
    return g_state.active
               ? SuiZkLoginProposalTerminalResult::ui_error
               : SuiZkLoginProposalTerminalResult::invalid_state;
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_consistency_error()
{
    return g_state.active
               ? SuiZkLoginProposalTerminalResult::consistency_error
               : SuiZkLoginProposalTerminalResult::invalid_state;
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_commit()
{
    if (!g_state.active ||
        g_state.stage != SuiZkLoginProposalStage::auth_verifying) {
        return SuiZkLoginProposalTerminalResult::invalid_state;
    }
    g_state.stage = SuiZkLoginProposalStage::committing;
    switch (store_sui_zklogin_credential(&g_state.record)) {
        case SuiZkLoginCredentialWriteResult::stored:
            return SuiZkLoginProposalTerminalResult::activated;
        case SuiZkLoginCredentialWriteResult::storage_error:
            return SuiZkLoginProposalTerminalResult::storage_error;
        case SuiZkLoginCredentialWriteResult::consistency_error:
            return SuiZkLoginProposalTerminalResult::consistency_error;
        case SuiZkLoginCredentialWriteResult::invalid_record:
        default:
            return SuiZkLoginProposalTerminalResult::invalid_proof;
    }
}

}  // namespace stopwatch_target
