#include "sui_zklogin_proposal_flow.h"

#include <string.h>

#include "protocol_input_copy.h"
#include "sui/zklogin_proof_payload.h"

namespace signing {
namespace {

struct SuiZkLoginProposalState {
    bool active = false;
    SuiZkLoginProposalStage stage = SuiZkLoginProposalStage::idle;
    char request_id[kRequestIdSize] = {};
    char session_id[kSessionIdSize] = {};
    TimeoutWindow request_window = kTimeoutWindowNone;
    SuiZkLoginProofRecord record = {};

    void clear()
    {
        memset(this, 0, sizeof(*this));
        stage = SuiZkLoginProposalStage::idle;
        request_window = kTimeoutWindowNone;
    }
};

SuiZkLoginProposalState g_state;

SuiZkLoginProposalBeginResult map_parse_result(
    SuiZkLoginProofPayloadParseResult result)
{
    switch (result) {
        case SuiZkLoginProofPayloadParseResult::ok:
            return SuiZkLoginProposalBeginResult::ok;
        case SuiZkLoginProofPayloadParseResult::invalid_argument:
            return SuiZkLoginProposalBeginResult::invalid_argument;
        case SuiZkLoginProofPayloadParseResult::encode_error:
            return SuiZkLoginProposalBeginResult::encode_error;
        case SuiZkLoginProofPayloadParseResult::invalid_proof:
        default:
            return SuiZkLoginProposalBeginResult::invalid_proof;
    }
}

}  // namespace

bool sui_zklogin_proposal_flow_active()
{
    return g_state.active;
}

void sui_zklogin_proposal_flow_clear()
{
    g_state.clear();
}

SuiZkLoginProposalSnapshot sui_zklogin_proposal_flow_snapshot()
{
    return SuiZkLoginProposalSnapshot{
        g_state.active,
        g_state.stage,
        g_state.request_id,
        g_state.session_id,
        g_state.request_window,
        g_state.record.address,
        g_state.record.network,
        g_state.record.issuer,
        g_state.record.max_epoch,
        g_state.record.proof_hash,
    };
}

SuiZkLoginProposalBeginResult sui_zklogin_proposal_flow_begin(
    JsonVariantConst params,
    const char* request_id,
    const char* session_id,
    TickType_t now,
    TimeoutWindow request_window)
{
    g_state.clear();
    if (!copy_nonempty_c_string(request_id, g_state.request_id, sizeof(g_state.request_id)) ||
        !copy_nonempty_c_string(session_id, g_state.session_id, sizeof(g_state.session_id)) ||
        !timeout_window_valid_and_open_at(request_window, now)) {
        g_state.clear();
        return SuiZkLoginProposalBeginResult::invalid_argument;
    }
    const SuiZkLoginProposalBeginResult parse_result =
        map_parse_result(parse_sui_zklogin_proof_payload(params, &g_state.record));
    if (parse_result != SuiZkLoginProposalBeginResult::ok) {
        g_state.clear();
        return parse_result;
    }
    g_state.request_window = request_window;
    g_state.stage = SuiZkLoginProposalStage::reviewing;
    g_state.active = true;
    return SuiZkLoginProposalBeginResult::ok;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_continue_to_pin(
    TickType_t now)
{
    if (!g_state.active) {
        return SuiZkLoginProposalTransitionResult::inactive;
    }
    if (g_state.stage != SuiZkLoginProposalStage::reviewing) {
        return SuiZkLoginProposalTransitionResult::wrong_stage;
    }
    if (timeout_window_reached(g_state.request_window, now)) {
        return SuiZkLoginProposalTransitionResult::timed_out;
    }
    g_state.stage = SuiZkLoginProposalStage::pin_entry;
    return SuiZkLoginProposalTransitionResult::ok;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_return_to_review(
    TickType_t now)
{
    if (!g_state.active) {
        return SuiZkLoginProposalTransitionResult::inactive;
    }
    if (g_state.stage != SuiZkLoginProposalStage::pin_entry) {
        return SuiZkLoginProposalTransitionResult::wrong_stage;
    }
    if (timeout_window_reached(g_state.request_window, now)) {
        return SuiZkLoginProposalTransitionResult::timed_out;
    }
    g_state.stage = SuiZkLoginProposalStage::reviewing;
    return SuiZkLoginProposalTransitionResult::ok;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_mark_pin_verifying()
{
    if (!g_state.active) {
        return SuiZkLoginProposalTransitionResult::inactive;
    }
    if (g_state.stage != SuiZkLoginProposalStage::pin_entry) {
        return SuiZkLoginProposalTransitionResult::wrong_stage;
    }
    g_state.stage = SuiZkLoginProposalStage::pin_verifying;
    return SuiZkLoginProposalTransitionResult::ok;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_return_to_pin_entry()
{
    if (!g_state.active) {
        return SuiZkLoginProposalTransitionResult::inactive;
    }
    if (g_state.stage != SuiZkLoginProposalStage::pin_verifying) {
        return SuiZkLoginProposalTransitionResult::wrong_stage;
    }
    g_state.stage = SuiZkLoginProposalStage::pin_entry;
    return SuiZkLoginProposalTransitionResult::ok;
}

bool sui_zklogin_proposal_flow_deadline_reached(TickType_t now)
{
    return g_state.active && timeout_window_reached(g_state.request_window, now);
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_flow_record_rejected()
{
    return g_state.active
               ? SuiZkLoginProposalTerminalResult::rejected
               : SuiZkLoginProposalTerminalResult::invalid_state;
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_flow_record_timed_out()
{
    return g_state.active
               ? SuiZkLoginProposalTerminalResult::timed_out
               : SuiZkLoginProposalTerminalResult::invalid_state;
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_flow_record_ui_error()
{
    return g_state.active
               ? SuiZkLoginProposalTerminalResult::ui_error
               : SuiZkLoginProposalTerminalResult::invalid_state;
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_flow_commit()
{
    if (!g_state.active || g_state.stage != SuiZkLoginProposalStage::pin_verifying) {
        return SuiZkLoginProposalTerminalResult::invalid_state;
    }
    g_state.stage = SuiZkLoginProposalStage::committing;
    switch (store_sui_zklogin_proof_record(&g_state.record)) {
        case SuiZkLoginProofRecordWriteResult::stored:
            return SuiZkLoginProposalTerminalResult::activated;
        case SuiZkLoginProofRecordWriteResult::storage_error:
            return SuiZkLoginProposalTerminalResult::storage_error;
        case SuiZkLoginProofRecordWriteResult::consistency_error:
            return SuiZkLoginProposalTerminalResult::consistency_error;
        case SuiZkLoginProofRecordWriteResult::invalid_record:
        default:
            return SuiZkLoginProposalTerminalResult::invalid_proof;
    }
}

const char* sui_zklogin_proposal_begin_result_reason(
    SuiZkLoginProposalBeginResult result)
{
    switch (result) {
        case SuiZkLoginProposalBeginResult::encode_error:
            return "encode_error";
        case SuiZkLoginProposalBeginResult::invalid_argument:
            return "invalid_argument";
        case SuiZkLoginProposalBeginResult::invalid_proof:
        case SuiZkLoginProposalBeginResult::ok:
        default:
            return "invalid_proof";
    }
}

}  // namespace signing
