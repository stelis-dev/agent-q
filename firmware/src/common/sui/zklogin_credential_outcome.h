#pragma once

namespace signing {

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

const char* sui_zklogin_proposal_terminal_status(
    SuiZkLoginProposalTerminalResult result);
const char* sui_zklogin_proposal_terminal_reason(
    SuiZkLoginProposalTerminalResult result);
bool sui_zklogin_proposal_terminal_ends_session(
    SuiZkLoginProposalTerminalResult result);

}  // namespace signing
