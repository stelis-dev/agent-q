#include "sui/zklogin_credential_outcome.h"

namespace signing {

const char* sui_zklogin_proposal_terminal_status(
    SuiZkLoginProposalTerminalResult result)
{
    switch (result) {
        case SuiZkLoginProposalTerminalResult::activated:
            return "activated";
        case SuiZkLoginProposalTerminalResult::rejected:
            return "rejected";
        case SuiZkLoginProposalTerminalResult::timed_out:
            return "timed_out";
        case SuiZkLoginProposalTerminalResult::invalid_proof:
            return "invalid_proof";
        case SuiZkLoginProposalTerminalResult::ui_error:
            return "ui_error";
        case SuiZkLoginProposalTerminalResult::storage_error:
            return "storage_error";
        case SuiZkLoginProposalTerminalResult::consistency_error:
            return "consistency_error";
        case SuiZkLoginProposalTerminalResult::invalid_state:
        default:
            return "";
    }
}

const char* sui_zklogin_proposal_terminal_reason(
    SuiZkLoginProposalTerminalResult result)
{
    switch (result) {
        case SuiZkLoginProposalTerminalResult::activated:
            return "device_confirmed";
        case SuiZkLoginProposalTerminalResult::rejected:
            return "device_rejected";
        case SuiZkLoginProposalTerminalResult::timed_out:
            return "timeout";
        case SuiZkLoginProposalTerminalResult::invalid_proof:
            return "invalid_proof";
        case SuiZkLoginProposalTerminalResult::ui_error:
            return "ui_error";
        case SuiZkLoginProposalTerminalResult::storage_error:
            return "storage_error";
        case SuiZkLoginProposalTerminalResult::consistency_error:
            return "consistency_error";
        case SuiZkLoginProposalTerminalResult::invalid_state:
        default:
            return "invalid_state";
    }
}

bool sui_zklogin_proposal_terminal_ends_session(
    SuiZkLoginProposalTerminalResult result)
{
    return result == SuiZkLoginProposalTerminalResult::activated ||
           result == SuiZkLoginProposalTerminalResult::consistency_error;
}

}  // namespace signing
