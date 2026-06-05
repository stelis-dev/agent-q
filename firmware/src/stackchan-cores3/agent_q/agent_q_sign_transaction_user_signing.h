#pragma once

#include "agent_q_sign_transaction_user_flow.h"
#include "agent_q_sui_signing_service.h"

namespace agent_q {

enum class AgentQSignTransactionUserSigningHandoffResult {
    ok,
    inactive,
    wrong_stage,
    invalid_output,
    payload_unavailable,
    output_too_small,
    signing_failed,
    terminal_error,
};

struct AgentQSignTransactionUserSigningOutput {
    uint8_t signature[kSuiEd25519SignatureBytes];
    size_t signature_size;
};

struct AgentQSignTransactionUserSigningHandoffReport {
    AgentQSignTransactionUserSigningHandoffResult result;
    AgentQSignTransactionUserTransitionResult flow_result;
    SuiTransactionSigningResult signing_result;
};

void sign_transaction_user_signing_output_wipe(
    AgentQSignTransactionUserSigningOutput* output);

AgentQSignTransactionUserSigningHandoffReport
sign_transaction_user_signing_execute_critical_section(
    AgentQSignTransactionUserSigningOutput* output);

const char* sign_transaction_user_signing_handoff_result_name(
    AgentQSignTransactionUserSigningHandoffResult result);

}  // namespace agent_q
