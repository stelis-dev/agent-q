#pragma once

#include "agent_q_sign_by_user_flow.h"
#include "agent_q_sui_signing_service.h"

namespace agent_q {

enum class AgentQSignByUserSigningHandoffResult {
    ok,
    inactive,
    wrong_stage,
    invalid_output,
    payload_unavailable,
    output_too_small,
    signing_failed,
    terminal_error,
};

struct AgentQSignByUserSigningOutput {
    uint8_t signature[kSuiEd25519SignatureBytes];
    size_t signature_size;
};

struct AgentQSignByUserSigningHandoffReport {
    AgentQSignByUserSigningHandoffResult result;
    AgentQSignByUserTransitionResult flow_result;
    SuiTransactionSigningResult signing_result;
};

void sign_by_user_signing_output_wipe(
    AgentQSignByUserSigningOutput* output);

AgentQSignByUserSigningHandoffReport
sign_by_user_signing_execute_critical_section(
    AgentQSignByUserSigningOutput* output);

const char* sign_by_user_signing_handoff_result_name(
    AgentQSignByUserSigningHandoffResult result);

}  // namespace agent_q
