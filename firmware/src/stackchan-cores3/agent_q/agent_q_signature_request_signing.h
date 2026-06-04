#pragma once

#include "agent_q_signature_request_flow.h"
#include "agent_q_sui_signing_service.h"

namespace agent_q {

enum class AgentQSignatureRequestSigningHandoffResult {
    ok,
    inactive,
    wrong_stage,
    invalid_output,
    payload_unavailable,
    output_too_small,
    signing_failed,
    terminal_error,
};

struct AgentQSignatureRequestSigningOutput {
    uint8_t signature[kSuiEd25519SignatureBytes];
    size_t signature_size;
};

struct AgentQSignatureRequestSigningHandoffReport {
    AgentQSignatureRequestSigningHandoffResult result;
    AgentQSignatureRequestTransitionResult flow_result;
    SuiTransactionSigningResult signing_result;
};

void signature_request_signing_output_wipe(
    AgentQSignatureRequestSigningOutput* output);

AgentQSignatureRequestSigningHandoffReport
signature_request_signing_execute_critical_section(
    AgentQSignatureRequestSigningOutput* output);

const char* signature_request_signing_handoff_result_name(
    AgentQSignatureRequestSigningHandoffResult result);

}  // namespace agent_q
