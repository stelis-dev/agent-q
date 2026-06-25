#pragma once

#include "agent_q_user_signing_flow.h"
#include "agent_q_sui_signing_service.h"

namespace agent_q {

enum class AgentQUserSigningHandoffResult {
    ok,
    inactive,
    wrong_stage,
    invalid_output,
    payload_unavailable,
    output_too_small,
    response_unavailable,
    signing_failed,
    terminal_error,
};

struct AgentQUserSigningOutput {
    AgentQSigningRoute signing_route;
    uint8_t signature[kSuiSignatureEnvelopeMaxBytes];
    size_t signature_size;
    uint8_t message_bytes[kAgentQSuiSignPersonalMessageMaxBytes];
    size_t message_bytes_size;
};

struct AgentQUserSigningHandoffReport {
    AgentQUserSigningHandoffResult result;
    AgentQUserSigningTransitionResult flow_result;
    SuiSigningStatus signing_status;
};

using AgentQUserSigningOutputReadyFn =
    bool (*)(
        const AgentQUserSigningFlowCoreSnapshot& snapshot,
        const AgentQUserSigningOutput& output,
        void* context);

void user_signing_output_wipe(
    AgentQUserSigningOutput* output);

AgentQUserSigningHandoffReport
user_signing_execute_critical_section(
    AgentQUserSigningOutput* output,
    AgentQUserSigningOutputReadyFn output_ready,
    void* context);

const char* user_signing_handoff_result_name(
    AgentQUserSigningHandoffResult result);

}  // namespace agent_q
