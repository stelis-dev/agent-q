#pragma once

#include <ArduinoJson.h>

#include "agent_q_approval_history.h"
#include "agent_q_method_limits.h"

namespace agent_q {

enum class AgentQMethodRuntimeStatus {
    invalid_params,
    rejected,
};

struct AgentQMethodRuntimeResult {
    AgentQMethodRuntimeStatus status;
    const char* code;
    const char* message;
    bool has_approval_history;
    struct {
        AgentQApprovalHistoryDecision decision;
        AgentQApprovalHistoryConfirmationKind confirmation_kind;
        char chain[kAgentQApprovalHistoryChainSize];
        char method[kAgentQApprovalHistoryMethodSize];
        char reason_code[kAgentQApprovalHistoryReasonCodeSize];
        char payload_digest[kAgentQApprovalHistoryDigestSize];
        char policy_hash[kAgentQApprovalHistoryDigestSize];
        char rule_ref[kAgentQApprovalHistoryRuleRefSize];
    } approval_history;
};

AgentQMethodRuntimeResult evaluate_call_method(
    const char* chain,
    const char* method,
    JsonVariant params);
void clear_method_runtime_result(AgentQMethodRuntimeResult* result);

}  // namespace agent_q
