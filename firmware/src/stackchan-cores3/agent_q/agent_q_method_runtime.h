#pragma once

#include <ArduinoJson.h>

#include "agent_q_approval_history.h"
#include "agent_q_method_limits.h"
#include "agent_q_sign_by_user_limits.h"

namespace agent_q {

enum class AgentQSignByPolicyRuntimeStatus {
    invalid_params,
    unsupported_transaction,
    account_unavailable,
    account_mismatch,
    policy_error,
    policy_rejected,
    policy_authorized,
};

struct AgentQSignByPolicyRuntimeResult {
    AgentQSignByPolicyRuntimeStatus status;
    const char* code;
    const char* message;
    char chain[kAgentQApprovalHistoryChainSize];
    char method[kAgentQApprovalHistoryMethodSize];
    char reason_code[kAgentQApprovalHistoryReasonCodeSize];
    char payload_digest[kAgentQApprovalHistoryDigestSize];
    char policy_hash[kAgentQApprovalHistoryDigestSize];
    char rule_ref[kAgentQApprovalHistoryRuleRefSize];
    uint8_t tx_bytes[kAgentQSuiSignTransactionTxBytesMaxBytes];
    size_t tx_bytes_size;
};

AgentQSignByPolicyRuntimeResult evaluate_sign_by_policy(
    const char* chain,
    const char* method,
    JsonVariant params);
void clear_sign_by_policy_runtime_result(AgentQSignByPolicyRuntimeResult* result);

}  // namespace agent_q
