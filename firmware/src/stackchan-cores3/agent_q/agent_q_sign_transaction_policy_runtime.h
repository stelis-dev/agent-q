#pragma once

#include "agent_q_approval_history.h"
#include "agent_q_sign_route.h"
#include "agent_q_sign_transaction_limits.h"
#include "agent_q_sui_signing_preparation.h"
#include "agent_q_user_signing_limits.h"

namespace agent_q {

enum class AgentQSignTransactionPolicyRuntimeStatus {
    invalid_params,
    unsupported_method,
    unsupported_transaction,
    account_unavailable,
    account_mismatch,
    policy_error,
    policy_rejected,
    policy_authorized,
};

struct AgentQSignTransactionPolicyRuntimeResult {
    AgentQSignTransactionPolicyRuntimeStatus status;
    const char* code;
    const char* message;
    char chain[kAgentQApprovalHistoryChainSize];
    char method[kAgentQApprovalHistoryMethodSize];
    char reason_code[kAgentQApprovalHistoryReasonCodeSize];
    char payload_digest[kAgentQApprovalHistoryDigestSize];
    char policy_hash[kAgentQApprovalHistoryDigestSize];
    char rule_ref[kAgentQApprovalHistoryRuleRefSize];
    const uint8_t* tx_bytes;
    size_t tx_bytes_size;
};

AgentQSignTransactionPolicyRuntimeResult evaluate_sign_transaction_policy(
    const AgentQSuiPreparedSignTransaction& prepared);
void clear_sign_transaction_policy_runtime_result(AgentQSignTransactionPolicyRuntimeResult* result);

}  // namespace agent_q
