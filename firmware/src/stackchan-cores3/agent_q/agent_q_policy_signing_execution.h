#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_approval_history.h"
#include "agent_q_persistent_material.h"
#include "agent_q_sign_transaction_policy_runtime.h"
#include "agent_q_signing_method.h"
#include "agent_q_sui_signing_service.h"

namespace agent_q {

enum class AgentQPolicySigningExecutionStatus {
    request_error,
    policy_rejected,
    history_error,
    account_error,
    signing_failed,
    signed_success,
};

struct AgentQPolicySigningExecutionResult {
    AgentQPolicySigningExecutionStatus status;
    AgentQSigningMethod signing_method;
    const char* code;
    const char* message;
    char policy_hash[kAgentQApprovalHistoryDigestSize];
    char rule_ref[kAgentQApprovalHistoryRuleRefSize];
    uint8_t signature[kSuiEd25519SignatureBytes];
    size_t signature_size;
};

AgentQPolicySigningExecutionResult execute_policy_sign_transaction(
    const AgentQSignTransactionPolicyRuntimeResult& policy_result,
    const AgentQPersistentMaterialOps& material_ops);

void clear_policy_signing_execution_result(AgentQPolicySigningExecutionResult* result);

}  // namespace agent_q
