#pragma once

#include <stddef.h>
#include <stdint.h>

#include "approval_history.h"
#include "persistent_material.h"
#include "sign_transaction_policy_runtime.h"
#include "signing_route.h"
#include "sui_signing_service.h"

namespace signing {

enum class PolicySigningExecutionStatus {
    request_error,
    policy_rejected,
    history_error,
    account_error,
    signing_failed,
    signed_success,
};

struct PolicySigningExecutionResult {
    PolicySigningExecutionStatus status;
    Route signing_route;
    const char* code;
    const char* message;
    char policy_hash[kApprovalHistoryDigestSize];
    char rule_ref[kApprovalHistoryRuleRefSize];
    uint8_t signature[kSuiSignatureEnvelopeMaxBytes];
    size_t signature_size;
};

PolicySigningExecutionResult execute_policy_sign_transaction(
    const SignTransactionPolicyRuntimeResult& policy_result,
    const PersistentMaterialOps& material_ops);

void clear_policy_signing_execution_result(PolicySigningExecutionResult* result);

}  // namespace signing
