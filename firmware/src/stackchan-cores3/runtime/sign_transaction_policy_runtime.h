#pragma once

#include "protocol/approval_history.h"
#include "protocol/sign_route.h"
#include "sui/signing_limits.h"
#include "sui_signing_preparation.h"
#include "user_signing_limits.h"

namespace signing {

enum class SignTransactionPolicyRuntimeStatus {
    invalid_params,
    unsupported_method,
    unsupported_transaction,
    account_unavailable,
    account_mismatch,
    policy_error,
    policy_rejected,
    policy_authorized,
};

struct SignTransactionPolicyRuntimeResult {
    SignTransactionPolicyRuntimeStatus status;
    const char* code;
    const char* message;
    char chain[kApprovalHistoryChainSize];
    char method[kApprovalHistoryMethodSize];
    char reason_code[kApprovalHistoryReasonCodeSize];
    char payload_digest[kApprovalHistoryDigestSize];
    char policy_hash[kApprovalHistoryDigestSize];
    char rule_ref[kApprovalHistoryRuleRefSize];
    const uint8_t* tx_bytes;
    size_t tx_bytes_size;
};

SignTransactionPolicyRuntimeResult evaluate_sign_transaction_policy(
    const SuiPreparedSignTransaction& prepared);
void clear_sign_transaction_policy_runtime_result(SignTransactionPolicyRuntimeResult* result);

}  // namespace signing
