#pragma once

#include <stddef.h>
#include <stdint.h>

#include "protocol/approval_history.h"
#include "sui/zklogin_signature.h"
#include "signing/user_signing_flow.h"

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

void clear_policy_signing_execution_result(PolicySigningExecutionResult* result);

}  // namespace signing
