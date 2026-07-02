#pragma once

#include <stddef.h>
#include <stdint.h>

#include "transaction_facts.h"

namespace signing {

enum class SuiSignTransactionAdapterResult {
    ok,
    invalid_argument,
    malformed_transaction,
    unsupported_transaction,
};

enum class SuiUserAuthorizationOutcome {
    unavailable,
    offline_facts_review,
    blind_signing,
};

enum class SuiPolicyAuthorizationOutcome {
    unavailable,
    policy_evaluation,
};

struct SuiSignTransactionAuthorizationCoverage {
    bool user_mode_authorization_covered;
    bool policy_mode_authorization_covered;
    SuiUserAuthorizationOutcome user_outcome;
    SuiPolicyAuthorizationOutcome policy_outcome;
};

SuiSignTransactionAdapterResult classify_sui_sign_transaction(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    SuiPolicySubjectFacts* policy_subject_out,
    SuiReviewSummary* review_summary_out,
    SuiSignTransactionAuthorizationCoverage* coverage_out);

}  // namespace signing
