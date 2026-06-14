#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_sui_transaction_facts.h"

namespace agent_q {

enum class AgentQSuiSignTransactionAdapterResult {
    ok,
    invalid_argument,
    malformed_transaction,
    unsupported_transaction,
};

enum class AgentQSuiUserAuthorizationOutcome {
    unavailable,
    offline_facts_review,
    blind_signing,
};

enum class AgentQSuiPolicyAuthorizationOutcome {
    unavailable,
    policy_evaluation,
};

struct AgentQSuiSignTransactionAuthorizationCoverage {
    bool user_mode_authorization_covered;
    bool policy_mode_authorization_covered;
    AgentQSuiUserAuthorizationOutcome user_outcome;
    AgentQSuiPolicyAuthorizationOutcome policy_outcome;
};

AgentQSuiSignTransactionAdapterResult classify_sui_sign_transaction(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    SuiPolicySubjectFacts* policy_subject_out,
    SuiReviewSummary* review_summary_out,
    AgentQSuiSignTransactionAuthorizationCoverage* coverage_out);

}  // namespace agent_q
