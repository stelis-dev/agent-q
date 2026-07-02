#pragma once

#include "document.h"
#include "sui/offline_policy_facts.h"

namespace signing {

enum class CurrentPolicyEvaluationStatus {
    invalid_argument,
    facts_incomplete,
    no_matching_scope,
    no_matching_policy,
    rejected,
    authorized,
};

struct CurrentPolicyEvaluationResult {
    CurrentPolicyEvaluationStatus status;
    const char* reason_code;
    const char* rule_ref;
};

CurrentPolicyEvaluationResult evaluate_current_policy_for_sui_sign_transaction(
    const CurrentPolicyDocument& policy,
    const char* network,
    const SuiOfflinePolicyConditionFacts& facts);

}  // namespace signing
