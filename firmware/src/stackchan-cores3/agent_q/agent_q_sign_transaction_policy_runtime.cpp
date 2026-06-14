#include "agent_q_sign_transaction_policy_runtime.h"

#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_policy_store.h"
#include "agent_q_sign_route.h"
#include "agent_q_common/policy/agent_q_policy_evaluator.h"

namespace agent_q {
namespace {

bool copy_runtime_string(char* output, size_t output_size, const char* value, bool required)
{
    if (output == nullptr || output_size == 0) {
        return false;
    }
    memset(output, 0, output_size);
    if (value == nullptr) {
        return !required;
    }
    size_t index = 0;
    while (value[index] != '\0') {
        if (index + 1 >= output_size) {
            memset(output, 0, output_size);
            return false;
        }
        output[index] = value[index];
        ++index;
    }
    if (required && index == 0) {
        memset(output, 0, output_size);
        return false;
    }
    output[index] = '\0';
    return true;
}

AgentQSignTransactionPolicyRuntimeResult make_result(
    AgentQSignTransactionPolicyRuntimeStatus status,
    const char* code,
    const char* message)
{
    AgentQSignTransactionPolicyRuntimeResult result = {};
    result.status = status;
    result.code = code;
    result.message = message;
    return result;
}

bool fill_sign_metadata(
    AgentQSignTransactionPolicyRuntimeResult* result,
    const char* code,
    AgentQSupportedSignRoute route,
    const char* payload_digest,
    const char* policy_hash,
    const char* rule_ref)
{
    if (result == nullptr) {
        return false;
    }
    return copy_runtime_string(result->chain, sizeof(result->chain), sign_route_wire_chain(route), true) &&
           copy_runtime_string(result->method, sizeof(result->method), sign_route_wire_method(route), true) &&
           copy_runtime_string(result->reason_code, sizeof(result->reason_code), code, true) &&
           copy_runtime_string(result->payload_digest, sizeof(result->payload_digest), payload_digest, true) &&
           copy_runtime_string(result->policy_hash, sizeof(result->policy_hash), policy_hash, true) &&
           copy_runtime_string(result->rule_ref, sizeof(result->rule_ref), rule_ref, true);
}

AgentQSignTransactionPolicyRuntimeResult make_policy_rejected_result(
    AgentQSupportedSignRoute route,
    const char* payload_digest,
    const char* policy_hash,
    const char* rule_ref,
    const char* reason_code)
{
    AgentQSignTransactionPolicyRuntimeResult result = make_result(
        AgentQSignTransactionPolicyRuntimeStatus::policy_rejected,
        "policy_rejected",
        "The signing request was rejected by device policy.");
    if (!fill_sign_metadata(
            &result,
            reason_code,
            route,
            payload_digest,
            policy_hash,
            rule_ref)) {
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::policy_error,
            "policy_error",
            "Active policy is unavailable.");
    }
    return result;
}

AgentQSignTransactionPolicyRuntimeResult make_policy_authorized_result(
    const AgentQSuiPreparedSignTransaction& prepared,
    const AgentQStoredPolicyDocument& policy,
    const char* rule_ref,
    const char* reason_code)
{
    AgentQSignTransactionPolicyRuntimeResult result = make_result(
        AgentQSignTransactionPolicyRuntimeStatus::policy_authorized,
        "policy_authorized",
        "Device policy authorized signing.");
    if (!fill_sign_metadata(
            &result,
            reason_code,
            prepared.route,
            prepared.payload_digest,
            policy.policy_id,
            rule_ref)) {
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::policy_error,
            "policy_error",
            "Active policy is unavailable.");
    }
    result.tx_bytes = prepared.tx_bytes;
    result.tx_bytes_size = prepared.tx_bytes_size;
    return result;
}

AgentQSignTransactionPolicyRuntimeResult policy_evaluation_result_to_runtime_result(
    const AgentQSuiPreparedSignTransaction& prepared,
    const AgentQStoredPolicyDocument& policy,
    const AgentQCurrentPolicyEvaluationResult& evaluation)
{
    const char* rule_ref =
        evaluation.rule_ref != nullptr && evaluation.rule_ref[0] != '\0'
            ? evaluation.rule_ref
            : "default";
    const char* reason_code =
        evaluation.reason_code != nullptr && evaluation.reason_code[0] != '\0'
            ? evaluation.reason_code
            : "policy_rejected";
    switch (evaluation.status) {
        case AgentQCurrentPolicyEvaluationStatus::authorized:
            return make_policy_authorized_result(
                prepared,
                policy,
                rule_ref,
                reason_code);
        case AgentQCurrentPolicyEvaluationStatus::invalid_argument:
            return make_policy_rejected_result(
                prepared.route,
                prepared.payload_digest,
                policy.policy_id,
                rule_ref,
                "invalid_policy");
        case AgentQCurrentPolicyEvaluationStatus::facts_incomplete:
        case AgentQCurrentPolicyEvaluationStatus::no_matching_scope:
        case AgentQCurrentPolicyEvaluationStatus::no_matching_policy:
        case AgentQCurrentPolicyEvaluationStatus::rejected:
            return make_policy_rejected_result(
                prepared.route,
                prepared.payload_digest,
                policy.policy_id,
                rule_ref,
                reason_code);
    }
    return make_policy_rejected_result(
        prepared.route,
        prepared.payload_digest,
        policy.policy_id,
        rule_ref,
        "policy_rejected");
}

AgentQSignTransactionPolicyRuntimeResult evaluate_sui_sign_transaction(
    const AgentQSuiPreparedSignTransaction& prepared)
{
    if (prepared.tx_bytes_size == 0 ||
        prepared.tx_bytes == nullptr ||
        prepared.payload_digest[0] == '\0') {
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::invalid_params,
            "invalid_params",
            "Prepared sui/sign_transaction request is invalid.");
    }
    if (!prepared.policy_mode_authorization_covered ||
        prepared.policy_authorization_outcome !=
            AgentQSuiPolicyAuthorizationOutcome::policy_evaluation ||
        prepared.sui_offline_policy_facts == nullptr) {
        AgentQStoredPolicySummary policy_summary = {};
        if (!read_active_policy_summary(&policy_summary)) {
            return make_result(
                AgentQSignTransactionPolicyRuntimeStatus::policy_error,
                "policy_error",
                "Active policy is unavailable.");
        }
        return make_policy_rejected_result(
            prepared.route,
            prepared.payload_digest,
            policy_summary.policy_id,
            "default",
            "policy_coverage_incomplete");
    }

    AgentQStoredPolicyDocument policy = {};
    if (!read_active_policy_document(&policy) ||
        policy.document == nullptr) {
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::policy_error,
            "policy_error",
            "Active policy is unavailable.");
    }
    const AgentQCurrentPolicyEvaluationResult evaluation =
        evaluate_agent_q_current_policy_for_sui_sign_transaction(
            *policy.document,
            prepared.network,
            *prepared.sui_offline_policy_facts);
    return policy_evaluation_result_to_runtime_result(
        prepared,
        policy,
        evaluation);
}

}  // namespace

AgentQSignTransactionPolicyRuntimeResult evaluate_sign_transaction_policy(
    const AgentQSuiPreparedSignTransaction& prepared)
{
    if (prepared.route == AgentQSupportedSignRoute::sui_sign_transaction) {
        return evaluate_sui_sign_transaction(prepared);
    }
    // Policy runtime is also a direct adapter boundary in host tests and
    // non-USB callers. Keep this fail-closed assertion even though USB preflight
    // normally selects the route first.
    return make_result(
        AgentQSignTransactionPolicyRuntimeStatus::unsupported_method,
        "unsupported_method",
        "Signing route is not supported by the transaction policy adapter.");
}

void clear_sign_transaction_policy_runtime_result(AgentQSignTransactionPolicyRuntimeResult* result)
{
    if (result == nullptr) {
        return;
    }
    memset(result, 0, sizeof(*result));
}

}  // namespace agent_q
