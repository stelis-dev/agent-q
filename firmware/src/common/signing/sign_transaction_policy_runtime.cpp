#include "signing/sign_transaction_policy_runtime.h"

#include <string.h>

#include "policy/policy_store.h"
#include "protocol/sign_route.h"
#include "policy/evaluator.h"

namespace signing {
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

SignTransactionPolicyRuntimeResult make_result(
    SignTransactionPolicyRuntimeStatus status,
    const char* code,
    const char* message)
{
    SignTransactionPolicyRuntimeResult result = {};
    result.status = status;
    result.code = code;
    result.message = message;
    return result;
}

bool fill_sign_metadata(
    SignTransactionPolicyRuntimeResult* result,
    const char* code,
    SupportedSignRoute route,
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

SignTransactionPolicyRuntimeResult make_policy_rejected_result(
    SupportedSignRoute route,
    const char* payload_digest,
    const char* policy_hash,
    const char* rule_ref,
    const char* reason_code)
{
    SignTransactionPolicyRuntimeResult result = make_result(
        SignTransactionPolicyRuntimeStatus::policy_rejected,
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
            SignTransactionPolicyRuntimeStatus::policy_error,
            "policy_unavailable",
            "Active policy is unavailable.");
    }
    return result;
}

SignTransactionPolicyRuntimeResult make_policy_authorized_result(
    const SuiPreparedSignTransaction& prepared,
    const StoredPolicyDocument& policy,
    const char* rule_ref,
    const char* reason_code)
{
    SignTransactionPolicyRuntimeResult result = make_result(
        SignTransactionPolicyRuntimeStatus::policy_authorized,
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
            SignTransactionPolicyRuntimeStatus::policy_error,
            "policy_unavailable",
            "Active policy is unavailable.");
    }
    result.tx_bytes = prepared.tx_bytes;
    result.tx_bytes_size = prepared.tx_bytes_size;
    return result;
}

SignTransactionPolicyRuntimeResult policy_evaluation_result_to_runtime_result(
    const SuiPreparedSignTransaction& prepared,
    const StoredPolicyDocument& policy,
    const CurrentPolicyEvaluationResult& evaluation)
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
        case CurrentPolicyEvaluationStatus::authorized:
            return make_policy_authorized_result(
                prepared,
                policy,
                rule_ref,
                reason_code);
        case CurrentPolicyEvaluationStatus::invalid_argument:
            return make_policy_rejected_result(
                prepared.route,
                prepared.payload_digest,
                policy.policy_id,
                rule_ref,
                "invalid_policy");
        case CurrentPolicyEvaluationStatus::facts_incomplete:
        case CurrentPolicyEvaluationStatus::no_matching_scope:
        case CurrentPolicyEvaluationStatus::no_matching_policy:
        case CurrentPolicyEvaluationStatus::rejected:
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

SignTransactionPolicyRuntimeResult evaluate_sui_sign_transaction(
    const SuiPreparedSignTransaction& prepared)
{
    if (prepared.tx_bytes_size == 0 ||
        prepared.tx_bytes == nullptr ||
        prepared.payload_digest[0] == '\0') {
        return make_result(
            SignTransactionPolicyRuntimeStatus::invalid_params,
            "invalid_params",
            "Prepared sui/sign_transaction request is invalid.");
    }
    if (!prepared.policy_mode_authorization_covered ||
        prepared.policy_authorization_outcome !=
            SuiPolicyAuthorizationOutcome::policy_evaluation ||
        prepared.sui_offline_policy_facts == nullptr) {
        StoredPolicySummary policy_summary = {};
        if (!read_active_policy_summary(&policy_summary)) {
            return make_result(
                SignTransactionPolicyRuntimeStatus::policy_error,
                "policy_unavailable",
                "Active policy is unavailable.");
        }
        return make_policy_rejected_result(
            prepared.route,
            prepared.payload_digest,
            policy_summary.policy_id,
            "default",
            "policy_coverage_incomplete");
    }

    StoredPolicyDocument policy = {};
    if (!read_active_policy_document(&policy) ||
        policy.document == nullptr) {
        return make_result(
            SignTransactionPolicyRuntimeStatus::policy_error,
            "policy_unavailable",
            "Active policy is unavailable.");
    }
    const CurrentPolicyEvaluationResult evaluation =
        evaluate_current_policy_for_sui_sign_transaction(
            *policy.document,
            prepared.network,
            *prepared.sui_offline_policy_facts);
    return policy_evaluation_result_to_runtime_result(
        prepared,
        policy,
        evaluation);
}

}  // namespace

SignTransactionPolicyRuntimeResult evaluate_sign_transaction_policy(
    const SuiPreparedSignTransaction& prepared)
{
    if (prepared.route == SupportedSignRoute::sui_sign_transaction) {
        return evaluate_sui_sign_transaction(prepared);
    }
    // Policy runtime is also a direct adapter boundary in host tests and
    // non-USB callers. Keep this fail-closed assertion even though USB preflight
    // normally selects the route first.
    return make_result(
        SignTransactionPolicyRuntimeStatus::unsupported_method,
        "unsupported_method",
        "Signing route is not supported by the transaction policy adapter.");
}

void clear_sign_transaction_policy_runtime_result(SignTransactionPolicyRuntimeResult* result)
{
    if (result == nullptr) {
        return;
    }
    memset(result, 0, sizeof(*result));
}

}  // namespace signing
