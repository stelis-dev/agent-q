#include "agent_q_sign_transaction_policy_runtime.h"

#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_policy_store.h"
#include "agent_q_sign_route.h"
#include "agent_q_common/policy/agent_q_policy_runtime.h"
#include "agent_q_common/sui/agent_q_sui_method_adapter.h"

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
    const char* chain,
    const char* method,
    const char* payload_digest,
    const char* policy_hash,
    const char* rule_ref)
{
    if (result == nullptr) {
        return false;
    }
    return copy_runtime_string(result->chain, sizeof(result->chain), chain, true) &&
           copy_runtime_string(result->method, sizeof(result->method), method, true) &&
           copy_runtime_string(result->reason_code, sizeof(result->reason_code), code, true) &&
           copy_runtime_string(result->payload_digest, sizeof(result->payload_digest), payload_digest, true) &&
           copy_runtime_string(result->policy_hash, sizeof(result->policy_hash), policy_hash, true) &&
           copy_runtime_string(result->rule_ref, sizeof(result->rule_ref), rule_ref, true);
}

const char* policy_rule_ref(const AgentQPolicyDecision& decision)
{
    if (decision.reason == AgentQPolicyDecisionReason::matched_rule &&
        decision.rule_id != nullptr &&
        decision.rule_id[0] != '\0') {
        return decision.rule_id;
    }
    return "default";
}

AgentQSignTransactionPolicyRuntimeResult evaluate_sui_sign_transaction(
    const AgentQSuiPreparedSignTransaction& prepared)
{
    if (prepared.route != AgentQSupportedSignRoute::sui_sign_transaction ||
        prepared.tx_bytes_size == 0 ||
        prepared.payload_digest[0] == '\0') {
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::invalid_params,
            "invalid_params",
            "Prepared sui/sign_transaction request is invalid.");
    }

    AgentQSuiSignTransactionPolicyFacts policy_facts = {};
    if (!make_sui_sign_transaction_policy_facts(prepared.sui_transfer, &policy_facts)) {
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::unsupported_transaction,
            "unsupported_transaction",
            "Transaction shape is not supported.");
    }

    AgentQStoredPolicySummary policy_summary = {};
    if (!read_active_policy_summary(&policy_summary)) {
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::policy_error,
            "policy_error",
            "Active policy is unavailable.");
    }

    const AgentQPolicyDecision decision =
        evaluate_agent_q_policy_runtime(active_policy_provider(), policy_facts.facts);
    if (decision.reason == AgentQPolicyDecisionReason::invalid_policy) {
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::policy_error,
            "policy_error",
            "Active policy is unavailable.");
    }

    const char* rule_ref = policy_rule_ref(decision);
    if (decision.action != AgentQPolicyAction::sign) {
        AgentQSignTransactionPolicyRuntimeResult result = make_result(
            AgentQSignTransactionPolicyRuntimeStatus::policy_rejected,
            "policy_rejected",
            "The signing request was rejected by device policy.");
        if (!fill_sign_metadata(
                &result,
                "policy_rejected",
                "sui",
                "sign_transaction",
                prepared.payload_digest,
                policy_summary.policy_id,
                rule_ref)) {
            return make_result(
                AgentQSignTransactionPolicyRuntimeStatus::policy_error,
                "policy_error",
                "Active policy is unavailable.");
        }
        return result;
    }

    AgentQSignTransactionPolicyRuntimeResult result = make_result(
        AgentQSignTransactionPolicyRuntimeStatus::policy_authorized,
        "policy_signed",
        "Policy authorized signing.");
    if (!fill_sign_metadata(
            &result,
            "policy_signed",
            "sui",
            "sign_transaction",
            prepared.payload_digest,
            policy_summary.policy_id,
            rule_ref)) {
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::policy_error,
            "policy_error",
            "Active policy is unavailable.");
    }
    memcpy(result.tx_bytes, prepared.tx_bytes, prepared.tx_bytes_size);
    result.tx_bytes_size = prepared.tx_bytes_size;
    return result;
}

}  // namespace

AgentQSignTransactionPolicyRuntimeResult evaluate_sign_transaction_policy(
    const AgentQSuiPreparedSignTransaction& prepared)
{
    if (prepared.route == AgentQSupportedSignRoute::sui_sign_transaction) {
        return evaluate_sui_sign_transaction(prepared);
    }
    return make_result(
        AgentQSignTransactionPolicyRuntimeStatus::invalid_params,
        "unsupported_method",
        "Signing route is not supported by the transaction policy adapter.");
}

void clear_sign_transaction_policy_runtime_result(AgentQSignTransactionPolicyRuntimeResult* result)
{
    if (result == nullptr) {
        return;
    }
    wipe_sensitive_buffer(result->tx_bytes, sizeof(result->tx_bytes));
    memset(result, 0, sizeof(*result));
}

}  // namespace agent_q
