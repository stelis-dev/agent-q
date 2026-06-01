#include "agent_q_method_runtime.h"

#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_call_method_validation.h"
#include "agent_q_json_input.h"
#include "agent_q_policy_store.h"
#include "agent_q_common/policy/agent_q_policy_runtime.h"
#include "agent_q_common/sui/agent_q_sui_method_adapter.h"
#include "agent_q_common/sui/agent_q_sui_transaction_facts.h"

extern "C" {
#include "byte_conversions.h"
}

namespace agent_q {
namespace {

bool copy_runtime_history_string(char* output, size_t output_size, const char* value, bool required)
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

AgentQMethodRuntimeResult invalid_params(const char* message)
{
    return AgentQMethodRuntimeResult{
        AgentQMethodRuntimeStatus::invalid_params,
        "invalid_params",
        message,
        false,
        {},
    };
}

AgentQMethodRuntimeResult rejected(const char* code, const char* message)
{
    return AgentQMethodRuntimeResult{
        AgentQMethodRuntimeStatus::rejected,
        code,
        message,
        false,
        {},
    };
}

AgentQMethodRuntimeResult rejected_with_history(
    const char* code,
    const char* message,
    AgentQApprovalHistoryDecision decision,
    AgentQApprovalHistoryConfirmationKind confirmation_kind,
    const char* chain,
    const char* method,
    const char* payload_digest,
    const char* policy_hash,
    const char* rule_ref)
{
    AgentQMethodRuntimeResult result = rejected(code, message);
    result.has_approval_history = true;
    result.approval_history.decision = decision;
    result.approval_history.confirmation_kind = confirmation_kind;
    if (!copy_runtime_history_string(result.approval_history.chain, sizeof(result.approval_history.chain), chain, true) ||
        !copy_runtime_history_string(result.approval_history.method, sizeof(result.approval_history.method), method, true) ||
        !copy_runtime_history_string(result.approval_history.reason_code, sizeof(result.approval_history.reason_code), code, true) ||
        !copy_runtime_history_string(result.approval_history.payload_digest, sizeof(result.approval_history.payload_digest), payload_digest, false) ||
        !copy_runtime_history_string(result.approval_history.policy_hash, sizeof(result.approval_history.policy_hash), policy_hash, false) ||
        !copy_runtime_history_string(result.approval_history.rule_ref, sizeof(result.approval_history.rule_ref), rule_ref, false)) {
        memset(&result.approval_history, 0, sizeof(result.approval_history));
        result.has_approval_history = true;
    }
    return result;
}

AgentQMethodRuntimeResult evaluate_sui_sign_transaction(JsonVariant params)
{
    size_t decoded_tx_size = 0;
    if (!validate_sui_sign_transaction_params(params, &decoded_tx_size)) {
        return invalid_params("Invalid sui/sign_transaction params.");
    }

    const char* network = nullptr;
    const char* tx_bytes_base64 = nullptr;
    if (!agent_q_json_value_c_string(params["network"], &network) ||
        !agent_q_json_value_c_string(params["txBytes"], &tx_bytes_base64)) {
        return invalid_params("Invalid sui/sign_transaction params.");
    }
    uint8_t tx_bytes[kSuiSignTransactionTxBytesMaxBytes] = {};
    if (base64_to_bytes(tx_bytes_base64, strlen(tx_bytes_base64), tx_bytes, sizeof(tx_bytes)) != 0) {
        return invalid_params("Invalid sui/sign_transaction txBytes.");
    }

    char payload_digest[agent_q::kAgentQApprovalHistoryDigestSize] = {};
    const bool digest_ready =
        approval_history_digest_payload(tx_bytes, decoded_tx_size, payload_digest, sizeof(payload_digest));

    SuiTransferFacts sui_facts = {};
    const SuiTransactionFactsResult parse_result =
        parse_sui_transfer_facts(tx_bytes, decoded_tx_size, &sui_facts);
    wipe_sensitive_buffer(tx_bytes, sizeof(tx_bytes));

    if (parse_result == SuiTransactionFactsResult::malformed) {
        return rejected(
            "malformed_transaction",
            "Transaction bytes are malformed.");
    }
    if (parse_result != SuiTransactionFactsResult::ok) {
        return rejected(
            "unsupported_transaction",
            "Transaction shape is not supported.");
    }

    AgentQSuiSignTransactionPolicyFacts policy_facts = {};
    if (!make_sui_sign_transaction_policy_facts(sui_facts, network, &policy_facts)) {
        return rejected(
            "unsupported_transaction",
            "Transaction shape is not supported.");
    }

    AgentQStoredPolicySummary policy_summary = {};
    const bool policy_summary_ready = read_active_policy_summary(&policy_summary);
    const AgentQPolicyDecision decision =
        evaluate_agent_q_policy_runtime(active_policy_provider(), policy_facts.facts);
    if (decision.reason == AgentQPolicyDecisionReason::invalid_policy) {
        return rejected(
            "policy_error",
            "Active policy is unavailable.");
    }
    if (decision.action == AgentQPolicyAction::reject) {
        const char* rule_ref = "default";
        if (decision.reason == AgentQPolicyDecisionReason::matched_rule &&
            decision.rule_id != nullptr &&
            decision.rule_id[0] != '\0') {
            rule_ref = decision.rule_id;
        }
        return rejected_with_history(
            "policy_rejected",
            "The request was rejected by device policy.",
            AgentQApprovalHistoryDecision::policy_rejected,
            AgentQApprovalHistoryConfirmationKind::policy,
            "sui",
            "sign_transaction",
            digest_ready ? payload_digest : nullptr,
            policy_summary_ready ? policy_summary.policy_id : nullptr,
            rule_ref);
    }

    return rejected(
        "policy_action_not_implemented",
        "Policy action is not implemented.");
}

}  // namespace

AgentQMethodRuntimeResult evaluate_call_method(
    const char* chain,
    const char* method,
    JsonVariant params)
{
    if (chain != nullptr && method != nullptr &&
        strcmp(chain, "sui") == 0 && strcmp(method, "sign_transaction") == 0) {
        return evaluate_sui_sign_transaction(params);
    }

    return rejected(
        "unsupported_method",
        "Method is not supported.");
}

}  // namespace agent_q
