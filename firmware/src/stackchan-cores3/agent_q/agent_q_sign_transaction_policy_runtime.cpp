#include "agent_q_sign_transaction_policy_runtime.h"

#include <string.h>

#include "agent_q_base64.h"
#include "agent_q_bip39.h"
#include "agent_q_json_input.h"
#include "agent_q_policy_store.h"
#include "agent_q_sui_signing_authority.h"
#include "agent_q_common/policy/agent_q_policy_runtime.h"
#include "agent_q_common/sui/agent_q_sui_method_adapter.h"
#include "agent_q_common/sui/agent_q_sui_transaction_facts.h"

extern "C" {
#include "byte_conversions.h"
}

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

bool supported_network(const char* network)
{
    return network != nullptr &&
           (strcmp(network, "mainnet") == 0 ||
            strcmp(network, "testnet") == 0 ||
            strcmp(network, "devnet") == 0 ||
            strcmp(network, "localnet") == 0);
}

bool params_fields_supported(JsonObjectConst params)
{
    for (JsonPairConst pair : params) {
        if (!agent_q_json_string_equals(pair.key(), "network") &&
            !agent_q_json_string_equals(pair.key(), "txBytes")) {
            return false;
        }
    }
    return true;
}

bool validate_sign_transaction_params(JsonVariant params, size_t* decoded_tx_size)
{
    if (decoded_tx_size != nullptr) {
        *decoded_tx_size = 0;
    }
    JsonObjectConst params_object = params.as<JsonObjectConst>();
    if (params_object.isNull() || !params_fields_supported(params_object)) {
        return false;
    }
    const char* network = nullptr;
    const char* tx_bytes_base64 = nullptr;
    if (!agent_q_json_value_c_string(params_object["network"], &network) ||
        !supported_network(network) ||
        !agent_q_json_value_c_string(params_object["txBytes"], &tx_bytes_base64)) {
        return false;
    }
    return validate_canonical_base64(
        tx_bytes_base64,
        kAgentQSuiSignTransactionTxBytesMaxBase64Size,
        kAgentQSuiSignTransactionTxBytesMaxBytes,
        decoded_tx_size);
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

AgentQSignTransactionPolicyRuntimeResult evaluate_sui_sign_transaction(JsonVariant params)
{
    size_t decoded_tx_size = 0;
    if (!validate_sign_transaction_params(params, &decoded_tx_size)) {
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::invalid_params,
            "invalid_params",
            "Invalid sui/sign_transaction params.");
    }

    const char* tx_bytes_base64 = nullptr;
    if (!agent_q_json_value_c_string(params["txBytes"], &tx_bytes_base64)) {
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::invalid_params,
            "invalid_params",
            "Invalid sui/sign_transaction params.");
    }

    uint8_t tx_bytes[kAgentQSuiSignTransactionTxBytesMaxBytes] = {};
    if (base64_to_bytes(tx_bytes_base64, strlen(tx_bytes_base64), tx_bytes, sizeof(tx_bytes)) != 0) {
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::invalid_params,
            "invalid_params",
            "Invalid sui/sign_transaction txBytes.");
    }

    char payload_digest[kAgentQApprovalHistoryDigestSize] = {};
    const bool digest_ready =
        approval_history_digest_payload(tx_bytes, decoded_tx_size, payload_digest, sizeof(payload_digest));

    SuiTransferFacts sui_facts = {};
    const SuiTransactionFactsResult parse_result =
        parse_sui_transfer_facts(tx_bytes, decoded_tx_size, &sui_facts);

    if (parse_result != SuiTransactionFactsResult::ok) {
        wipe_sensitive_buffer(tx_bytes, sizeof(tx_bytes));
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::unsupported_transaction,
            parse_result == SuiTransactionFactsResult::malformed
                ? "malformed_transaction"
                : "unsupported_transaction",
            parse_result == SuiTransactionFactsResult::malformed
                ? "Transaction bytes are malformed."
                : "Transaction shape is not supported.");
    }

    AgentQSuiSignTransactionPolicyFacts policy_facts = {};
    if (!make_sui_sign_transaction_policy_facts(sui_facts, &policy_facts) || !digest_ready) {
        wipe_sensitive_buffer(tx_bytes, sizeof(tx_bytes));
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::unsupported_transaction,
            "unsupported_transaction",
            "Transaction shape is not supported.");
    }

    const AgentQSuiSigningAccountBindingResult account_result =
        verify_sui_signing_stored_account_binding(sui_facts);
    if (account_result != AgentQSuiSigningAccountBindingResult::ok) {
        wipe_sensitive_buffer(tx_bytes, sizeof(tx_bytes));
        return account_result == AgentQSuiSigningAccountBindingResult::account_unavailable
                   ? make_result(
                         AgentQSignTransactionPolicyRuntimeStatus::account_unavailable,
                         "account_unavailable",
                         "Stored signing account is unavailable.")
                   : make_result(
                         AgentQSignTransactionPolicyRuntimeStatus::account_mismatch,
                         "invalid_account",
                         "Transaction sender or gas owner is not the device account.");
    }

    AgentQStoredPolicySummary policy_summary = {};
    if (!read_active_policy_summary(&policy_summary)) {
        wipe_sensitive_buffer(tx_bytes, sizeof(tx_bytes));
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::policy_error,
            "policy_error",
            "Active policy is unavailable.");
    }

    const AgentQPolicyDecision decision =
        evaluate_agent_q_policy_runtime(active_policy_provider(), policy_facts.facts);
    if (decision.reason == AgentQPolicyDecisionReason::invalid_policy) {
        wipe_sensitive_buffer(tx_bytes, sizeof(tx_bytes));
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
                payload_digest,
                policy_summary.policy_id,
                rule_ref)) {
            wipe_sensitive_buffer(tx_bytes, sizeof(tx_bytes));
            return make_result(
                AgentQSignTransactionPolicyRuntimeStatus::policy_error,
                "policy_error",
                "Active policy is unavailable.");
        }
        wipe_sensitive_buffer(tx_bytes, sizeof(tx_bytes));
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
            payload_digest,
            policy_summary.policy_id,
            rule_ref)) {
        wipe_sensitive_buffer(tx_bytes, sizeof(tx_bytes));
        return make_result(
            AgentQSignTransactionPolicyRuntimeStatus::policy_error,
            "policy_error",
            "Active policy is unavailable.");
    }
    memcpy(result.tx_bytes, tx_bytes, decoded_tx_size);
    result.tx_bytes_size = decoded_tx_size;
    wipe_sensitive_buffer(tx_bytes, sizeof(tx_bytes));
    return result;
}

}  // namespace

AgentQSignTransactionPolicyRuntimeResult evaluate_sign_transaction_policy(
    const char* chain,
    const char* method,
    JsonVariant params)
{
    if (chain != nullptr && method != nullptr &&
        strcmp(chain, "sui") == 0 && strcmp(method, "sign_transaction") == 0) {
        return evaluate_sui_sign_transaction(params);
    }

    return make_result(
        AgentQSignTransactionPolicyRuntimeStatus::invalid_params,
        "unsupported_method",
        "Method is not supported.");
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
