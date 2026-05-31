#include "agent_q_method_runtime.h"

#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_call_method_validation.h"
#include "agent_q_policy_store.h"
#include "agent_q_common/policy/agent_q_policy_runtime.h"
#include "agent_q_common/sui/agent_q_sui_policy_adapter.h"
#include "agent_q_common/sui/agent_q_sui_transaction_facts.h"

extern "C" {
#include "byte_conversions.h"
}

namespace agent_q {
namespace {

AgentQMethodRuntimeResult invalid_params(const char* message)
{
    return AgentQMethodRuntimeResult{
        AgentQMethodRuntimeStatus::invalid_params,
        "invalid_params",
        message,
    };
}

AgentQMethodRuntimeResult rejected(const char* code, const char* message)
{
    return AgentQMethodRuntimeResult{
        AgentQMethodRuntimeStatus::rejected,
        code,
        message,
    };
}

AgentQMethodRuntimeResult evaluate_sui_sign_transaction(JsonVariant params)
{
    size_t decoded_tx_size = 0;
    if (!validate_sui_sign_transaction_params(params, &decoded_tx_size)) {
        return invalid_params("Invalid sui/sign_transaction params.");
    }

    const char* network = params["network"].as<const char*>();
    const char* tx_bytes_base64 = params["txBytes"].as<const char*>();
    uint8_t tx_bytes[kSuiSignTransactionTxBytesMaxBytes] = {};
    if (base64_to_bytes(tx_bytes_base64, strlen(tx_bytes_base64), tx_bytes, sizeof(tx_bytes)) != 0) {
        return invalid_params("Invalid sui/sign_transaction txBytes.");
    }

    SuiTransferFacts sui_facts = {};
    const SuiTransactionFactsResult parse_result =
        parse_sui_transfer_facts(tx_bytes, decoded_tx_size, &sui_facts);
    wipe_sensitive_buffer(tx_bytes, sizeof(tx_bytes));

    if (parse_result == SuiTransactionFactsResult::malformed) {
        return rejected("malformed_transaction", "Transaction bytes are malformed.");
    }
    if (parse_result != SuiTransactionFactsResult::ok) {
        return rejected("unsupported_transaction", "Transaction shape is not supported.");
    }

    AgentQTransactionFacts policy_facts = {};
    if (!make_sui_transfer_policy_facts(sui_facts, network, &policy_facts)) {
        return rejected("unsupported_transaction", "Transaction shape is not supported.");
    }

    const AgentQPolicyDecision decision =
        evaluate_agent_q_policy_runtime(active_policy_provider(), policy_facts);
    if (decision.reason == AgentQPolicyDecisionReason::invalid_policy) {
        return rejected("policy_error", "Active policy is unavailable.");
    }
    if (decision.action == AgentQPolicyAction::reject) {
        return rejected("policy_rejected", "The request was rejected by device policy.");
    }

    return rejected("policy_action_not_implemented", "Policy action is not implemented.");
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

    return rejected("unsupported_method", "Method is not supported.");
}

}  // namespace agent_q
