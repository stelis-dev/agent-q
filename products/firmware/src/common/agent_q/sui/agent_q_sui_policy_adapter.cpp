#include "agent_q_sui_policy_adapter.h"

#include <string.h>

namespace agent_q {
namespace {

constexpr const char* kSuiAsset = "0x2::sui::SUI";

bool string_present(const char* value)
{
    return value != nullptr && value[0] != '\0';
}

}  // namespace

bool make_sui_transfer_policy_facts(
    const SuiTransferFacts& sui_facts,
    const char* network,
    AgentQTransactionFacts* out)
{
    if (out == nullptr) {
        return false;
    }
    *out = {};

    if (!string_present(network) ||
        !string_present(sui_facts.recipient) ||
        !string_present(sui_facts.amount) ||
        !string_present(sui_facts.gas_budget) ||
        strcmp(sui_facts.asset, kSuiAsset) != 0 ||
        sui_facts.command_count != 2) {
        return false;
    }

    out->chain = kAgentQSuiPolicyChain;
    out->operation = kAgentQSuiPolicyOperationSignTransaction;
    out->network = network;
    out->kind = kAgentQSuiPolicyKindTransfer;
    out->recipient = sui_facts.recipient;
    out->amount = sui_facts.amount;
    out->gas_budget = sui_facts.gas_budget;
    return true;
}

}  // namespace agent_q
