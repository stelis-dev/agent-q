#pragma once

#include "agent_q_sui_transaction_facts.h"

#include "../policy/agent_q_policy_v0.h"

namespace agent_q {

constexpr const char* kAgentQSuiPolicyChain = "sui";
constexpr const char* kAgentQSuiPolicyOperationSignTransaction = "sign_transaction";
constexpr const char* kAgentQSuiPolicyKindTransfer = "transfer";

bool make_sui_transfer_policy_facts(
    const SuiTransferFacts& sui_facts,
    const char* network,
    AgentQTransactionFacts* out);

}  // namespace agent_q
