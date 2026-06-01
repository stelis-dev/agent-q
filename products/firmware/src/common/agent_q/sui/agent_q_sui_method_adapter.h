#pragma once

#include "agent_q_sui_transaction_facts.h"

#include "../policy/agent_q_policy_v0.h"

namespace agent_q {

constexpr const char* kAgentQSuiPolicyChain = "sui";
constexpr const char* kAgentQSuiPolicyOperationSignTransaction = "sign_transaction";
constexpr const char* kAgentQPolicyIntentSingleAssetTransfer = "single_asset_transfer";
constexpr const char* kAgentQSuiPolicyCommandShapeRestrictedTransfer = "restricted_transfer";
constexpr size_t kAgentQSuiTransferPolicyFactCount = 11;

struct AgentQSuiSignTransactionPolicyFacts {
    AgentQPolicyFact entries[kAgentQSuiTransferPolicyFactCount];
    AgentQPolicyFacts facts;
};

bool make_sui_sign_transaction_policy_facts(
    const SuiTransferFacts& sui_facts,
    const char* network,
    AgentQSuiSignTransactionPolicyFacts* out);

}  // namespace agent_q
