#pragma once

#include "agent_q_sui_transaction_facts.h"

#include "../policy/agent_q_policy_schema.h"
#include "../policy/agent_q_policy_v0.h"

namespace agent_q {

constexpr const char* kAgentQSuiPolicyChain = "sui";
constexpr const char* kAgentQSuiPolicyOperationSignTransaction = "sign_transaction";
constexpr const char* kAgentQPolicyIntentProgrammableTransaction = "programmable_transaction";
constexpr const char* kAgentQSuiPolicyCommandKindMoveCall = "move_call";
constexpr const char* kAgentQSuiPolicyCommandKindSplitCoins = "split_coins";
constexpr const char* kAgentQSuiPolicyCommandKindTransferObjects = "transfer_objects";
constexpr size_t kAgentQSuiSignTransactionPolicyFactCount = kAgentQPolicyMaxFacts;

struct AgentQSuiSignTransactionPolicyFacts {
    AgentQPolicyFact entries[kAgentQSuiSignTransactionPolicyFactCount];
    char command_count[kSuiU64StringBufferSize];
    char command_type_argument_counts[kSuiPolicyFactMaxCommands][kSuiU64StringBufferSize];
    AgentQPolicyFacts facts;
};

bool make_sui_sign_transaction_policy_facts(
    const SuiPolicySubjectFacts& sui_facts,
    AgentQSuiSignTransactionPolicyFacts* out);

AgentQPolicyMethodDescriptor sui_sign_transaction_policy_method_descriptor();

}  // namespace agent_q
