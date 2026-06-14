#pragma once

#include "agent_q_sui_token_flow_facts.h"
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
constexpr const char* kAgentQSuiPolicyCommandKindMergeCoins = "merge_coins";
constexpr size_t kAgentQSuiPolicyRequestNetworkSize = 9;
constexpr size_t kAgentQSuiSignTransactionPolicyFactCount = kAgentQPolicyMaxFacts;

struct AgentQSuiSignTransactionPolicySubject {
    SuiPolicySubjectFacts transaction;
    SuiTokenFlowFacts token_flow;
    char request_network[kAgentQSuiPolicyRequestNetworkSize];
};

struct AgentQSuiSignTransactionPolicyFacts {
    AgentQPolicyFact entries[kAgentQSuiSignTransactionPolicyFactCount];
    char command_count[kSuiU64StringBufferSize];
    char command_type_argument_counts[kSuiPolicyFactMaxCommands][kSuiU64StringBufferSize];
    char recipient_count[kSuiU64StringBufferSize];
    AgentQPolicyFacts facts;
};

bool build_sui_sign_transaction_policy_subject(
    const SuiParsedTransactionFacts& parsed,
    const char* request_network,
    AgentQSuiSignTransactionPolicySubject* out);

bool make_sui_sign_transaction_policy_facts(
    const AgentQSuiSignTransactionPolicySubject& subject,
    AgentQSuiSignTransactionPolicyFacts* out);

bool sui_sign_transaction_policy_authorization_covered(
    const SuiPolicySubjectFacts& transaction,
    const SuiTokenFlowFacts& token_flow);

bool sui_sign_transaction_policy_sign_rule_is_bounded(const AgentQPolicyRule& rule);
bool sui_sign_transaction_policy_build_sign_rule_summary(
    const AgentQPolicyRule& rule,
    char* output,
    size_t output_size);

AgentQPolicyMethodDescriptor sui_sign_transaction_policy_method_descriptor();

}  // namespace agent_q
