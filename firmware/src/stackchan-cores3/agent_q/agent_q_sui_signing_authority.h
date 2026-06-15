#pragma once

#include "agent_q_common/sui/agent_q_sui_transaction_facts.h"
#include "agent_q_sui_zklogin_proof_store.h"

namespace agent_q {

enum class AgentQSuiSigningAccountBindingResult {
    ok,
    account_unavailable,
    active_identity_unavailable,
    account_mismatch,
};

enum class AgentQSuiSigningActiveIdentityNetworkResult {
    ok,
    account_unavailable,
    active_identity_unavailable,
    network_mismatch,
};

AgentQSuiSigningAccountBindingResult verify_sui_signing_active_account_binding(
    const SuiPolicySubjectFacts& facts);
AgentQSuiSigningActiveIdentityNetworkResult verify_sui_signing_active_identity_network(
    const AgentQSuiActiveIdentity& active_identity,
    const char* request_network);
AgentQSuiSigningActiveIdentityNetworkResult verify_sui_signing_active_identity_network(
    const char* request_network);

}  // namespace agent_q
