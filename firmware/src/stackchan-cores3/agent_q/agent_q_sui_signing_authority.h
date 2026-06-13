#pragma once

#include "agent_q_common/sui/agent_q_sui_transaction_facts.h"

namespace agent_q {

enum class AgentQSuiSigningAccountBindingResult {
    ok,
    account_unavailable,
    account_mismatch,
};

AgentQSuiSigningAccountBindingResult verify_sui_signing_stored_account_binding(
    const SuiPolicySubjectFacts& facts);

}  // namespace agent_q
