#pragma once

#include "agent_q_common/sui/agent_q_sui_transaction_facts.h"

namespace agent_q {

enum class AgentQSuiSigningAccountBindingResult {
    ok,
    account_unavailable,
    account_mismatch,
};

AgentQSuiSigningAccountBindingResult verify_sui_signing_stored_account_binding(
    const SuiTransferFacts& facts);

const char* sui_signing_account_binding_result_name(
    AgentQSuiSigningAccountBindingResult result);

}  // namespace agent_q
