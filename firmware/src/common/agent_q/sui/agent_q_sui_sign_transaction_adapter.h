#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_sui_transaction_facts.h"

namespace agent_q {

enum class AgentQSuiSignTransactionAdapterResult {
    ok,
    invalid_argument,
    malformed_transaction,
    unsupported_transaction,
};

AgentQSuiSignTransactionAdapterResult classify_sui_sign_transaction(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    SuiTransactionPolicyFacts* out);

}  // namespace agent_q
