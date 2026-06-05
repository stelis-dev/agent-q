#pragma once

#include <stddef.h>

#include "agent_q_request_id.h"

namespace agent_q {

constexpr size_t kAgentQSignTransactionUserIdSize = kAgentQRequestIdSize;
constexpr size_t kAgentQSignTransactionUserChainSize = 33;
constexpr size_t kAgentQSignTransactionUserMethodSize = 65;
constexpr size_t kAgentQSignTransactionUserNetworkSize = 9;

}  // namespace agent_q
