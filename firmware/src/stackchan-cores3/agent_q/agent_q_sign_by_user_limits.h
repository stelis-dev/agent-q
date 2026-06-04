#pragma once

#include <stddef.h>

#include "agent_q_request_id.h"

namespace agent_q {

constexpr size_t kAgentQSignByUserIdSize = kAgentQRequestIdSize;
constexpr size_t kAgentQSignByUserChainSize = 33;
constexpr size_t kAgentQSignByUserMethodSize = 65;
constexpr size_t kAgentQSignByUserNetworkSize = 9;

}  // namespace agent_q
