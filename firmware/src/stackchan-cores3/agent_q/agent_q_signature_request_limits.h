#pragma once

#include <stddef.h>

#include "agent_q_request_id.h"

namespace agent_q {

constexpr size_t kAgentQSignatureRequestIdSize = kAgentQRequestIdSize;
constexpr size_t kAgentQSignatureRequestChainSize = 33;
constexpr size_t kAgentQSignatureRequestMethodSize = 65;
constexpr size_t kAgentQSignatureRequestNetworkSize = 9;

}  // namespace agent_q
