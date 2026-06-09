#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_sign_route.h"

namespace agent_q {

constexpr size_t kAgentQSignRequestIdentitySize = 32;

bool sign_request_identity(
    AgentQSupportedSignRoute route,
    const char* network,
    const char* canonical_base64_payload,
    uint8_t* output,
    size_t output_size);

}  // namespace agent_q
