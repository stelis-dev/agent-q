#pragma once

// Test-only entry point: the default-reject AgentQPolicyProvider used by host
// policy tests. Production code installs and reads the active policy from stored
// policy material, not via this accessor, so it is declared here rather than in
// the product header. Defined in agent_q_policy_runtime.cpp.
#include "agent_q_policy_runtime.h"

namespace agent_q {

AgentQPolicyProvider agent_q_default_reject_policy_provider();

}  // namespace agent_q
