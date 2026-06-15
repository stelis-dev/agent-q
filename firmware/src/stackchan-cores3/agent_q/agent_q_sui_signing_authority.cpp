#include "agent_q_sui_signing_authority.h"

#include <string.h>

#include "agent_q_sui_zklogin_proof_store.h"

namespace agent_q {

AgentQSuiSigningAccountBindingResult verify_sui_signing_active_account_binding(
    const SuiPolicySubjectFacts& facts)
{
    const AgentQSuiActiveIdentity active_identity = resolve_active_sui_identity();
    if (active_identity.kind == AgentQSuiActiveIdentityKind::error) {
        return active_identity.error == AgentQSuiActiveIdentityError::native_account_unavailable
                   ? AgentQSuiSigningAccountBindingResult::account_unavailable
                   : AgentQSuiSigningAccountBindingResult::active_identity_unavailable;
    }
    const bool matches =
        strcmp(facts.sender, active_identity.address) == 0 &&
        strcmp(facts.gas_owner, active_identity.address) == 0;
    return matches ? AgentQSuiSigningAccountBindingResult::ok
                   : AgentQSuiSigningAccountBindingResult::account_mismatch;
}

}  // namespace agent_q
