#include "agent_q_sui_signing_authority.h"

#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_sui_account_store.h"

namespace agent_q {

AgentQSuiSigningAccountBindingResult verify_sui_signing_stored_account_binding(
    const SuiTransactionPolicyFacts& facts)
{
    uint8_t public_key[kSuiEd25519PublicKeyBytes] = {};
    char stored_address[kSuiAddressBufferSize] = {};
    const SuiAccountDerivationResult result =
        derive_sui_ed25519_account_from_stored_root(
            public_key,
            stored_address,
            sizeof(stored_address));
    wipe_sensitive_buffer(public_key, sizeof(public_key));
    if (result != SuiAccountDerivationResult::ok) {
        memset(stored_address, 0, sizeof(stored_address));
        return AgentQSuiSigningAccountBindingResult::account_unavailable;
    }
    const bool matches =
        strcmp(facts.sender, stored_address) == 0 &&
        strcmp(facts.gas_owner, stored_address) == 0;
    memset(stored_address, 0, sizeof(stored_address));
    return matches ? AgentQSuiSigningAccountBindingResult::ok
                   : AgentQSuiSigningAccountBindingResult::account_mismatch;
}

}  // namespace agent_q
