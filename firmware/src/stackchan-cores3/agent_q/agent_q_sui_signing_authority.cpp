#include "agent_q_sui_signing_authority.h"

#include <string.h>

namespace agent_q {

namespace {

AgentQSuiSigningActiveIdentityNetworkResult active_identity_error_to_network_result(
    AgentQSuiActiveIdentityError error)
{
    return error == AgentQSuiActiveIdentityError::native_account_unavailable
               ? AgentQSuiSigningActiveIdentityNetworkResult::account_unavailable
               : AgentQSuiSigningActiveIdentityNetworkResult::active_identity_unavailable;
}

}  // namespace

AgentQSuiSigningAccountBindingResult verify_sui_signing_active_account_binding(
    const SuiPolicySubjectFacts& facts,
    const AgentQSuiActiveIdentity& active_identity,
    const AgentQSuiAccountSettings& account_settings)
{
    if (active_identity.kind == AgentQSuiActiveIdentityKind::error) {
        return active_identity.error == AgentQSuiActiveIdentityError::native_account_unavailable
                   ? AgentQSuiSigningAccountBindingResult::account_unavailable
                   : AgentQSuiSigningAccountBindingResult::active_identity_unavailable;
    }
    const bool sender_matches = strcmp(facts.sender, active_identity.address) == 0;
    if (!sender_matches) {
        return AgentQSuiSigningAccountBindingResult::account_mismatch;
    }
    const bool gas_owner_matches = strcmp(facts.gas_owner, active_identity.address) == 0;
    if (gas_owner_matches || account_settings.accept_gas_sponsor) {
        return AgentQSuiSigningAccountBindingResult::ok;
    }
    return AgentQSuiSigningAccountBindingResult::account_mismatch;
}

AgentQSuiSigningActiveIdentityNetworkResult verify_sui_signing_active_identity_network(
    const AgentQSuiActiveIdentity& active_identity,
    const char* request_network)
{
    if (active_identity.kind == AgentQSuiActiveIdentityKind::error) {
        return active_identity_error_to_network_result(active_identity.error);
    }
    if (active_identity.kind == AgentQSuiActiveIdentityKind::zklogin) {
        if (request_network == nullptr || request_network[0] == '\0') {
            return AgentQSuiSigningActiveIdentityNetworkResult::network_mismatch;
        }
        return strcmp(active_identity.zklogin.network, request_network) == 0
                   ? AgentQSuiSigningActiveIdentityNetworkResult::ok
                   : AgentQSuiSigningActiveIdentityNetworkResult::network_mismatch;
    }
    return active_identity.kind == AgentQSuiActiveIdentityKind::native
               ? AgentQSuiSigningActiveIdentityNetworkResult::ok
               : AgentQSuiSigningActiveIdentityNetworkResult::active_identity_unavailable;
}

AgentQSuiSigningActiveIdentityNetworkResult verify_sui_signing_active_identity_network(
    const char* request_network)
{
    return verify_sui_signing_active_identity_network(
        resolve_active_sui_identity(),
        request_network);
}

}  // namespace agent_q
