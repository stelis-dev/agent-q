#include "sui_signing_authority.h"

#include <string.h>

namespace signing {

namespace {

SuiSigningActiveIdentityNetworkResult active_identity_error_to_network_result(
    SuiActiveIdentityError error)
{
    return error == SuiActiveIdentityError::native_account_unavailable
               ? SuiSigningActiveIdentityNetworkResult::account_unavailable
               : SuiSigningActiveIdentityNetworkResult::active_identity_unavailable;
}

}  // namespace

SuiSigningAccountBindingResult verify_sui_signing_active_account_binding(
    const SuiPolicySubjectFacts& facts,
    const SuiActiveIdentity& active_identity,
    const SuiAccountSettings& account_settings)
{
    if (active_identity.kind == SuiActiveIdentityKind::error) {
        return active_identity.error == SuiActiveIdentityError::native_account_unavailable
                   ? SuiSigningAccountBindingResult::account_unavailable
                   : SuiSigningAccountBindingResult::active_identity_unavailable;
    }
    const bool sender_matches = strcmp(facts.sender, active_identity.address) == 0;
    if (!sender_matches) {
        return SuiSigningAccountBindingResult::account_mismatch;
    }
    const bool gas_owner_matches = strcmp(facts.gas_owner, active_identity.address) == 0;
    if (gas_owner_matches || account_settings.accept_gas_sponsor) {
        return SuiSigningAccountBindingResult::ok;
    }
    return SuiSigningAccountBindingResult::account_mismatch;
}

SuiSigningActiveIdentityNetworkResult verify_sui_signing_active_identity_network(
    const SuiActiveIdentity& active_identity,
    const char* request_network)
{
    if (active_identity.kind == SuiActiveIdentityKind::error) {
        return active_identity_error_to_network_result(active_identity.error);
    }
    if (active_identity.kind == SuiActiveIdentityKind::zklogin) {
        if (request_network == nullptr || request_network[0] == '\0') {
            return SuiSigningActiveIdentityNetworkResult::network_mismatch;
        }
        return strcmp(active_identity.zklogin.network, request_network) == 0
                   ? SuiSigningActiveIdentityNetworkResult::ok
                   : SuiSigningActiveIdentityNetworkResult::network_mismatch;
    }
    return active_identity.kind == SuiActiveIdentityKind::native
               ? SuiSigningActiveIdentityNetworkResult::ok
               : SuiSigningActiveIdentityNetworkResult::active_identity_unavailable;
}

SuiSigningActiveIdentityNetworkResult verify_sui_signing_active_identity_network(
    const char* request_network)
{
    return verify_sui_signing_active_identity_network(
        resolve_active_sui_identity(),
        request_network);
}

}  // namespace signing
