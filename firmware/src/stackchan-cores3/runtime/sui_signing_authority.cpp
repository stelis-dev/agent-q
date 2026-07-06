#include "sui_signing_authority.h"

#include <string.h>

#include "sui/account_binding.h"

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
    const SuiTransactionAccountBindingResult binding =
        verify_sui_transaction_account_binding(
            facts,
            active_identity.address,
            account_settings.accept_gas_sponsor);
    return binding == SuiTransactionAccountBindingResult::ok
               ? SuiSigningAccountBindingResult::ok
               : SuiSigningAccountBindingResult::account_mismatch;
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
