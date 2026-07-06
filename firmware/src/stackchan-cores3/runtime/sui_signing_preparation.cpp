#include "sui_signing_preparation.h"

#include <string.h>

#include "sui/signing_preparation.h"
#include "sui_account_settings.h"
#include "sui_signing_authority.h"
#include "sui_zklogin_proof_store.h"

namespace signing {
namespace {

SuiSigningPreparationResult active_identity_network_result_to_preparation_result(
    SuiSigningActiveIdentityNetworkResult result)
{
    switch (result) {
        case SuiSigningActiveIdentityNetworkResult::ok:
            return SuiSigningPreparationResult::ok;
        case SuiSigningActiveIdentityNetworkResult::account_unavailable:
            return SuiSigningPreparationResult::account_unavailable;
        case SuiSigningActiveIdentityNetworkResult::active_identity_unavailable:
            return SuiSigningPreparationResult::active_identity_unavailable;
        case SuiSigningActiveIdentityNetworkResult::network_mismatch:
        default:
            return SuiSigningPreparationResult::invalid_network;
    }
}

SuiSigningPreparationResult account_binding_result_to_preparation_result(
    SuiSigningAccountBindingResult result)
{
    switch (result) {
        case SuiSigningAccountBindingResult::ok:
            return SuiSigningPreparationResult::ok;
        case SuiSigningAccountBindingResult::account_unavailable:
            return SuiSigningPreparationResult::account_unavailable;
        case SuiSigningAccountBindingResult::active_identity_unavailable:
            return SuiSigningPreparationResult::active_identity_unavailable;
        case SuiSigningAccountBindingResult::account_mismatch:
        default:
            return SuiSigningPreparationResult::invalid_account;
    }
}

SuiSigningPreparationResult check_stackchan_transaction_account(
    const SuiPolicySubjectFacts& facts,
    const char* network,
    void*)
{
    const SuiActiveIdentity active_identity = resolve_active_sui_identity();
    SuiAccountSettings account_settings = kDefaultSuiAccountSettings;
    if (active_identity.kind != SuiActiveIdentityKind::error &&
        !read_sui_account_settings(&account_settings)) {
        return SuiSigningPreparationResult::invalid_account;
    }
    const SuiSigningPreparationResult account_result =
        account_binding_result_to_preparation_result(
            verify_sui_signing_active_account_binding(
                facts,
                active_identity,
                account_settings));
    if (account_result != SuiSigningPreparationResult::ok) {
        return account_result;
    }
    return active_identity_network_result_to_preparation_result(
        verify_sui_signing_active_identity_network(active_identity, network));
}

SuiSigningPreparationResult check_stackchan_personal_message_account(
    const char* network,
    char account_address[kSuiAddressStringBufferSize],
    void*)
{
    const SuiActiveIdentity active_identity = resolve_active_sui_identity();
    if (active_identity.kind == SuiActiveIdentityKind::error) {
        return active_identity.error == SuiActiveIdentityError::native_account_unavailable
                   ? SuiSigningPreparationResult::account_unavailable
                   : SuiSigningPreparationResult::active_identity_unavailable;
    }
    if (active_identity.kind != SuiActiveIdentityKind::native &&
        active_identity.kind != SuiActiveIdentityKind::zklogin) {
        return SuiSigningPreparationResult::invalid_account;
    }
    const SuiSigningPreparationResult network_result =
        active_identity_network_result_to_preparation_result(
            verify_sui_signing_active_identity_network(active_identity, network));
    if (network_result != SuiSigningPreparationResult::ok) {
        return network_result;
    }
    memcpy(account_address, active_identity.address, kSuiAddressStringBufferSize);
    return SuiSigningPreparationResult::ok;
}

constexpr SuiSigningPreparationOps kStackChanSigningPreparationOps{
    check_stackchan_transaction_account,
    check_stackchan_personal_message_account,
    nullptr,
};

}  // namespace

SuiSigningPreparationResult prepare_sui_sign_transaction(
    SupportedSignRoute route,
    const char* network,
    const char* tx_bytes_base64,
    size_t decoded_tx_size,
    SuiPreparedSignTransaction* out)
{
    return prepare_sui_sign_transaction_base64(
        route,
        network,
        tx_bytes_base64,
        decoded_tx_size,
        kStackChanSigningPreparationOps,
        out);
}

SuiSigningPreparationResult prepare_sui_sign_personal_message(
    SupportedSignRoute route,
    const char* network,
    const char* message_base64,
    size_t decoded_message_size,
    SuiPreparedPersonalMessage* out)
{
    return prepare_sui_sign_personal_message_base64(
        route,
        network,
        message_base64,
        decoded_message_size,
        kStackChanSigningPreparationOps,
        out);
}

void clear_prepared_sui_sign_transaction(SuiPreparedSignTransaction* prepared)
{
    clear_sui_prepared_sign_transaction(prepared);
}

void clear_prepared_sui_sign_personal_message(SuiPreparedPersonalMessage* prepared)
{
    clear_sui_prepared_personal_message(prepared);
}

}  // namespace signing
