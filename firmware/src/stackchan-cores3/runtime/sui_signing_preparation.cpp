#include "sui_signing_preparation.h"

#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "bip39.h"
#include "sui_account_settings.h"
#include "sui_signing_authority.h"
#include "sui_zklogin_proof_store.h"
#include "sui/sign_transaction_adapter.h"

extern "C" {
#include "byte_conversions.h"
}

namespace signing {
namespace {

bool copy_network(const char* input, char* output, size_t output_size)
{
    if (input == nullptr || output == nullptr || output_size == 0) {
        return false;
    }
    memset(output, 0, output_size);
    size_t index = 0;
    while (input[index] != '\0') {
        if (index + 1 >= output_size) {
            memset(output, 0, output_size);
            return false;
        }
        output[index] = input[index];
        ++index;
    }
    return index > 0;
}

SuiSigningPreparationResult validate_encoded_payload_size(
    const char* base64,
    size_t caller_decoded_size,
    size_t max_base64_size,
    size_t max_decoded_size)
{
    size_t actual_decoded_size = 0;
    if (base64 == nullptr) {
        return SuiSigningPreparationResult::invalid_params;
    }
    if (strlen(base64) > max_base64_size) {
        return SuiSigningPreparationResult::payload_too_large;
    }
    if (!validate_canonical_base64_syntax(
            base64,
            max_base64_size,
            &actual_decoded_size)) {
        return SuiSigningPreparationResult::invalid_params;
    }
    if (actual_decoded_size > max_decoded_size) {
        return SuiSigningPreparationResult::payload_too_large;
    }
    if (actual_decoded_size != caller_decoded_size) {
        return SuiSigningPreparationResult::invalid_params;
    }
    return SuiSigningPreparationResult::ok;
}

void prepare_policy_condition_facts(SuiPreparedSignTransaction* out)
{
    if (out == nullptr ||
        out->tx_bytes == nullptr ||
        out->tx_bytes_size == 0) {
        return;
    }
    out->policy_mode_authorization_covered = false;
    out->policy_authorization_outcome = SuiPolicyAuthorizationOutcome::unavailable;
    out->sui_offline_policy_facts =
        static_cast<SuiOfflinePolicyConditionFacts*>(malloc(sizeof(SuiOfflinePolicyConditionFacts)));
    if (out->sui_offline_policy_facts == nullptr) {
        return;
    }
    memset(out->sui_offline_policy_facts, 0, sizeof(*out->sui_offline_policy_facts));
    const SuiTransactionFactsResult result =
        parse_sui_offline_policy_condition_facts(
            out->tx_bytes,
            out->tx_bytes_size,
            out->sui_offline_policy_facts);
    if (result == SuiTransactionFactsResult::ok &&
        out->sui_offline_policy_facts->valid_transaction_data &&
        out->sui_offline_policy_facts->completeness ==
            SuiOfflinePolicyFactsCompleteness::complete) {
        out->policy_mode_authorization_covered = true;
        out->policy_authorization_outcome =
            SuiPolicyAuthorizationOutcome::policy_evaluation;
    }
}

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

SuiSigningPreparationResult prepare_sui_sign_transaction_owned_common(
    SupportedSignRoute route,
    const char* network,
    uint8_t* tx_bytes,
    size_t tx_bytes_size,
    SuiPreparedSignTransaction* out)
{
    if (out == nullptr) {
        if (tx_bytes != nullptr) {
            wipe_sensitive_buffer(tx_bytes, tx_bytes_size);
            free(tx_bytes);
        }
        return SuiSigningPreparationResult::invalid_argument;
    }
    clear_prepared_sui_sign_transaction(out);
    if (route != SupportedSignRoute::sui_sign_transaction ||
        network == nullptr ||
        tx_bytes == nullptr ||
        tx_bytes_size == 0 ||
        tx_bytes_size > kSuiSignTransactionTxBytesMaxBytes) {
        if (tx_bytes != nullptr) {
            wipe_sensitive_buffer(tx_bytes, tx_bytes_size);
            free(tx_bytes);
        }
        return tx_bytes_size > kSuiSignTransactionTxBytesMaxBytes
                   ? SuiSigningPreparationResult::payload_too_large
                   : SuiSigningPreparationResult::invalid_argument;
    }

    out->route = route;
    out->tx_bytes = tx_bytes;
    out->tx_bytes_size = tx_bytes_size;
    if (!copy_network(network, out->network, sizeof(out->network))) {
        clear_prepared_sui_sign_transaction(out);
        return SuiSigningPreparationResult::invalid_argument;
    }
    if (!approval_history_digest_payload(
            out->tx_bytes,
            out->tx_bytes_size,
            out->payload_digest,
            sizeof(out->payload_digest))) {
        clear_prepared_sui_sign_transaction(out);
        return SuiSigningPreparationResult::digest_error;
    }
    SuiSignTransactionAuthorizationCoverage authorization_coverage = {};
    const SuiSignTransactionAdapterResult adapter_result =
        classify_sui_sign_transaction(
            out->tx_bytes,
            out->tx_bytes_size,
            &out->sui_policy_subject,
            &out->sui_review,
            &authorization_coverage);
    if (adapter_result != SuiSignTransactionAdapterResult::ok) {
        clear_prepared_sui_sign_transaction(out);
        return adapter_result ==
                       SuiSignTransactionAdapterResult::malformed_transaction
                   ? SuiSigningPreparationResult::malformed_transaction
                   : SuiSigningPreparationResult::unsupported_transaction;
    }
    out->user_mode_authorization_covered =
        authorization_coverage.user_mode_authorization_covered;
    out->policy_mode_authorization_covered =
        authorization_coverage.policy_mode_authorization_covered;
    out->user_authorization_outcome = authorization_coverage.user_outcome;
    out->policy_authorization_outcome = authorization_coverage.policy_outcome;
    const SuiActiveIdentity active_identity = resolve_active_sui_identity();
    SuiAccountSettings account_settings = kDefaultSuiAccountSettings;
    if (active_identity.kind != SuiActiveIdentityKind::error &&
        !read_sui_account_settings(&account_settings)) {
        clear_prepared_sui_sign_transaction(out);
        return SuiSigningPreparationResult::invalid_account;
    }
    const SuiSigningAccountBindingResult account_result =
        verify_sui_signing_active_account_binding(
            out->sui_policy_subject,
            active_identity,
            account_settings);
    if (account_result != SuiSigningAccountBindingResult::ok) {
        clear_prepared_sui_sign_transaction(out);
        switch (account_result) {
            case SuiSigningAccountBindingResult::account_unavailable:
                return SuiSigningPreparationResult::account_unavailable;
            case SuiSigningAccountBindingResult::active_identity_unavailable:
                return SuiSigningPreparationResult::active_identity_unavailable;
            case SuiSigningAccountBindingResult::account_mismatch:
            case SuiSigningAccountBindingResult::ok:
                return SuiSigningPreparationResult::invalid_account;
        }
        return SuiSigningPreparationResult::invalid_account;
    }
    const SuiSigningPreparationResult network_result =
        active_identity_network_result_to_preparation_result(
            verify_sui_signing_active_identity_network(active_identity, out->network));
    if (network_result != SuiSigningPreparationResult::ok) {
        clear_prepared_sui_sign_transaction(out);
        return network_result;
    }
    prepare_policy_condition_facts(out);
    return SuiSigningPreparationResult::ok;
}

}  // namespace

SuiSigningPreparationResult prepare_sui_sign_transaction(
    SupportedSignRoute route,
    const char* network,
    const char* tx_bytes_base64,
    size_t decoded_tx_size,
    SuiPreparedSignTransaction* out)
{
    if (out == nullptr) {
        return SuiSigningPreparationResult::invalid_argument;
    }
    clear_prepared_sui_sign_transaction(out);
    // Adapter boundary assertion: callers may reach this helper outside the
    // USB preflight path, so route mismatch must fail before decoding.
    if (route != SupportedSignRoute::sui_sign_transaction ||
        network == nullptr ||
        tx_bytes_base64 == nullptr ||
        decoded_tx_size == 0) {
        return SuiSigningPreparationResult::invalid_argument;
    }
    const SuiSigningPreparationResult size_result =
        validate_encoded_payload_size(
            tx_bytes_base64,
            decoded_tx_size,
            kSuiSignTransactionTxBytesMaxBase64Size,
            kSuiSignTransactionTxBytesMaxBytes);
    if (size_result != SuiSigningPreparationResult::ok) {
        return size_result;
    }
    uint8_t* tx_bytes = static_cast<uint8_t*>(malloc(decoded_tx_size));
    if (tx_bytes == nullptr) {
        return SuiSigningPreparationResult::payload_too_large;
    }
    memset(tx_bytes, 0, decoded_tx_size);
    if (base64_to_bytes(
            tx_bytes_base64,
            strlen(tx_bytes_base64),
            tx_bytes,
            decoded_tx_size) != 0) {
        wipe_sensitive_buffer(tx_bytes, decoded_tx_size);
        free(tx_bytes);
        return SuiSigningPreparationResult::invalid_params;
    }
    return prepare_sui_sign_transaction_owned_common(
        route,
        network,
        tx_bytes,
        decoded_tx_size,
        out);
}

SuiSigningPreparationResult prepare_sui_sign_personal_message(
    SupportedSignRoute route,
    const char* network,
    const char* message_base64,
    size_t decoded_message_size,
    SuiPreparedPersonalMessage* out)
{
    if (out == nullptr) {
        return SuiSigningPreparationResult::invalid_argument;
    }
    clear_prepared_sui_sign_personal_message(out);
    // Adapter boundary assertion: callers may reach this helper outside the
    // USB preflight path, so route mismatch must fail before decoding.
    if (route != SupportedSignRoute::sui_sign_personal_message ||
        network == nullptr ||
        message_base64 == nullptr ||
        decoded_message_size == 0) {
        return SuiSigningPreparationResult::invalid_argument;
    }
    const SuiSigningPreparationResult size_result =
        validate_encoded_payload_size(
            message_base64,
            decoded_message_size,
            kSuiSignPersonalMessageMaxBase64Size,
            kSuiSignPersonalMessageMaxBytes);
    if (size_result != SuiSigningPreparationResult::ok) {
        return size_result;
    }
    out->route = route;
    if (!copy_network(network, out->network, sizeof(out->network))) {
        clear_prepared_sui_sign_personal_message(out);
        return SuiSigningPreparationResult::invalid_argument;
    }
    if (base64_to_bytes(
            message_base64,
            strlen(message_base64),
            out->message,
            sizeof(out->message)) != 0) {
        clear_prepared_sui_sign_personal_message(out);
        return SuiSigningPreparationResult::invalid_params;
    }
    out->message_size = decoded_message_size;
    if (!approval_history_digest_payload(
            out->message,
            out->message_size,
            out->payload_digest,
            sizeof(out->payload_digest))) {
        clear_prepared_sui_sign_personal_message(out);
        return SuiSigningPreparationResult::digest_error;
    }
    const SuiActiveIdentity active_identity = resolve_active_sui_identity();
    if (active_identity.kind == SuiActiveIdentityKind::error) {
        clear_prepared_sui_sign_personal_message(out);
        return active_identity.error == SuiActiveIdentityError::native_account_unavailable
                   ? SuiSigningPreparationResult::account_unavailable
                   : SuiSigningPreparationResult::active_identity_unavailable;
    }
    if (active_identity.kind != SuiActiveIdentityKind::native &&
        active_identity.kind != SuiActiveIdentityKind::zklogin) {
        clear_prepared_sui_sign_personal_message(out);
        return SuiSigningPreparationResult::invalid_account;
    }
    const SuiSigningPreparationResult network_result =
        active_identity_network_result_to_preparation_result(
            verify_sui_signing_active_identity_network(active_identity, out->network));
    if (network_result != SuiSigningPreparationResult::ok) {
        clear_prepared_sui_sign_personal_message(out);
        return network_result;
    }
    memcpy(out->account_address, active_identity.address, sizeof(out->account_address));
    return SuiSigningPreparationResult::ok;
}

void clear_prepared_sui_sign_transaction(SuiPreparedSignTransaction* prepared)
{
    if (prepared == nullptr) {
        return;
    }
    if (prepared->tx_bytes != nullptr && prepared->tx_bytes_size > 0) {
        wipe_sensitive_buffer(prepared->tx_bytes, prepared->tx_bytes_size);
        free(prepared->tx_bytes);
    }
    if (prepared->sui_offline_policy_facts != nullptr) {
        wipe_sensitive_buffer(
            prepared->sui_offline_policy_facts,
            sizeof(*prepared->sui_offline_policy_facts));
        free(prepared->sui_offline_policy_facts);
    }
    memset(prepared, 0, sizeof(*prepared));
}

void clear_prepared_sui_sign_personal_message(SuiPreparedPersonalMessage* prepared)
{
    if (prepared == nullptr) {
        return;
    }
    wipe_sensitive_buffer(prepared->message, sizeof(prepared->message));
    memset(prepared, 0, sizeof(*prepared));
}

}  // namespace signing
