#include "sui/signing_preparation.h"

#include <stdlib.h>
#include <string.h>

#include "protocol/base64.h"
#include "sui/sign_transaction_adapter.h"

extern "C" {
#include "byte_conversions.h"
}

namespace signing {
namespace {

void wipe_buffer(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

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
        static_cast<SuiOfflinePolicyConditionFacts*>(
            malloc(sizeof(SuiOfflinePolicyConditionFacts)));
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

}  // namespace

SuiSigningPreparationResult prepare_sui_sign_transaction_owned(
    SupportedSignRoute route,
    const char* network,
    uint8_t* tx_bytes,
    size_t tx_bytes_size,
    const SuiSigningPreparationOps& ops,
    SuiPreparedSignTransaction* out)
{
    if (out == nullptr) {
        if (tx_bytes != nullptr) {
            wipe_buffer(tx_bytes, tx_bytes_size);
            free(tx_bytes);
        }
        return SuiSigningPreparationResult::invalid_argument;
    }
    clear_sui_prepared_sign_transaction(out);
    if (route != SupportedSignRoute::sui_sign_transaction ||
        network == nullptr ||
        tx_bytes == nullptr ||
        tx_bytes_size == 0 ||
        tx_bytes_size > kSuiSignTransactionTxBytesMaxBytes ||
        ops.check_transaction_account == nullptr) {
        if (tx_bytes != nullptr) {
            wipe_buffer(tx_bytes, tx_bytes_size);
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
        clear_sui_prepared_sign_transaction(out);
        return SuiSigningPreparationResult::invalid_network;
    }
    if (!approval_history_digest_payload(
            out->tx_bytes,
            out->tx_bytes_size,
            out->payload_digest,
            sizeof(out->payload_digest))) {
        clear_sui_prepared_sign_transaction(out);
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
        clear_sui_prepared_sign_transaction(out);
        return adapter_result ==
                       SuiSignTransactionAdapterResult::malformed_transaction
                   ? SuiSigningPreparationResult::malformed_transaction
                   : SuiSigningPreparationResult::unsupported_transaction;
    }
    out->user_mode_authorization_covered =
        authorization_coverage.user_mode_authorization_covered;
    out->user_authorization_outcome = authorization_coverage.user_outcome;
    out->policy_mode_authorization_covered =
        authorization_coverage.policy_mode_authorization_covered;
    out->policy_authorization_outcome = authorization_coverage.policy_outcome;
    const SuiSigningPreparationResult account_result =
        ops.check_transaction_account(out->sui_policy_subject, out->network, ops.context);
    if (account_result != SuiSigningPreparationResult::ok) {
        clear_sui_prepared_sign_transaction(out);
        return account_result;
    }
    prepare_policy_condition_facts(out);
    return SuiSigningPreparationResult::ok;
}

SuiSigningPreparationResult prepare_sui_sign_transaction_base64(
    SupportedSignRoute route,
    const char* network,
    const char* tx_bytes_base64,
    size_t decoded_tx_size,
    const SuiSigningPreparationOps& ops,
    SuiPreparedSignTransaction* out)
{
    if (out == nullptr) {
        return SuiSigningPreparationResult::invalid_argument;
    }
    clear_sui_prepared_sign_transaction(out);
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
        wipe_buffer(tx_bytes, decoded_tx_size);
        free(tx_bytes);
        return SuiSigningPreparationResult::invalid_params;
    }
    return prepare_sui_sign_transaction_owned(
        route,
        network,
        tx_bytes,
        decoded_tx_size,
        ops,
        out);
}

SuiSigningPreparationResult prepare_sui_sign_personal_message_bytes(
    SupportedSignRoute route,
    const char* network,
    const uint8_t* message,
    size_t message_size,
    const SuiSigningPreparationOps& ops,
    SuiPreparedPersonalMessage* out)
{
    if (out == nullptr) {
        return SuiSigningPreparationResult::invalid_argument;
    }
    clear_sui_prepared_personal_message(out);
    if (route != SupportedSignRoute::sui_sign_personal_message ||
        network == nullptr ||
        message == nullptr ||
        message_size == 0 ||
        message_size > kSuiSignPersonalMessageMaxBytes ||
        ops.check_personal_message_account == nullptr) {
        return message_size > kSuiSignPersonalMessageMaxBytes
                   ? SuiSigningPreparationResult::payload_too_large
                   : SuiSigningPreparationResult::invalid_argument;
    }
    out->route = route;
    if (!copy_network(network, out->network, sizeof(out->network))) {
        clear_sui_prepared_personal_message(out);
        return SuiSigningPreparationResult::invalid_network;
    }
    memcpy(out->message, message, message_size);
    out->message_size = message_size;
    if (!approval_history_digest_payload(
            out->message,
            out->message_size,
            out->payload_digest,
            sizeof(out->payload_digest))) {
        clear_sui_prepared_personal_message(out);
        return SuiSigningPreparationResult::digest_error;
    }
    const SuiSigningPreparationResult account_result =
        ops.check_personal_message_account(
            out->network,
            out->account_address,
            ops.context);
    if (account_result != SuiSigningPreparationResult::ok) {
        clear_sui_prepared_personal_message(out);
        return account_result;
    }
    return SuiSigningPreparationResult::ok;
}

SuiSigningPreparationResult prepare_sui_sign_personal_message_base64(
    SupportedSignRoute route,
    const char* network,
    const char* message_base64,
    size_t decoded_message_size,
    const SuiSigningPreparationOps& ops,
    SuiPreparedPersonalMessage* out)
{
    if (out == nullptr) {
        return SuiSigningPreparationResult::invalid_argument;
    }
    clear_sui_prepared_personal_message(out);
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
    uint8_t message[kSuiSignPersonalMessageMaxBytes] = {};
    if (base64_to_bytes(
            message_base64,
            strlen(message_base64),
            message,
            sizeof(message)) != 0) {
        wipe_buffer(message, sizeof(message));
        return SuiSigningPreparationResult::invalid_params;
    }
    const SuiSigningPreparationResult result =
        prepare_sui_sign_personal_message_bytes(
            route,
            network,
            message,
            decoded_message_size,
            ops,
            out);
    wipe_buffer(message, sizeof(message));
    return result;
}

void clear_sui_prepared_sign_transaction(SuiPreparedSignTransaction* prepared)
{
    if (prepared == nullptr) {
        return;
    }
    if (prepared->tx_bytes != nullptr && prepared->tx_bytes_size > 0) {
        wipe_buffer(prepared->tx_bytes, prepared->tx_bytes_size);
        free(prepared->tx_bytes);
    }
    if (prepared->sui_offline_policy_facts != nullptr) {
        wipe_buffer(
            prepared->sui_offline_policy_facts,
            sizeof(*prepared->sui_offline_policy_facts));
        free(prepared->sui_offline_policy_facts);
    }
    memset(prepared, 0, sizeof(*prepared));
}

void clear_sui_prepared_personal_message(SuiPreparedPersonalMessage* prepared)
{
    if (prepared == nullptr) {
        return;
    }
    wipe_buffer(prepared->message, sizeof(prepared->message));
    memset(prepared, 0, sizeof(*prepared));
}

}  // namespace signing
