#include "agent_q_sui_signing_preparation.h"

#include <string.h>

#include "agent_q_base64.h"
#include "agent_q_bip39.h"
#include "agent_q_sui_account_store.h"
#include "agent_q_sui_signing_authority.h"
#include "agent_q_common/sui/agent_q_sui_sign_transaction_adapter.h"

extern "C" {
#include "byte_conversions.h"
}

namespace agent_q {
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

AgentQSuiSigningPreparationResult validate_encoded_payload_size(
    const char* base64,
    size_t caller_decoded_size,
    size_t max_decoded_size)
{
    size_t actual_decoded_size = 0;
    if (!validate_canonical_base64_syntax(
            base64,
            kAgentQSignRequestBase64MaxSize,
            &actual_decoded_size)) {
        return AgentQSuiSigningPreparationResult::invalid_params;
    }
    if (actual_decoded_size > max_decoded_size) {
        return AgentQSuiSigningPreparationResult::unsupported_payload_size;
    }
    if (actual_decoded_size != caller_decoded_size) {
        return AgentQSuiSigningPreparationResult::invalid_params;
    }
    return AgentQSuiSigningPreparationResult::ok;
}

}  // namespace

AgentQSuiSigningPreparationResult prepare_sui_sign_transaction(
    AgentQSupportedSignRoute route,
    const char* network,
    const char* tx_bytes_base64,
    size_t decoded_tx_size,
    AgentQSuiPreparedSignTransaction* out)
{
    if (out == nullptr) {
        return AgentQSuiSigningPreparationResult::invalid_argument;
    }
    clear_prepared_sui_sign_transaction(out);
    // Adapter boundary assertion: callers may reach this helper outside the
    // USB preflight path, so route mismatch must fail before decoding.
    if (route != AgentQSupportedSignRoute::sui_sign_transaction ||
        network == nullptr ||
        tx_bytes_base64 == nullptr ||
        decoded_tx_size == 0) {
        return AgentQSuiSigningPreparationResult::invalid_argument;
    }
    const AgentQSuiSigningPreparationResult size_result =
        validate_encoded_payload_size(
            tx_bytes_base64,
            decoded_tx_size,
            kAgentQSuiSignTransactionTxBytesMaxBytes);
    if (size_result != AgentQSuiSigningPreparationResult::ok) {
        return size_result;
    }
    out->route = route;
    if (!copy_network(network, out->network, sizeof(out->network))) {
        clear_prepared_sui_sign_transaction(out);
        return AgentQSuiSigningPreparationResult::invalid_argument;
    }
    if (base64_to_bytes(
            tx_bytes_base64,
            strlen(tx_bytes_base64),
            out->tx_bytes,
            sizeof(out->tx_bytes)) != 0) {
        clear_prepared_sui_sign_transaction(out);
        return AgentQSuiSigningPreparationResult::invalid_params;
    }
    out->tx_bytes_size = decoded_tx_size;
    if (!approval_history_digest_payload(
            out->tx_bytes,
            out->tx_bytes_size,
            out->payload_digest,
            sizeof(out->payload_digest))) {
        clear_prepared_sui_sign_transaction(out);
        return AgentQSuiSigningPreparationResult::digest_error;
    }
    const AgentQSuiSignTransactionAdapterResult adapter_result =
        classify_sui_sign_transaction(
            out->tx_bytes,
            out->tx_bytes_size,
            &out->sui_transfer);
    if (adapter_result != AgentQSuiSignTransactionAdapterResult::ok) {
        clear_prepared_sui_sign_transaction(out);
        return adapter_result ==
                       AgentQSuiSignTransactionAdapterResult::malformed_transaction
                   ? AgentQSuiSigningPreparationResult::malformed_transaction
                   : AgentQSuiSigningPreparationResult::unsupported_transaction;
    }
    const AgentQSuiSigningAccountBindingResult account_result =
        verify_sui_signing_stored_account_binding(out->sui_transfer);
    if (account_result != AgentQSuiSigningAccountBindingResult::ok) {
        clear_prepared_sui_sign_transaction(out);
        return account_result == AgentQSuiSigningAccountBindingResult::account_unavailable
                   ? AgentQSuiSigningPreparationResult::account_unavailable
                   : AgentQSuiSigningPreparationResult::invalid_account;
    }
    return AgentQSuiSigningPreparationResult::ok;
}

AgentQSuiSigningPreparationResult prepare_sui_sign_personal_message(
    AgentQSupportedSignRoute route,
    const char* network,
    const char* message_base64,
    size_t decoded_message_size,
    AgentQSuiPreparedPersonalMessage* out)
{
    if (out == nullptr) {
        return AgentQSuiSigningPreparationResult::invalid_argument;
    }
    clear_prepared_sui_sign_personal_message(out);
    // Adapter boundary assertion: callers may reach this helper outside the
    // USB preflight path, so route mismatch must fail before decoding.
    if (route != AgentQSupportedSignRoute::sui_sign_personal_message ||
        network == nullptr ||
        message_base64 == nullptr ||
        decoded_message_size == 0) {
        return AgentQSuiSigningPreparationResult::invalid_argument;
    }
    const AgentQSuiSigningPreparationResult size_result =
        validate_encoded_payload_size(
            message_base64,
            decoded_message_size,
            kAgentQSuiSignPersonalMessageMaxBytes);
    if (size_result != AgentQSuiSigningPreparationResult::ok) {
        return size_result;
    }
    out->route = route;
    if (!copy_network(network, out->network, sizeof(out->network))) {
        clear_prepared_sui_sign_personal_message(out);
        return AgentQSuiSigningPreparationResult::invalid_argument;
    }
    if (base64_to_bytes(
            message_base64,
            strlen(message_base64),
            out->message,
            sizeof(out->message)) != 0) {
        clear_prepared_sui_sign_personal_message(out);
        return AgentQSuiSigningPreparationResult::invalid_params;
    }
    out->message_size = decoded_message_size;
    if (!approval_history_digest_payload(
            out->message,
            out->message_size,
            out->payload_digest,
            sizeof(out->payload_digest))) {
        clear_prepared_sui_sign_personal_message(out);
        return AgentQSuiSigningPreparationResult::digest_error;
    }
    uint8_t public_key[kSuiEd25519PublicKeyBytes] = {};
    const SuiAccountDerivationResult account_result =
        derive_sui_ed25519_account_from_stored_root(
            public_key,
            out->account_address,
            sizeof(out->account_address));
    wipe_sensitive_buffer(public_key, sizeof(public_key));
    if (account_result != SuiAccountDerivationResult::ok) {
        clear_prepared_sui_sign_personal_message(out);
        return AgentQSuiSigningPreparationResult::account_unavailable;
    }
    return AgentQSuiSigningPreparationResult::ok;
}

void clear_prepared_sui_sign_transaction(AgentQSuiPreparedSignTransaction* prepared)
{
    if (prepared == nullptr) {
        return;
    }
    wipe_sensitive_buffer(prepared->tx_bytes, sizeof(prepared->tx_bytes));
    memset(prepared, 0, sizeof(*prepared));
}

void clear_prepared_sui_sign_personal_message(AgentQSuiPreparedPersonalMessage* prepared)
{
    if (prepared == nullptr) {
        return;
    }
    wipe_sensitive_buffer(prepared->message, sizeof(prepared->message));
    memset(prepared, 0, sizeof(*prepared));
}

}  // namespace agent_q
