#pragma once

#include "protocol/sign_route.h"
#include "sui/signing_preparation_types.h"

namespace signing {

using SuiSignTransactionAccountCheckFn =
    SuiSigningPreparationResult (*)(
        const SuiPolicySubjectFacts& facts,
        const char* network,
        void* context);

using SuiSignPersonalMessageAccountCheckFn =
    SuiSigningPreparationResult (*)(
        const char* network,
        char account_address[kSuiAddressStringBufferSize],
        void* context);

struct SuiSigningPreparationOps {
    SuiSignTransactionAccountCheckFn check_transaction_account;
    SuiSignPersonalMessageAccountCheckFn check_personal_message_account;
    void* context;
};

SuiSigningPreparationResult prepare_sui_sign_transaction_owned(
    SupportedSignRoute route,
    const char* network,
    uint8_t* tx_bytes,
    size_t tx_bytes_size,
    const SuiSigningPreparationOps& ops,
    SuiPreparedSignTransaction* out);

SuiSigningPreparationResult prepare_sui_sign_transaction_base64(
    SupportedSignRoute route,
    const char* network,
    const char* tx_bytes_base64,
    size_t decoded_tx_size,
    const SuiSigningPreparationOps& ops,
    SuiPreparedSignTransaction* out);

SuiSigningPreparationResult prepare_sui_sign_personal_message_bytes(
    SupportedSignRoute route,
    const char* network,
    const uint8_t* message,
    size_t message_size,
    const SuiSigningPreparationOps& ops,
    SuiPreparedPersonalMessage* out);

SuiSigningPreparationResult prepare_sui_sign_personal_message_base64(
    SupportedSignRoute route,
    const char* network,
    const char* message_base64,
    size_t decoded_message_size,
    const SuiSigningPreparationOps& ops,
    SuiPreparedPersonalMessage* out);

void clear_sui_prepared_sign_transaction(SuiPreparedSignTransaction* prepared);
void clear_sui_prepared_personal_message(SuiPreparedPersonalMessage* prepared);

}  // namespace signing
