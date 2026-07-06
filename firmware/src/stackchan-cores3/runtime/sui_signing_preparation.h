#pragma once

#include "protocol/sign_route.h"
#include "sui/signing_preparation_types.h"

namespace signing {

SuiSigningPreparationResult prepare_sui_sign_transaction(
    SupportedSignRoute route,
    const char* network,
    const char* tx_bytes_base64,
    size_t decoded_tx_size,
    SuiPreparedSignTransaction* out);

SuiSigningPreparationResult prepare_sui_sign_personal_message(
    SupportedSignRoute route,
    const char* network,
    const char* message_base64,
    size_t decoded_message_size,
    SuiPreparedPersonalMessage* out);

void clear_prepared_sui_sign_transaction(SuiPreparedSignTransaction* prepared);
void clear_prepared_sui_sign_personal_message(SuiPreparedPersonalMessage* prepared);

}  // namespace signing
