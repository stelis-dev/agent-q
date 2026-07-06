#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sui/personal_message_intent.h"
#include "sui/zklogin_signature.h"

namespace signing {

enum class SuiSigningStatus {
    ok,
    invalid_input,
    root_material_unavailable,
    mnemonic_error,
    signing_error,
    active_identity_unavailable,
    signature_output_too_small,
    zklogin_envelope_error,
};

SuiSigningStatus sign_sui_ed25519_transaction_from_stored_root(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    uint8_t signature_out[kSuiEd25519SignatureBytes]);

SuiSigningStatus sign_sui_transaction_from_active_identity(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    uint8_t signature_out[kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out);

SuiSigningStatus sign_sui_ed25519_personal_message_from_stored_root(
    const uint8_t* message,
    size_t message_size,
    uint8_t signature_out[kSuiEd25519SignatureBytes]);

SuiSigningStatus sign_sui_personal_message_from_active_identity(
    const uint8_t* message,
    size_t message_size,
    uint8_t signature_out[kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out);

const char* sui_signing_status_to_string(SuiSigningStatus result);

}  // namespace signing
