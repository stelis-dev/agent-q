#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sui/personal_message_intent.h"
#include "sui/zklogin_signature.h"
#include "sui/signing_limits.h"

namespace stopwatch_target {

enum class SuiZkLoginSigningResult {
    ok,
    invalid_input,
    account_unavailable,
    signing_error,
    signature_output_too_small,
    zklogin_envelope_error,
};

SuiZkLoginSigningResult sign_sui_zklogin_personal_message(
    const uint8_t* message,
    size_t message_size,
    uint8_t signature_out[signing::kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out);

SuiZkLoginSigningResult sign_sui_zklogin_transaction(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    uint8_t signature_out[signing::kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out);

const char* sui_zklogin_signing_result_name(SuiZkLoginSigningResult result);

}  // namespace stopwatch_target
