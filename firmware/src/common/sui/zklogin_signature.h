#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sui/zklogin_proof_record.h"

namespace signing {

constexpr size_t kSuiEd25519SignatureBytes = 97;
constexpr size_t kSuiEd25519SignatureBase64Chars = 132;
constexpr size_t kSuiZkLoginSignatureBcsMaxBytes = 2048;
constexpr size_t kSuiZkLoginSignatureMaxBytes = 1 + kSuiZkLoginSignatureBcsMaxBytes;
constexpr size_t kSuiSignatureEnvelopeMaxBytes = kSuiZkLoginSignatureMaxBytes;
constexpr size_t kSuiSignatureEnvelopeBase64MaxChars =
    ((kSuiSignatureEnvelopeMaxBytes + 2) / 3) * 4;

enum class SuiZkLoginSignatureBuildResult {
    ok,
    invalid_input,
    output_too_small,
    bcs_too_large,
};

SuiZkLoginSignatureBuildResult build_sui_zklogin_signature_envelope(
    const SuiZkLoginSignatureInputs& inputs,
    const char* max_epoch,
    const uint8_t* user_signature,
    size_t user_signature_size,
    uint8_t* output,
    size_t output_size,
    size_t* output_size_written);

const char* sui_zklogin_signature_build_result_name(
    SuiZkLoginSignatureBuildResult result);

}  // namespace signing
