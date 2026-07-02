#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sui_signing_service.h"
#include "sui_zklogin_proof_store.h"

namespace signing {

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
