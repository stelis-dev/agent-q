#pragma once

#include <stddef.h>
#include <stdint.h>

namespace agent_q {

constexpr size_t kSuiEd25519SignatureBytes = 97;
constexpr size_t kSuiEd25519SignatureBase64Chars = 132;

enum class SuiTransactionSigningResult {
    ok,
    invalid_input,
    root_material_unavailable,
    mnemonic_error,
    signing_error,
};

SuiTransactionSigningResult sign_sui_ed25519_transaction_from_stored_root(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    uint8_t signature_out[kSuiEd25519SignatureBytes]);

const char* sui_transaction_signing_result_to_string(SuiTransactionSigningResult result);

}  // namespace agent_q
