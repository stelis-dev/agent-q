#include "agent_q_sui_signing_service.h"

#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_root_material.h"
#include "agent_q_sui_key_derivation.h"

extern "C" {
#include "sign.h"
}

namespace agent_q {
namespace {

void clear_signature_output(uint8_t* signature_out)
{
    if (signature_out != nullptr) {
        wipe_sensitive_buffer(signature_out, kSuiEd25519SignatureBytes);
    }
}

struct TransactionSigningContext {
    const uint8_t* tx_bytes;
    size_t tx_bytes_size;
    uint8_t* signature_out;
    bool attempted;
};

bool sign_transaction_with_seed(
    const uint8_t private_seed[kSuiEd25519PrivateSeedBytes],
    void* context_ptr)
{
    TransactionSigningContext* context =
        static_cast<TransactionSigningContext*>(context_ptr);
    if (context == nullptr || context->tx_bytes == nullptr || context->tx_bytes_size == 0 ||
        context->signature_out == nullptr) {
        return false;
    }
    context->attempted = true;
    return sui_signing_sign_ed25519(
               context->signature_out,
               context->tx_bytes,
               context->tx_bytes_size,
               private_seed) == 0;
}

SuiTransactionSigningResult sign_sui_ed25519_transaction_from_mnemonic(
    const char* mnemonic,
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    uint8_t signature_out[kSuiEd25519SignatureBytes])
{
    clear_signature_output(signature_out);
    if (mnemonic == nullptr || mnemonic[0] == '\0' || tx_bytes == nullptr || tx_bytes_size == 0 ||
        signature_out == nullptr) {
        return SuiTransactionSigningResult::invalid_input;
    }

    TransactionSigningContext context{
        tx_bytes,
        tx_bytes_size,
        signature_out,
        false,
    };
    if (!with_sui_ed25519_private_seed(mnemonic, sign_transaction_with_seed, &context)) {
        clear_signature_output(signature_out);
        return context.attempted ? SuiTransactionSigningResult::signing_error
                                 : SuiTransactionSigningResult::mnemonic_error;
    }
    return SuiTransactionSigningResult::ok;
}

}  // namespace

SuiTransactionSigningResult sign_sui_ed25519_transaction_from_stored_root(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    uint8_t signature_out[kSuiEd25519SignatureBytes])
{
    clear_signature_output(signature_out);
    if (tx_bytes == nullptr || tx_bytes_size == 0 || signature_out == nullptr) {
        return SuiTransactionSigningResult::invalid_input;
    }

    uint8_t root_material[kRootMaterialBytes] = {};
    if (!read_root_material(root_material, sizeof(root_material))) {
        wipe_sensitive_buffer(root_material, sizeof(root_material));
        return SuiTransactionSigningResult::root_material_unavailable;
    }

    char mnemonic[kBip39MnemonicMaxChars] = {};
    const bool mnemonic_ok =
        make_bip39_mnemonic_12_words(root_material, mnemonic, sizeof(mnemonic));
    wipe_sensitive_buffer(root_material, sizeof(root_material));
    if (!mnemonic_ok) {
        wipe_sensitive_buffer(mnemonic, sizeof(mnemonic));
        return SuiTransactionSigningResult::mnemonic_error;
    }

    const SuiTransactionSigningResult result =
        sign_sui_ed25519_transaction_from_mnemonic(
            mnemonic, tx_bytes, tx_bytes_size, signature_out);
    wipe_sensitive_buffer(mnemonic, sizeof(mnemonic));
    return result;
}

const char* sui_transaction_signing_result_to_string(SuiTransactionSigningResult result)
{
    switch (result) {
        case SuiTransactionSigningResult::ok:
            return "ok";
        case SuiTransactionSigningResult::invalid_input:
            return "invalid_input";
        case SuiTransactionSigningResult::root_material_unavailable:
            return "root_material_unavailable";
        case SuiTransactionSigningResult::mnemonic_error:
            return "mnemonic_error";
        case SuiTransactionSigningResult::signing_error:
            return "signing_error";
    }
    return "unknown";
}

}  // namespace agent_q
