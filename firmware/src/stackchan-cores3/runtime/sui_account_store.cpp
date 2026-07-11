#include "sui_account_store.h"

#include "bip39.h"
#include "stackchan_keystore.h"

#include <string.h>

namespace signing {
namespace {

void clear_public_account_outputs(uint8_t* public_key_out, char* address_out, size_t address_out_size)
{
    if (public_key_out != nullptr) {
        memset(public_key_out, 0, kSuiEd25519PublicKeyBytes);
    }
    if (address_out != nullptr && address_out_size > 0) {
        memset(address_out, 0, address_out_size);
    }
}

struct AccountDerivationContext {
    uint8_t* public_key_out;
    char* address_out;
    size_t address_out_size;
    SuiAccountDerivationResult result;
};

bool derive_account_with_root(
    const uint8_t* root_material,
    size_t root_material_size,
    void* context_ptr)
{
    auto* context = static_cast<AccountDerivationContext*>(context_ptr);
    if (context == nullptr || root_material == nullptr ||
        root_material_size != kStackChanRootMaterialBytes) {
        return false;
    }

    char mnemonic[kBip39MnemonicMaxChars] = {};
    if (!make_bip39_mnemonic_12_words(
            root_material, mnemonic, sizeof(mnemonic))) {
        wipe_sensitive_buffer(mnemonic, sizeof(mnemonic));
        context->result = SuiAccountDerivationResult::mnemonic_error;
        return true;
    }

    const bool account_ok = derive_sui_ed25519_account(
        mnemonic,
        context->public_key_out,
        context->address_out,
        context->address_out_size);
    wipe_sensitive_buffer(mnemonic, sizeof(mnemonic));
    context->result = account_ok
        ? SuiAccountDerivationResult::ok
        : SuiAccountDerivationResult::derivation_error;
    return true;
}

}  // namespace

SuiAccountDerivationResult derive_sui_ed25519_account_from_stored_root(
    uint8_t public_key_out[kSuiEd25519PublicKeyBytes],
    char* address_out,
    size_t address_out_size)
{
    clear_public_account_outputs(public_key_out, address_out, address_out_size);
    if (public_key_out == nullptr || address_out == nullptr || address_out_size < kSuiAddressBufferSize) {
        return SuiAccountDerivationResult::derivation_error;
    }

    AccountDerivationContext context{
        public_key_out,
        address_out,
        address_out_size,
        SuiAccountDerivationResult::derivation_error,
    };
    if (stackchan_keystore_with_root(derive_account_with_root, &context) !=
        KeystoreOperationStatus::success) {
        return SuiAccountDerivationResult::root_material_unavailable;
    }
    return context.result;
}

}  // namespace signing
