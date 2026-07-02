#include "sui_account_store.h"

#include "bip39.h"
#include "root_material.h"

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

    uint8_t root_material[kRootMaterialBytes] = {};
    if (!read_root_material(root_material, sizeof(root_material))) {
        wipe_sensitive_buffer(root_material, sizeof(root_material));
        return SuiAccountDerivationResult::root_material_unavailable;
    }

    char mnemonic[kBip39MnemonicMaxChars] = {};
    const bool mnemonic_ok =
        make_bip39_mnemonic_12_words(root_material, mnemonic, sizeof(mnemonic));
    wipe_sensitive_buffer(root_material, sizeof(root_material));
    if (!mnemonic_ok) {
        wipe_sensitive_buffer(mnemonic, sizeof(mnemonic));
        return SuiAccountDerivationResult::mnemonic_error;
    }

    const bool account_ok =
        derive_sui_ed25519_account(mnemonic, public_key_out, address_out, address_out_size);
    wipe_sensitive_buffer(mnemonic, sizeof(mnemonic));
    return account_ok ? SuiAccountDerivationResult::ok : SuiAccountDerivationResult::derivation_error;
}

}  // namespace signing
