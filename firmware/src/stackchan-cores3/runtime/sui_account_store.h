#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sui_account.h"

namespace signing {

enum class SuiAccountDerivationResult {
    ok,
    root_material_unavailable,
    mnemonic_error,
    derivation_error,
};

// Read Firmware-owned stored root material, derive the Sui Ed25519 account 0,
// and wipe all root/mnemonic/private-key scratch before returning. Only public
// account material is written to the caller-owned output buffers.
SuiAccountDerivationResult derive_sui_ed25519_account_from_stored_root(
    uint8_t public_key_out[kSuiEd25519PublicKeyBytes],
    char* address_out,
    size_t address_out_size);

}  // namespace signing
