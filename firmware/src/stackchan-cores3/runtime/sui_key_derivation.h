#pragma once

#include <stddef.h>
#include <stdint.h>

namespace signing {

constexpr size_t kSuiEd25519PrivateSeedBytes = 32;

using SuiEd25519PrivateSeedConsumer =
    bool (*)(const uint8_t seed[kSuiEd25519PrivateSeedBytes], void* context);

// Internal Firmware-only derivation for the Sui standard account 0 path:
// m/44'/784'/0'/0'/0' with SLIP-0010 Ed25519 hardened derivation.
//
// The derived private seed is passed only to the supplied consumer and is wiped
// before this function returns. The consumer must not copy it outside volatile
// scratch. This function must not be used in a protocol, UI, log, or adapter
// response path.
bool with_sui_ed25519_private_seed(
    const char* mnemonic,
    SuiEd25519PrivateSeedConsumer consumer,
    void* context);

}  // namespace signing
