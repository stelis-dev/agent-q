#pragma once

#include <stddef.h>
#include <stdint.h>

namespace signing {

constexpr size_t kSuiEd25519PublicKeyBytes = 32;
// "0x" + 64 lowercase hex characters + NUL terminator.
constexpr size_t kSuiAddressBufferSize = 67;

// Derive the Sui Ed25519 account at the standard Sui derivation path
// m/44'/784'/0'/0'/0' (SLIP-0010 for Ed25519, every level hardened) from a
// BIP-39 mnemonic with an empty passphrase.
//
// On success writes the raw 32-byte Ed25519 public key to public_key_out and
// the lowercase "0x..." Sui address string (66 characters + NUL) to
// address_out, and returns true. address_out_size must be at least
// kSuiAddressBufferSize.
//
// Only public material is returned. All intermediate secret material (BIP-39
// seed, derived private key) is wiped before returning. Returns false without
// writing a partial account on any failure.
bool derive_sui_ed25519_account(
    const char* mnemonic,
    uint8_t public_key_out[kSuiEd25519PublicKeyBytes],
    char* address_out,
    size_t address_out_size);

}  // namespace signing
