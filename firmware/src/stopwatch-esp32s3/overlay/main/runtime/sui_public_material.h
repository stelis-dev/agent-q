#pragma once

#include <stddef.h>
#include <stdint.h>

namespace stopwatch_target {

constexpr uint8_t kSuiSignatureSchemeFlagEd25519 = 0x00;
constexpr size_t kSuiEd25519SeedBytes = 32;
constexpr size_t kSuiEd25519PublicKeyBytes = 32;
constexpr size_t kSuiSchemePrefixedEd25519PublicKeyBytes =
    1 + kSuiEd25519PublicKeyBytes;
constexpr size_t kSuiSchemePrefixedEd25519PublicKeyBase64Size = 45;
constexpr size_t kSuiAddressBufferSize = 67;

struct SuiEd25519Preparation {
    uint8_t scheme_prefixed_public_key[kSuiSchemePrefixedEd25519PublicKeyBytes];
    char public_key_base64[kSuiSchemePrefixedEd25519PublicKeyBase64Size];
    char address[kSuiAddressBufferSize];
};

enum class SuiPublicMaterialResult {
    ok,
    invalid_argument,
    crypto_error,
    encode_error,
};

SuiPublicMaterialResult derive_sui_ed25519_preparation_from_seed(
    const uint8_t seed[kSuiEd25519SeedBytes],
    SuiEd25519Preparation* out);
bool sui_address_format_valid(const char* value);

}  // namespace stopwatch_target
