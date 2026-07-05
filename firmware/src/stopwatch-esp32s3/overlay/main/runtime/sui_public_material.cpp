#include "sui_public_material.h"

#include <string.h>

#include "sensitive_memory.h"

extern "C" {
#include "byte_conversions.h"
#include "key_management.h"
}

namespace stopwatch_target {
namespace {

void clear_preparation(SuiEd25519Preparation* out)
{
    if (out != nullptr) {
        memset(out, 0, sizeof(*out));
    }
}

bool is_lower_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

}  // namespace

SuiPublicMaterialResult derive_sui_ed25519_preparation_from_seed(
    const uint8_t seed[kSuiEd25519SeedBytes],
    SuiEd25519Preparation* out)
{
    clear_preparation(out);
    if (seed == nullptr || out == nullptr) {
        return SuiPublicMaterialResult::invalid_argument;
    }

    uint8_t public_key[kSuiEd25519PublicKeyBytes] = {};
    if (microsui_derive_public_key_ed25519(public_key, seed) != 0) {
        wipe_sensitive_buffer(public_key, sizeof(public_key));
        return SuiPublicMaterialResult::crypto_error;
    }

    uint8_t address[32] = {};
    if (microsui_derive_sui_address_ed25519(address, public_key) != 0) {
        wipe_sensitive_buffer(public_key, sizeof(public_key));
        wipe_sensitive_buffer(address, sizeof(address));
        return SuiPublicMaterialResult::crypto_error;
    }

    out->scheme_prefixed_public_key[0] = kSuiSignatureSchemeFlagEd25519;
    memcpy(out->scheme_prefixed_public_key + 1, public_key, sizeof(public_key));
    out->address[0] = '0';
    out->address[1] = 'x';
    bytes_to_hex(address, sizeof(address), out->address + 2);

    if (bytes_to_base64(
            out->scheme_prefixed_public_key,
            sizeof(out->scheme_prefixed_public_key),
            out->public_key_base64,
            sizeof(out->public_key_base64)) != 0 ||
        out->public_key_base64[0] == '\0') {
        clear_preparation(out);
        wipe_sensitive_buffer(public_key, sizeof(public_key));
        wipe_sensitive_buffer(address, sizeof(address));
        return SuiPublicMaterialResult::encode_error;
    }

    wipe_sensitive_buffer(public_key, sizeof(public_key));
    wipe_sensitive_buffer(address, sizeof(address));
    return SuiPublicMaterialResult::ok;
}

bool sui_address_format_valid(const char* value)
{
    if (value == nullptr || value[0] != '0' || value[1] != 'x') {
        return false;
    }
    for (size_t index = 2; index < kSuiAddressBufferSize - 1; ++index) {
        if (!is_lower_hex(value[index])) {
            return false;
        }
    }
    return value[kSuiAddressBufferSize - 1] == '\0';
}

}  // namespace stopwatch_target
