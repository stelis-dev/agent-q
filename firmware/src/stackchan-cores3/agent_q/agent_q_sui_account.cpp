#include "agent_q_sui_account.h"

#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_sui_key_derivation.h"

extern "C" {
#include "byte_conversions.h"
#include "key_management.h"
}

namespace agent_q {
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

struct PublicAccountDerivationContext {
    uint8_t* public_key_out;
    char* address_out;
    size_t address_out_size;
};

bool derive_public_account_from_seed(
    const uint8_t ed25519_seed[kSuiEd25519PrivateSeedBytes],
    void* context_ptr)
{
    PublicAccountDerivationContext* context =
        static_cast<PublicAccountDerivationContext*>(context_ptr);
    if (context == nullptr || context->public_key_out == nullptr ||
        context->address_out == nullptr || context->address_out_size < kSuiAddressBufferSize) {
        return false;
    }

    uint8_t public_key[kSuiEd25519PublicKeyBytes];
    const int public_key_result = microsui_derive_public_key_ed25519(public_key, ed25519_seed);
    if (public_key_result != 0) {
        wipe_sensitive_buffer(public_key, sizeof(public_key));
        return false;
    }

    uint8_t address[32];
    const int address_result = microsui_derive_sui_address_ed25519(address, public_key);
    if (address_result != 0) {
        wipe_sensitive_buffer(public_key, sizeof(public_key));
        wipe_sensitive_buffer(address, sizeof(address));
        return false;
    }

    memcpy(context->public_key_out, public_key, sizeof(public_key));
    context->address_out[0] = '0';
    context->address_out[1] = 'x';
    bytes_to_hex(address, 32, context->address_out + 2);  // lowercase hex, NUL-terminated

    wipe_sensitive_buffer(public_key, sizeof(public_key));
    wipe_sensitive_buffer(address, sizeof(address));
    return true;
}

}  // namespace

bool derive_sui_ed25519_account(
    const char* mnemonic,
    uint8_t public_key_out[kSuiEd25519PublicKeyBytes],
    char* address_out,
    size_t address_out_size)
{
    clear_public_account_outputs(public_key_out, address_out, address_out_size);
    if (mnemonic == nullptr || public_key_out == nullptr || address_out == nullptr ||
        address_out_size < kSuiAddressBufferSize) {
        return false;
    }
    const size_t mnemonic_len = strlen(mnemonic);
    if (mnemonic_len == 0) {
        return false;
    }

    PublicAccountDerivationContext context{
        public_key_out,
        address_out,
        address_out_size,
    };
    if (!with_sui_ed25519_private_seed(mnemonic, derive_public_account_from_seed, &context)) {
        clear_public_account_outputs(public_key_out, address_out, address_out_size);
        return false;
    }
    return true;
}

}  // namespace agent_q
