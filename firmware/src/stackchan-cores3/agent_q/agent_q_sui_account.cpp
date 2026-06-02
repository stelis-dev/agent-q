#include "agent_q_sui_account.h"

#include <string.h>

extern "C" {
#include "byte_conversions.h"
#include "key_management.h"
#include "lib/monocypher/monocypher.h"
}

namespace agent_q {
namespace {

constexpr uint32_t kPbkdf2Iterations = 2048;
constexpr size_t kBip39SeedBytes = 64;
constexpr size_t kSlip10KeyBytes = 32;

// Sui standard account 0: m/44'/784'/0'/0'/0'. SLIP-0010 Ed25519 requires every
// level to be hardened; the hardening bit is applied during derivation.
constexpr uint32_t kSuiDerivationPath[5] = {44u, 784u, 0u, 0u, 0u};

void clear_public_account_outputs(uint8_t* public_key_out, char* address_out, size_t address_out_size)
{
    if (public_key_out != nullptr) {
        memset(public_key_out, 0, kSuiEd25519PublicKeyBytes);
    }
    if (address_out != nullptr && address_out_size > 0) {
        memset(address_out, 0, address_out_size);
    }
}

// BIP-39 seed = PBKDF2-HMAC-SHA512(password = mnemonic, salt = "mnemonic" +
// passphrase, c = 2048, dkLen = 64). Passphrase is empty in this flow, so the
// salt is exactly "mnemonic". The derived key length equals the HMAC-SHA512
// output length, so a single PBKDF2 block (INT(1)) produces the whole seed.
void pbkdf2_hmac_sha512_seed(
    const uint8_t* password, size_t password_len, uint8_t seed_out[kBip39SeedBytes])
{
    uint8_t block[12];
    static const uint8_t kSalt[8] = {'m', 'n', 'e', 'm', 'o', 'n', 'i', 'c'};
    memcpy(block, kSalt, sizeof(kSalt));
    block[8] = 0x00;
    block[9] = 0x00;
    block[10] = 0x00;
    block[11] = 0x01;  // INT(1), big-endian block index.

    uint8_t u[kBip39SeedBytes];
    uint8_t t[kBip39SeedBytes];
    crypto_sha512_hmac(u, password, password_len, block, sizeof(block));  // U1
    memcpy(t, u, sizeof(t));
    for (uint32_t iteration = 1; iteration < kPbkdf2Iterations; ++iteration) {
        crypto_sha512_hmac(u, password, password_len, u, sizeof(u));  // U(n+1) = PRF(pw, U(n))
        for (size_t index = 0; index < sizeof(t); ++index) {
            t[index] ^= u[index];
        }
    }
    memcpy(seed_out, t, kBip39SeedBytes);

    crypto_wipe(u, sizeof(u));
    crypto_wipe(t, sizeof(t));
    crypto_wipe(block, sizeof(block));
}

// SLIP-0010 Ed25519 derivation. Master: I = HMAC-SHA512("ed25519 seed", seed);
// key = I[0:32], chain code = I[32:64]. Hardened child i:
// I = HMAC-SHA512(chain_code, 0x00 || key || ser32(i)); key/chain code = split.
void slip10_ed25519_derive(const uint8_t seed[kBip39SeedBytes], uint8_t key_out[kSlip10KeyBytes])
{
    uint8_t i_buffer[64];
    static const uint8_t kCurve[12] = {'e', 'd', '2', '5', '5', '1', '9', ' ', 's', 'e', 'e', 'd'};
    crypto_sha512_hmac(i_buffer, kCurve, sizeof(kCurve), seed, kBip39SeedBytes);

    uint8_t key[kSlip10KeyBytes];
    uint8_t chain_code[kSlip10KeyBytes];
    memcpy(key, i_buffer, sizeof(key));
    memcpy(chain_code, i_buffer + 32, sizeof(chain_code));

    for (size_t level = 0; level < 5; ++level) {
        const uint32_t hardened = kSuiDerivationPath[level] | 0x80000000u;
        uint8_t data[37];
        data[0] = 0x00;
        memcpy(data + 1, key, sizeof(key));
        data[33] = static_cast<uint8_t>(hardened >> 24);
        data[34] = static_cast<uint8_t>(hardened >> 16);
        data[35] = static_cast<uint8_t>(hardened >> 8);
        data[36] = static_cast<uint8_t>(hardened);
        crypto_sha512_hmac(i_buffer, chain_code, sizeof(chain_code), data, sizeof(data));
        memcpy(key, i_buffer, sizeof(key));
        memcpy(chain_code, i_buffer + 32, sizeof(chain_code));
        crypto_wipe(data, sizeof(data));
    }

    memcpy(key_out, key, kSlip10KeyBytes);

    crypto_wipe(i_buffer, sizeof(i_buffer));
    crypto_wipe(key, sizeof(key));
    crypto_wipe(chain_code, sizeof(chain_code));
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

    uint8_t seed[kBip39SeedBytes];
    pbkdf2_hmac_sha512_seed(reinterpret_cast<const uint8_t*>(mnemonic), mnemonic_len, seed);

    uint8_t ed25519_seed[kSlip10KeyBytes];
    slip10_ed25519_derive(seed, ed25519_seed);
    crypto_wipe(seed, sizeof(seed));

    uint8_t public_key[kSuiEd25519PublicKeyBytes];
    const int public_key_result = microsui_derive_public_key_ed25519(public_key, ed25519_seed);
    crypto_wipe(ed25519_seed, sizeof(ed25519_seed));
    if (public_key_result != 0) {
        crypto_wipe(public_key, sizeof(public_key));
        return false;
    }

    uint8_t address[32];
    const int address_result = microsui_derive_sui_address_ed25519(address, public_key);
    if (address_result != 0) {
        crypto_wipe(public_key, sizeof(public_key));
        crypto_wipe(address, sizeof(address));
        return false;
    }

    memcpy(public_key_out, public_key, sizeof(public_key));
    address_out[0] = '0';
    address_out[1] = 'x';
    bytes_to_hex(address, 32, address_out + 2);  // lowercase hex, NUL-terminated

    crypto_wipe(public_key, sizeof(public_key));
    crypto_wipe(address, sizeof(address));
    return true;
}

}  // namespace agent_q
