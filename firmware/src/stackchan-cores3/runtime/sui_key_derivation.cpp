#include "sui_key_derivation.h"

#include <string.h>

#include "bip39.h"

extern "C" {
#include "lib/monocypher/monocypher.h"
}

namespace signing {
namespace {

constexpr uint32_t kPbkdf2Iterations = 2048;
constexpr size_t kBip39SeedBytes = 64;

// Sui standard account 0: m/44'/784'/0'/0'/0'. SLIP-0010 Ed25519 requires every
// level to be hardened; the hardening bit is applied during derivation.
constexpr uint32_t kSuiDerivationPath[5] = {44u, 784u, 0u, 0u, 0u};

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
void slip10_ed25519_derive(
    const uint8_t seed[kBip39SeedBytes],
    uint8_t key_out[kSuiEd25519PrivateSeedBytes])
{
    uint8_t i_buffer[64];
    static const uint8_t kCurve[12] = {'e', 'd', '2', '5', '5', '1', '9', ' ', 's', 'e', 'e', 'd'};
    crypto_sha512_hmac(i_buffer, kCurve, sizeof(kCurve), seed, kBip39SeedBytes);

    uint8_t key[kSuiEd25519PrivateSeedBytes];
    uint8_t chain_code[kSuiEd25519PrivateSeedBytes];
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

    memcpy(key_out, key, kSuiEd25519PrivateSeedBytes);

    crypto_wipe(i_buffer, sizeof(i_buffer));
    crypto_wipe(key, sizeof(key));
    crypto_wipe(chain_code, sizeof(chain_code));
}

}  // namespace

bool with_sui_ed25519_private_seed(
    const char* mnemonic,
    SuiEd25519PrivateSeedConsumer consumer,
    void* context)
{
    if (mnemonic == nullptr || mnemonic[0] == '\0' || consumer == nullptr) {
        return false;
    }

    uint8_t bip39_seed[kBip39SeedBytes];
    uint8_t private_seed[kSuiEd25519PrivateSeedBytes];
    pbkdf2_hmac_sha512_seed(
        reinterpret_cast<const uint8_t*>(mnemonic), strlen(mnemonic), bip39_seed);
    slip10_ed25519_derive(bip39_seed, private_seed);
    crypto_wipe(bip39_seed, sizeof(bip39_seed));
    const bool result = consumer(private_seed, context);
    crypto_wipe(private_seed, sizeof(private_seed));
    return result;
}

}  // namespace signing
