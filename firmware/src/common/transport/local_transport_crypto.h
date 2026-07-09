#pragma once

#include <stddef.h>
#include <stdint.h>

namespace signing {

constexpr size_t kLocalTransportCryptoKeyBytes = 32;
constexpr size_t kLocalTransportCryptoTagBytes = 16;
constexpr size_t kLocalTransportCryptoHashBytes = 32;
constexpr size_t kLocalTransportCryptoNonceBytes = 12;

struct LocalTransportCryptoBuffer {
    const uint8_t* data = nullptr;
    size_t length = 0;
};

struct LocalTransportCryptoOps {
    bool (*random_bytes)(uint8_t* output, size_t output_len, void* context) = nullptr;
    bool (*x25519_public_key)(
        uint8_t output[kLocalTransportCryptoKeyBytes],
        const uint8_t secret[kLocalTransportCryptoKeyBytes],
        void* context) = nullptr;
    bool (*x25519_shared_secret)(
        uint8_t output[kLocalTransportCryptoKeyBytes],
        const uint8_t secret[kLocalTransportCryptoKeyBytes],
        const uint8_t public_key[kLocalTransportCryptoKeyBytes],
        void* context) = nullptr;
    bool (*sha256)(
        const LocalTransportCryptoBuffer* parts,
        size_t part_count,
        uint8_t output[kLocalTransportCryptoHashBytes],
        void* context) = nullptr;
    bool (*hmac_sha256)(
        const uint8_t* key,
        size_t key_len,
        const LocalTransportCryptoBuffer* parts,
        size_t part_count,
        uint8_t output[kLocalTransportCryptoHashBytes],
        void* context) = nullptr;
    bool (*aes256_gcm_encrypt)(
        const uint8_t key[kLocalTransportCryptoKeyBytes],
        const uint8_t nonce[kLocalTransportCryptoNonceBytes],
        const uint8_t* aad,
        size_t aad_len,
        const uint8_t* plaintext,
        size_t plaintext_len,
        uint8_t* ciphertext,
        uint8_t tag[kLocalTransportCryptoTagBytes],
        void* context) = nullptr;
    bool (*aes256_gcm_decrypt)(
        const uint8_t key[kLocalTransportCryptoKeyBytes],
        const uint8_t nonce[kLocalTransportCryptoNonceBytes],
        const uint8_t* aad,
        size_t aad_len,
        const uint8_t* ciphertext,
        size_t ciphertext_len,
        const uint8_t tag[kLocalTransportCryptoTagBytes],
        uint8_t* plaintext,
        void* context) = nullptr;
    void* context = nullptr;
};

bool local_transport_crypto_ops_valid(const LocalTransportCryptoOps& ops);

void local_transport_wipe_bytes(uint8_t* bytes, size_t bytes_len);

}  // namespace signing
