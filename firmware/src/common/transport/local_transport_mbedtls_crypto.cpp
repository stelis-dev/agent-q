#include "transport/local_transport_mbedtls_crypto.h"

#include <string.h>

#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

extern "C" {
#include "lib/monocypher/monocypher.h"
}

namespace signing {
namespace {

bool random_bytes(uint8_t* output, size_t output_len, void* context)
{
    LocalTransportMbedtlsCryptoContext* provider =
        static_cast<LocalTransportMbedtlsCryptoContext*>(context);
    return provider != nullptr && provider->random_bytes != nullptr &&
           provider->random_bytes(output, output_len, provider->random_context);
}

bool x25519_public_key(
    uint8_t output[kLocalTransportCryptoKeyBytes],
    const uint8_t secret[kLocalTransportCryptoKeyBytes],
    void*)
{
    if (output == nullptr || secret == nullptr) {
        return false;
    }
    crypto_x25519_public_key(output, secret);
    return true;
}

bool x25519_shared_secret(
    uint8_t output[kLocalTransportCryptoKeyBytes],
    const uint8_t secret[kLocalTransportCryptoKeyBytes],
    const uint8_t public_key[kLocalTransportCryptoKeyBytes],
    void*)
{
    if (output == nullptr || secret == nullptr || public_key == nullptr) {
        return false;
    }
    crypto_x25519(output, secret, public_key);
    return true;
}

bool sha256(
    const LocalTransportCryptoBuffer* parts,
    size_t part_count,
    uint8_t output[kLocalTransportCryptoHashBytes],
    void*)
{
    if (parts == nullptr || output == nullptr) {
        return false;
    }
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    bool ok = mbedtls_sha256_starts(&ctx, 0) == 0;
    for (size_t index = 0; ok && index < part_count; ++index) {
        if (parts[index].length > 0 && parts[index].data == nullptr) {
            ok = false;
            break;
        }
        if (parts[index].length > 0) {
            ok = mbedtls_sha256_update(&ctx, parts[index].data, parts[index].length) == 0;
        }
    }
    if (ok) {
        ok = mbedtls_sha256_finish(&ctx, output) == 0;
    }
    mbedtls_sha256_free(&ctx);
    if (!ok) {
        local_transport_wipe_bytes(output, kLocalTransportCryptoHashBytes);
    }
    return ok;
}

bool hmac_sha256(
    const uint8_t* key,
    size_t key_len,
    const LocalTransportCryptoBuffer* parts,
    size_t part_count,
    uint8_t output[kLocalTransportCryptoHashBytes],
    void*)
{
    if ((key_len > 0 && key == nullptr) || parts == nullptr || output == nullptr) {
        return false;
    }
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == nullptr) {
        return false;
    }
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    bool ok = mbedtls_md_setup(&ctx, info, 1) == 0 &&
              mbedtls_md_hmac_starts(&ctx, key, key_len) == 0;
    for (size_t index = 0; ok && index < part_count; ++index) {
        if (parts[index].length > 0 && parts[index].data == nullptr) {
            ok = false;
            break;
        }
        if (parts[index].length > 0) {
            ok = mbedtls_md_hmac_update(&ctx, parts[index].data, parts[index].length) == 0;
        }
    }
    if (ok) {
        ok = mbedtls_md_hmac_finish(&ctx, output) == 0;
    }
    mbedtls_md_free(&ctx);
    if (!ok) {
        local_transport_wipe_bytes(output, kLocalTransportCryptoHashBytes);
    }
    return ok;
}

bool aes256_gcm_encrypt(
    const uint8_t key[kLocalTransportCryptoKeyBytes],
    const uint8_t nonce[kLocalTransportCryptoNonceBytes],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t tag[kLocalTransportCryptoTagBytes],
    void*)
{
    if (key == nullptr || nonce == nullptr || (aad_len > 0 && aad == nullptr) ||
        (plaintext_len > 0 && plaintext == nullptr) ||
        (plaintext_len > 0 && ciphertext == nullptr) || tag == nullptr) {
        return false;
    }
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    bool ok = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
              mbedtls_gcm_crypt_and_tag(
                  &ctx,
                  MBEDTLS_GCM_ENCRYPT,
                  plaintext_len,
                  nonce,
                  kLocalTransportCryptoNonceBytes,
                  aad,
                  aad_len,
                  plaintext,
                  ciphertext,
                  kLocalTransportCryptoTagBytes,
                  tag) == 0;
    mbedtls_gcm_free(&ctx);
    if (!ok) {
        if (ciphertext != nullptr) {
            local_transport_wipe_bytes(ciphertext, plaintext_len);
        }
        local_transport_wipe_bytes(tag, kLocalTransportCryptoTagBytes);
    }
    return ok;
}

bool aes256_gcm_decrypt(
    const uint8_t key[kLocalTransportCryptoKeyBytes],
    const uint8_t nonce[kLocalTransportCryptoNonceBytes],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[kLocalTransportCryptoTagBytes],
    uint8_t* plaintext,
    void*)
{
    if (key == nullptr || nonce == nullptr || (aad_len > 0 && aad == nullptr) ||
        (ciphertext_len > 0 && ciphertext == nullptr) ||
        (ciphertext_len > 0 && plaintext == nullptr) || tag == nullptr) {
        return false;
    }
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    bool ok = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
              mbedtls_gcm_auth_decrypt(
                  &ctx,
                  ciphertext_len,
                  nonce,
                  kLocalTransportCryptoNonceBytes,
                  aad,
                  aad_len,
                  tag,
                  kLocalTransportCryptoTagBytes,
                  ciphertext,
                  plaintext) == 0;
    mbedtls_gcm_free(&ctx);
    if (!ok && plaintext != nullptr) {
        local_transport_wipe_bytes(plaintext, ciphertext_len);
    }
    return ok;
}

}  // namespace

LocalTransportCryptoOps local_transport_mbedtls_crypto_ops(
    LocalTransportMbedtlsCryptoContext* context)
{
    return LocalTransportCryptoOps{
        random_bytes,
        x25519_public_key,
        x25519_shared_secret,
        sha256,
        hmac_sha256,
        aes256_gcm_encrypt,
        aes256_gcm_decrypt,
        context,
    };
}

}  // namespace signing
