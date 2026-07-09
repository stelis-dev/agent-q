#include "transport/local_transport_crypto.h"

namespace signing {

bool local_transport_crypto_ops_valid(const LocalTransportCryptoOps& ops)
{
    return ops.random_bytes != nullptr &&
           ops.x25519_public_key != nullptr &&
           ops.x25519_shared_secret != nullptr &&
           ops.sha256 != nullptr &&
           ops.hmac_sha256 != nullptr &&
           ops.aes256_gcm_encrypt != nullptr &&
           ops.aes256_gcm_decrypt != nullptr;
}

void local_transport_wipe_bytes(uint8_t* bytes, size_t bytes_len)
{
    if (bytes == nullptr) {
        return;
    }
    volatile uint8_t* cursor = bytes;
    for (size_t index = 0; index < bytes_len; ++index) {
        cursor[index] = 0;
    }
}

}  // namespace signing
