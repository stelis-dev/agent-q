#include "local_transport_crypto_adapter.h"

#include "entropy.h"
#include "transport/local_transport_mbedtls_crypto.h"

namespace signing {
namespace {

bool random_bytes(uint8_t* output, size_t output_len, void*)
{
    return fill_secure_random(output, output_len);
}

}  // namespace

const LocalTransportCryptoOps& stackchan_local_transport_crypto_ops()
{
    static LocalTransportMbedtlsCryptoContext context{
        random_bytes,
        nullptr,
    };
    static const LocalTransportCryptoOps ops =
        local_transport_mbedtls_crypto_ops(&context);
    return ops;
}

}  // namespace signing
