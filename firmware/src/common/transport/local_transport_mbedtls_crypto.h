#pragma once

#include "transport/local_transport_crypto.h"

namespace signing {

struct LocalTransportMbedtlsCryptoContext {
    bool (*random_bytes)(uint8_t* output, size_t output_len, void* context);
    void* random_context;
};

LocalTransportCryptoOps local_transport_mbedtls_crypto_ops(
    LocalTransportMbedtlsCryptoContext* context);

}  // namespace signing
