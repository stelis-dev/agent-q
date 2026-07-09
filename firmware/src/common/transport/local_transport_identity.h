#pragma once

#include <stddef.h>
#include <stdint.h>

#include "transport/local_transport_optical_payload.h"

namespace signing {

constexpr size_t kLocalTransportStaticKeyBytes = kLocalTransportX25519KeyBytes;

struct LocalTransportPairingIdentity {
    uint8_t public_key[kLocalTransportStaticKeyBytes];
    uint8_t fingerprint[kLocalTransportIdentityFingerprintBytes];
};

struct LocalTransportPairingIdentitySecret {
    uint8_t secret_key[kLocalTransportStaticKeyBytes];
    uint8_t public_key[kLocalTransportStaticKeyBytes];
    uint8_t fingerprint[kLocalTransportIdentityFingerprintBytes];
};

}  // namespace signing
