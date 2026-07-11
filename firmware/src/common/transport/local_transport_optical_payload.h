#pragma once

#include <stddef.h>
#include <stdint.h>

namespace signing {

constexpr size_t kLocalTransportIdentityFingerprintBytes = 8;
constexpr size_t kLocalTransportX25519KeyBytes = 32;
constexpr size_t kLocalTransportPairingNonceBytes = 8;
constexpr size_t kLocalTransportFingerprintHexBytes =
    (kLocalTransportIdentityFingerprintBytes * 2) + 1;
constexpr size_t kLocalTransportOpticalPayloadMaxBytes = 128;

constexpr const char* kLocalTransportKindBle = "ble";
constexpr const char* kLocalTransportBleServiceUuidHex =
    "a6e31d1051a14f7a9b0a0a1c00000001";

struct LocalTransportOpticalPayloadFields {
    const char* transport_kind;
    const char* endpoint_descriptor_hex;
    const uint8_t* identity_fingerprint;
    size_t identity_fingerprint_size;
    const uint8_t* nonce;
    size_t nonce_size;
    uint32_t expiry_seconds;
};

bool local_transport_build_optical_payload(
    const LocalTransportOpticalPayloadFields& fields,
    char* payload,
    size_t payload_size,
    char* fingerprint_hex,
    size_t fingerprint_hex_size);

}  // namespace signing
