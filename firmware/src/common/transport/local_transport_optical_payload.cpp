#include "local_transport_optical_payload.h"

#include <stdio.h>
#include <string.h>

namespace signing {
namespace {

constexpr size_t kLocalTransportNonceHexBytes =
    (kLocalTransportPairingNonceBytes * 2) + 1;

bool write_hex(const uint8_t* bytes, size_t bytes_len, char* output, size_t output_size)
{
    static constexpr char kHex[] = "0123456789abcdef";
    if (bytes == nullptr || output == nullptr || output_size < (bytes_len * 2) + 1) {
        return false;
    }
    for (size_t index = 0; index < bytes_len; ++index) {
        output[index * 2] = kHex[(bytes[index] >> 4) & 0x0F];
        output[(index * 2) + 1] = kHex[bytes[index] & 0x0F];
    }
    output[bytes_len * 2] = '\0';
    return true;
}

bool has_text(const char* value)
{
    return value != nullptr && value[0] != '\0';
}

}  // namespace

bool local_transport_build_optical_payload(
    const LocalTransportOpticalPayloadFields& fields,
    char* payload,
    size_t payload_size,
    char* fingerprint_hex,
    size_t fingerprint_hex_size)
{
    if (payload == nullptr || payload_size == 0 ||
        fingerprint_hex == nullptr || fingerprint_hex_size == 0) {
        return false;
    }
    payload[0] = '\0';
    fingerprint_hex[0] = '\0';

    if (!has_text(fields.transport_kind) || !has_text(fields.endpoint_descriptor_hex) ||
        fields.identity_fingerprint == nullptr ||
        fields.identity_fingerprint_size != kLocalTransportIdentityFingerprintBytes ||
        fields.nonce == nullptr ||
        fields.nonce_size != kLocalTransportPairingNonceBytes ||
        fields.expiry_seconds == 0) {
        return false;
    }

    char nonce_hex[kLocalTransportNonceHexBytes] = {};
    if (!write_hex(
            fields.identity_fingerprint,
            fields.identity_fingerprint_size,
            fingerprint_hex,
            fingerprint_hex_size) ||
        !write_hex(fields.nonce, fields.nonce_size, nonce_hex, sizeof(nonce_hex))) {
        fingerprint_hex[0] = '\0';
        return false;
    }

    const int written = snprintf(
        payload,
        payload_size,
        "aqlt:1?k=%s&svc=%s&idfp=%s&non=%s&exp=%u",
        fields.transport_kind,
        fields.endpoint_descriptor_hex,
        fingerprint_hex,
        nonce_hex,
        static_cast<unsigned>(fields.expiry_seconds));
    if (written <= 0 || static_cast<size_t>(written) >= payload_size) {
        payload[0] = '\0';
        fingerprint_hex[0] = '\0';
        return false;
    }
    return true;
}

}  // namespace signing
