#include "local_transport_optical_payload.h"

#include <stdio.h>
#include <string.h>

namespace signing {
namespace {

constexpr size_t kLocalTransportNonceHexBytes =
    (kLocalTransportPairingNonceBytes * 2) + 1;
constexpr size_t kLocalTransportBleServiceUuidHexBytes =
    (kLocalTransportBleServiceUuidBytes * 2);
constexpr const char* kPayloadPrefix = "aqlt:1?k=";
constexpr const char* kServiceMarker = "&svc=";
constexpr const char* kFingerprintMarker = "&idfp=";
constexpr const char* kNonceMarker = "&non=";
constexpr const char* kExpiryMarker = "&exp=";

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

bool read_hex_nibble(char value, uint8_t* output)
{
    if (output == nullptr) {
        return false;
    }
    if (value >= '0' && value <= '9') {
        *output = static_cast<uint8_t>(value - '0');
        return true;
    }
    if (value >= 'a' && value <= 'f') {
        *output = static_cast<uint8_t>(10 + value - 'a');
        return true;
    }
    return false;
}

bool read_hex_bytes(const char* input, size_t input_size, uint8_t* output, size_t output_size)
{
    if (input == nullptr || output == nullptr || input_size != output_size * 2) {
        return false;
    }
    for (size_t index = 0; index < output_size; ++index) {
        uint8_t high = 0;
        uint8_t low = 0;
        if (!read_hex_nibble(input[index * 2], &high) ||
            !read_hex_nibble(input[(index * 2) + 1], &low)) {
            return false;
        }
        output[index] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
}

bool consume_literal(const char*& cursor, const char* literal)
{
    if (cursor == nullptr || literal == nullptr) {
        return false;
    }
    const size_t literal_len = strlen(literal);
    if (strncmp(cursor, literal, literal_len) != 0) {
        return false;
    }
    cursor += literal_len;
    return true;
}

bool consume_text(const char*& cursor, const char* expected)
{
    return consume_literal(cursor, expected);
}

bool parse_expiry_seconds(const char* input, uint32_t* output)
{
    if (input == nullptr || output == nullptr || input[0] == '\0') {
        return false;
    }
    if (input[0] == '0') {
        return false;
    }

    uint32_t value = 0;
    for (const char* cursor = input; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
        const uint32_t digit = static_cast<uint32_t>(*cursor - '0');
        if (value > (UINT32_MAX - digit) / 10) {
            return false;
        }
        value = (value * 10) + digit;
    }
    if (value == 0) {
        return false;
    }
    *output = value;
    return true;
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

LocalTransportOpticalPayloadStatus local_transport_parse_optical_payload(
    const char* payload,
    LocalTransportParsedOpticalPayload* output)
{
    if (payload == nullptr || output == nullptr) {
        return LocalTransportOpticalPayloadStatus::invalid_argument;
    }
    memset(output, 0, sizeof(*output));

    const size_t payload_len = strlen(payload);
    if (payload_len == 0 || payload_len >= kLocalTransportOpticalPayloadMaxBytes) {
        return LocalTransportOpticalPayloadStatus::invalid_length;
    }

    const char* cursor = payload;
    if (!consume_literal(cursor, kPayloadPrefix)) {
        return LocalTransportOpticalPayloadStatus::invalid_format;
    }
    if (!consume_text(cursor, kLocalTransportKindBle)) {
        return LocalTransportOpticalPayloadStatus::unsupported_transport;
    }
    if (!consume_literal(cursor, kServiceMarker)) {
        return LocalTransportOpticalPayloadStatus::invalid_format;
    }
    if (strncmp(cursor, kLocalTransportBleServiceUuidHex, kLocalTransportBleServiceUuidHexBytes) != 0) {
        return LocalTransportOpticalPayloadStatus::unsupported_endpoint;
    }
    if (!read_hex_bytes(
            cursor,
            kLocalTransportBleServiceUuidHexBytes,
            output->service_uuid,
            sizeof(output->service_uuid))) {
        return LocalTransportOpticalPayloadStatus::invalid_hex;
    }
    cursor += kLocalTransportBleServiceUuidHexBytes;

    if (!consume_literal(cursor, kFingerprintMarker)) {
        return LocalTransportOpticalPayloadStatus::invalid_format;
    }
    if (!read_hex_bytes(
            cursor,
            kLocalTransportIdentityFingerprintBytes * 2,
            output->identity_fingerprint,
            sizeof(output->identity_fingerprint))) {
        return LocalTransportOpticalPayloadStatus::invalid_hex;
    }
    cursor += kLocalTransportIdentityFingerprintBytes * 2;

    if (!consume_literal(cursor, kNonceMarker)) {
        return LocalTransportOpticalPayloadStatus::invalid_format;
    }
    if (!read_hex_bytes(
            cursor,
            kLocalTransportPairingNonceBytes * 2,
            output->nonce,
            sizeof(output->nonce))) {
        return LocalTransportOpticalPayloadStatus::invalid_hex;
    }
    cursor += kLocalTransportPairingNonceBytes * 2;

    if (!consume_literal(cursor, kExpiryMarker)) {
        return LocalTransportOpticalPayloadStatus::invalid_format;
    }
    if (!parse_expiry_seconds(cursor, &output->expiry_seconds)) {
        memset(output, 0, sizeof(*output));
        return LocalTransportOpticalPayloadStatus::invalid_expiry;
    }

    return LocalTransportOpticalPayloadStatus::ok;
}

}  // namespace signing
