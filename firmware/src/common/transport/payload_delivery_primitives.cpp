#include "transport/payload_delivery_primitives.h"

#include <stdio.h>
#include <string.h>

namespace signing {
namespace {

bool id_matches_prefix(const char* value, const char* prefix, size_t max_size)
{
    if (value == nullptr || prefix == nullptr) {
        return false;
    }
    const size_t prefix_size = strlen(prefix);
    const size_t value_size = strlen(value);
    if (value_size <= prefix_size ||
        value_size + 1 > max_size ||
        strncmp(value, prefix, prefix_size) != 0) {
        return false;
    }
    for (size_t index = prefix_size; index < value_size; ++index) {
        const char ch = value[index];
        if ((ch < 'A' || ch > 'Z') &&
            (ch < 'a' || ch > 'z') &&
            (ch < '0' || ch > '9') &&
            ch != '_' &&
            ch != '.' &&
            ch != '-') {
            return false;
        }
    }
    return true;
}

bool format_opaque_id(const char* prefix, uint64_t value, char* output, size_t output_size)
{
    if (prefix == nullptr || output == nullptr || output_size == 0) {
        return false;
    }
    constexpr char kHex[] = "0123456789abcdef";
    const size_t prefix_size = strlen(prefix);
    constexpr size_t kHexDigits = 16;
    if (prefix_size + kHexDigits + 1 > output_size) {
        return false;
    }
    memcpy(output, prefix, prefix_size);
    for (size_t index = 0; index < kHexDigits; ++index) {
        const size_t shift = (kHexDigits - 1 - index) * 4;
        output[prefix_size + index] = kHex[(value >> shift) & 0x0f];
    }
    output[prefix_size + kHexDigits] = '\0';
    return true;
}

}  // namespace

bool payload_delivery_transfer_id_format_valid(const char* value)
{
    return id_matches_prefix(value, "transfer_", kPayloadDeliveryTransferIdSize);
}

bool payload_delivery_payload_ref_format_valid(const char* value)
{
    return id_matches_prefix(value, "payload_", kPayloadDeliveryPayloadRefSize);
}

bool payload_delivery_payload_digest_format_valid(const char* value)
{
    constexpr const char* kPrefix = "sha256:";
    if (value == nullptr ||
        strlen(value) != kPayloadDeliveryDigestSize - 1 ||
        strncmp(value, kPrefix, strlen(kPrefix)) != 0) {
        return false;
    }
    for (const char* cursor = value + strlen(kPrefix); *cursor != '\0'; ++cursor) {
        const char ch = *cursor;
        if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) {
            return false;
        }
    }
    return true;
}

bool payload_delivery_format_transfer_id(uint64_t value, char* output, size_t output_size)
{
    return format_opaque_id("transfer_", value, output, output_size);
}

bool payload_delivery_format_payload_ref(uint64_t value, char* output, size_t output_size)
{
    return format_opaque_id("payload_", value, output, output_size);
}

uint32_t payload_delivery_timeout_window_ms_for_size(size_t size_bytes)
{
    const size_t chunk_count =
        (size_bytes / kPayloadDeliveryDefaultChunkMaxBytes) +
        ((size_bytes % kPayloadDeliveryDefaultChunkMaxBytes) == 0 ? 0 : 1);
    uint64_t window_ms =
        static_cast<uint64_t>(kPayloadDeliveryBaseWindowMs) +
        static_cast<uint64_t>(chunk_count) *
            static_cast<uint64_t>(kPayloadDeliveryPerChunkWindowMs);
    if (window_ms > kPayloadDeliveryMaxWindowMs) {
        window_ms = kPayloadDeliveryMaxWindowMs;
    }
    return static_cast<uint32_t>(window_ms);
}

const char* payload_delivery_result_name(PayloadDeliveryResult result)
{
    switch (result) {
        case PayloadDeliveryResult::ok:
            return "ok";
        case PayloadDeliveryResult::invalid_argument:
            return "invalid_argument";
        case PayloadDeliveryResult::invalid_state:
            return "invalid_state";
        case PayloadDeliveryResult::invalid_session:
            return "invalid_session";
        case PayloadDeliveryResult::payload_too_large:
            return "payload_too_large";
        case PayloadDeliveryResult::invalid_payload_digest:
            return "invalid_payload_digest";
        case PayloadDeliveryResult::invalid_transfer_id:
            return "invalid_transfer_id";
        case PayloadDeliveryResult::invalid_payload_ref:
            return "invalid_payload_ref";
        case PayloadDeliveryResult::allocation_failed:
            return "allocation_failed";
        case PayloadDeliveryResult::chunk_too_large:
            return "chunk_too_large";
        case PayloadDeliveryResult::offset_mismatch:
            return "offset_mismatch";
        case PayloadDeliveryResult::payload_overflow:
            return "payload_overflow";
        case PayloadDeliveryResult::size_mismatch:
            return "size_mismatch";
        case PayloadDeliveryResult::digest_mismatch:
            return "digest_mismatch";
        case PayloadDeliveryResult::digest_error:
            return "digest_error";
        case PayloadDeliveryResult::not_found:
            return "not_found";
    }
    return "unknown";
}

const char* payload_delivery_transfer_error_code(PayloadDeliveryResult result)
{
    switch (result) {
        case PayloadDeliveryResult::invalid_session:
            return "invalid_session";
        case PayloadDeliveryResult::invalid_state:
            return "busy";
        case PayloadDeliveryResult::payload_too_large:
            return "payload_too_large";
        case PayloadDeliveryResult::allocation_failed:
        case PayloadDeliveryResult::digest_error:
            return "internal_output_error";
        case PayloadDeliveryResult::not_found:
            return "unknown_request";
        case PayloadDeliveryResult::ok:
            return "internal_output_error";
        case PayloadDeliveryResult::invalid_argument:
        case PayloadDeliveryResult::invalid_payload_digest:
        case PayloadDeliveryResult::invalid_transfer_id:
        case PayloadDeliveryResult::invalid_payload_ref:
        case PayloadDeliveryResult::chunk_too_large:
        case PayloadDeliveryResult::offset_mismatch:
        case PayloadDeliveryResult::payload_overflow:
        case PayloadDeliveryResult::size_mismatch:
        case PayloadDeliveryResult::digest_mismatch:
        default:
            return "invalid_params";
    }
}

}  // namespace signing
