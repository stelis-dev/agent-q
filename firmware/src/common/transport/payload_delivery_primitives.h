#pragma once

#include <stddef.h>
#include <stdint.h>

namespace signing {

constexpr size_t kPayloadDeliveryDigestSize = 72;       // "sha256:" + 64 hex + NUL.
constexpr size_t kPayloadDeliveryTransferIdSize = 82;   // "transfer_" + 72 chars + NUL.
constexpr size_t kPayloadDeliveryPayloadRefSize = 81;   // "payload_" + 72 chars + NUL.
constexpr size_t kPayloadDeliveryDefaultMaxBytes = 128 * 1024;
constexpr size_t kPayloadDeliveryDefaultChunkMaxBytes = 2700;
constexpr uint32_t kPayloadDeliveryBaseWindowMs = 30000;
constexpr uint32_t kPayloadDeliveryPerChunkWindowMs = 1000;
constexpr uint32_t kPayloadDeliveryMaxWindowMs = 180000;

enum class PayloadDeliveryResult {
    ok,
    invalid_argument,
    invalid_state,
    invalid_session,
    payload_too_large,
    invalid_payload_digest,
    invalid_transfer_id,
    invalid_payload_ref,
    allocation_failed,
    chunk_too_large,
    offset_mismatch,
    payload_overflow,
    size_mismatch,
    digest_mismatch,
    digest_error,
    not_found,
};

bool payload_delivery_transfer_id_format_valid(const char* value);
bool payload_delivery_payload_ref_format_valid(const char* value);
bool payload_delivery_payload_digest_format_valid(const char* value);
bool payload_delivery_format_transfer_id(uint64_t value, char* output, size_t output_size);
bool payload_delivery_format_payload_ref(uint64_t value, char* output, size_t output_size);
uint32_t payload_delivery_timeout_window_ms_for_size(size_t size_bytes);
const char* payload_delivery_result_name(PayloadDeliveryResult result);
const char* payload_delivery_transfer_error_code(PayloadDeliveryResult result);

}  // namespace signing
