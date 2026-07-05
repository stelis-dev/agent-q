#pragma once

#include <stddef.h>
#include <stdint.h>

#include "session_state.h"
#include "transport/payload_delivery_admission.h"
#include "transport/payload_delivery_primitives.h"

namespace stopwatch_target {

constexpr size_t kPayloadTransferMaxBytes = signing::kPayloadDeliveryDefaultMaxBytes;
constexpr size_t kPayloadTransferChunkMaxBytes = signing::kPayloadDeliveryDefaultChunkMaxBytes;
constexpr size_t kPayloadDigestSize = signing::kPayloadDeliveryDigestSize;
constexpr size_t kPayloadTransferIdSize = signing::kPayloadDeliveryTransferIdSize;
constexpr size_t kPayloadRefSize = signing::kPayloadDeliveryPayloadRefSize;
constexpr uint32_t kPayloadTransferBaseWindowMs = signing::kPayloadDeliveryBaseWindowMs;
constexpr uint32_t kPayloadTransferPerChunkWindowMs = signing::kPayloadDeliveryPerChunkWindowMs;
constexpr uint32_t kPayloadTransferMaxWindowMs = signing::kPayloadDeliveryMaxWindowMs;

enum class PayloadTransferStatus {
    idle,
    receiving,
    finalized,
};

using PayloadTransferAdmissionOperation = signing::PayloadDeliveryOperationKind;
using PayloadTransferAdmissionResult = signing::PayloadDeliveryAdmissionResult;
using PayloadTransferAdmissionReason = signing::PayloadDeliveryAdmissionReason;
using PayloadTransferAdmissionDecision = signing::PayloadDeliveryAdmissionDecision;
using PayloadTransferResult = signing::PayloadDeliveryResult;

using PayloadDigestFn = bool (*)(const uint8_t* data, size_t size, char out[kPayloadDigestSize]);

struct PayloadTransferBeginOutput {
    char transfer_id[kPayloadTransferIdSize];
    size_t received_bytes;
    size_t chunk_max_bytes;
};

struct PayloadTransferFinishOutput {
    char payload_ref[kPayloadRefSize];
    size_t size_bytes;
    char payload_digest[kPayloadDigestSize];
};

struct PayloadTransferView {
    const uint8_t* bytes;
    size_t size_bytes;
};

struct PayloadTransferOwnedPayload {
    uint8_t* bytes;
    size_t size_bytes;
};

struct PayloadTransferSnapshot {
    PayloadTransferStatus status;
    char session_id[kSessionIdSize];
    char transfer_id[kPayloadTransferIdSize];
    char payload_ref[kPayloadRefSize];
    size_t declared_size_bytes;
    size_t received_bytes;
    uint32_t started_at_ms;
    uint32_t deadline_ms;
};

void payload_transfer_state_init();
void payload_transfer_clear_all();
bool payload_transfer_clear_expired(uint32_t now_ms);
bool payload_transfer_clear_for_session(const char* session_id);
PayloadTransferSnapshot payload_transfer_snapshot(uint32_t now_ms);
PayloadTransferAdmissionDecision payload_transfer_admit_operation(
    uint32_t now_ms,
    PayloadTransferAdmissionOperation operation);
bool payload_transfer_admission_blocks_sensitive_flow(
    const PayloadTransferAdmissionDecision& decision);
PayloadTransferResult payload_transfer_begin(
    uint32_t now_ms,
    const char* session_id,
    size_t total_bytes,
    const char* payload_digest,
    PayloadTransferBeginOutput* output);
PayloadTransferResult payload_transfer_append_chunk(
    uint32_t now_ms,
    const char* session_id,
    const char* transfer_id,
    size_t offset_bytes,
    const uint8_t* chunk,
    size_t chunk_size,
    size_t* received_bytes_out);
PayloadTransferResult payload_transfer_reject_chunk_too_large(
    uint32_t now_ms,
    const char* session_id,
    const char* transfer_id);
PayloadTransferResult payload_transfer_finish(
    uint32_t now_ms,
    const char* session_id,
    const char* transfer_id,
    PayloadDigestFn digest_fn,
    PayloadTransferFinishOutput* output);
PayloadTransferResult payload_transfer_abort(
    uint32_t now_ms,
    const char* session_id,
    const char* transfer_id,
    const char* payload_ref);
PayloadTransferResult payload_transfer_resolve(
    uint32_t now_ms,
    const char* session_id,
    const char* payload_ref,
    PayloadTransferView* output);
PayloadTransferResult payload_transfer_take(
    uint32_t now_ms,
    const char* session_id,
    const char* payload_ref,
    PayloadTransferOwnedPayload* output);
void payload_transfer_wipe_owned_payload(PayloadTransferOwnedPayload* payload);

}  // namespace stopwatch_target
