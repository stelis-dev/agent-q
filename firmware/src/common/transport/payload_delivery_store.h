#pragma once

#include <stddef.h>
#include <stdint.h>

#include "protocol/session_id.h"
#include "transport/timeout_window.h"
#include "transport/payload_delivery_primitives.h"

namespace signing {

enum class PayloadDeliveryState {
    idle,
    receiving,
    finalized,
};

struct PayloadDeliveryLimits {
    size_t chunk_max_bytes;
    size_t payload_max_bytes;
};

using PayloadDeliveryDigestFn =
    bool (*)(const uint8_t* payload, size_t payload_size, char* output, size_t output_size);

struct PayloadDeliveryBeginInput {
    const char* session_id;
    size_t size_bytes;
    const char* payload_digest;
    PayloadDeliveryLimits limits;
    TimeoutWindow timeout_window;
};

struct PayloadDeliveryBeginOutput {
    char transfer_id[kPayloadDeliveryTransferIdSize];
    size_t received_bytes;
    size_t chunk_max_bytes;
};

struct PayloadDeliveryChunkInput {
    const char* session_id;
    const char* transfer_id;
    size_t offset_bytes;
    const uint8_t* chunk;
    size_t chunk_size;
};

struct PayloadDeliveryFinishInput {
    const char* session_id;
    const char* transfer_id;
    PayloadDeliveryDigestFn digest_payload;
};

struct PayloadDeliveryAbortInput {
    const char* session_id;
    const char* transfer_id;
    const char* payload_ref;
};

struct PayloadDeliveryDescriptor {
    char session_id[kSessionIdSize];
    char payload_ref[kPayloadDeliveryPayloadRefSize];
    size_t size_bytes;
    char payload_digest[kPayloadDeliveryDigestSize];
};

struct PayloadDeliveryFinishOutput {
    PayloadDeliveryDescriptor descriptor;
};

struct PayloadDeliveryView {
    PayloadDeliveryDescriptor descriptor;
    const uint8_t* bytes;
    size_t size_bytes;
};

struct PayloadDeliveryOwnedPayload {
    PayloadDeliveryDescriptor descriptor;
    uint8_t* bytes;
    size_t size_bytes;
};

struct PayloadDeliverySnapshot {
    PayloadDeliveryState state;
    char session_id[kSessionIdSize];
    char transfer_id[kPayloadDeliveryTransferIdSize];
    char payload_ref[kPayloadDeliveryPayloadRefSize];
    size_t declared_size_bytes;
    size_t received_bytes;
    size_t chunk_max_bytes;
    size_t payload_max_bytes;
    TimeoutWindow timeout_window;
};

void payload_delivery_store_reset();
// Advances volatile payload delivery state to now_tick before returning a
// snapshot. Expired scratch is wiped by this call.
PayloadDeliverySnapshot payload_delivery_advance_and_snapshot(TimeoutTick now_tick);

PayloadDeliveryResult payload_delivery_begin(
    TimeoutTick now_tick,
    const PayloadDeliveryBeginInput& input,
    PayloadDeliveryBeginOutput* output);
PayloadDeliveryResult payload_delivery_append_chunk(
    TimeoutTick now_tick,
    const PayloadDeliveryChunkInput& input,
    size_t* received_bytes_out);
PayloadDeliveryResult payload_delivery_reject_chunk_too_large(
    TimeoutTick now_tick,
    const char* session_id,
    const char* transfer_id);
PayloadDeliveryResult payload_delivery_finish(
    TimeoutTick now_tick,
    const PayloadDeliveryFinishInput& input,
    PayloadDeliveryFinishOutput* output);
PayloadDeliveryResult payload_delivery_abort(
    TimeoutTick now_tick,
    const PayloadDeliveryAbortInput& input);
PayloadDeliveryResult payload_delivery_resolve_finalized(
    TimeoutTick now_tick,
    const char* session_id,
    const char* payload_ref,
    PayloadDeliveryView* output);
PayloadDeliveryResult payload_delivery_take_finalized(
    TimeoutTick now_tick,
    const char* session_id,
    const char* payload_ref,
    PayloadDeliveryOwnedPayload* output);

bool payload_delivery_clear_for_session(const char* session_id);
bool payload_delivery_clear_expired(uint64_t now_tick);
void payload_delivery_clear_all();

}  // namespace signing
