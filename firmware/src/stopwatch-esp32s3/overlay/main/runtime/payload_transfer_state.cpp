#include "payload_transfer_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sensitive_memory.h"
#include "transport/timeout_window.h"

namespace stopwatch_target {
namespace {

struct PayloadTransferState {
    PayloadTransferStatus status = PayloadTransferStatus::idle;
    char session_id[kSessionIdSize] = {};
    char transfer_id[kPayloadTransferIdSize] = {};
    char payload_ref[kPayloadRefSize] = {};
    size_t declared_size_bytes = 0;
    size_t received_bytes = 0;
    signing::TimeoutWindow timeout_window = signing::kTimeoutWindowNone;
    char expected_digest[kPayloadDigestSize] = {};
    uint8_t* buffer = nullptr;
};

PayloadTransferState g_state;
uint64_t g_next_transfer_id = 1;
uint64_t g_next_payload_ref = 1;

signing::PayloadDeliveryAdmissionState admission_state_from_transfer(
    PayloadTransferStatus status)
{
    switch (status) {
        case PayloadTransferStatus::idle:
            return signing::PayloadDeliveryAdmissionState::idle;
        case PayloadTransferStatus::receiving:
            return signing::PayloadDeliveryAdmissionState::receiving;
        case PayloadTransferStatus::finalized:
            return signing::PayloadDeliveryAdmissionState::finalized;
    }
    return signing::PayloadDeliveryAdmissionState::idle;
}

void wipe_and_free_buffer()
{
    if (g_state.buffer != nullptr) {
        wipe_sensitive_buffer(g_state.buffer, g_state.declared_size_bytes);
        free(g_state.buffer);
        g_state.buffer = nullptr;
    }
}

void reset_state_without_wipe()
{
    memset(&g_state, 0, sizeof(g_state));
    g_state.status = PayloadTransferStatus::idle;
}

bool string_equal(const char* left, const char* right)
{
    return left != nullptr && right != nullptr && strcmp(left, right) == 0;
}

bool clear_if_expired(uint32_t now_ms)
{
    if (g_state.status == PayloadTransferStatus::idle ||
        !signing::timeout_window_reached(g_state.timeout_window, now_ms)) {
        return false;
    }
    payload_transfer_clear_all();
    return true;
}

PayloadTransferResult validate_active_transfer_ref(
    const char* session_id,
    const char* transfer_id)
{
    if (!session_id_format_valid(session_id)) {
        return PayloadTransferResult::invalid_session;
    }
    if (!signing::payload_delivery_transfer_id_format_valid(transfer_id)) {
        return PayloadTransferResult::invalid_transfer_id;
    }
    if (!string_equal(session_id, g_state.session_id)) {
        return PayloadTransferResult::invalid_session;
    }
    if (!string_equal(transfer_id, g_state.transfer_id)) {
        return PayloadTransferResult::not_found;
    }
    return PayloadTransferResult::ok;
}

PayloadTransferResult validate_finalized_payload_ref(
    const char* session_id,
    const char* payload_ref)
{
    if (!session_id_format_valid(session_id)) {
        return PayloadTransferResult::invalid_session;
    }
    if (!signing::payload_delivery_payload_ref_format_valid(payload_ref)) {
        return PayloadTransferResult::invalid_payload_ref;
    }
    if (!string_equal(session_id, g_state.session_id)) {
        return PayloadTransferResult::invalid_session;
    }
    if (!string_equal(payload_ref, g_state.payload_ref)) {
        return PayloadTransferResult::not_found;
    }
    return PayloadTransferResult::ok;
}

void fill_snapshot(PayloadTransferSnapshot* snapshot)
{
    if (snapshot == nullptr) {
        return;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->status = g_state.status;
    memcpy(snapshot->session_id, g_state.session_id, sizeof(snapshot->session_id));
    memcpy(snapshot->transfer_id, g_state.transfer_id, sizeof(snapshot->transfer_id));
    memcpy(snapshot->payload_ref, g_state.payload_ref, sizeof(snapshot->payload_ref));
    snapshot->declared_size_bytes = g_state.declared_size_bytes;
    snapshot->received_bytes = g_state.received_bytes;
    snapshot->started_at_ms = g_state.timeout_window.started_at;
    snapshot->deadline_ms = g_state.timeout_window.deadline;
}

}  // namespace

void payload_transfer_state_init()
{
    payload_transfer_clear_all();
    g_next_transfer_id = 1;
    g_next_payload_ref = 1;
}

void payload_transfer_clear_all()
{
    wipe_and_free_buffer();
    reset_state_without_wipe();
}

bool payload_transfer_clear_for_session(const char* session_id)
{
    if (!session_id_format_valid(session_id)) {
        return false;
    }
    if (g_state.status != PayloadTransferStatus::idle &&
        string_equal(g_state.session_id, session_id)) {
        payload_transfer_clear_all();
        return true;
    }
    return false;
}

bool payload_transfer_clear_expired(uint32_t now_ms)
{
    return clear_if_expired(now_ms);
}

PayloadTransferSnapshot payload_transfer_snapshot(uint32_t now_ms)
{
    clear_if_expired(now_ms);
    PayloadTransferSnapshot snapshot;
    fill_snapshot(&snapshot);
    return snapshot;
}

PayloadTransferAdmissionDecision payload_transfer_admit_operation(
    uint32_t now_ms,
    PayloadTransferAdmissionOperation operation)
{
    const PayloadTransferSnapshot snapshot = payload_transfer_snapshot(now_ms);
    return signing::payload_delivery_admit_operation_for_state(
        admission_state_from_transfer(snapshot.status),
        operation);
}

bool payload_transfer_admission_blocks_sensitive_flow(
    const PayloadTransferAdmissionDecision& decision)
{
    return decision.result == PayloadTransferAdmissionResult::busy &&
           (decision.reason == PayloadTransferAdmissionReason::blocked_incomplete_transfer ||
            decision.reason == PayloadTransferAdmissionReason::blocked_pending_finalized_payload ||
            decision.reason == PayloadTransferAdmissionReason::blocked_unrelated_sensitive_flow);
}

PayloadTransferResult payload_transfer_begin(
    uint32_t now_ms,
    const char* session_id,
    size_t total_bytes,
    const char* payload_digest,
    PayloadTransferBeginOutput* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return PayloadTransferResult::invalid_argument;
    }
    clear_if_expired(now_ms);
    if (!session_id_format_valid(session_id)) {
        return PayloadTransferResult::invalid_session;
    }
    if (g_state.status != PayloadTransferStatus::idle) {
        return PayloadTransferResult::invalid_state;
    }
    if (total_bytes == 0 || total_bytes > kPayloadTransferMaxBytes) {
        return PayloadTransferResult::payload_too_large;
    }
    if (!signing::payload_delivery_payload_digest_format_valid(payload_digest)) {
        return PayloadTransferResult::invalid_payload_digest;
    }
    const uint32_t window_ms =
        signing::payload_delivery_timeout_window_ms_for_size(total_bytes);
    const signing::TimeoutWindow timeout_window =
        signing::timeout_window_from_deadline(now_ms, now_ms + window_ms);
    if (!signing::timeout_window_valid_and_open_at(timeout_window, now_ms)) {
        return PayloadTransferResult::invalid_argument;
    }

    uint8_t* buffer = static_cast<uint8_t*>(malloc(total_bytes));
    if (buffer == nullptr) {
        return PayloadTransferResult::allocation_failed;
    }
    memset(buffer, 0, total_bytes);

    g_state.buffer = buffer;
    g_state.status = PayloadTransferStatus::receiving;
    snprintf(g_state.session_id, sizeof(g_state.session_id), "%s", session_id);
    if (!signing::payload_delivery_format_transfer_id(
            g_next_transfer_id++,
            g_state.transfer_id,
            sizeof(g_state.transfer_id))) {
        payload_transfer_clear_all();
        return PayloadTransferResult::invalid_argument;
    }
    snprintf(g_state.expected_digest, sizeof(g_state.expected_digest), "%s", payload_digest);
    g_state.declared_size_bytes = total_bytes;
    g_state.received_bytes = 0;
    g_state.timeout_window = timeout_window;

    memcpy(output->transfer_id, g_state.transfer_id, sizeof(output->transfer_id));
    output->received_bytes = 0;
    output->chunk_max_bytes = kPayloadTransferChunkMaxBytes;
    return PayloadTransferResult::ok;
}

PayloadTransferResult payload_transfer_append_chunk(
    uint32_t now_ms,
    const char* session_id,
    const char* transfer_id,
    size_t offset_bytes,
    const uint8_t* chunk,
    size_t chunk_size,
    size_t* received_bytes_out)
{
    if (received_bytes_out != nullptr) {
        *received_bytes_out = 0;
    }
    clear_if_expired(now_ms);
    if (chunk == nullptr || chunk_size == 0) {
        return PayloadTransferResult::invalid_argument;
    }
    if (g_state.status == PayloadTransferStatus::idle) {
        return PayloadTransferResult::not_found;
    }
    if (g_state.status != PayloadTransferStatus::receiving) {
        return PayloadTransferResult::invalid_state;
    }
    const PayloadTransferResult ref_result =
        validate_active_transfer_ref(session_id, transfer_id);
    if (ref_result != PayloadTransferResult::ok) {
        return ref_result;
    }
    if (chunk_size > kPayloadTransferChunkMaxBytes) {
        payload_transfer_clear_all();
        return PayloadTransferResult::chunk_too_large;
    }
    if (offset_bytes != g_state.received_bytes) {
        payload_transfer_clear_all();
        return PayloadTransferResult::offset_mismatch;
    }
    if (chunk_size > g_state.declared_size_bytes - g_state.received_bytes) {
        payload_transfer_clear_all();
        return PayloadTransferResult::payload_overflow;
    }
    memcpy(g_state.buffer + g_state.received_bytes, chunk, chunk_size);
    g_state.received_bytes += chunk_size;
    if (received_bytes_out != nullptr) {
        *received_bytes_out = g_state.received_bytes;
    }
    return PayloadTransferResult::ok;
}

PayloadTransferResult payload_transfer_reject_chunk_too_large(
    uint32_t now_ms,
    const char* session_id,
    const char* transfer_id)
{
    clear_if_expired(now_ms);
    if (g_state.status == PayloadTransferStatus::idle) {
        return PayloadTransferResult::not_found;
    }
    if (g_state.status != PayloadTransferStatus::receiving) {
        return PayloadTransferResult::invalid_state;
    }
    const PayloadTransferResult ref_result =
        validate_active_transfer_ref(session_id, transfer_id);
    if (ref_result != PayloadTransferResult::ok) {
        return ref_result;
    }
    payload_transfer_clear_all();
    return PayloadTransferResult::chunk_too_large;
}

PayloadTransferResult payload_transfer_finish(
    uint32_t now_ms,
    const char* session_id,
    const char* transfer_id,
    PayloadDigestFn digest_fn,
    PayloadTransferFinishOutput* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr || digest_fn == nullptr) {
        return PayloadTransferResult::invalid_argument;
    }
    clear_if_expired(now_ms);
    if (g_state.status == PayloadTransferStatus::idle) {
        return PayloadTransferResult::not_found;
    }
    if (g_state.status != PayloadTransferStatus::receiving) {
        return PayloadTransferResult::invalid_state;
    }
    const PayloadTransferResult ref_result =
        validate_active_transfer_ref(session_id, transfer_id);
    if (ref_result != PayloadTransferResult::ok) {
        return ref_result;
    }
    if (g_state.received_bytes != g_state.declared_size_bytes) {
        payload_transfer_clear_all();
        return PayloadTransferResult::size_mismatch;
    }
    char actual_digest[kPayloadDigestSize] = {};
    if (!digest_fn(g_state.buffer, g_state.declared_size_bytes, actual_digest)) {
        payload_transfer_clear_all();
        return PayloadTransferResult::digest_error;
    }
    if (!string_equal(actual_digest, g_state.expected_digest)) {
        payload_transfer_clear_all();
        return PayloadTransferResult::digest_mismatch;
    }

    if (!signing::payload_delivery_format_payload_ref(
            g_next_payload_ref++,
            g_state.payload_ref,
            sizeof(g_state.payload_ref))) {
        payload_transfer_clear_all();
        return PayloadTransferResult::invalid_argument;
    }
    g_state.transfer_id[0] = '\0';
    g_state.status = PayloadTransferStatus::finalized;

    memcpy(output->payload_ref, g_state.payload_ref, sizeof(output->payload_ref));
    output->size_bytes = g_state.declared_size_bytes;
    memcpy(output->payload_digest, g_state.expected_digest, sizeof(output->payload_digest));
    return PayloadTransferResult::ok;
}

PayloadTransferResult payload_transfer_abort(
    uint32_t now_ms,
    const char* session_id,
    const char* transfer_id,
    const char* payload_ref)
{
    clear_if_expired(now_ms);
    const bool has_transfer_id = transfer_id != nullptr && transfer_id[0] != '\0';
    const bool has_payload_ref = payload_ref != nullptr && payload_ref[0] != '\0';
    if (session_id == nullptr || has_transfer_id == has_payload_ref) {
        return PayloadTransferResult::invalid_argument;
    }
    if (has_transfer_id) {
        if (g_state.status != PayloadTransferStatus::receiving) {
            return PayloadTransferResult::not_found;
        }
        const PayloadTransferResult ref_result =
            validate_active_transfer_ref(session_id, transfer_id);
        if (ref_result != PayloadTransferResult::ok) {
            return ref_result;
        }
    } else {
        if (g_state.status != PayloadTransferStatus::finalized) {
            return PayloadTransferResult::not_found;
        }
        const PayloadTransferResult ref_result =
            validate_finalized_payload_ref(session_id, payload_ref);
        if (ref_result != PayloadTransferResult::ok) {
            return ref_result;
        }
    }
    payload_transfer_clear_all();
    return PayloadTransferResult::ok;
}

PayloadTransferResult payload_transfer_resolve(
    uint32_t now_ms,
    const char* session_id,
    const char* payload_ref,
    PayloadTransferView* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return PayloadTransferResult::invalid_argument;
    }
    clear_if_expired(now_ms);
    if (g_state.status != PayloadTransferStatus::finalized) {
        return PayloadTransferResult::not_found;
    }
    const PayloadTransferResult ref_result =
        validate_finalized_payload_ref(session_id, payload_ref);
    if (ref_result != PayloadTransferResult::ok) {
        return ref_result;
    }
    output->bytes = g_state.buffer;
    output->size_bytes = g_state.declared_size_bytes;
    return PayloadTransferResult::ok;
}

PayloadTransferResult payload_transfer_take(
    uint32_t now_ms,
    const char* session_id,
    const char* payload_ref,
    PayloadTransferOwnedPayload* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return PayloadTransferResult::invalid_argument;
    }

    PayloadTransferView view = {};
    const PayloadTransferResult result =
        payload_transfer_resolve(now_ms, session_id, payload_ref, &view);
    if (result != PayloadTransferResult::ok) {
        return result;
    }

    output->bytes = g_state.buffer;
    output->size_bytes = g_state.declared_size_bytes;
    g_state.buffer = nullptr;
    reset_state_without_wipe();
    return PayloadTransferResult::ok;
}

void payload_transfer_wipe_owned_payload(PayloadTransferOwnedPayload* payload)
{
    if (payload == nullptr) {
        return;
    }
    if (payload->bytes != nullptr) {
        wipe_sensitive_buffer(payload->bytes, payload->size_bytes);
        free(payload->bytes);
    }
    payload->bytes = nullptr;
    payload->size_bytes = 0;
}

}  // namespace stopwatch_target
