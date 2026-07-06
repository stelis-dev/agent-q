#include "payload_delivery_store.h"

#include <stdlib.h>
#include <string.h>

#include "transport/timeout_window.h"

namespace signing {
namespace {

struct PayloadDeliveryStore {
    PayloadDeliveryState state = PayloadDeliveryState::idle;
    char session_id[kSessionIdSize] = {};
    char transfer_id[kPayloadDeliveryTransferIdSize] = {};
    char payload_ref[kPayloadDeliveryPayloadRefSize] = {};
    size_t declared_size_bytes = 0;
    size_t received_bytes = 0;
    size_t chunk_max_bytes = 0;
    size_t payload_max_bytes = 0;
    TimeoutWindow timeout_window = kTimeoutWindowNone;
    char expected_payload_digest[kPayloadDeliveryDigestSize] = {};
    uint8_t* buffer = nullptr;
};

PayloadDeliveryStore g_store;
uint64_t g_next_transfer_id = 1;
uint64_t g_next_payload_ref = 1;

void wipe_bytes(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool string_equal(const char* left, const char* right)
{
    if (left == nullptr || right == nullptr) {
        return false;
    }
    return strcmp(left, right) == 0;
}

bool copy_nonempty_string(const char* input, char* output, size_t output_size)
{
    if (input == nullptr || output == nullptr || output_size == 0) {
        return false;
    }
    const size_t length = strlen(input);
    if (length == 0 || length + 1 > output_size) {
        memset(output, 0, output_size);
        return false;
    }
    memcpy(output, input, length + 1);
    return true;
}

void wipe_and_free_buffer()
{
    if (g_store.buffer != nullptr) {
        wipe_bytes(g_store.buffer, g_store.declared_size_bytes);
        free(g_store.buffer);
        g_store.buffer = nullptr;
    }
}

void reset_store_without_wipe()
{
    memset(&g_store, 0, sizeof(g_store));
    g_store.state = PayloadDeliveryState::idle;
}

void clear_store()
{
    wipe_and_free_buffer();
    reset_store_without_wipe();
}

bool advance_store_to(TimeoutTick now_tick)
{
    if (g_store.state == PayloadDeliveryState::idle ||
        !timeout_window_reached(g_store.timeout_window, now_tick)) {
        return false;
    }
    clear_store();
    return true;
}

PayloadDeliverySnapshot snapshot_current_store()
{
    PayloadDeliverySnapshot snapshot = {};
    snapshot.state = g_store.state;
    memcpy(snapshot.session_id, g_store.session_id, sizeof(snapshot.session_id));
    memcpy(snapshot.transfer_id, g_store.transfer_id, sizeof(snapshot.transfer_id));
    memcpy(snapshot.payload_ref, g_store.payload_ref, sizeof(snapshot.payload_ref));
    snapshot.declared_size_bytes = g_store.declared_size_bytes;
    snapshot.received_bytes = g_store.received_bytes;
    snapshot.chunk_max_bytes = g_store.chunk_max_bytes;
    snapshot.payload_max_bytes = g_store.payload_max_bytes;
    snapshot.timeout_window = g_store.timeout_window;
    return snapshot;
}

bool active_session_matches(const char* session_id)
{
    return session_id_format_valid(session_id) &&
           string_equal(g_store.session_id, session_id);
}

PayloadDeliveryResult validate_active_transfer_ref(
    const char* session_id,
    const char* transfer_id)
{
    if (!session_id_format_valid(session_id)) {
        return PayloadDeliveryResult::invalid_session;
    }
    if (!payload_delivery_transfer_id_format_valid(transfer_id)) {
        return PayloadDeliveryResult::invalid_transfer_id;
    }
    if (!string_equal(g_store.session_id, session_id)) {
        return PayloadDeliveryResult::invalid_session;
    }
    if (!string_equal(g_store.transfer_id, transfer_id)) {
        return PayloadDeliveryResult::not_found;
    }
    return PayloadDeliveryResult::ok;
}

PayloadDeliveryResult validate_finalized_payload_ref(
    const char* session_id,
    const char* payload_ref)
{
    if (!session_id_format_valid(session_id)) {
        return PayloadDeliveryResult::invalid_session;
    }
    if (!payload_delivery_payload_ref_format_valid(payload_ref)) {
        return PayloadDeliveryResult::invalid_payload_ref;
    }
    if (!string_equal(g_store.session_id, session_id)) {
        return PayloadDeliveryResult::invalid_session;
    }
    if (!string_equal(g_store.payload_ref, payload_ref)) {
        return PayloadDeliveryResult::not_found;
    }
    return PayloadDeliveryResult::ok;
}

void fill_descriptor(PayloadDeliveryDescriptor* descriptor)
{
    if (descriptor == nullptr) {
        return;
    }
    memset(descriptor, 0, sizeof(*descriptor));
    memcpy(descriptor->session_id, g_store.session_id, sizeof(descriptor->session_id));
    memcpy(descriptor->payload_ref, g_store.payload_ref, sizeof(descriptor->payload_ref));
    descriptor->size_bytes = g_store.declared_size_bytes;
    memcpy(
        descriptor->payload_digest,
        g_store.expected_payload_digest,
        sizeof(descriptor->payload_digest));
}

PayloadDeliveryResult validate_begin_input(
    TimeoutTick now_tick,
    const PayloadDeliveryBeginInput& input)
{
    if (!session_id_format_valid(input.session_id)) {
        return PayloadDeliveryResult::invalid_session;
    }
    if (input.size_bytes == 0 ||
        input.limits.payload_max_bytes == 0 ||
        input.size_bytes > input.limits.payload_max_bytes ||
        input.limits.payload_max_bytes > kPayloadDeliveryDefaultMaxBytes) {
        return PayloadDeliveryResult::payload_too_large;
    }
    if (input.limits.chunk_max_bytes == 0 ||
        input.limits.chunk_max_bytes > input.limits.payload_max_bytes) {
        return PayloadDeliveryResult::invalid_argument;
    }
    if (!timeout_window_valid(input.timeout_window) ||
        !timeout_window_open_at(input.timeout_window, now_tick)) {
        return PayloadDeliveryResult::invalid_argument;
    }
    if (!payload_delivery_payload_digest_format_valid(input.payload_digest)) {
        return PayloadDeliveryResult::invalid_payload_digest;
    }
    return PayloadDeliveryResult::ok;
}

}  // namespace

void payload_delivery_store_reset()
{
    clear_store();
    g_next_transfer_id = 1;
    g_next_payload_ref = 1;
}

PayloadDeliverySnapshot payload_delivery_advance_and_snapshot(TimeoutTick now_tick)
{
    advance_store_to(now_tick);
    return snapshot_current_store();
}

PayloadDeliveryResult payload_delivery_begin(
    TimeoutTick now_tick,
    const PayloadDeliveryBeginInput& input,
    PayloadDeliveryBeginOutput* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    advance_store_to(now_tick);
    if (output == nullptr) {
        return PayloadDeliveryResult::invalid_argument;
    }
    if (g_store.state != PayloadDeliveryState::idle) {
        return PayloadDeliveryResult::invalid_state;
    }
    const PayloadDeliveryResult validation = validate_begin_input(now_tick, input);
    if (validation != PayloadDeliveryResult::ok) {
        return validation;
    }

    uint8_t* buffer = static_cast<uint8_t*>(malloc(input.size_bytes));
    if (buffer == nullptr) {
        return PayloadDeliveryResult::allocation_failed;
    }
    memset(buffer, 0, input.size_bytes);

    g_store.buffer = buffer;
    g_store.state = PayloadDeliveryState::receiving;
    copy_nonempty_string(input.session_id, g_store.session_id, sizeof(g_store.session_id));
    g_store.declared_size_bytes = input.size_bytes;
    g_store.received_bytes = 0;
    g_store.chunk_max_bytes = input.limits.chunk_max_bytes;
    g_store.payload_max_bytes = input.limits.payload_max_bytes;
    g_store.timeout_window = input.timeout_window;
    copy_nonempty_string(
        input.payload_digest,
        g_store.expected_payload_digest,
        sizeof(g_store.expected_payload_digest));
    if (!payload_delivery_format_transfer_id(
            g_next_transfer_id++,
            g_store.transfer_id,
            sizeof(g_store.transfer_id))) {
        clear_store();
        return PayloadDeliveryResult::invalid_argument;
    }

    memcpy(output->transfer_id, g_store.transfer_id, sizeof(output->transfer_id));
    output->received_bytes = g_store.received_bytes;
    output->chunk_max_bytes = g_store.chunk_max_bytes;
    return PayloadDeliveryResult::ok;
}

PayloadDeliveryResult payload_delivery_append_chunk(
    TimeoutTick now_tick,
    const PayloadDeliveryChunkInput& input,
    size_t* received_bytes_out)
{
    if (received_bytes_out != nullptr) {
        *received_bytes_out = 0;
    }
    advance_store_to(now_tick);
    if (input.chunk == nullptr || input.chunk_size == 0) {
        return PayloadDeliveryResult::invalid_argument;
    }
    if (g_store.state == PayloadDeliveryState::idle) {
        return PayloadDeliveryResult::not_found;
    }
    if (g_store.state != PayloadDeliveryState::receiving) {
        return PayloadDeliveryResult::invalid_state;
    }
    const PayloadDeliveryResult ref_result =
        validate_active_transfer_ref(input.session_id, input.transfer_id);
    if (ref_result != PayloadDeliveryResult::ok) {
        return ref_result;
    }
    if (input.chunk_size > g_store.chunk_max_bytes) {
        clear_store();
        return PayloadDeliveryResult::chunk_too_large;
    }
    if (input.offset_bytes != g_store.received_bytes) {
        clear_store();
        return PayloadDeliveryResult::offset_mismatch;
    }
    if (input.chunk_size > g_store.declared_size_bytes - g_store.received_bytes) {
        clear_store();
        return PayloadDeliveryResult::payload_overflow;
    }

    memcpy(g_store.buffer + g_store.received_bytes, input.chunk, input.chunk_size);
    g_store.received_bytes += input.chunk_size;
    if (received_bytes_out != nullptr) {
        *received_bytes_out = g_store.received_bytes;
    }
    return PayloadDeliveryResult::ok;
}

PayloadDeliveryResult payload_delivery_reject_chunk_too_large(
    TimeoutTick now_tick,
    const char* session_id,
    const char* transfer_id)
{
    advance_store_to(now_tick);
    if (g_store.state == PayloadDeliveryState::idle) {
        return PayloadDeliveryResult::not_found;
    }
    if (g_store.state != PayloadDeliveryState::receiving) {
        return PayloadDeliveryResult::invalid_state;
    }
    const PayloadDeliveryResult ref_result =
        validate_active_transfer_ref(session_id, transfer_id);
    if (ref_result != PayloadDeliveryResult::ok) {
        return ref_result;
    }
    clear_store();
    return PayloadDeliveryResult::chunk_too_large;
}

PayloadDeliveryResult payload_delivery_finish(
    TimeoutTick now_tick,
    const PayloadDeliveryFinishInput& input,
    PayloadDeliveryFinishOutput* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    advance_store_to(now_tick);
    if (output == nullptr) {
        return PayloadDeliveryResult::invalid_argument;
    }
    if (g_store.state == PayloadDeliveryState::idle) {
        return PayloadDeliveryResult::not_found;
    }
    if (g_store.state != PayloadDeliveryState::receiving) {
        return PayloadDeliveryResult::invalid_state;
    }
    const PayloadDeliveryResult ref_result =
        validate_active_transfer_ref(input.session_id, input.transfer_id);
    if (ref_result != PayloadDeliveryResult::ok) {
        return ref_result;
    }
    if (g_store.received_bytes != g_store.declared_size_bytes) {
        clear_store();
        return PayloadDeliveryResult::size_mismatch;
    }

    char actual_digest[kPayloadDeliveryDigestSize] = {};
    if (input.digest_payload == nullptr) {
        clear_store();
        return PayloadDeliveryResult::invalid_argument;
    }
    if (!input.digest_payload(
            g_store.buffer,
            g_store.declared_size_bytes,
            actual_digest,
            sizeof(actual_digest))) {
        clear_store();
        return PayloadDeliveryResult::digest_error;
    }
    if (!string_equal(actual_digest, g_store.expected_payload_digest)) {
        clear_store();
        return PayloadDeliveryResult::digest_mismatch;
    }

    if (!payload_delivery_format_payload_ref(
            g_next_payload_ref++,
            g_store.payload_ref,
            sizeof(g_store.payload_ref))) {
        clear_store();
        return PayloadDeliveryResult::invalid_argument;
    }
    g_store.state = PayloadDeliveryState::finalized;
    g_store.transfer_id[0] = '\0';
    fill_descriptor(&output->descriptor);
    return PayloadDeliveryResult::ok;
}

PayloadDeliveryResult payload_delivery_abort(
    TimeoutTick now_tick,
    const PayloadDeliveryAbortInput& input)
{
    advance_store_to(now_tick);
    const bool has_transfer_id = input.transfer_id != nullptr && input.transfer_id[0] != '\0';
    const bool has_payload_ref = input.payload_ref != nullptr && input.payload_ref[0] != '\0';
    if (input.session_id == nullptr || has_transfer_id == has_payload_ref) {
        return PayloadDeliveryResult::invalid_argument;
    }
    if (has_transfer_id) {
        if (g_store.state != PayloadDeliveryState::receiving) {
            return PayloadDeliveryResult::not_found;
        }
        const PayloadDeliveryResult ref_result =
            validate_active_transfer_ref(input.session_id, input.transfer_id);
        if (ref_result != PayloadDeliveryResult::ok) {
            return ref_result;
        }
        clear_store();
        return PayloadDeliveryResult::ok;
    }
    if (g_store.state != PayloadDeliveryState::finalized) {
        return PayloadDeliveryResult::not_found;
    }
    const PayloadDeliveryResult ref_result =
        validate_finalized_payload_ref(input.session_id, input.payload_ref);
    if (ref_result != PayloadDeliveryResult::ok) {
        return ref_result;
    }
    clear_store();
    return PayloadDeliveryResult::ok;
}

PayloadDeliveryResult payload_delivery_resolve_finalized(
    TimeoutTick now_tick,
    const char* session_id,
    const char* payload_ref,
    PayloadDeliveryView* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    advance_store_to(now_tick);
    if (output == nullptr) {
        return PayloadDeliveryResult::invalid_argument;
    }
    if (g_store.state != PayloadDeliveryState::finalized) {
        return PayloadDeliveryResult::not_found;
    }
    const PayloadDeliveryResult ref_result =
        validate_finalized_payload_ref(session_id, payload_ref);
    if (ref_result != PayloadDeliveryResult::ok) {
        return ref_result;
    }
    fill_descriptor(&output->descriptor);
    output->bytes = g_store.buffer;
    output->size_bytes = g_store.declared_size_bytes;
    return PayloadDeliveryResult::ok;
}

PayloadDeliveryResult payload_delivery_take_finalized(
    TimeoutTick now_tick,
    const char* session_id,
    const char* payload_ref,
    PayloadDeliveryOwnedPayload* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    advance_store_to(now_tick);
    if (output == nullptr) {
        return PayloadDeliveryResult::invalid_argument;
    }
    if (g_store.state != PayloadDeliveryState::finalized) {
        return PayloadDeliveryResult::not_found;
    }
    const PayloadDeliveryResult ref_result =
        validate_finalized_payload_ref(session_id, payload_ref);
    if (ref_result != PayloadDeliveryResult::ok) {
        return ref_result;
    }
    fill_descriptor(&output->descriptor);
    output->bytes = g_store.buffer;
    output->size_bytes = g_store.declared_size_bytes;
    g_store.buffer = nullptr;
    reset_store_without_wipe();
    return PayloadDeliveryResult::ok;
}

bool payload_delivery_clear_for_session(const char* session_id)
{
    if (g_store.state == PayloadDeliveryState::idle ||
        !active_session_matches(session_id)) {
        return false;
    }
    clear_store();
    return true;
}

bool payload_delivery_clear_expired(uint64_t now_tick)
{
    return advance_store_to(static_cast<TimeoutTick>(now_tick));
}

void payload_delivery_clear_all()
{
    clear_store();
}

}  // namespace signing
