#include "agent_q_payload_delivery_store.h"

#include <stdlib.h>
#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_timeout_window.h"

namespace agent_q {
namespace {

struct AgentQPayloadDeliveryStore {
    AgentQPayloadDeliveryState state = AgentQPayloadDeliveryState::idle;
    char session_id[kAgentQSessionIdSize] = {};
    char upload_id[kAgentQPayloadDeliveryUploadIdSize] = {};
    char payload_ref[kAgentQPayloadDeliveryPayloadRefSize] = {};
    AgentQSupportedSignRoute route = AgentQSupportedSignRoute::unsupported;
    char payload_kind[kAgentQPayloadDeliveryPayloadKindSize] = {};
    size_t declared_size_bytes = 0;
    size_t received_bytes = 0;
    size_t chunk_max_bytes = 0;
    size_t payload_max_bytes = 0;
    AgentQTimeoutWindow timeout_window = kAgentQTimeoutWindowNone;
    char expected_payload_digest[kAgentQApprovalHistoryDigestSize] = {};
    uint8_t* buffer = nullptr;
};

AgentQPayloadDeliveryStore g_store;
uint64_t g_next_upload_id = 1;
uint64_t g_next_payload_ref = 1;

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
        wipe_sensitive_buffer(g_store.buffer, g_store.declared_size_bytes);
        free(g_store.buffer);
        g_store.buffer = nullptr;
    }
}

void reset_store_without_wipe()
{
    memset(&g_store, 0, sizeof(g_store));
    g_store.state = AgentQPayloadDeliveryState::idle;
    g_store.route = AgentQSupportedSignRoute::unsupported;
}

void clear_store()
{
    wipe_and_free_buffer();
    reset_store_without_wipe();
}

bool advance_store_to(AgentQTimeoutTick now_tick)
{
    if (g_store.state == AgentQPayloadDeliveryState::idle ||
        !timeout_window_reached(g_store.timeout_window, now_tick)) {
        return false;
    }
    clear_store();
    return true;
}

AgentQPayloadDeliverySnapshot snapshot_current_store()
{
    AgentQPayloadDeliverySnapshot snapshot = {};
    snapshot.state = g_store.state;
    memcpy(snapshot.session_id, g_store.session_id, sizeof(snapshot.session_id));
    memcpy(snapshot.upload_id, g_store.upload_id, sizeof(snapshot.upload_id));
    memcpy(snapshot.payload_ref, g_store.payload_ref, sizeof(snapshot.payload_ref));
    snapshot.route = g_store.route;
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

AgentQPayloadDeliveryResult validate_active_upload_ref(
    const char* session_id,
    const char* upload_id)
{
    if (!session_id_format_valid(session_id)) {
        return AgentQPayloadDeliveryResult::invalid_session;
    }
    if (!payload_delivery_upload_id_format_valid(upload_id)) {
        return AgentQPayloadDeliveryResult::invalid_upload_id;
    }
    if (!string_equal(g_store.session_id, session_id)) {
        return AgentQPayloadDeliveryResult::invalid_session;
    }
    if (!string_equal(g_store.upload_id, upload_id)) {
        return AgentQPayloadDeliveryResult::not_found;
    }
    return AgentQPayloadDeliveryResult::ok;
}

AgentQPayloadDeliveryResult validate_finalized_payload_ref(
    const char* session_id,
    const char* payload_ref)
{
    if (!session_id_format_valid(session_id)) {
        return AgentQPayloadDeliveryResult::invalid_session;
    }
    if (!payload_delivery_payload_ref_format_valid(payload_ref)) {
        return AgentQPayloadDeliveryResult::invalid_payload_ref;
    }
    if (!string_equal(g_store.session_id, session_id)) {
        return AgentQPayloadDeliveryResult::invalid_session;
    }
    if (!string_equal(g_store.payload_ref, payload_ref)) {
        return AgentQPayloadDeliveryResult::not_found;
    }
    return AgentQPayloadDeliveryResult::ok;
}

void fill_descriptor(AgentQPayloadDeliveryDescriptor* descriptor)
{
    if (descriptor == nullptr) {
        return;
    }
    memset(descriptor, 0, sizeof(*descriptor));
    memcpy(descriptor->session_id, g_store.session_id, sizeof(descriptor->session_id));
    memcpy(descriptor->payload_ref, g_store.payload_ref, sizeof(descriptor->payload_ref));
    descriptor->route = g_store.route;
    copy_nonempty_string(
        sign_route_wire_chain(g_store.route),
        descriptor->chain,
        sizeof(descriptor->chain));
    copy_nonempty_string(
        sign_route_wire_method(g_store.route),
        descriptor->method,
        sizeof(descriptor->method));
    memcpy(descriptor->payload_kind, g_store.payload_kind, sizeof(descriptor->payload_kind));
    descriptor->size_bytes = g_store.declared_size_bytes;
    memcpy(
        descriptor->payload_digest,
        g_store.expected_payload_digest,
        sizeof(descriptor->payload_digest));
}

AgentQPayloadDeliveryResult validate_begin_input(
    AgentQTimeoutTick now_tick,
    const AgentQPayloadDeliveryBeginInput& input)
{
    if (!session_id_format_valid(input.session_id)) {
        return AgentQPayloadDeliveryResult::invalid_session;
    }
    if (input.route != AgentQSupportedSignRoute::sui_sign_transaction) {
        return AgentQPayloadDeliveryResult::unsupported_method;
    }
    if (!string_equal(input.payload_kind, kAgentQPayloadDeliveryPayloadKindTransaction)) {
        return AgentQPayloadDeliveryResult::unsupported_payload_kind;
    }
    if (input.size_bytes == 0 ||
        input.limits.payload_max_bytes == 0 ||
        input.size_bytes > input.limits.payload_max_bytes ||
        input.limits.payload_max_bytes > kAgentQPayloadDeliveryDefaultMaxBytes) {
        return AgentQPayloadDeliveryResult::unsupported_payload_size;
    }
    if (input.limits.chunk_max_bytes == 0 ||
        input.limits.chunk_max_bytes > input.limits.payload_max_bytes) {
        return AgentQPayloadDeliveryResult::invalid_argument;
    }
    if (!timeout_window_valid(input.timeout_window) ||
        !timeout_window_open_at(input.timeout_window, now_tick)) {
        return AgentQPayloadDeliveryResult::invalid_argument;
    }
    if (!payload_delivery_payload_digest_format_valid(input.payload_digest)) {
        return AgentQPayloadDeliveryResult::invalid_payload_digest;
    }
    return AgentQPayloadDeliveryResult::ok;
}

}  // namespace

void payload_delivery_store_reset()
{
    clear_store();
    g_next_upload_id = 1;
    g_next_payload_ref = 1;
}

AgentQPayloadDeliverySnapshot payload_delivery_advance_and_snapshot(AgentQTimeoutTick now_tick)
{
    advance_store_to(now_tick);
    return snapshot_current_store();
}

AgentQPayloadDeliveryResult payload_delivery_begin(
    AgentQTimeoutTick now_tick,
    const AgentQPayloadDeliveryBeginInput& input,
    AgentQPayloadDeliveryBeginOutput* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    advance_store_to(now_tick);
    if (output == nullptr) {
        return AgentQPayloadDeliveryResult::invalid_argument;
    }
    if (g_store.state != AgentQPayloadDeliveryState::idle) {
        return AgentQPayloadDeliveryResult::invalid_state;
    }
    const AgentQPayloadDeliveryResult validation = validate_begin_input(now_tick, input);
    if (validation != AgentQPayloadDeliveryResult::ok) {
        return validation;
    }

    uint8_t* buffer = static_cast<uint8_t*>(malloc(input.size_bytes));
    if (buffer == nullptr) {
        return AgentQPayloadDeliveryResult::allocation_failed;
    }
    memset(buffer, 0, input.size_bytes);

    g_store.buffer = buffer;
    g_store.state = AgentQPayloadDeliveryState::receiving;
    copy_nonempty_string(input.session_id, g_store.session_id, sizeof(g_store.session_id));
    g_store.route = input.route;
    copy_nonempty_string(input.payload_kind, g_store.payload_kind, sizeof(g_store.payload_kind));
    g_store.declared_size_bytes = input.size_bytes;
    g_store.received_bytes = 0;
    g_store.chunk_max_bytes = input.limits.chunk_max_bytes;
    g_store.payload_max_bytes = input.limits.payload_max_bytes;
    g_store.timeout_window = input.timeout_window;
    copy_nonempty_string(
        input.payload_digest,
        g_store.expected_payload_digest,
        sizeof(g_store.expected_payload_digest));
    if (!payload_delivery_format_upload_id(
            g_next_upload_id++,
            g_store.upload_id,
            sizeof(g_store.upload_id))) {
        clear_store();
        return AgentQPayloadDeliveryResult::invalid_argument;
    }

    memcpy(output->upload_id, g_store.upload_id, sizeof(output->upload_id));
    output->received_bytes = g_store.received_bytes;
    output->chunk_max_bytes = g_store.chunk_max_bytes;
    return AgentQPayloadDeliveryResult::ok;
}

AgentQPayloadDeliveryResult payload_delivery_append_chunk(
    AgentQTimeoutTick now_tick,
    const AgentQPayloadDeliveryChunkInput& input,
    size_t* received_bytes_out)
{
    if (received_bytes_out != nullptr) {
        *received_bytes_out = 0;
    }
    advance_store_to(now_tick);
    if (input.chunk == nullptr || input.chunk_size == 0) {
        return AgentQPayloadDeliveryResult::invalid_argument;
    }
    if (g_store.state == AgentQPayloadDeliveryState::idle) {
        return AgentQPayloadDeliveryResult::not_found;
    }
    if (g_store.state != AgentQPayloadDeliveryState::receiving) {
        return AgentQPayloadDeliveryResult::invalid_state;
    }
    const AgentQPayloadDeliveryResult ref_result =
        validate_active_upload_ref(input.session_id, input.upload_id);
    if (ref_result != AgentQPayloadDeliveryResult::ok) {
        return ref_result;
    }
    if (input.chunk_size > g_store.chunk_max_bytes) {
        clear_store();
        return AgentQPayloadDeliveryResult::chunk_too_large;
    }
    if (input.offset_bytes != g_store.received_bytes) {
        clear_store();
        return AgentQPayloadDeliveryResult::offset_mismatch;
    }
    if (input.chunk_size > g_store.declared_size_bytes - g_store.received_bytes) {
        clear_store();
        return AgentQPayloadDeliveryResult::payload_overflow;
    }

    memcpy(g_store.buffer + g_store.received_bytes, input.chunk, input.chunk_size);
    g_store.received_bytes += input.chunk_size;
    if (received_bytes_out != nullptr) {
        *received_bytes_out = g_store.received_bytes;
    }
    return AgentQPayloadDeliveryResult::ok;
}

AgentQPayloadDeliveryResult payload_delivery_reject_chunk_too_large(
    AgentQTimeoutTick now_tick,
    const char* session_id,
    const char* upload_id)
{
    advance_store_to(now_tick);
    if (g_store.state == AgentQPayloadDeliveryState::idle) {
        return AgentQPayloadDeliveryResult::not_found;
    }
    if (g_store.state != AgentQPayloadDeliveryState::receiving) {
        return AgentQPayloadDeliveryResult::invalid_state;
    }
    const AgentQPayloadDeliveryResult ref_result =
        validate_active_upload_ref(session_id, upload_id);
    if (ref_result != AgentQPayloadDeliveryResult::ok) {
        return ref_result;
    }
    clear_store();
    return AgentQPayloadDeliveryResult::chunk_too_large;
}

AgentQPayloadDeliveryResult payload_delivery_finish(
    AgentQTimeoutTick now_tick,
    const AgentQPayloadDeliveryFinishInput& input,
    AgentQPayloadDeliveryFinishOutput* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    advance_store_to(now_tick);
    if (output == nullptr) {
        return AgentQPayloadDeliveryResult::invalid_argument;
    }
    if (g_store.state == AgentQPayloadDeliveryState::idle) {
        return AgentQPayloadDeliveryResult::not_found;
    }
    if (g_store.state != AgentQPayloadDeliveryState::receiving) {
        return AgentQPayloadDeliveryResult::invalid_state;
    }
    const AgentQPayloadDeliveryResult ref_result =
        validate_active_upload_ref(input.session_id, input.upload_id);
    if (ref_result != AgentQPayloadDeliveryResult::ok) {
        return ref_result;
    }
    if (g_store.received_bytes != g_store.declared_size_bytes) {
        clear_store();
        return AgentQPayloadDeliveryResult::size_mismatch;
    }

    char actual_digest[kAgentQApprovalHistoryDigestSize] = {};
    if (!approval_history_digest_payload(
            g_store.buffer,
            g_store.declared_size_bytes,
            actual_digest,
            sizeof(actual_digest))) {
        clear_store();
        return AgentQPayloadDeliveryResult::digest_error;
    }
    if (!string_equal(actual_digest, g_store.expected_payload_digest)) {
        clear_store();
        return AgentQPayloadDeliveryResult::digest_mismatch;
    }

    if (!payload_delivery_format_payload_ref(
            g_next_payload_ref++,
            g_store.payload_ref,
            sizeof(g_store.payload_ref))) {
        clear_store();
        return AgentQPayloadDeliveryResult::invalid_argument;
    }
    g_store.state = AgentQPayloadDeliveryState::finalized;
    g_store.upload_id[0] = '\0';
    fill_descriptor(&output->descriptor);
    return AgentQPayloadDeliveryResult::ok;
}

AgentQPayloadDeliveryResult payload_delivery_abort(
    AgentQTimeoutTick now_tick,
    const AgentQPayloadDeliveryAbortInput& input)
{
    advance_store_to(now_tick);
    const bool has_upload_id = input.upload_id != nullptr && input.upload_id[0] != '\0';
    const bool has_payload_ref = input.payload_ref != nullptr && input.payload_ref[0] != '\0';
    if (input.session_id == nullptr || has_upload_id == has_payload_ref) {
        return AgentQPayloadDeliveryResult::invalid_argument;
    }
    if (has_upload_id) {
        if (g_store.state != AgentQPayloadDeliveryState::receiving) {
            return AgentQPayloadDeliveryResult::not_found;
        }
        const AgentQPayloadDeliveryResult ref_result =
            validate_active_upload_ref(input.session_id, input.upload_id);
        if (ref_result != AgentQPayloadDeliveryResult::ok) {
            return ref_result;
        }
        clear_store();
        return AgentQPayloadDeliveryResult::ok;
    }
    if (g_store.state != AgentQPayloadDeliveryState::finalized) {
        return AgentQPayloadDeliveryResult::not_found;
    }
    const AgentQPayloadDeliveryResult ref_result =
        validate_finalized_payload_ref(input.session_id, input.payload_ref);
    if (ref_result != AgentQPayloadDeliveryResult::ok) {
        return ref_result;
    }
    clear_store();
    return AgentQPayloadDeliveryResult::ok;
}

AgentQPayloadDeliveryResult payload_delivery_resolve_finalized(
    AgentQTimeoutTick now_tick,
    const char* session_id,
    const char* payload_ref,
    AgentQPayloadDeliveryView* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    advance_store_to(now_tick);
    if (output == nullptr) {
        return AgentQPayloadDeliveryResult::invalid_argument;
    }
    if (g_store.state != AgentQPayloadDeliveryState::finalized) {
        return AgentQPayloadDeliveryResult::not_found;
    }
    const AgentQPayloadDeliveryResult ref_result =
        validate_finalized_payload_ref(session_id, payload_ref);
    if (ref_result != AgentQPayloadDeliveryResult::ok) {
        return ref_result;
    }
    fill_descriptor(&output->descriptor);
    output->bytes = g_store.buffer;
    output->size_bytes = g_store.declared_size_bytes;
    return AgentQPayloadDeliveryResult::ok;
}

AgentQPayloadDeliveryResult payload_delivery_take_finalized(
    AgentQTimeoutTick now_tick,
    const char* session_id,
    const char* payload_ref,
    AgentQPayloadDeliveryOwnedPayload* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    advance_store_to(now_tick);
    if (output == nullptr) {
        return AgentQPayloadDeliveryResult::invalid_argument;
    }
    if (g_store.state != AgentQPayloadDeliveryState::finalized) {
        return AgentQPayloadDeliveryResult::not_found;
    }
    const AgentQPayloadDeliveryResult ref_result =
        validate_finalized_payload_ref(session_id, payload_ref);
    if (ref_result != AgentQPayloadDeliveryResult::ok) {
        return ref_result;
    }
    fill_descriptor(&output->descriptor);
    output->bytes = g_store.buffer;
    output->size_bytes = g_store.declared_size_bytes;
    g_store.buffer = nullptr;
    reset_store_without_wipe();
    return AgentQPayloadDeliveryResult::ok;
}

bool payload_delivery_clear_for_session(const char* session_id)
{
    if (g_store.state == AgentQPayloadDeliveryState::idle ||
        !active_session_matches(session_id)) {
        return false;
    }
    clear_store();
    return true;
}

bool payload_delivery_clear_expired(uint64_t now_tick)
{
    return advance_store_to(static_cast<AgentQTimeoutTick>(now_tick));
}

void payload_delivery_clear_all()
{
    clear_store();
}

const char* payload_delivery_result_name(AgentQPayloadDeliveryResult result)
{
    switch (result) {
        case AgentQPayloadDeliveryResult::ok:
            return "ok";
        case AgentQPayloadDeliveryResult::invalid_argument:
            return "invalid_argument";
        case AgentQPayloadDeliveryResult::invalid_state:
            return "invalid_state";
        case AgentQPayloadDeliveryResult::invalid_session:
            return "invalid_session";
        case AgentQPayloadDeliveryResult::unsupported_method:
            return "unsupported_method";
        case AgentQPayloadDeliveryResult::unsupported_payload_kind:
            return "unsupported_payload_kind";
        case AgentQPayloadDeliveryResult::unsupported_payload_size:
            return "unsupported_payload_size";
        case AgentQPayloadDeliveryResult::invalid_payload_digest:
            return "invalid_payload_digest";
        case AgentQPayloadDeliveryResult::invalid_upload_id:
            return "invalid_upload_id";
        case AgentQPayloadDeliveryResult::invalid_payload_ref:
            return "invalid_payload_ref";
        case AgentQPayloadDeliveryResult::allocation_failed:
            return "allocation_failed";
        case AgentQPayloadDeliveryResult::chunk_too_large:
            return "chunk_too_large";
        case AgentQPayloadDeliveryResult::offset_mismatch:
            return "offset_mismatch";
        case AgentQPayloadDeliveryResult::payload_overflow:
            return "payload_overflow";
        case AgentQPayloadDeliveryResult::size_mismatch:
            return "size_mismatch";
        case AgentQPayloadDeliveryResult::digest_mismatch:
            return "digest_mismatch";
        case AgentQPayloadDeliveryResult::digest_error:
            return "digest_error";
        case AgentQPayloadDeliveryResult::not_found:
            return "not_found";
    }
    return "unknown";
}

}  // namespace agent_q
