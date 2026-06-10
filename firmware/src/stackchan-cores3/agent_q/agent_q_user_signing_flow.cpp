#include "agent_q_user_signing_flow.h"

#include <stdint.h>
#include <string.h>

#include "agent_q_protocol_input_copy.h"

#include "agent_q_bip39.h"
#include "agent_q_sui_account_store.h"
#include "agent_q_sui_network.h"

namespace agent_q {
namespace {

struct AgentQUserSigningFlowState {
    AgentQUserSigningStage stage = AgentQUserSigningStage::none;
    AgentQUserSigningTerminalResult terminal_result =
        AgentQUserSigningTerminalResult::none;
    AgentQSigningRoute signing_route = AgentQSigningRoute::unsupported;
    char request_id[kAgentQUserSigningIdSize] = {};
    uint8_t request_identity[kAgentQSignRequestIdentitySize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    char chain[kAgentQUserSigningChainSize] = {};
    char method[kAgentQUserSigningMethodSize] = {};
    char network[kAgentQUserSigningNetworkSize] = {};
    char payload_digest[kAgentQApprovalHistoryDigestSize] = {};
    AgentQTimeoutWindow request_window = kAgentQTimeoutWindowNone;
    AgentQTimeoutWindow pin_input_window = kAgentQTimeoutWindowNone;
    AgentQPausedTimeoutWindow paused_pin_input_window = kAgentQPausedTimeoutWindowNone;
    uint8_t signable_payload[kAgentQUserSigningPayloadMaxBytes] = {};
    size_t signable_payload_size = 0;
    bool signable_payload_available = false;
    SuiTransactionPolicyFacts sui_facts = {};
    char account_address[kSuiAddressBufferSize] = {};
    char message_preview[kAgentQSignPersonalMessagePreviewSize] = {};

    bool active() const
    {
        return stage != AgentQUserSigningStage::none;
    }

    void wipe_payload()
    {
        wipe_sensitive_buffer(signable_payload, sizeof(signable_payload));
        signable_payload_size = 0;
        signable_payload_available = false;
    }

    void wipe_review_metadata()
    {
        wipe_sensitive_buffer(session_id, sizeof(session_id));
        wipe_sensitive_buffer(network, sizeof(network));
        request_window = kAgentQTimeoutWindowNone;
        pin_input_window = kAgentQTimeoutWindowNone;
        paused_pin_input_window = kAgentQPausedTimeoutWindowNone;
        memset(&sui_facts, 0, sizeof(sui_facts));
        wipe_sensitive_buffer(account_address, sizeof(account_address));
        wipe_sensitive_buffer(message_preview, sizeof(message_preview));
    }

    void clear()
    {
        wipe_payload();
        stage = AgentQUserSigningStage::none;
        terminal_result = AgentQUserSigningTerminalResult::none;
        signing_route = AgentQSigningRoute::unsupported;
        wipe_sensitive_buffer(request_id, sizeof(request_id));
        wipe_sensitive_buffer(request_identity, sizeof(request_identity));
        wipe_sensitive_buffer(chain, sizeof(chain));
        wipe_sensitive_buffer(method, sizeof(method));
        wipe_sensitive_buffer(payload_digest, sizeof(payload_digest));
        wipe_review_metadata();
    }

    void terminalize(AgentQUserSigningTerminalResult result)
    {
        wipe_payload();
        wipe_review_metadata();
        terminal_result = result;
        stage = AgentQUserSigningStage::terminal;
    }
};

AgentQUserSigningFlowState g_state;

struct AgentQUserSigningBeginMetadata {
    AgentQSigningRoute route = AgentQSigningRoute::unsupported;
    char request_id[kAgentQUserSigningIdSize] = {};
    uint8_t request_identity[kAgentQSignRequestIdentitySize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    char chain[kAgentQUserSigningChainSize] = {};
    char method[kAgentQUserSigningMethodSize] = {};
    char network[kAgentQUserSigningNetworkSize] = {};
    AgentQTimeoutWindow request_window = kAgentQTimeoutWindowNone;
};

bool printable_ascii(uint8_t value)
{
    return value >= 0x20 && value <= 0x7e;
}

void make_message_preview(const uint8_t* message, size_t message_size, char* output, size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return;
    }
    output[0] = '\0';
    if (message == nullptr || message_size == 0) {
        return;
    }
    const size_t max_payload = output_size > 4 ? output_size - 4 : output_size - 1;
    size_t written = 0;
    for (; written < message_size && written < max_payload; ++written) {
        output[written] = printable_ascii(message[written])
                              ? static_cast<char>(message[written])
                              : '.';
    }
    if (written < message_size && written + 3 < output_size) {
        output[written++] = '.';
        output[written++] = '.';
        output[written++] = '.';
    }
    output[written < output_size ? written : output_size - 1] = '\0';
}

AgentQUserSigningFlowBeginResult prepare_common_begin_metadata(
    const char* request_id,
    const uint8_t* request_identity,
    const char* session_id,
    AgentQSigningRoute route,
    const char* network,
    AgentQTimeoutWindow request_window,
    AgentQUserSigningBeginMetadata* output)
{
    if (output == nullptr) {
        return AgentQUserSigningFlowBeginResult::invalid_argument;
    }
    memset(output, 0, sizeof(*output));
    output->route = AgentQSigningRoute::unsupported;
    if (request_id == nullptr ||
        request_identity == nullptr ||
        session_id == nullptr ||
        route == AgentQSigningRoute::unsupported ||
        network == nullptr) {
        return AgentQUserSigningFlowBeginResult::invalid_argument;
    }
    if (!timeout_window_valid(request_window)) {
        return AgentQUserSigningFlowBeginResult::invalid_deadline;
    }
    if (!copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id)) ||
        !copy_nonempty_c_string(session_id, output->session_id, sizeof(output->session_id)) ||
        !copy_nonempty_c_string(sign_route_wire_chain(route), output->chain, sizeof(output->chain)) ||
        !copy_nonempty_c_string(sign_route_wire_method(route), output->method, sizeof(output->method)) ||
        !copy_nonempty_c_string(network, output->network, sizeof(output->network))) {
        memset(output, 0, sizeof(*output));
        return AgentQUserSigningFlowBeginResult::invalid_argument;
    }
    if (session_validate(output->session_id) != AgentQSessionValidationResult::ok) {
        memset(output, 0, sizeof(*output));
        return AgentQUserSigningFlowBeginResult::invalid_session;
    }
    if (!sui_network_supported(output->network)) {
        memset(output, 0, sizeof(*output));
        return AgentQUserSigningFlowBeginResult::invalid_network;
    }
    output->route = route;
    memcpy(output->request_identity, request_identity, sizeof(output->request_identity));
    output->request_window = request_window;
    return AgentQUserSigningFlowBeginResult::ok;
}

void apply_common_begin_metadata(
    const AgentQUserSigningBeginMetadata& metadata,
    const char* payload_digest)
{
    g_state.signing_route = metadata.route;
    memcpy(g_state.request_id, metadata.request_id, sizeof(g_state.request_id));
    memcpy(
        g_state.request_identity,
        metadata.request_identity,
        sizeof(g_state.request_identity));
    memcpy(g_state.session_id, metadata.session_id, sizeof(g_state.session_id));
    memcpy(g_state.chain, metadata.chain, sizeof(g_state.chain));
    memcpy(g_state.method, metadata.method, sizeof(g_state.method));
    memcpy(g_state.network, metadata.network, sizeof(g_state.network));
    memcpy(g_state.payload_digest, payload_digest, sizeof(g_state.payload_digest));
    g_state.request_window = metadata.request_window;
    g_state.pin_input_window = kAgentQTimeoutWindowNone;
    g_state.stage = AgentQUserSigningStage::reviewing;
}

void apply_signable_payload(const uint8_t* payload, size_t payload_size)
{
    memcpy(g_state.signable_payload, payload, payload_size);
    g_state.signable_payload_size = payload_size;
    g_state.signable_payload_available = true;
}

AgentQUserSigningFlowBeginResult validate_prepared_payload_metadata(
    size_t payload_size,
    size_t max_payload_size,
    const char* payload_digest)
{
    if (payload_size == 0 || payload_size > max_payload_size) {
        return AgentQUserSigningFlowBeginResult::invalid_payload;
    }
    if (payload_digest == nullptr || payload_digest[0] == '\0') {
        return AgentQUserSigningFlowBeginResult::digest_error;
    }
    return AgentQUserSigningFlowBeginResult::ok;
}

AgentQUserSigningFlowBeginResult begin_common_review_state(
    const AgentQUserSigningBeginMetadata& metadata,
    const uint8_t* payload,
    size_t payload_size,
    size_t max_payload_size,
    const char* payload_digest)
{
    const AgentQUserSigningFlowBeginResult payload_result =
        validate_prepared_payload_metadata(payload_size, max_payload_size, payload_digest);
    if (payload_result != AgentQUserSigningFlowBeginResult::ok) {
        return payload_result;
    }

    g_state.clear();
    apply_common_begin_metadata(metadata, payload_digest);
    apply_signable_payload(payload, payload_size);
    return AgentQUserSigningFlowBeginResult::ok;
}

bool any_deadline_reached(TickType_t now)
{
    if (g_state.stage == AgentQUserSigningStage::reviewing) {
        return timeout_window_reached(g_state.request_window, now);
    }
    if (g_state.stage == AgentQUserSigningStage::pin_entry) {
        return timeout_window_reached(g_state.pin_input_window, now);
    }
    return false;
}

bool rejectable_stage(AgentQUserSigningStage stage)
{
    return stage == AgentQUserSigningStage::reviewing;
}

bool precritical_cleanup_stage(AgentQUserSigningStage stage)
{
    return stage == AgentQUserSigningStage::reviewing ||
           stage == AgentQUserSigningStage::pin_entry ||
           stage == AgentQUserSigningStage::history_write;
}

AgentQUserSigningTransitionResult terminalize_if_rejectable(
    AgentQUserSigningTerminalResult result)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage == AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::busy;
    }
    if (!rejectable_stage(g_state.stage)) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    g_state.terminalize(result);
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult terminalize_if_precritical_cleanup(
    AgentQUserSigningTerminalResult result)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage == AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::busy;
    }
    if (!precritical_cleanup_stage(g_state.stage)) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    g_state.terminalize(result);
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult terminalize_invalid_session()
{
    g_state.terminalize(AgentQUserSigningTerminalResult::canceled);
    return AgentQUserSigningTransitionResult::invalid_session;
}

AgentQUserSigningTransitionResult require_active_session()
{
    if (session_validate(g_state.session_id) != AgentQSessionValidationResult::ok) {
        return terminalize_invalid_session();
    }
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult terminalize_if_deadline_expired(TickType_t now)
{
    if (any_deadline_reached(now)) {
        g_state.terminalize(AgentQUserSigningTerminalResult::timed_out);
        return AgentQUserSigningTransitionResult::deadline_expired;
    }
    return AgentQUserSigningTransitionResult::ok;
}

bool same_history_write_request(const AgentQUserSigningFlowSnapshot& snapshot)
{
    return g_state.active() &&
           snapshot.active &&
           snapshot.stage == AgentQUserSigningStage::history_write &&
           g_state.stage == AgentQUserSigningStage::history_write &&
           strcmp(g_state.request_id, snapshot.request_id) == 0 &&
           memcmp(
               g_state.request_identity,
               snapshot.request_identity,
               sizeof(g_state.request_identity)) == 0 &&
           strcmp(g_state.session_id, snapshot.session_id) == 0 &&
           strcmp(g_state.chain, snapshot.chain) == 0 &&
           strcmp(g_state.method, snapshot.method) == 0 &&
           g_state.signing_route == snapshot.signing_route &&
           strcmp(g_state.network, snapshot.network) == 0 &&
           strcmp(g_state.payload_digest, snapshot.payload_digest) == 0 &&
           g_state.signable_payload_size == snapshot.signable_payload_size &&
           g_state.signable_payload_available == snapshot.signable_payload_available;
}

struct AgentQUserSigningTerminalWireFields {
    const char* status;
    const char* reason;
};

AgentQUserSigningTerminalWireFields terminal_wire_fields(
    AgentQUserSigningTerminalResult result)
{
    switch (result) {
        case AgentQUserSigningTerminalResult::signed_success:
            return {"signed", "device_confirmed"};
        case AgentQUserSigningTerminalResult::rejected:
            return {"user_rejected", "user_rejected"};
        case AgentQUserSigningTerminalResult::timed_out:
            return {"user_timed_out", "user_timed_out"};
        case AgentQUserSigningTerminalResult::signing_failed:
            return {"signing_failed", "signing_failed"};
        case AgentQUserSigningTerminalResult::canceled:
        case AgentQUserSigningTerminalResult::history_error:
        case AgentQUserSigningTerminalResult::none:
        default:
            return {"", ""};
    }
}

}  // namespace

AgentQUserSigningTransitionResult user_signing_flow_clear()
{
    if (g_state.stage == AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::busy;
    }
    const bool was_active = g_state.active();
    g_state.clear();
    return was_active ? AgentQUserSigningTransitionResult::ok
                      : AgentQUserSigningTransitionResult::inactive;
}

bool user_signing_flow_active()
{
    return g_state.active();
}

bool user_signing_flow_in_signing_critical_section()
{
    return g_state.stage == AgentQUserSigningStage::signing_critical_section;
}

bool user_signing_flow_session_matches(const char* session_id)
{
    return g_state.active() &&
           session_id != nullptr &&
           g_state.session_id[0] != '\0' &&
           strcmp(g_state.session_id, session_id) == 0;
}

AgentQSessionValidationResult user_signing_flow_validate_session()
{
    if (!g_state.active() || g_state.session_id[0] == '\0') {
        return AgentQSessionValidationResult::missing;
    }
    return session_validate(g_state.session_id);
}

AgentQUserSigningFlowSnapshot user_signing_flow_snapshot()
{
    AgentQUserSigningFlowSnapshot snapshot = {};
    snapshot.active = g_state.active();
    snapshot.stage = g_state.stage;
    snapshot.terminal_result = g_state.terminal_result;
    snapshot.signing_route = g_state.signing_route;
    memcpy(snapshot.request_id, g_state.request_id, sizeof(snapshot.request_id));
    memcpy(
        snapshot.request_identity,
        g_state.request_identity,
        sizeof(snapshot.request_identity));
    memcpy(snapshot.session_id, g_state.session_id, sizeof(snapshot.session_id));
    memcpy(snapshot.chain, g_state.chain, sizeof(snapshot.chain));
    memcpy(snapshot.method, g_state.method, sizeof(snapshot.method));
    memcpy(snapshot.network, g_state.network, sizeof(snapshot.network));
    memcpy(snapshot.payload_digest, g_state.payload_digest, sizeof(snapshot.payload_digest));
    snapshot.request_window = g_state.request_window;
    snapshot.pin_input_window = g_state.pin_input_window;
    snapshot.signable_payload_size = g_state.signable_payload_size;
    snapshot.signable_payload_available = g_state.signable_payload_available;
    snapshot.sui_facts = g_state.sui_facts;
    memcpy(snapshot.account_address, g_state.account_address, sizeof(snapshot.account_address));
    memcpy(snapshot.message_preview, g_state.message_preview, sizeof(snapshot.message_preview));
    return snapshot;
}

AgentQUserSigningFlowBeginResult user_signing_flow_begin(
    const AgentQUserSigningTransactionBeginInput& input)
{
    if (g_state.active()) {
        return AgentQUserSigningFlowBeginResult::active;
    }
    // User-flow boundary assertion: a prepared value must still match the
    // selected route before any review UI state or signable scratch is created.
    if (input.route != AgentQSigningRoute::sui_sign_transaction ||
        input.prepared == nullptr ||
        input.prepared->route != input.route) {
        return AgentQUserSigningFlowBeginResult::invalid_argument;
    }
    AgentQUserSigningBeginMetadata metadata = {};
    const AgentQUserSigningFlowBeginResult metadata_result =
        prepare_common_begin_metadata(
            input.request_id,
            input.request_identity,
            input.session_id,
            input.route,
            input.prepared->network,
            input.request_window,
            &metadata);
    if (metadata_result != AgentQUserSigningFlowBeginResult::ok) {
        return metadata_result;
    }
    const AgentQUserSigningFlowBeginResult begin_result =
        begin_common_review_state(
            metadata,
            input.prepared->tx_bytes,
            input.prepared->tx_bytes_size,
            kAgentQSuiSignTransactionTxBytesMaxBytes,
            input.prepared->payload_digest);
    if (begin_result != AgentQUserSigningFlowBeginResult::ok) {
        return begin_result;
    }

    g_state.sui_facts = input.prepared->sui_facts;
    return AgentQUserSigningFlowBeginResult::ok;
}

AgentQUserSigningFlowBeginResult user_signing_flow_begin_personal_message(
    const AgentQUserSigningPersonalMessageBeginInput& input)
{
    if (g_state.active()) {
        return AgentQUserSigningFlowBeginResult::active;
    }
    // User-flow boundary assertion: a prepared value must still match the
    // selected route before any review UI state or signable scratch is created.
    if (input.route != AgentQSigningRoute::sui_sign_personal_message ||
        input.prepared == nullptr ||
        input.prepared->route != input.route) {
        return AgentQUserSigningFlowBeginResult::invalid_argument;
    }
    AgentQUserSigningBeginMetadata metadata = {};
    const AgentQUserSigningFlowBeginResult metadata_result =
        prepare_common_begin_metadata(
            input.request_id,
            input.request_identity,
            input.session_id,
            input.route,
            input.prepared->network,
            input.request_window,
            &metadata);
    if (metadata_result != AgentQUserSigningFlowBeginResult::ok) {
        return metadata_result;
    }
    const AgentQUserSigningFlowBeginResult begin_result =
        begin_common_review_state(
            metadata,
            input.prepared->message,
            input.prepared->message_size,
            kAgentQSuiSignPersonalMessageMaxBytes,
            input.prepared->payload_digest);
    if (begin_result != AgentQUserSigningFlowBeginResult::ok) {
        return begin_result;
    }

    memcpy(g_state.account_address, input.prepared->account_address, sizeof(g_state.account_address));
    make_message_preview(
        input.prepared->message,
        input.prepared->message_size,
        g_state.message_preview,
        sizeof(g_state.message_preview));
    return AgentQUserSigningFlowBeginResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_accept_review(
    TickType_t now,
    AgentQTimeoutWindow pin_input_window)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::reviewing) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (!timeout_window_valid(pin_input_window)) {
        return AgentQUserSigningTransitionResult::invalid_deadline;
    }
    AgentQUserSigningTransitionResult guard = require_active_session();
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    const TickType_t capped_pin_deadline =
        timeout_window_cap_deadline(g_state.request_window, pin_input_window.deadline);
    if (timeout_window_tick_reached(now, capped_pin_deadline)) {
        g_state.terminalize(AgentQUserSigningTerminalResult::timed_out);
        return AgentQUserSigningTransitionResult::deadline_expired;
    }
    g_state.stage = AgentQUserSigningStage::pin_entry;
    g_state.paused_pin_input_window = kAgentQPausedTimeoutWindowNone;
    g_state.pin_input_window =
        timeout_window_from_deadline(pin_input_window.started_at, capped_pin_deadline);
    if (!timeout_window_valid(g_state.pin_input_window)) {
        g_state.terminalize(AgentQUserSigningTerminalResult::timed_out);
        return AgentQUserSigningTransitionResult::deadline_expired;
    }
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_return_to_review(
    TickType_t now,
    AgentQTimeoutWindow review_window)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::pin_entry) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (!timeout_window_valid(review_window)) {
        return AgentQUserSigningTransitionResult::invalid_deadline;
    }
    AgentQUserSigningTransitionResult guard = require_active_session();
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    if (timeout_window_reached(review_window, now)) {
        g_state.terminalize(AgentQUserSigningTerminalResult::timed_out);
        return AgentQUserSigningTransitionResult::deadline_expired;
    }
    g_state.stage = AgentQUserSigningStage::reviewing;
    g_state.request_window = review_window;
    g_state.pin_input_window = kAgentQTimeoutWindowNone;
    g_state.paused_pin_input_window = kAgentQPausedTimeoutWindowNone;
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_refresh_pin_deadline(TickType_t now)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::pin_entry) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    const AgentQUserSigningTransitionResult guard = require_active_session();
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    const AgentQTimeoutWindow resumed =
        timeout_window_resume_at(g_state.paused_pin_input_window, now);
    if (!timeout_window_valid(resumed)) {
        return AgentQUserSigningTransitionResult::invalid_deadline;
    }
    g_state.pin_input_window = resumed;
    g_state.paused_pin_input_window = kAgentQPausedTimeoutWindowNone;
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_pause_pin_deadline(TickType_t now)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::pin_entry) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    const AgentQUserSigningTransitionResult guard = require_active_session();
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    if (timeout_window_reached(g_state.pin_input_window, now)) {
        g_state.terminalize(AgentQUserSigningTerminalResult::timed_out);
        return AgentQUserSigningTransitionResult::deadline_expired;
    }
    g_state.paused_pin_input_window =
        timeout_window_pause_at(g_state.pin_input_window, now);
    if (!timeout_paused_window_valid(g_state.paused_pin_input_window)) {
        g_state.paused_pin_input_window = kAgentQPausedTimeoutWindowNone;
        return AgentQUserSigningTransitionResult::invalid_deadline;
    }
    g_state.pin_input_window = kAgentQTimeoutWindowNone;
    return AgentQUserSigningTransitionResult::ok;
}

bool user_signing_flow_deadline_reached(TickType_t now)
{
    return g_state.active() && any_deadline_reached(now);
}

AgentQUserSigningTransitionResult
user_signing_flow_record_pin_verified_and_write_confirmation_history(
    TickType_t now,
    AgentQUserSigningHistoryWriteFn write_fn,
    void* context)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::pin_entry) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (write_fn == nullptr) {
        return AgentQUserSigningTransitionResult::invalid_argument;
    }
    if (timeout_window_active(g_state.pin_input_window)) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    AgentQUserSigningTransitionResult guard = require_active_session();
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    g_state.stage = AgentQUserSigningStage::history_write;
    g_state.pin_input_window = kAgentQTimeoutWindowNone;
    g_state.paused_pin_input_window = kAgentQPausedTimeoutWindowNone;

    guard = require_active_session();
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    const AgentQUserSigningFlowSnapshot snapshot =
        user_signing_flow_snapshot();
    const bool write_ok = write_fn(snapshot, context);
    if (!same_history_write_request(snapshot)) {
        return AgentQUserSigningTransitionResult::stale_state;
    }
    if (!write_ok) {
        g_state.terminalize(AgentQUserSigningTerminalResult::history_error);
        return AgentQUserSigningTransitionResult::history_error;
    }
    g_state.stage = AgentQUserSigningStage::signing_critical_section;
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult
user_signing_flow_record_physical_confirmed_and_write_confirmation_history(
    TickType_t now,
    AgentQUserSigningHistoryWriteFn write_fn,
    void* context)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::reviewing) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (write_fn == nullptr) {
        return AgentQUserSigningTransitionResult::invalid_argument;
    }
    AgentQUserSigningTransitionResult guard = require_active_session();
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != AgentQUserSigningTransitionResult::ok) {
        return guard;
    }
    g_state.stage = AgentQUserSigningStage::history_write;
    g_state.pin_input_window = kAgentQTimeoutWindowNone;
    g_state.paused_pin_input_window = kAgentQPausedTimeoutWindowNone;

    const AgentQUserSigningFlowSnapshot snapshot =
        user_signing_flow_snapshot();
    const bool write_ok = write_fn(snapshot, context);
    if (!same_history_write_request(snapshot)) {
        return AgentQUserSigningTransitionResult::stale_state;
    }
    if (!write_ok) {
        g_state.terminalize(AgentQUserSigningTerminalResult::history_error);
        return AgentQUserSigningTransitionResult::history_error;
    }
    g_state.stage = AgentQUserSigningStage::signing_critical_section;
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_consume_signable_payload(
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size)
{
    if (output_size != nullptr) {
        *output_size = 0;
    }
    if (output != nullptr && output_capacity > 0) {
        memset(output, 0, output_capacity);
    }
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (!g_state.signable_payload_available || g_state.signable_payload_size == 0) {
        return AgentQUserSigningTransitionResult::payload_unavailable;
    }
    if (output == nullptr || output_capacity < g_state.signable_payload_size || output_size == nullptr) {
        return AgentQUserSigningTransitionResult::output_too_small;
    }
    memcpy(output, g_state.signable_payload, g_state.signable_payload_size);
    *output_size = g_state.signable_payload_size;
    g_state.wipe_payload();
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_record_device_rejected()
{
    return terminalize_if_rejectable(AgentQUserSigningTerminalResult::rejected);
}

AgentQUserSigningTransitionResult user_signing_flow_record_timeout(TickType_t now)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage == AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::busy;
    }
    if (g_state.stage != AgentQUserSigningStage::reviewing &&
        g_state.stage != AgentQUserSigningStage::pin_entry) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (!any_deadline_reached(now)) {
        return AgentQUserSigningTransitionResult::deadline_not_reached;
    }
    g_state.terminalize(AgentQUserSigningTerminalResult::timed_out);
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_record_signing_failed()
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    g_state.terminalize(AgentQUserSigningTerminalResult::signing_failed);
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_complete_signed()
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage != AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::wrong_stage;
    }
    if (g_state.signable_payload_available) {
        return AgentQUserSigningTransitionResult::payload_not_consumed;
    }
    g_state.terminalize(AgentQUserSigningTerminalResult::signed_success);
    return AgentQUserSigningTransitionResult::ok;
}

AgentQUserSigningTransitionResult user_signing_flow_cancel_for_disconnect(
    const char* session_id)
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (!user_signing_flow_session_matches(session_id)) {
        return AgentQUserSigningTransitionResult::invalid_session;
    }
    return terminalize_if_precritical_cleanup(AgentQUserSigningTerminalResult::canceled);
}

AgentQUserSigningTransitionResult user_signing_flow_cancel_for_session_loss()
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    if (g_state.stage == AgentQUserSigningStage::signing_critical_section) {
        return AgentQUserSigningTransitionResult::busy;
    }
    if (session_validate(g_state.session_id) == AgentQSessionValidationResult::ok) {
        return AgentQUserSigningTransitionResult::session_still_active;
    }
    return terminalize_if_precritical_cleanup(AgentQUserSigningTerminalResult::canceled);
}

AgentQUserSigningTransitionResult user_signing_flow_cancel_for_ui_loss()
{
    if (!g_state.active()) {
        return AgentQUserSigningTransitionResult::inactive;
    }
    return terminalize_if_precritical_cleanup(AgentQUserSigningTerminalResult::canceled);
}

AgentQUserSigningTransitionResult user_signing_flow_cancel_for_pin_loss()
{
    return user_signing_flow_cancel_for_ui_loss();
}

bool user_signing_flow_terminal_pending()
{
    return g_state.stage == AgentQUserSigningStage::terminal &&
           g_state.terminal_result != AgentQUserSigningTerminalResult::none;
}

bool user_signing_flow_consume_terminal_result(
    AgentQUserSigningTerminalResult* output)
{
    if (!user_signing_flow_terminal_pending() || output == nullptr) {
        return false;
    }
    *output = g_state.terminal_result;
    g_state.clear();
    return true;
}

const char* user_signing_flow_terminal_status(
    AgentQUserSigningTerminalResult result)
{
    return terminal_wire_fields(result).status;
}

const char* user_signing_flow_terminal_reason(
    AgentQUserSigningTerminalResult result)
{
    return terminal_wire_fields(result).reason;
}

}  // namespace agent_q
