#include "signing/user_signing_flow.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "protocol/protocol_input_copy.h"
#include "sui/network.h"

namespace signing {
namespace {

void wipe_user_signing_buffer(void* data, size_t size);

struct UserSigningFlowState {
    UserSigningStage stage = UserSigningStage::none;
    UserSigningTerminalResult terminal_result =
        UserSigningTerminalResult::none;
    Route signing_route = Route::unsupported;
    char request_id[kUserSigningIdSize] = {};
    uint8_t request_identity[kSignRequestIdentitySize] = {};
    char session_id[kSessionIdSize] = {};
    char chain[kUserSigningChainSize] = {};
    char method[kUserSigningMethodSize] = {};
    char network[kUserSigningNetworkSize] = {};
    char payload_digest[kApprovalHistoryDigestSize] = {};
    TimeoutWindow request_window = kTimeoutWindowNone;
    PausedTimeoutWindow paused_request_window = kPausedTimeoutWindowNone;
    TimeoutWindow pin_input_window = kTimeoutWindowNone;
    PausedTimeoutWindow paused_pin_input_window = kPausedTimeoutWindowNone;
    uint8_t* signable_payload = nullptr;
    size_t signable_payload_size = 0;
    bool signable_payload_available = false;
    bool blind_signing_confirmation = false;
    SuiPolicySubjectFacts sui_policy_subject = {};
    SuiReviewSummary sui_review = {};
    char account_address[kSuiAddressStringBufferSize] = {};
    char message_preview[kSignPersonalMessagePreviewSize] = {};

    bool active() const
    {
        return stage != UserSigningStage::none;
    }

    void wipe_payload()
    {
        if (signable_payload != nullptr && signable_payload_size > 0) {
            wipe_user_signing_buffer(signable_payload, signable_payload_size);
            free(signable_payload);
        }
        signable_payload = nullptr;
        signable_payload_size = 0;
        signable_payload_available = false;
    }

    void wipe_review_metadata()
    {
        wipe_user_signing_buffer(session_id, sizeof(session_id));
        wipe_user_signing_buffer(network, sizeof(network));
        request_window = kTimeoutWindowNone;
        paused_request_window = kPausedTimeoutWindowNone;
        pin_input_window = kTimeoutWindowNone;
        paused_pin_input_window = kPausedTimeoutWindowNone;
        blind_signing_confirmation = false;
        memset(&sui_policy_subject, 0, sizeof(sui_policy_subject));
        memset(&sui_review, 0, sizeof(sui_review));
        wipe_user_signing_buffer(account_address, sizeof(account_address));
        wipe_user_signing_buffer(message_preview, sizeof(message_preview));
    }

    void clear()
    {
        wipe_payload();
        stage = UserSigningStage::none;
        terminal_result = UserSigningTerminalResult::none;
        signing_route = Route::unsupported;
        wipe_user_signing_buffer(request_id, sizeof(request_id));
        wipe_user_signing_buffer(request_identity, sizeof(request_identity));
        wipe_user_signing_buffer(chain, sizeof(chain));
        wipe_user_signing_buffer(method, sizeof(method));
        wipe_user_signing_buffer(payload_digest, sizeof(payload_digest));
        wipe_review_metadata();
    }

    void terminalize(UserSigningTerminalResult result)
    {
        wipe_payload();
        wipe_review_metadata();
        terminal_result = result;
        stage = UserSigningStage::terminal;
    }
};

UserSigningFlowState g_state;
UserSigningSessionValidateFn g_validate_session = nullptr;
void* g_validate_session_context = nullptr;

struct UserSigningBeginMetadata {
    Route route = Route::unsupported;
    char request_id[kUserSigningIdSize] = {};
    uint8_t request_identity[kSignRequestIdentitySize] = {};
    char session_id[kSessionIdSize] = {};
    char chain[kUserSigningChainSize] = {};
    char method[kUserSigningMethodSize] = {};
    char network[kUserSigningNetworkSize] = {};
    TimeoutWindow request_window = kTimeoutWindowNone;
};

bool printable_ascii(uint8_t value)
{
    return value >= 0x20 && value <= 0x7e;
}

void wipe_user_signing_buffer(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

SessionValidationResult validate_flow_session(const char* session_id)
{
    if (!session_id_format_valid(session_id)) {
        return SessionValidationResult::invalid_format;
    }
    if (g_validate_session == nullptr) {
        return SessionValidationResult::missing;
    }
    return g_validate_session(session_id, g_validate_session_context);
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

UserSigningFlowBeginResult prepare_common_begin_metadata(
    const char* request_id,
    const uint8_t* request_identity,
    const char* session_id,
    Route route,
    const char* network,
    TimeoutWindow request_window,
    TickType_t now,
    UserSigningBeginMetadata* output)
{
    if (output == nullptr) {
        return UserSigningFlowBeginResult::invalid_argument;
    }
    memset(output, 0, sizeof(*output));
    output->route = Route::unsupported;
    if (request_id == nullptr ||
        request_identity == nullptr ||
        session_id == nullptr ||
        route == Route::unsupported ||
        network == nullptr) {
        return UserSigningFlowBeginResult::invalid_argument;
    }
    if (!timeout_window_valid_and_open_at(request_window, now)) {
        return UserSigningFlowBeginResult::invalid_deadline;
    }
    if (!copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id)) ||
        !copy_nonempty_c_string(session_id, output->session_id, sizeof(output->session_id)) ||
        !copy_nonempty_c_string(sign_route_wire_chain(route), output->chain, sizeof(output->chain)) ||
        !copy_nonempty_c_string(sign_route_wire_method(route), output->method, sizeof(output->method)) ||
        !copy_nonempty_c_string(network, output->network, sizeof(output->network))) {
        memset(output, 0, sizeof(*output));
        return UserSigningFlowBeginResult::invalid_argument;
    }
    if (validate_flow_session(output->session_id) != SessionValidationResult::ok) {
        memset(output, 0, sizeof(*output));
        return UserSigningFlowBeginResult::invalid_session;
    }
    if (!sui_network_supported(output->network)) {
        memset(output, 0, sizeof(*output));
        return UserSigningFlowBeginResult::invalid_network;
    }
    output->route = route;
    memcpy(output->request_identity, request_identity, sizeof(output->request_identity));
    output->request_window = request_window;
    return UserSigningFlowBeginResult::ok;
}

void apply_common_begin_metadata(
    const UserSigningBeginMetadata& metadata,
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
    g_state.paused_request_window = kPausedTimeoutWindowNone;
    g_state.pin_input_window = kTimeoutWindowNone;
    g_state.stage = UserSigningStage::reviewing;
}

bool apply_signable_payload_copy(const uint8_t* payload, size_t payload_size)
{
    if (payload == nullptr || payload_size == 0) {
        return false;
    }
    uint8_t* copy = static_cast<uint8_t*>(malloc(payload_size));
    if (copy == nullptr) {
        return false;
    }
    memcpy(copy, payload, payload_size);
    g_state.signable_payload = copy;
    g_state.signable_payload_size = payload_size;
    g_state.signable_payload_available = true;
    return true;
}

bool apply_signable_payload_owned(uint8_t* payload, size_t payload_size)
{
    if (payload == nullptr || payload_size == 0) {
        return false;
    }
    g_state.signable_payload = payload;
    g_state.signable_payload_size = payload_size;
    g_state.signable_payload_available = true;
    return true;
}

UserSigningFlowBeginResult validate_prepared_payload_metadata(
    size_t payload_size,
    size_t max_payload_size,
    const char* payload_digest)
{
    if (payload_size == 0 || payload_size > max_payload_size) {
        return UserSigningFlowBeginResult::invalid_payload;
    }
    if (payload_digest == nullptr || payload_digest[0] == '\0') {
        return UserSigningFlowBeginResult::digest_error;
    }
    return UserSigningFlowBeginResult::ok;
}

UserSigningFlowBeginResult begin_common_review_state_with_copy(
    const UserSigningBeginMetadata& metadata,
    const uint8_t* payload,
    size_t payload_size,
    size_t max_payload_size,
    const char* payload_digest)
{
    const UserSigningFlowBeginResult payload_result =
        validate_prepared_payload_metadata(payload_size, max_payload_size, payload_digest);
    if (payload_result != UserSigningFlowBeginResult::ok) {
        return payload_result;
    }

    g_state.clear();
    apply_common_begin_metadata(metadata, payload_digest);
    if (!apply_signable_payload_copy(payload, payload_size)) {
        g_state.clear();
        return UserSigningFlowBeginResult::invalid_payload;
    }
    return UserSigningFlowBeginResult::ok;
}

UserSigningFlowBeginResult begin_common_review_state_with_owned_payload(
    const UserSigningBeginMetadata& metadata,
    uint8_t* payload,
    size_t payload_size,
    size_t max_payload_size,
    const char* payload_digest)
{
    const UserSigningFlowBeginResult payload_result =
        validate_prepared_payload_metadata(payload_size, max_payload_size, payload_digest);
    if (payload_result != UserSigningFlowBeginResult::ok) {
        return payload_result;
    }

    g_state.clear();
    apply_common_begin_metadata(metadata, payload_digest);
    if (!apply_signable_payload_owned(payload, payload_size)) {
        g_state.clear();
        return UserSigningFlowBeginResult::invalid_payload;
    }
    return UserSigningFlowBeginResult::ok;
}

bool review_deadline_paused()
{
    return timeout_paused_window_valid(g_state.paused_request_window);
}

TickType_t review_pause_fallback_deadline()
{
    if (!review_deadline_paused()) {
        return 0;
    }
    const TickType_t duration =
        g_state.paused_request_window.window.deadline -
        g_state.paused_request_window.window.started_at;
    return g_state.paused_request_window.paused_at + duration;
}

UserSigningTransitionResult resume_review_deadline_if_paused(TickType_t now)
{
    if (!review_deadline_paused()) {
        return UserSigningTransitionResult::ok;
    }
    const TimeoutWindow resumed =
        timeout_window_resume_at(g_state.paused_request_window, now);
    if (!timeout_window_valid(resumed)) {
        return UserSigningTransitionResult::invalid_deadline;
    }
    g_state.request_window = resumed;
    g_state.paused_request_window = kPausedTimeoutWindowNone;
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult apply_review_pause_fallback(TickType_t now)
{
    if (g_state.stage != UserSigningStage::reviewing ||
        !review_deadline_paused()) {
        return UserSigningTransitionResult::ok;
    }
    const TickType_t fallback_deadline = review_pause_fallback_deadline();
    if (fallback_deadline == 0 ||
        !timeout_window_tick_reached(now, fallback_deadline)) {
        return UserSigningTransitionResult::ok;
    }
    const TimeoutWindow resumed =
        timeout_window_resume_at(g_state.paused_request_window, fallback_deadline);
    g_state.paused_request_window = kPausedTimeoutWindowNone;
    g_state.request_window = resumed;
    if (!timeout_window_valid(resumed) ||
        timeout_window_reached(resumed, now)) {
        g_state.terminalize(UserSigningTerminalResult::timed_out);
        return UserSigningTransitionResult::deadline_expired;
    }
    return UserSigningTransitionResult::ok;
}

bool apply_deadline_transition_and_report_reached(TickType_t now)
{
    if (g_state.stage == UserSigningStage::reviewing) {
        const UserSigningTransitionResult fallback =
            apply_review_pause_fallback(now);
        if (fallback == UserSigningTransitionResult::deadline_expired) {
            return true;
        }
        return timeout_window_reached(g_state.request_window, now);
    }
    if (g_state.stage == UserSigningStage::pin_entry) {
        return timeout_window_reached(g_state.pin_input_window, now);
    }
    return false;
}

bool rejectable_stage(UserSigningStage stage)
{
    return stage == UserSigningStage::reviewing;
}

bool precritical_cleanup_stage(UserSigningStage stage)
{
    return stage == UserSigningStage::reviewing ||
           stage == UserSigningStage::pin_entry ||
           stage == UserSigningStage::history_write;
}

UserSigningTransitionResult terminalize_if_rejectable(
    UserSigningTerminalResult result)
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage == UserSigningStage::signing_critical_section) {
        return UserSigningTransitionResult::busy;
    }
    if (!rejectable_stage(g_state.stage)) {
        return UserSigningTransitionResult::wrong_stage;
    }
    g_state.terminalize(result);
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult terminalize_if_precritical_cleanup(
    UserSigningTerminalResult result)
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage == UserSigningStage::signing_critical_section) {
        return UserSigningTransitionResult::busy;
    }
    if (!precritical_cleanup_stage(g_state.stage)) {
        return UserSigningTransitionResult::wrong_stage;
    }
    g_state.terminalize(result);
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult terminalize_invalid_session()
{
    g_state.terminalize(UserSigningTerminalResult::canceled);
    return UserSigningTransitionResult::invalid_session;
}

UserSigningTransitionResult require_active_session()
{
    if (validate_flow_session(g_state.session_id) != SessionValidationResult::ok) {
        return terminalize_invalid_session();
    }
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult terminalize_if_deadline_expired(TickType_t now)
{
    if (apply_deadline_transition_and_report_reached(now)) {
        if (g_state.stage != UserSigningStage::terminal) {
            g_state.terminalize(UserSigningTerminalResult::timed_out);
        }
        return UserSigningTransitionResult::deadline_expired;
    }
    return UserSigningTransitionResult::ok;
}

void populate_core_snapshot(UserSigningFlowCoreSnapshot& snapshot)
{
    memset(&snapshot, 0, sizeof(snapshot));
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
    snapshot.blind_signing_confirmation = g_state.blind_signing_confirmation;
}

bool same_history_write_request(const UserSigningFlowCoreSnapshot& snapshot)
{
    return g_state.active() &&
           snapshot.active &&
           snapshot.stage == UserSigningStage::history_write &&
           g_state.stage == UserSigningStage::history_write &&
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
           g_state.signable_payload_available == snapshot.signable_payload_available &&
           g_state.blind_signing_confirmation == snapshot.blind_signing_confirmation;
}

struct UserSigningTerminalWireFields {
    const char* status;
    const char* reason;
};

UserSigningTerminalWireFields terminal_wire_fields(
    UserSigningTerminalResult result)
{
    switch (result) {
        case UserSigningTerminalResult::signed_success:
            return {"signed", "device_confirmed"};
        case UserSigningTerminalResult::rejected:
            return {"user_rejected", "user_rejected"};
        case UserSigningTerminalResult::timed_out:
            return {"user_timed_out", "user_timed_out"};
        case UserSigningTerminalResult::signing_failed:
            return {"signing_failed", "signing_failed"};
        case UserSigningTerminalResult::canceled:
        case UserSigningTerminalResult::history_error:
        case UserSigningTerminalResult::none:
        default:
            return {"", ""};
    }
}

}  // namespace

UserSigningTransitionResult user_signing_flow_clear()
{
    if (g_state.stage == UserSigningStage::signing_critical_section) {
        return UserSigningTransitionResult::busy;
    }
    const bool was_active = g_state.active();
    g_state.clear();
    return was_active ? UserSigningTransitionResult::ok
                      : UserSigningTransitionResult::inactive;
}

void user_signing_flow_set_session_validator(
    UserSigningSessionValidateFn validate_fn,
    void* context)
{
    g_validate_session = validate_fn;
    g_validate_session_context = context;
}

bool user_signing_flow_active()
{
    return g_state.active();
}

bool user_signing_flow_in_signing_critical_section()
{
    return g_state.stage == UserSigningStage::signing_critical_section;
}

bool user_signing_flow_session_matches(const char* session_id)
{
    return g_state.active() &&
           session_id != nullptr &&
           g_state.session_id[0] != '\0' &&
           strcmp(g_state.session_id, session_id) == 0;
}

SessionValidationResult user_signing_flow_validate_session()
{
    if (!g_state.active() || g_state.session_id[0] == '\0') {
        return SessionValidationResult::missing;
    }
    return validate_flow_session(g_state.session_id);
}

UserSigningFlowCoreSnapshot user_signing_flow_core_snapshot()
{
    UserSigningFlowCoreSnapshot snapshot = {};
    populate_core_snapshot(snapshot);
    return snapshot;
}

UserSigningReviewTimerState user_signing_flow_review_timer_state(TickType_t now)
{
    UserSigningReviewTimerState state = {};
    state.display_window = kTimeoutWindowNone;
    if (!g_state.active() ||
        g_state.stage != UserSigningStage::reviewing) {
        return state;
    }
    if (review_deadline_paused()) {
        state.available = true;
        state.paused = true;
        state.display_window = g_state.paused_request_window.window;
        state.display_tick = g_state.paused_request_window.paused_at;
        return state;
    }
    if (!timeout_window_active(g_state.request_window) ||
        timeout_window_reached(g_state.request_window, now)) {
        return state;
    }
    state.available = true;
    state.display_window = g_state.request_window;
    state.display_tick = now;
    return state;
}

bool user_signing_flow_snapshot_copy(UserSigningFlowSnapshot* output)
{
    if (output == nullptr) {
        return false;
    }
    memset(output, 0, sizeof(*output));
    populate_core_snapshot(*output);
    output->sui_policy_subject = g_state.sui_policy_subject;
    output->sui_review = g_state.sui_review;
    memcpy(output->account_address, g_state.account_address, sizeof(output->account_address));
    memcpy(output->message_preview, g_state.message_preview, sizeof(output->message_preview));
    return true;
}

UserSigningFlowSnapshot user_signing_flow_snapshot()
{
    UserSigningFlowSnapshot snapshot = {};
    user_signing_flow_snapshot_copy(&snapshot);
    return snapshot;
}

UserSigningFlowBeginResult user_signing_flow_begin(
    TickType_t now,
    const UserSigningTransactionBeginInput& input)
{
    if (g_state.active()) {
        return UserSigningFlowBeginResult::active;
    }
    // User-flow boundary assertion: a prepared value must still match the
    // selected route before any review UI state or signable scratch is created.
    if (input.route != Route::sui_sign_transaction ||
        input.prepared == nullptr ||
        input.prepared->route != input.route) {
        return UserSigningFlowBeginResult::invalid_argument;
    }
    if (input.prepared->tx_bytes == nullptr) {
        return UserSigningFlowBeginResult::invalid_payload;
    }
    const UserSigningFlowBeginResult payload_result =
        validate_prepared_payload_metadata(
            input.prepared->tx_bytes_size,
            kSuiSignTransactionTxBytesMaxBytes,
            input.prepared->payload_digest);
    if (payload_result != UserSigningFlowBeginResult::ok) {
        return payload_result;
    }
    if (!input.prepared->user_mode_authorization_covered) {
        return UserSigningFlowBeginResult::unsupported_transaction;
    }
    bool blind_signing_review = false;
    switch (input.prepared->user_authorization_outcome) {
        case SuiUserAuthorizationOutcome::offline_facts_review:
            if (input.prepared->sui_review.status != SuiReviewSummaryStatus::ok) {
                return UserSigningFlowBeginResult::unsupported_transaction;
            }
            break;
        case SuiUserAuthorizationOutcome::blind_signing:
            if (input.prepared->sui_review.status !=
                SuiReviewSummaryStatus::insufficient_review) {
                return UserSigningFlowBeginResult::unsupported_transaction;
            }
            blind_signing_review = true;
            break;
        case SuiUserAuthorizationOutcome::unavailable:
            return UserSigningFlowBeginResult::unsupported_transaction;
    }
    UserSigningBeginMetadata metadata = {};
    const UserSigningFlowBeginResult metadata_result =
        prepare_common_begin_metadata(
            input.request_id,
            input.request_identity,
            input.session_id,
            input.route,
            input.prepared->network,
            input.request_window,
            now,
            &metadata);
    if (metadata_result != UserSigningFlowBeginResult::ok) {
        return metadata_result;
    }
    const UserSigningFlowBeginResult begin_result =
        begin_common_review_state_with_owned_payload(
            metadata,
            input.prepared->tx_bytes,
            input.prepared->tx_bytes_size,
            kSuiSignTransactionTxBytesMaxBytes,
            input.prepared->payload_digest);
    if (begin_result != UserSigningFlowBeginResult::ok) {
        return begin_result;
    }
    input.prepared->tx_bytes = nullptr;
    input.prepared->tx_bytes_size = 0;

    g_state.sui_policy_subject = input.prepared->sui_policy_subject;
    g_state.sui_review = input.prepared->sui_review;
    g_state.blind_signing_confirmation = blind_signing_review;
    return UserSigningFlowBeginResult::ok;
}

UserSigningFlowBeginResult user_signing_flow_begin_personal_message(
    TickType_t now,
    const UserSigningPersonalMessageBeginInput& input)
{
    if (g_state.active()) {
        return UserSigningFlowBeginResult::active;
    }
    // User-flow boundary assertion: a prepared value must still match the
    // selected route before any review UI state or signable scratch is created.
    if (input.route != Route::sui_sign_personal_message ||
        input.prepared == nullptr ||
        input.prepared->route != input.route) {
        return UserSigningFlowBeginResult::invalid_argument;
    }
    UserSigningBeginMetadata metadata = {};
    const UserSigningFlowBeginResult metadata_result =
        prepare_common_begin_metadata(
            input.request_id,
            input.request_identity,
            input.session_id,
            input.route,
            input.prepared->network,
            input.request_window,
            now,
            &metadata);
    if (metadata_result != UserSigningFlowBeginResult::ok) {
        return metadata_result;
    }
    const UserSigningFlowBeginResult begin_result =
        begin_common_review_state_with_copy(
            metadata,
            input.prepared->message,
            input.prepared->message_size,
            kSuiSignPersonalMessageMaxBytes,
            input.prepared->payload_digest);
    if (begin_result != UserSigningFlowBeginResult::ok) {
        return begin_result;
    }

    memcpy(g_state.account_address, input.prepared->account_address, sizeof(g_state.account_address));
    make_message_preview(
        input.prepared->message,
        input.prepared->message_size,
        g_state.message_preview,
        sizeof(g_state.message_preview));
    return UserSigningFlowBeginResult::ok;
}

UserSigningTransitionResult user_signing_flow_accept_review(
    TickType_t now,
    TimeoutWindow pin_input_window)
{
    TimeoutWindow capped_pin_input_window = kTimeoutWindowNone;
    const UserSigningTransitionResult prepared =
        user_signing_flow_prepare_review_pin_input_window(
            now,
            pin_input_window,
            &capped_pin_input_window);
    if (prepared != UserSigningTransitionResult::ok) {
        return prepared;
    }
    g_state.stage = UserSigningStage::pin_entry;
    g_state.paused_pin_input_window = kPausedTimeoutWindowNone;
    g_state.pin_input_window = capped_pin_input_window;
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult user_signing_flow_prepare_review_pin_input_window(
    TickType_t now,
    TimeoutWindow pin_input_window,
    TimeoutWindow* output)
{
    if (output != nullptr) {
        *output = kTimeoutWindowNone;
    }
    if (output == nullptr) {
        return UserSigningTransitionResult::invalid_argument;
    }
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage != UserSigningStage::reviewing) {
        return UserSigningTransitionResult::wrong_stage;
    }
    if (!timeout_window_valid_and_open_at(pin_input_window, now)) {
        return UserSigningTransitionResult::invalid_deadline;
    }
    UserSigningTransitionResult guard = require_active_session();
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    guard = resume_review_deadline_if_paused(now);
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    const TickType_t capped_pin_deadline =
        timeout_window_cap_deadline(g_state.request_window, pin_input_window.deadline);
    if (timeout_window_tick_reached(now, capped_pin_deadline)) {
        g_state.terminalize(UserSigningTerminalResult::timed_out);
        return UserSigningTransitionResult::deadline_expired;
    }
    *output =
        timeout_window_from_deadline(pin_input_window.started_at, capped_pin_deadline);
    if (!timeout_window_valid_and_open_at(*output, now)) {
        g_state.terminalize(UserSigningTerminalResult::timed_out);
        return UserSigningTransitionResult::deadline_expired;
    }
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult user_signing_flow_cap_request_backed_pin_input_window(
    TickType_t now,
    TimeoutWindow pin_input_window,
    TimeoutWindow* output)
{
    if (output != nullptr) {
        *output = kTimeoutWindowNone;
    }
    if (output == nullptr) {
        return UserSigningTransitionResult::invalid_argument;
    }
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage == UserSigningStage::reviewing) {
        return user_signing_flow_prepare_review_pin_input_window(
            now,
            pin_input_window,
            output);
    }
    if (g_state.stage != UserSigningStage::pin_entry) {
        return UserSigningTransitionResult::wrong_stage;
    }
    if (!timeout_window_valid_and_open_at(pin_input_window, now)) {
        return UserSigningTransitionResult::invalid_deadline;
    }
    UserSigningTransitionResult guard = require_active_session();
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    const TickType_t capped_pin_deadline =
        timeout_window_cap_deadline(g_state.request_window, pin_input_window.deadline);
    if (timeout_window_tick_reached(now, capped_pin_deadline)) {
        g_state.terminalize(UserSigningTerminalResult::timed_out);
        return UserSigningTransitionResult::deadline_expired;
    }
    *output =
        timeout_window_from_deadline(pin_input_window.started_at, capped_pin_deadline);
    if (!timeout_window_valid_and_open_at(*output, now)) {
        g_state.terminalize(UserSigningTerminalResult::timed_out);
        return UserSigningTransitionResult::deadline_expired;
    }
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult user_signing_flow_return_to_review(
    TickType_t now,
    TimeoutWindow review_window)
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage != UserSigningStage::pin_entry) {
        return UserSigningTransitionResult::wrong_stage;
    }
    if (!timeout_window_valid_and_open_at(review_window, now)) {
        return UserSigningTransitionResult::invalid_deadline;
    }
    UserSigningTransitionResult guard = require_active_session();
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    if (timeout_window_reached(review_window, now)) {
        g_state.terminalize(UserSigningTerminalResult::timed_out);
        return UserSigningTransitionResult::deadline_expired;
    }
    g_state.stage = UserSigningStage::reviewing;
    g_state.request_window = review_window;
    g_state.paused_request_window = kPausedTimeoutWindowNone;
    g_state.pin_input_window = kTimeoutWindowNone;
    g_state.paused_pin_input_window = kPausedTimeoutWindowNone;
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult user_signing_flow_pause_review_deadline(TickType_t now)
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage != UserSigningStage::reviewing) {
        return UserSigningTransitionResult::wrong_stage;
    }
    const UserSigningTransitionResult guard = require_active_session();
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    const UserSigningTransitionResult deadline =
        terminalize_if_deadline_expired(now);
    if (deadline != UserSigningTransitionResult::ok) {
        return deadline;
    }
    if (review_deadline_paused()) {
        return UserSigningTransitionResult::ok;
    }
    g_state.paused_request_window =
        timeout_window_pause_at(g_state.request_window, now);
    if (!timeout_paused_window_valid(g_state.paused_request_window)) {
        g_state.paused_request_window = kPausedTimeoutWindowNone;
        return UserSigningTransitionResult::invalid_deadline;
    }
    g_state.request_window = kTimeoutWindowNone;
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult user_signing_flow_resume_review_deadline(TickType_t now)
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage != UserSigningStage::reviewing) {
        return UserSigningTransitionResult::wrong_stage;
    }
    const UserSigningTransitionResult guard = require_active_session();
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    const UserSigningTransitionResult deadline =
        terminalize_if_deadline_expired(now);
    if (deadline != UserSigningTransitionResult::ok) {
        return deadline;
    }
    return resume_review_deadline_if_paused(now);
}

UserSigningTransitionResult user_signing_flow_refresh_pin_deadline(TickType_t now)
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage != UserSigningStage::pin_entry) {
        return UserSigningTransitionResult::wrong_stage;
    }
    const UserSigningTransitionResult guard = require_active_session();
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    const TimeoutWindow resumed =
        timeout_window_resume_at(g_state.paused_pin_input_window, now);
    if (!timeout_window_valid(resumed)) {
        return UserSigningTransitionResult::invalid_deadline;
    }
    g_state.pin_input_window = resumed;
    g_state.paused_pin_input_window = kPausedTimeoutWindowNone;
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult user_signing_flow_pause_pin_deadline(TickType_t now)
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage != UserSigningStage::pin_entry) {
        return UserSigningTransitionResult::wrong_stage;
    }
    const UserSigningTransitionResult guard = require_active_session();
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    if (timeout_window_reached(g_state.pin_input_window, now)) {
        g_state.terminalize(UserSigningTerminalResult::timed_out);
        return UserSigningTransitionResult::deadline_expired;
    }
    g_state.paused_pin_input_window =
        timeout_window_pause_at(g_state.pin_input_window, now);
    if (!timeout_paused_window_valid(g_state.paused_pin_input_window)) {
        g_state.paused_pin_input_window = kPausedTimeoutWindowNone;
        return UserSigningTransitionResult::invalid_deadline;
    }
    g_state.pin_input_window = kTimeoutWindowNone;
    return UserSigningTransitionResult::ok;
}

bool user_signing_flow_apply_deadline_transition(TickType_t now)
{
    return g_state.active() && apply_deadline_transition_and_report_reached(now);
}

UserSigningTransitionResult
user_signing_flow_record_pin_verified_and_write_confirmation_history(
    TickType_t now,
    UserSigningHistoryWriteFn write_fn,
    void* context)
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage != UserSigningStage::pin_entry) {
        return UserSigningTransitionResult::wrong_stage;
    }
    if (write_fn == nullptr) {
        return UserSigningTransitionResult::invalid_argument;
    }
    if (timeout_window_active(g_state.pin_input_window)) {
        return UserSigningTransitionResult::wrong_stage;
    }
    UserSigningTransitionResult guard = require_active_session();
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    g_state.stage = UserSigningStage::history_write;
    g_state.pin_input_window = kTimeoutWindowNone;
    g_state.paused_pin_input_window = kPausedTimeoutWindowNone;

    guard = require_active_session();
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    const UserSigningFlowCoreSnapshot snapshot =
        user_signing_flow_core_snapshot();
    const bool write_ok = write_fn(snapshot, context);
    if (!same_history_write_request(snapshot)) {
        return UserSigningTransitionResult::stale_state;
    }
    if (!write_ok) {
        g_state.terminalize(UserSigningTerminalResult::history_error);
        return UserSigningTransitionResult::history_error;
    }
    g_state.stage = UserSigningStage::signing_critical_section;
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult
user_signing_flow_record_physical_confirmed_and_write_confirmation_history(
    TickType_t now,
    UserSigningHistoryWriteFn write_fn,
    void* context)
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage != UserSigningStage::reviewing) {
        return UserSigningTransitionResult::wrong_stage;
    }
    if (write_fn == nullptr) {
        return UserSigningTransitionResult::invalid_argument;
    }
    UserSigningTransitionResult guard = require_active_session();
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    guard = terminalize_if_deadline_expired(now);
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    guard = resume_review_deadline_if_paused(now);
    if (guard != UserSigningTransitionResult::ok) {
        return guard;
    }
    g_state.stage = UserSigningStage::history_write;
    g_state.pin_input_window = kTimeoutWindowNone;
    g_state.paused_pin_input_window = kPausedTimeoutWindowNone;

    const UserSigningFlowCoreSnapshot snapshot =
        user_signing_flow_core_snapshot();
    const bool write_ok = write_fn(snapshot, context);
    if (!same_history_write_request(snapshot)) {
        return UserSigningTransitionResult::stale_state;
    }
    if (!write_ok) {
        g_state.terminalize(UserSigningTerminalResult::history_error);
        return UserSigningTransitionResult::history_error;
    }
    g_state.stage = UserSigningStage::signing_critical_section;
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult user_signing_flow_consume_signable_payload(
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
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage != UserSigningStage::signing_critical_section) {
        return UserSigningTransitionResult::wrong_stage;
    }
    if (!g_state.signable_payload_available || g_state.signable_payload_size == 0) {
        return UserSigningTransitionResult::payload_unavailable;
    }
    if (output == nullptr || output_capacity < g_state.signable_payload_size || output_size == nullptr) {
        return UserSigningTransitionResult::output_too_small;
    }
    memcpy(output, g_state.signable_payload, g_state.signable_payload_size);
    *output_size = g_state.signable_payload_size;
    g_state.wipe_payload();
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult user_signing_flow_take_signable_payload(
    uint8_t** output,
    size_t* output_size)
{
    if (output != nullptr) {
        *output = nullptr;
    }
    if (output_size != nullptr) {
        *output_size = 0;
    }
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage != UserSigningStage::signing_critical_section) {
        return UserSigningTransitionResult::wrong_stage;
    }
    if (!g_state.signable_payload_available ||
        g_state.signable_payload == nullptr ||
        g_state.signable_payload_size == 0) {
        return UserSigningTransitionResult::payload_unavailable;
    }
    if (output == nullptr || output_size == nullptr) {
        return UserSigningTransitionResult::invalid_argument;
    }
    *output = g_state.signable_payload;
    *output_size = g_state.signable_payload_size;
    g_state.signable_payload = nullptr;
    g_state.signable_payload_size = 0;
    g_state.signable_payload_available = false;
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult user_signing_flow_record_device_rejected()
{
    return terminalize_if_rejectable(UserSigningTerminalResult::rejected);
}

UserSigningTransitionResult user_signing_flow_record_timeout(TickType_t now)
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage == UserSigningStage::signing_critical_section) {
        return UserSigningTransitionResult::busy;
    }
    if (g_state.stage != UserSigningStage::reviewing &&
        g_state.stage != UserSigningStage::pin_entry) {
        return UserSigningTransitionResult::wrong_stage;
    }
    if (!apply_deadline_transition_and_report_reached(now)) {
        return UserSigningTransitionResult::deadline_not_reached;
    }
    if (g_state.stage != UserSigningStage::terminal) {
        g_state.terminalize(UserSigningTerminalResult::timed_out);
    }
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult user_signing_flow_record_signing_failed()
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage != UserSigningStage::signing_critical_section) {
        return UserSigningTransitionResult::wrong_stage;
    }
    g_state.terminalize(UserSigningTerminalResult::signing_failed);
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult user_signing_flow_complete_signed()
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage != UserSigningStage::signing_critical_section) {
        return UserSigningTransitionResult::wrong_stage;
    }
    if (g_state.signable_payload_available) {
        return UserSigningTransitionResult::payload_not_consumed;
    }
    g_state.terminalize(UserSigningTerminalResult::signed_success);
    return UserSigningTransitionResult::ok;
}

UserSigningTransitionResult user_signing_flow_cancel_for_disconnect(
    const char* session_id)
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (!user_signing_flow_session_matches(session_id)) {
        return UserSigningTransitionResult::invalid_session;
    }
    return terminalize_if_precritical_cleanup(UserSigningTerminalResult::canceled);
}

UserSigningTransitionResult user_signing_flow_cancel_for_session_loss()
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    if (g_state.stage == UserSigningStage::signing_critical_section) {
        return UserSigningTransitionResult::busy;
    }
    if (validate_flow_session(g_state.session_id) == SessionValidationResult::ok) {
        return UserSigningTransitionResult::session_still_active;
    }
    return terminalize_if_precritical_cleanup(UserSigningTerminalResult::canceled);
}

UserSigningTransitionResult user_signing_flow_cancel_for_ui_loss()
{
    if (!g_state.active()) {
        return UserSigningTransitionResult::inactive;
    }
    return terminalize_if_precritical_cleanup(UserSigningTerminalResult::canceled);
}

UserSigningTransitionResult user_signing_flow_cancel_for_pin_loss()
{
    return user_signing_flow_cancel_for_ui_loss();
}

bool user_signing_flow_terminal_pending()
{
    return g_state.stage == UserSigningStage::terminal &&
           g_state.terminal_result != UserSigningTerminalResult::none;
}

bool user_signing_flow_consume_terminal_result(
    UserSigningTerminalResult* output)
{
    if (!user_signing_flow_terminal_pending() || output == nullptr) {
        return false;
    }
    *output = g_state.terminal_result;
    g_state.clear();
    return true;
}

const char* user_signing_flow_terminal_status(
    UserSigningTerminalResult result)
{
    return terminal_wire_fields(result).status;
}

const char* user_signing_flow_terminal_reason(
    UserSigningTerminalResult result)
{
    return terminal_wire_fields(result).reason;
}

}  // namespace signing
