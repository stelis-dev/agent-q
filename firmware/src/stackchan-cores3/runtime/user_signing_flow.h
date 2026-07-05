#pragma once

#include <stddef.h>
#include <stdint.h>

#include "approval_history.h"
#include "sign_personal_message_limits.h"
#include "sign_request_identity.h"
#include "sign_transaction_limits.h"
#include "signing_route.h"
#include "session.h"
#include "transport/timeout_window.h"
#include "user_signing_limits.h"
#include "user_signing_review_timer_state.h"
#include "sui_account.h"
#include "sui_signing_preparation.h"
#include "sui/transaction_facts.h"
#include "freertos/FreeRTOS.h"

namespace signing {

enum class UserSigningFlowBeginResult {
    ok,
    active,
    invalid_argument,
    invalid_session,
    invalid_deadline,
    invalid_network,
    invalid_payload,
    malformed_transaction,
    unsupported_transaction,
    account_unavailable,
    invalid_account,
    digest_error,
};

enum class UserSigningStage {
    none,
    reviewing,
    pin_entry,
    history_write,
    signing_critical_section,
    terminal,
};

enum class UserSigningTerminalResult {
    none,
    signed_success,
    rejected,
    timed_out,
    canceled,
    history_error,
    signing_failed,
};

enum class UserSigningTransitionResult {
    ok,
    inactive,
    wrong_stage,
    invalid_argument,
    invalid_session,
    invalid_deadline,
    deadline_expired,
    deadline_not_reached,
    session_still_active,
    history_error,
    stale_state,
    output_too_small,
    payload_unavailable,
    payload_not_consumed,
    busy,
};

struct UserSigningTransactionBeginInput {
    const char* request_id;
    const uint8_t* request_identity;
    const char* session_id;
    Route route;
    SuiPreparedSignTransaction* prepared;
    TimeoutWindow request_window;
};

struct UserSigningPersonalMessageBeginInput {
    const char* request_id;
    const uint8_t* request_identity;
    const char* session_id;
    Route route;
    const SuiPreparedPersonalMessage* prepared;
    TimeoutWindow request_window;
};

// Small lifecycle snapshot for state gates, terminal handling, history writes,
// and signing handoff. Keep large review-only facts out of these paths.
struct UserSigningFlowCoreSnapshot {
    bool active;
    UserSigningStage stage;
    UserSigningTerminalResult terminal_result;
    Route signing_route;
    char request_id[kUserSigningIdSize];
    uint8_t request_identity[kSignRequestIdentitySize];
    char session_id[kSessionIdSize];
    char chain[kUserSigningChainSize];
    char method[kUserSigningMethodSize];
    char network[kUserSigningNetworkSize];
    char payload_digest[kApprovalHistoryDigestSize];
    TimeoutWindow request_window;
    TimeoutWindow pin_input_window;
    size_t signable_payload_size;
    bool signable_payload_available;
    bool blind_signing_confirmation;
};

// Full review snapshot. It includes compact review metadata and must be copied
// only into caller-owned or static scratch when rendering review UI details.
struct UserSigningFlowSnapshot : UserSigningFlowCoreSnapshot {
    SuiPolicySubjectFacts sui_policy_subject;
    SuiReviewSummary sui_review;
    char account_address[kSuiAddressBufferSize];
    char message_preview[kSignPersonalMessagePreviewSize];
};

using UserSigningHistoryWriteFn =
    bool (*)(const UserSigningFlowCoreSnapshot& snapshot, void* context);

UserSigningTransitionResult user_signing_flow_clear();
bool user_signing_flow_active();
bool user_signing_flow_session_matches(const char* session_id);
UserSigningFlowCoreSnapshot user_signing_flow_core_snapshot();
UserSigningReviewTimerState user_signing_flow_review_timer_state(TickType_t now);
bool user_signing_flow_snapshot_copy(UserSigningFlowSnapshot* output);
UserSigningFlowSnapshot user_signing_flow_snapshot();

UserSigningFlowBeginResult user_signing_flow_begin(
    TickType_t now,
    const UserSigningTransactionBeginInput& input);
UserSigningFlowBeginResult user_signing_flow_begin_personal_message(
    TickType_t now,
    const UserSigningPersonalMessageBeginInput& input);
UserSigningTransitionResult user_signing_flow_accept_review(
    TickType_t now,
    TimeoutWindow pin_input_window);
UserSigningTransitionResult user_signing_flow_prepare_review_pin_input_window(
    TickType_t now,
    TimeoutWindow pin_input_window,
    TimeoutWindow* output);
UserSigningTransitionResult user_signing_flow_cap_request_backed_pin_input_window(
    TickType_t now,
    TimeoutWindow pin_input_window,
    TimeoutWindow* output);
UserSigningTransitionResult user_signing_flow_return_to_review(
    TickType_t now,
    TimeoutWindow review_window);
UserSigningTransitionResult user_signing_flow_pause_review_deadline(TickType_t now);
UserSigningTransitionResult user_signing_flow_resume_review_deadline(TickType_t now);
UserSigningTransitionResult user_signing_flow_refresh_pin_deadline(TickType_t now);
UserSigningTransitionResult user_signing_flow_pause_pin_deadline(TickType_t now);
bool user_signing_flow_apply_deadline_transition(TickType_t now);
UserSigningTransitionResult
user_signing_flow_record_pin_verified_and_write_confirmation_history(
    TickType_t now,
    UserSigningHistoryWriteFn write_fn,
    void* context);
UserSigningTransitionResult
user_signing_flow_record_physical_confirmed_and_write_confirmation_history(
    TickType_t now,
    UserSigningHistoryWriteFn write_fn,
    void* context);
UserSigningTransitionResult user_signing_flow_consume_signable_payload(
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);
UserSigningTransitionResult user_signing_flow_take_signable_payload(
    uint8_t** output,
    size_t* output_size);

UserSigningTransitionResult user_signing_flow_record_device_rejected();
UserSigningTransitionResult user_signing_flow_record_timeout(TickType_t now);
UserSigningTransitionResult user_signing_flow_record_signing_failed();
UserSigningTransitionResult user_signing_flow_complete_signed();
UserSigningTransitionResult user_signing_flow_cancel_for_disconnect(
    const char* session_id);
UserSigningTransitionResult user_signing_flow_cancel_for_session_loss();
UserSigningTransitionResult user_signing_flow_cancel_for_ui_loss();
UserSigningTransitionResult user_signing_flow_cancel_for_pin_loss();

bool user_signing_flow_terminal_pending();
bool user_signing_flow_consume_terminal_result(
    UserSigningTerminalResult* output);

const char* user_signing_flow_terminal_status(
    UserSigningTerminalResult result);
const char* user_signing_flow_terminal_reason(
    UserSigningTerminalResult result);

}  // namespace signing
