#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_approval_history.h"
#include "agent_q_sign_personal_message_limits.h"
#include "agent_q_sign_request_identity.h"
#include "agent_q_sign_transaction_limits.h"
#include "agent_q_signing_route.h"
#include "agent_q_session.h"
#include "agent_q_timeout_window.h"
#include "agent_q_user_signing_limits.h"
#include "agent_q_sui_account.h"
#include "agent_q_sui_signing_preparation.h"
#include "agent_q_common/sui/agent_q_sui_transaction_facts.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQUserSigningFlowBeginResult {
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

enum class AgentQUserSigningStage {
    none,
    reviewing,
    pin_entry,
    history_write,
    signing_critical_section,
    terminal,
};

enum class AgentQUserSigningTerminalResult {
    none,
    signed_success,
    rejected,
    timed_out,
    canceled,
    history_error,
    signing_failed,
};

enum class AgentQUserSigningTransitionResult {
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

struct AgentQUserSigningTransactionBeginInput {
    const char* request_id;
    const uint8_t* request_identity;
    const char* session_id;
    AgentQSigningRoute route;
    const AgentQSuiPreparedSignTransaction* prepared;
    AgentQTimeoutWindow request_window;
};

struct AgentQUserSigningPersonalMessageBeginInput {
    const char* request_id;
    const uint8_t* request_identity;
    const char* session_id;
    AgentQSigningRoute route;
    const AgentQSuiPreparedPersonalMessage* prepared;
    AgentQTimeoutWindow request_window;
};

// Small lifecycle snapshot for state gates, terminal handling, history writes,
// and signing handoff. Keep large review-only facts out of these paths.
struct AgentQUserSigningFlowCoreSnapshot {
    bool active;
    AgentQUserSigningStage stage;
    AgentQUserSigningTerminalResult terminal_result;
    AgentQSigningRoute signing_route;
    char request_id[kAgentQUserSigningIdSize];
    uint8_t request_identity[kAgentQSignRequestIdentitySize];
    char session_id[kAgentQSessionIdSize];
    char chain[kAgentQUserSigningChainSize];
    char method[kAgentQUserSigningMethodSize];
    char network[kAgentQUserSigningNetworkSize];
    char payload_digest[kAgentQApprovalHistoryDigestSize];
    AgentQTimeoutWindow request_window;
    AgentQTimeoutWindow pin_input_window;
    size_t signable_payload_size;
    bool signable_payload_available;
};

// Full review snapshot. It includes the Sui fact matrix and must be copied only
// into caller-owned or static scratch when rendering review UI details.
struct AgentQUserSigningFlowSnapshot : AgentQUserSigningFlowCoreSnapshot {
    SuiTransactionPolicyFacts sui_facts;
    char account_address[kSuiAddressBufferSize];
    char message_preview[kAgentQSignPersonalMessagePreviewSize];
};

using AgentQUserSigningHistoryWriteFn =
    bool (*)(const AgentQUserSigningFlowCoreSnapshot& snapshot, void* context);

AgentQUserSigningTransitionResult user_signing_flow_clear();
bool user_signing_flow_active();
bool user_signing_flow_session_matches(const char* session_id);
AgentQUserSigningFlowCoreSnapshot user_signing_flow_core_snapshot();
bool user_signing_flow_snapshot_copy(AgentQUserSigningFlowSnapshot* output);
AgentQUserSigningFlowSnapshot user_signing_flow_snapshot();

AgentQUserSigningFlowBeginResult user_signing_flow_begin(
    const AgentQUserSigningTransactionBeginInput& input);
AgentQUserSigningFlowBeginResult user_signing_flow_begin_personal_message(
    const AgentQUserSigningPersonalMessageBeginInput& input);
AgentQUserSigningTransitionResult user_signing_flow_accept_review(
    TickType_t now,
    AgentQTimeoutWindow pin_input_window);
AgentQUserSigningTransitionResult user_signing_flow_return_to_review(
    TickType_t now,
    AgentQTimeoutWindow review_window);
AgentQUserSigningTransitionResult user_signing_flow_refresh_pin_deadline(TickType_t now);
AgentQUserSigningTransitionResult user_signing_flow_pause_pin_deadline(TickType_t now);
bool user_signing_flow_deadline_reached(TickType_t now);
AgentQUserSigningTransitionResult
user_signing_flow_record_pin_verified_and_write_confirmation_history(
    TickType_t now,
    AgentQUserSigningHistoryWriteFn write_fn,
    void* context);
AgentQUserSigningTransitionResult
user_signing_flow_record_physical_confirmed_and_write_confirmation_history(
    TickType_t now,
    AgentQUserSigningHistoryWriteFn write_fn,
    void* context);
AgentQUserSigningTransitionResult user_signing_flow_consume_signable_payload(
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

AgentQUserSigningTransitionResult user_signing_flow_record_device_rejected();
AgentQUserSigningTransitionResult user_signing_flow_record_timeout(TickType_t now);
AgentQUserSigningTransitionResult user_signing_flow_record_signing_failed();
AgentQUserSigningTransitionResult user_signing_flow_complete_signed();
AgentQUserSigningTransitionResult user_signing_flow_cancel_for_disconnect(
    const char* session_id);
AgentQUserSigningTransitionResult user_signing_flow_cancel_for_session_loss();
AgentQUserSigningTransitionResult user_signing_flow_cancel_for_ui_loss();
AgentQUserSigningTransitionResult user_signing_flow_cancel_for_pin_loss();

bool user_signing_flow_terminal_pending();
bool user_signing_flow_consume_terminal_result(
    AgentQUserSigningTerminalResult* output);

const char* user_signing_flow_terminal_status(
    AgentQUserSigningTerminalResult result);
const char* user_signing_flow_terminal_reason(
    AgentQUserSigningTerminalResult result);

}  // namespace agent_q
