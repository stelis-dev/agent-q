#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_approval_history.h"
#include "agent_q_method_limits.h"
#include "agent_q_session.h"
#include "agent_q_signature_request_limits.h"
#include "agent_q_common/sui/agent_q_sui_transaction_facts.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQSignatureRequestFlowBeginResult {
    ok,
    active,
    invalid_argument,
    invalid_session,
    invalid_deadline,
    unsupported_method,
    invalid_network,
    invalid_payload,
    invalid_transaction,
    invalid_summary,
    account_unavailable,
    invalid_account,
    digest_error,
};

enum class AgentQSignatureRequestStage {
    none,
    reviewing,
    pin_entry,
    history_write,
    signing_critical_section,
    terminal,
};

enum class AgentQSignatureRequestTerminalResult {
    none,
    signed_success,
    rejected,
    timed_out,
    canceled,
    history_error,
    signing_failed,
};

enum class AgentQSignatureRequestTransitionResult {
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

struct AgentQSignatureRequestBeginInput {
    const char* request_id;
    const char* session_id;
    const char* chain;
    const char* method;
    const char* network;
    const uint8_t* tx_bytes;
    size_t tx_bytes_size;
    TickType_t deadline;
};

struct AgentQSignatureRequestFlowSnapshot {
    bool active;
    AgentQSignatureRequestStage stage;
    AgentQSignatureRequestTerminalResult terminal_result;
    char request_id[kAgentQSignatureRequestIdSize];
    char session_id[kAgentQSessionIdSize];
    char chain[kAgentQSignatureRequestChainSize];
    char method[kAgentQSignatureRequestMethodSize];
    char network[kAgentQSignatureRequestNetworkSize];
    char payload_digest[kAgentQApprovalHistoryDigestSize];
    TickType_t deadline;
    TickType_t confirmation_deadline;
    size_t signable_payload_size;
    bool signable_payload_available;
    SuiTransferFacts sui_transfer;
};

using AgentQSignatureRequestHistoryWriteFn =
    bool (*)(const AgentQSignatureRequestFlowSnapshot& snapshot, void* context);

AgentQSignatureRequestTransitionResult signature_request_flow_clear();
bool signature_request_flow_active();
bool signature_request_flow_in_signing_critical_section();
bool signature_request_flow_session_matches(const char* session_id);
AgentQSessionValidationResult signature_request_flow_validate_session();
AgentQSignatureRequestFlowSnapshot signature_request_flow_snapshot();

AgentQSignatureRequestFlowBeginResult signature_request_flow_begin(
    const AgentQSignatureRequestBeginInput& input);
AgentQSignatureRequestTransitionResult signature_request_flow_accept_review(
    TickType_t now,
    TickType_t pin_deadline);
TickType_t signature_request_flow_retry_deadline(TickType_t fallback_deadline);
AgentQSignatureRequestTransitionResult signature_request_flow_refresh_pin_deadline(
    TickType_t pin_deadline);
AgentQSignatureRequestTransitionResult signature_request_flow_pause_pin_deadline();
bool signature_request_flow_deadline_reached(TickType_t now);
AgentQSignatureRequestTransitionResult
signature_request_flow_record_pin_verified_and_write_confirmation_history(
    TickType_t now,
    AgentQSignatureRequestHistoryWriteFn write_fn,
    void* context);
AgentQSignatureRequestTransitionResult signature_request_flow_consume_signable_payload(
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

AgentQSignatureRequestTransitionResult signature_request_flow_record_device_rejected();
AgentQSignatureRequestTransitionResult signature_request_flow_record_timeout(TickType_t now);
AgentQSignatureRequestTransitionResult signature_request_flow_record_signing_failed();
AgentQSignatureRequestTransitionResult signature_request_flow_complete_signed();
AgentQSignatureRequestTransitionResult signature_request_flow_cancel_for_disconnect(
    const char* session_id);
AgentQSignatureRequestTransitionResult signature_request_flow_cancel_for_session_loss();
AgentQSignatureRequestTransitionResult signature_request_flow_cancel_for_ui_loss();
AgentQSignatureRequestTransitionResult signature_request_flow_cancel_for_pin_loss();

bool signature_request_flow_terminal_pending();
bool signature_request_flow_consume_terminal_result(
    AgentQSignatureRequestTerminalResult* output);

const char* signature_request_flow_terminal_status(
    AgentQSignatureRequestTerminalResult result);
const char* signature_request_flow_terminal_reason(
    AgentQSignatureRequestTerminalResult result);

}  // namespace agent_q
