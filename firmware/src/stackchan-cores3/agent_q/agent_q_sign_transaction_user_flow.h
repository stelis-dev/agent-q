#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_approval_history.h"
#include "agent_q_sign_transaction_limits.h"
#include "agent_q_session.h"
#include "agent_q_sign_transaction_user_limits.h"
#include "agent_q_common/sui/agent_q_sui_transaction_facts.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQSignTransactionUserFlowBeginResult {
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

enum class AgentQSignTransactionUserStage {
    none,
    reviewing,
    pin_entry,
    history_write,
    signing_critical_section,
    terminal,
};

enum class AgentQSignTransactionUserTerminalResult {
    none,
    signed_success,
    rejected,
    timed_out,
    canceled,
    history_error,
    signing_failed,
};

enum class AgentQSignTransactionUserTransitionResult {
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

struct AgentQSignTransactionUserBeginInput {
    const char* request_id;
    const char* session_id;
    const char* chain;
    const char* method;
    const char* network;
    const uint8_t* tx_bytes;
    size_t tx_bytes_size;
    TickType_t request_deadline;
};

struct AgentQSignTransactionUserFlowSnapshot {
    bool active;
    AgentQSignTransactionUserStage stage;
    AgentQSignTransactionUserTerminalResult terminal_result;
    char request_id[kAgentQSignTransactionUserIdSize];
    char session_id[kAgentQSessionIdSize];
    char chain[kAgentQSignTransactionUserChainSize];
    char method[kAgentQSignTransactionUserMethodSize];
    char network[kAgentQSignTransactionUserNetworkSize];
    char payload_digest[kAgentQApprovalHistoryDigestSize];
    TickType_t request_deadline;
    TickType_t pin_input_deadline;
    size_t signable_payload_size;
    bool signable_payload_available;
    SuiTransferFacts sui_transfer;
};

using AgentQSignTransactionUserHistoryWriteFn =
    bool (*)(const AgentQSignTransactionUserFlowSnapshot& snapshot, void* context);

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_clear();
bool sign_transaction_user_flow_active();
bool sign_transaction_user_flow_in_signing_critical_section();
bool sign_transaction_user_flow_session_matches(const char* session_id);
AgentQSessionValidationResult sign_transaction_user_flow_validate_session();
AgentQSignTransactionUserFlowSnapshot sign_transaction_user_flow_snapshot();

AgentQSignTransactionUserFlowBeginResult sign_transaction_user_flow_begin(
    const AgentQSignTransactionUserBeginInput& input);
AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_accept_review(
    TickType_t now,
    TickType_t pin_deadline);
AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_refresh_pin_deadline(
    TickType_t pin_deadline);
AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_pause_pin_deadline();
bool sign_transaction_user_flow_deadline_reached(TickType_t now);
AgentQSignTransactionUserTransitionResult
sign_transaction_user_flow_record_pin_verified_and_write_confirmation_history(
    TickType_t now,
    AgentQSignTransactionUserHistoryWriteFn write_fn,
    void* context);
AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_consume_signable_payload(
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_record_device_rejected();
AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_record_timeout(TickType_t now);
AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_record_signing_failed();
AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_complete_signed();
AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_cancel_for_disconnect(
    const char* session_id);
AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_cancel_for_session_loss();
AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_cancel_for_ui_loss();
AgentQSignTransactionUserTransitionResult sign_transaction_user_flow_cancel_for_pin_loss();

bool sign_transaction_user_flow_terminal_pending();
bool sign_transaction_user_flow_consume_terminal_result(
    AgentQSignTransactionUserTerminalResult* output);

const char* sign_transaction_user_flow_terminal_status(
    AgentQSignTransactionUserTerminalResult result);
const char* sign_transaction_user_flow_terminal_reason(
    AgentQSignTransactionUserTerminalResult result);

}  // namespace agent_q
