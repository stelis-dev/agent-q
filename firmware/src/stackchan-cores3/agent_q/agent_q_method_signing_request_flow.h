#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_approval_history.h"
#include "agent_q_method_limits.h"
#include "agent_q_session.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

constexpr size_t kAgentQMethodSigningRequestIdSize = 80;
constexpr size_t kAgentQMethodSigningRequestPayloadMaxBytes =
    kAgentQSuiSignTransactionTxBytesMaxBytes;
constexpr size_t kAgentQMethodSigningRequestNetworkSize = 12;
constexpr size_t kAgentQMethodSigningRequestRecipientSize = 67;
constexpr size_t kAgentQMethodSigningRequestAssetSize = 32;
constexpr size_t kAgentQMethodSigningRequestU64Size = 21;

enum class AgentQMethodSigningRequestPolicyDecision {
    ask,
};

enum class AgentQMethodSigningRequestStage {
    inactive,
    awaiting_user,
    awaiting_history,
    signing_critical_section,
    terminal,
};

enum class AgentQMethodSigningRequestTerminalResult {
    none,
    user_approved,
    user_rejected,
    user_timeout,
    canceled,
    session_lost,
    ui_error,
    history_error,
    method_error,
};

enum class AgentQMethodSigningRequestTransitionResult {
    began,
    user_approved_waiting_history,
    history_durable,
    terminal_user_approved,
    terminal_user_rejected,
    terminal_user_timeout,
    terminal_canceled,
    terminal_session_lost,
    terminal_ui_error,
    terminal_history_error,
    terminal_method_error,
    active,
    inactive,
    invalid_argument,
    session_mismatch,
    deadline_not_reached,
    busy,
    terminal_pending,
};

struct AgentQMethodSigningRequestBeginInput {
    const char* request_id;
    const char* session_id;
    const char* chain;
    const char* method;
    const uint8_t* signable_payload;
    size_t signable_payload_size;
    const char* network;
    const char* recipient;
    const char* asset;
    const char* amount;
    const char* gas_budget;
    const char* gas_price;
    const char* payload_digest;
    const char* policy_hash;
    const char* rule_ref;
    AgentQMethodSigningRequestPolicyDecision policy_decision;
    TickType_t deadline;
};

struct AgentQMethodSigningRequestSnapshot {
    bool active;
    AgentQMethodSigningRequestStage stage;
    AgentQMethodSigningRequestPolicyDecision policy_decision;
    AgentQMethodSigningRequestTerminalResult terminal_result;
    const char* request_id;
    const char* session_id;
    const char* chain;
    const char* method;
    size_t signable_payload_size;
    const char* network;
    const char* recipient;
    const char* asset;
    const char* amount;
    const char* gas_budget;
    const char* gas_price;
    const char* payload_digest;
    const char* policy_hash;
    const char* rule_ref;
    TickType_t deadline;
};

struct AgentQMethodSigningRequestTerminalSnapshot {
    AgentQMethodSigningRequestTerminalResult result;
    char request_id[kAgentQMethodSigningRequestIdSize];
    char session_id[kAgentQSessionIdSize];
    char chain[kAgentQApprovalHistoryChainSize];
    char method[kAgentQApprovalHistoryMethodSize];
    char payload_digest[kAgentQApprovalHistoryDigestSize];
    char policy_hash[kAgentQApprovalHistoryDigestSize];
    char rule_ref[kAgentQApprovalHistoryRuleRefSize];
};

void method_signing_request_flow_clear();
bool method_signing_request_flow_active();
AgentQMethodSigningRequestSnapshot method_signing_request_flow_snapshot();

AgentQMethodSigningRequestTransitionResult method_signing_request_flow_begin(
    const AgentQMethodSigningRequestBeginInput& input);
bool method_signing_request_flow_deadline_reached(TickType_t now);
AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_user_approved(
    const char* session_id,
    TickType_t now);
AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_history_durable(
    const char* session_id);
bool method_signing_request_flow_copy_signable_payload(
    uint8_t* output,
    size_t output_size,
    size_t* copied_size);
AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_user_rejected(
    const char* session_id,
    TickType_t now);
AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_timeout(TickType_t now);
AgentQMethodSigningRequestTransitionResult method_signing_request_flow_cancel_for_disconnect(
    const char* session_id);
AgentQMethodSigningRequestTransitionResult method_signing_request_flow_cancel_for_session_loss(
    const char* session_id);
AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_ui_error(
    const char* session_id);
AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_history_error(
    const char* session_id);
AgentQMethodSigningRequestTransitionResult method_signing_request_flow_complete_approved(
    const char* session_id);
AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_method_error(
    const char* session_id);
bool method_signing_request_flow_consume_terminal(
    AgentQMethodSigningRequestTerminalSnapshot* output);

}  // namespace agent_q
