#pragma once

#include <stddef.h>

#include "agent_q_approval_history.h"
#include "agent_q_session.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

constexpr size_t kAgentQMethodApprovalRequestIdSize = 80;

enum class AgentQMethodApprovalPolicyDecision {
    ask,
};

enum class AgentQMethodApprovalStage {
    inactive,
    awaiting_user,
    signing_critical_section,
    terminal,
};

enum class AgentQMethodApprovalTerminalResult {
    none,
    user_approved,
    user_rejected,
    user_timeout,
    canceled,
    session_lost,
    ui_error,
    method_error,
};

enum class AgentQMethodApprovalTransitionResult {
    began,
    approved_for_signing,
    terminal_user_approved,
    terminal_user_rejected,
    terminal_user_timeout,
    terminal_canceled,
    terminal_session_lost,
    terminal_ui_error,
    terminal_method_error,
    active,
    inactive,
    invalid_argument,
    session_mismatch,
    deadline_not_reached,
    busy,
    terminal_pending,
};

struct AgentQMethodApprovalBeginInput {
    const char* request_id;
    const char* session_id;
    const char* chain;
    const char* method;
    const char* payload_digest;
    const char* policy_hash;
    const char* rule_ref;
    AgentQMethodApprovalPolicyDecision policy_decision;
    TickType_t deadline;
};

struct AgentQMethodApprovalSnapshot {
    bool active;
    AgentQMethodApprovalStage stage;
    AgentQMethodApprovalPolicyDecision policy_decision;
    AgentQMethodApprovalTerminalResult terminal_result;
    const char* request_id;
    const char* session_id;
    const char* chain;
    const char* method;
    const char* payload_digest;
    const char* policy_hash;
    const char* rule_ref;
    TickType_t deadline;
};

struct AgentQMethodApprovalTerminalSnapshot {
    AgentQMethodApprovalTerminalResult result;
    char request_id[kAgentQMethodApprovalRequestIdSize];
    char session_id[kAgentQSessionIdSize];
    char chain[kAgentQApprovalHistoryChainSize];
    char method[kAgentQApprovalHistoryMethodSize];
    char payload_digest[kAgentQApprovalHistoryDigestSize];
    char policy_hash[kAgentQApprovalHistoryDigestSize];
    char rule_ref[kAgentQApprovalHistoryRuleRefSize];
};

void method_approval_flow_clear();
bool method_approval_flow_active();
AgentQMethodApprovalSnapshot method_approval_flow_snapshot();

AgentQMethodApprovalTransitionResult method_approval_flow_begin(
    const AgentQMethodApprovalBeginInput& input);
bool method_approval_flow_deadline_reached(TickType_t now);
AgentQMethodApprovalTransitionResult method_approval_flow_approve_for_signing(
    const char* session_id,
    TickType_t now);
AgentQMethodApprovalTransitionResult method_approval_flow_record_user_rejected(
    const char* session_id,
    TickType_t now);
AgentQMethodApprovalTransitionResult method_approval_flow_record_timeout(TickType_t now);
AgentQMethodApprovalTransitionResult method_approval_flow_cancel_for_disconnect(
    const char* session_id);
AgentQMethodApprovalTransitionResult method_approval_flow_cancel_for_session_loss(
    const char* session_id);
AgentQMethodApprovalTransitionResult method_approval_flow_record_ui_error(
    const char* session_id);
AgentQMethodApprovalTransitionResult method_approval_flow_complete_approved(
    const char* session_id);
AgentQMethodApprovalTransitionResult method_approval_flow_record_method_error(
    const char* session_id);
bool method_approval_flow_consume_terminal(
    AgentQMethodApprovalTerminalSnapshot* output);

}  // namespace agent_q
