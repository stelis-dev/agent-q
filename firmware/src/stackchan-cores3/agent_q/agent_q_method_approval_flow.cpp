#include "agent_q_method_approval_flow.h"

#include <stdint.h>
#include <string.h>

namespace agent_q {
namespace {

struct MethodApprovalFlowState {
    AgentQMethodApprovalStage stage = AgentQMethodApprovalStage::inactive;
    AgentQMethodApprovalPolicyDecision policy_decision =
        AgentQMethodApprovalPolicyDecision::ask;
    AgentQMethodApprovalTerminalResult terminal_result =
        AgentQMethodApprovalTerminalResult::none;
    char request_id[kAgentQMethodApprovalRequestIdSize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    char chain[kAgentQApprovalHistoryChainSize] = {};
    char method[kAgentQApprovalHistoryMethodSize] = {};
    char payload_digest[kAgentQApprovalHistoryDigestSize] = {};
    char policy_hash[kAgentQApprovalHistoryDigestSize] = {};
    char rule_ref[kAgentQApprovalHistoryRuleRefSize] = {};
    TickType_t deadline = 0;

    void clear()
    {
        memset(this, 0, sizeof(*this));
        stage = AgentQMethodApprovalStage::inactive;
        policy_decision = AgentQMethodApprovalPolicyDecision::ask;
        terminal_result = AgentQMethodApprovalTerminalResult::none;
    }
};

MethodApprovalFlowState g_state;

bool copy_nonempty_c_string(const char* input, char* output, size_t output_size)
{
    if (input == nullptr || input[0] == '\0' || output == nullptr || output_size == 0) {
        return false;
    }
    size_t index = 0;
    while (input[index] != '\0' && index + 1 < output_size) {
        output[index] = input[index];
        ++index;
    }
    if (input[index] != '\0') {
        output[0] = '\0';
        return false;
    }
    output[index] = '\0';
    return true;
}

bool tick_reached(TickType_t now, TickType_t deadline)
{
    return deadline != 0 &&
           static_cast<int32_t>(now - deadline) >= 0;
}

bool session_matches(const char* session_id)
{
    return session_id != nullptr &&
           g_state.session_id[0] != '\0' &&
           strcmp(g_state.session_id, session_id) == 0;
}

bool has_terminal()
{
    return g_state.stage == AgentQMethodApprovalStage::terminal;
}

AgentQMethodApprovalTransitionResult transition_result_for_terminal(
    AgentQMethodApprovalTerminalResult terminal)
{
    switch (terminal) {
        case AgentQMethodApprovalTerminalResult::user_approved:
            return AgentQMethodApprovalTransitionResult::terminal_user_approved;
        case AgentQMethodApprovalTerminalResult::user_rejected:
            return AgentQMethodApprovalTransitionResult::terminal_user_rejected;
        case AgentQMethodApprovalTerminalResult::user_timeout:
            return AgentQMethodApprovalTransitionResult::terminal_user_timeout;
        case AgentQMethodApprovalTerminalResult::canceled:
            return AgentQMethodApprovalTransitionResult::terminal_canceled;
        case AgentQMethodApprovalTerminalResult::session_lost:
            return AgentQMethodApprovalTransitionResult::terminal_session_lost;
        case AgentQMethodApprovalTerminalResult::ui_error:
            return AgentQMethodApprovalTransitionResult::terminal_ui_error;
        case AgentQMethodApprovalTerminalResult::method_error:
            return AgentQMethodApprovalTransitionResult::terminal_method_error;
        case AgentQMethodApprovalTerminalResult::none:
        default:
            return AgentQMethodApprovalTransitionResult::invalid_argument;
    }
}

AgentQMethodApprovalTransitionResult record_terminal(
    AgentQMethodApprovalTerminalResult terminal)
{
    if (g_state.stage == AgentQMethodApprovalStage::inactive) {
        return AgentQMethodApprovalTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodApprovalTransitionResult::terminal_pending;
    }
    g_state.stage = AgentQMethodApprovalStage::terminal;
    g_state.terminal_result = terminal;
    return transition_result_for_terminal(terminal);
}

AgentQMethodApprovalTransitionResult record_awaiting_terminal_for_session(
    const char* session_id,
    TickType_t now,
    AgentQMethodApprovalTerminalResult terminal)
{
    if (g_state.stage == AgentQMethodApprovalStage::inactive) {
        return AgentQMethodApprovalTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodApprovalTransitionResult::terminal_pending;
    }
    if (g_state.stage != AgentQMethodApprovalStage::awaiting_user) {
        return AgentQMethodApprovalTransitionResult::busy;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodApprovalTransitionResult::session_mismatch;
    }
    if (tick_reached(now, g_state.deadline)) {
        return record_terminal(AgentQMethodApprovalTerminalResult::user_timeout);
    }
    return record_terminal(terminal);
}

void copy_terminal_snapshot(AgentQMethodApprovalTerminalSnapshot* output)
{
    output->result = g_state.terminal_result;
    memcpy(output->request_id, g_state.request_id, sizeof(output->request_id));
    memcpy(output->session_id, g_state.session_id, sizeof(output->session_id));
    memcpy(output->chain, g_state.chain, sizeof(output->chain));
    memcpy(output->method, g_state.method, sizeof(output->method));
    memcpy(output->payload_digest, g_state.payload_digest, sizeof(output->payload_digest));
    memcpy(output->policy_hash, g_state.policy_hash, sizeof(output->policy_hash));
    memcpy(output->rule_ref, g_state.rule_ref, sizeof(output->rule_ref));
}

}  // namespace

void method_approval_flow_clear()
{
    g_state.clear();
}

bool method_approval_flow_active()
{
    return g_state.stage != AgentQMethodApprovalStage::inactive;
}

AgentQMethodApprovalSnapshot method_approval_flow_snapshot()
{
    return AgentQMethodApprovalSnapshot{
        method_approval_flow_active(),
        g_state.stage,
        g_state.policy_decision,
        g_state.terminal_result,
        g_state.request_id,
        g_state.session_id,
        g_state.chain,
        g_state.method,
        g_state.payload_digest,
        g_state.policy_hash,
        g_state.rule_ref,
        g_state.deadline,
    };
}

AgentQMethodApprovalTransitionResult method_approval_flow_begin(
    const AgentQMethodApprovalBeginInput& input)
{
    if (method_approval_flow_active()) {
        return AgentQMethodApprovalTransitionResult::active;
    }
    if (input.policy_decision != AgentQMethodApprovalPolicyDecision::ask ||
        input.deadline == 0) {
        return AgentQMethodApprovalTransitionResult::invalid_argument;
    }

    MethodApprovalFlowState next = {};
    next.clear();
    if (!copy_nonempty_c_string(input.request_id, next.request_id, sizeof(next.request_id)) ||
        !copy_nonempty_c_string(input.session_id, next.session_id, sizeof(next.session_id)) ||
        !copy_nonempty_c_string(input.chain, next.chain, sizeof(next.chain)) ||
        !copy_nonempty_c_string(input.method, next.method, sizeof(next.method)) ||
        !copy_nonempty_c_string(input.payload_digest, next.payload_digest, sizeof(next.payload_digest)) ||
        !copy_nonempty_c_string(input.policy_hash, next.policy_hash, sizeof(next.policy_hash)) ||
        !copy_nonempty_c_string(input.rule_ref, next.rule_ref, sizeof(next.rule_ref))) {
        return AgentQMethodApprovalTransitionResult::invalid_argument;
    }
    next.stage = AgentQMethodApprovalStage::awaiting_user;
    next.policy_decision = input.policy_decision;
    next.deadline = input.deadline;
    g_state = next;
    return AgentQMethodApprovalTransitionResult::began;
}

bool method_approval_flow_deadline_reached(TickType_t now)
{
    return g_state.stage == AgentQMethodApprovalStage::awaiting_user &&
           tick_reached(now, g_state.deadline);
}

AgentQMethodApprovalTransitionResult method_approval_flow_approve_for_signing(
    const char* session_id,
    TickType_t now)
{
    if (g_state.stage == AgentQMethodApprovalStage::inactive) {
        return AgentQMethodApprovalTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodApprovalTransitionResult::terminal_pending;
    }
    if (g_state.stage != AgentQMethodApprovalStage::awaiting_user) {
        return AgentQMethodApprovalTransitionResult::busy;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodApprovalTransitionResult::session_mismatch;
    }
    if (tick_reached(now, g_state.deadline)) {
        return record_terminal(AgentQMethodApprovalTerminalResult::user_timeout);
    }
    g_state.stage = AgentQMethodApprovalStage::signing_critical_section;
    return AgentQMethodApprovalTransitionResult::approved_for_signing;
}

AgentQMethodApprovalTransitionResult method_approval_flow_record_user_rejected(
    const char* session_id,
    TickType_t now)
{
    return record_awaiting_terminal_for_session(
        session_id,
        now,
        AgentQMethodApprovalTerminalResult::user_rejected);
}

AgentQMethodApprovalTransitionResult method_approval_flow_record_timeout(TickType_t now)
{
    if (g_state.stage == AgentQMethodApprovalStage::inactive) {
        return AgentQMethodApprovalTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodApprovalTransitionResult::terminal_pending;
    }
    if (g_state.stage != AgentQMethodApprovalStage::awaiting_user) {
        return AgentQMethodApprovalTransitionResult::busy;
    }
    if (!tick_reached(now, g_state.deadline)) {
        return AgentQMethodApprovalTransitionResult::deadline_not_reached;
    }
    return record_terminal(AgentQMethodApprovalTerminalResult::user_timeout);
}

AgentQMethodApprovalTransitionResult method_approval_flow_cancel_for_disconnect(
    const char* session_id)
{
    if (g_state.stage == AgentQMethodApprovalStage::inactive) {
        return AgentQMethodApprovalTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodApprovalTransitionResult::terminal_pending;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodApprovalTransitionResult::session_mismatch;
    }
    if (g_state.stage == AgentQMethodApprovalStage::signing_critical_section) {
        return AgentQMethodApprovalTransitionResult::busy;
    }
    return record_terminal(AgentQMethodApprovalTerminalResult::canceled);
}

AgentQMethodApprovalTransitionResult method_approval_flow_cancel_for_session_loss(
    const char* session_id)
{
    if (g_state.stage == AgentQMethodApprovalStage::inactive) {
        return AgentQMethodApprovalTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodApprovalTransitionResult::terminal_pending;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodApprovalTransitionResult::session_mismatch;
    }
    if (g_state.stage == AgentQMethodApprovalStage::signing_critical_section) {
        return AgentQMethodApprovalTransitionResult::busy;
    }
    return record_terminal(AgentQMethodApprovalTerminalResult::session_lost);
}

AgentQMethodApprovalTransitionResult method_approval_flow_record_ui_error(
    const char* session_id)
{
    if (g_state.stage == AgentQMethodApprovalStage::inactive) {
        return AgentQMethodApprovalTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodApprovalTransitionResult::terminal_pending;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodApprovalTransitionResult::session_mismatch;
    }
    if (g_state.stage == AgentQMethodApprovalStage::signing_critical_section) {
        return AgentQMethodApprovalTransitionResult::busy;
    }
    return record_terminal(AgentQMethodApprovalTerminalResult::ui_error);
}

AgentQMethodApprovalTransitionResult method_approval_flow_complete_approved(
    const char* session_id)
{
    if (g_state.stage == AgentQMethodApprovalStage::inactive) {
        return AgentQMethodApprovalTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodApprovalTransitionResult::terminal_pending;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodApprovalTransitionResult::session_mismatch;
    }
    if (g_state.stage != AgentQMethodApprovalStage::signing_critical_section) {
        return AgentQMethodApprovalTransitionResult::busy;
    }
    return record_terminal(AgentQMethodApprovalTerminalResult::user_approved);
}

AgentQMethodApprovalTransitionResult method_approval_flow_record_method_error(
    const char* session_id)
{
    if (g_state.stage == AgentQMethodApprovalStage::inactive) {
        return AgentQMethodApprovalTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodApprovalTransitionResult::terminal_pending;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodApprovalTransitionResult::session_mismatch;
    }
    if (g_state.stage != AgentQMethodApprovalStage::signing_critical_section) {
        return AgentQMethodApprovalTransitionResult::busy;
    }
    return record_terminal(AgentQMethodApprovalTerminalResult::method_error);
}

bool method_approval_flow_consume_terminal(
    AgentQMethodApprovalTerminalSnapshot* output)
{
    if (output == nullptr || !has_terminal()) {
        return false;
    }
    copy_terminal_snapshot(output);
    g_state.clear();
    return true;
}

}  // namespace agent_q
