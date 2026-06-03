#include "agent_q_method_signing_request_flow.h"

#include <stdint.h>
#include <string.h>

namespace agent_q {
namespace {

struct MethodSigningRequestFlowState {
    AgentQMethodSigningRequestStage stage = AgentQMethodSigningRequestStage::inactive;
    AgentQMethodSigningRequestPolicyDecision policy_decision =
        AgentQMethodSigningRequestPolicyDecision::ask;
    AgentQMethodSigningRequestTerminalResult terminal_result =
        AgentQMethodSigningRequestTerminalResult::none;
    char request_id[kAgentQMethodSigningRequestIdSize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    char chain[kAgentQApprovalHistoryChainSize] = {};
    char method[kAgentQApprovalHistoryMethodSize] = {};
    uint8_t signable_payload[kAgentQMethodSigningRequestPayloadMaxBytes] = {};
    size_t signable_payload_size = 0;
    char network[kAgentQMethodSigningRequestNetworkSize] = {};
    char recipient[kAgentQMethodSigningRequestRecipientSize] = {};
    char asset[kAgentQMethodSigningRequestAssetSize] = {};
    char amount[kAgentQMethodSigningRequestU64Size] = {};
    char gas_budget[kAgentQMethodSigningRequestU64Size] = {};
    char gas_price[kAgentQMethodSigningRequestU64Size] = {};
    char payload_digest[kAgentQApprovalHistoryDigestSize] = {};
    char policy_hash[kAgentQApprovalHistoryDigestSize] = {};
    char rule_ref[kAgentQApprovalHistoryRuleRefSize] = {};
    TickType_t deadline = 0;

    void wipe_signable_payload()
    {
        volatile uint8_t* cursor = signable_payload;
        for (size_t index = 0; index < sizeof(signable_payload); ++index) {
            cursor[index] = 0;
        }
        signable_payload_size = 0;
    }

    void clear()
    {
        wipe_signable_payload();
        memset(this, 0, sizeof(*this));
        stage = AgentQMethodSigningRequestStage::inactive;
        policy_decision = AgentQMethodSigningRequestPolicyDecision::ask;
        terminal_result = AgentQMethodSigningRequestTerminalResult::none;
    }
};

MethodSigningRequestFlowState g_state;

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

bool copy_signable_payload(
    const uint8_t* input,
    size_t input_size,
    uint8_t* output,
    size_t output_size,
    size_t* copied_size)
{
    if (copied_size != nullptr) {
        *copied_size = 0;
    }
    if (input == nullptr || output == nullptr || copied_size == nullptr ||
        input_size == 0 || input_size > output_size) {
        return false;
    }
    memcpy(output, input, input_size);
    *copied_size = input_size;
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
    return g_state.stage == AgentQMethodSigningRequestStage::terminal;
}

AgentQMethodSigningRequestTransitionResult transition_result_for_terminal(
    AgentQMethodSigningRequestTerminalResult terminal)
{
    switch (terminal) {
        case AgentQMethodSigningRequestTerminalResult::user_approved:
            return AgentQMethodSigningRequestTransitionResult::terminal_user_approved;
        case AgentQMethodSigningRequestTerminalResult::user_rejected:
            return AgentQMethodSigningRequestTransitionResult::terminal_user_rejected;
        case AgentQMethodSigningRequestTerminalResult::user_timeout:
            return AgentQMethodSigningRequestTransitionResult::terminal_user_timeout;
        case AgentQMethodSigningRequestTerminalResult::canceled:
            return AgentQMethodSigningRequestTransitionResult::terminal_canceled;
        case AgentQMethodSigningRequestTerminalResult::session_lost:
            return AgentQMethodSigningRequestTransitionResult::terminal_session_lost;
        case AgentQMethodSigningRequestTerminalResult::ui_error:
            return AgentQMethodSigningRequestTransitionResult::terminal_ui_error;
        case AgentQMethodSigningRequestTerminalResult::history_error:
            return AgentQMethodSigningRequestTransitionResult::terminal_history_error;
        case AgentQMethodSigningRequestTerminalResult::method_error:
            return AgentQMethodSigningRequestTransitionResult::terminal_method_error;
        case AgentQMethodSigningRequestTerminalResult::none:
        default:
            return AgentQMethodSigningRequestTransitionResult::invalid_argument;
    }
}

AgentQMethodSigningRequestTransitionResult record_terminal(
    AgentQMethodSigningRequestTerminalResult terminal)
{
    if (g_state.stage == AgentQMethodSigningRequestStage::inactive) {
        return AgentQMethodSigningRequestTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodSigningRequestTransitionResult::terminal_pending;
    }
    AgentQMethodSigningRequestTransitionResult result =
        transition_result_for_terminal(terminal);
    if (result == AgentQMethodSigningRequestTransitionResult::invalid_argument) {
        return result;
    }
    g_state.wipe_signable_payload();
    g_state.stage = AgentQMethodSigningRequestStage::terminal;
    g_state.terminal_result = terminal;
    return result;
}

AgentQMethodSigningRequestTransitionResult record_awaiting_terminal_for_session(
    const char* session_id,
    TickType_t now,
    AgentQMethodSigningRequestTerminalResult terminal)
{
    if (g_state.stage == AgentQMethodSigningRequestStage::inactive) {
        return AgentQMethodSigningRequestTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodSigningRequestTransitionResult::terminal_pending;
    }
    if (g_state.stage != AgentQMethodSigningRequestStage::awaiting_user) {
        return AgentQMethodSigningRequestTransitionResult::busy;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodSigningRequestTransitionResult::session_mismatch;
    }
    if (tick_reached(now, g_state.deadline)) {
        return record_terminal(AgentQMethodSigningRequestTerminalResult::user_timeout);
    }
    return record_terminal(terminal);
}

void copy_terminal_snapshot(AgentQMethodSigningRequestTerminalSnapshot* output)
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

void method_signing_request_flow_clear()
{
    g_state.clear();
}

bool method_signing_request_flow_active()
{
    return g_state.stage != AgentQMethodSigningRequestStage::inactive;
}

AgentQMethodSigningRequestSnapshot method_signing_request_flow_snapshot()
{
    return AgentQMethodSigningRequestSnapshot{
        method_signing_request_flow_active(),
        g_state.stage,
        g_state.policy_decision,
        g_state.terminal_result,
        g_state.request_id,
        g_state.session_id,
        g_state.chain,
        g_state.method,
        g_state.signable_payload_size,
        g_state.network,
        g_state.recipient,
        g_state.asset,
        g_state.amount,
        g_state.gas_budget,
        g_state.gas_price,
        g_state.payload_digest,
        g_state.policy_hash,
        g_state.rule_ref,
        g_state.deadline,
    };
}

AgentQMethodSigningRequestTransitionResult method_signing_request_flow_begin(
    const AgentQMethodSigningRequestBeginInput& input)
{
    if (method_signing_request_flow_active()) {
        return AgentQMethodSigningRequestTransitionResult::active;
    }
    if (input.policy_decision != AgentQMethodSigningRequestPolicyDecision::ask ||
        input.deadline == 0 ||
        input.signable_payload == nullptr ||
        input.signable_payload_size == 0 ||
        input.signable_payload_size > kAgentQMethodSigningRequestPayloadMaxBytes) {
        return AgentQMethodSigningRequestTransitionResult::invalid_argument;
    }

    MethodSigningRequestFlowState next = {};
    next.clear();
    if (!copy_nonempty_c_string(input.request_id, next.request_id, sizeof(next.request_id)) ||
        !copy_nonempty_c_string(input.session_id, next.session_id, sizeof(next.session_id)) ||
        !copy_nonempty_c_string(input.chain, next.chain, sizeof(next.chain)) ||
        !copy_nonempty_c_string(input.method, next.method, sizeof(next.method)) ||
        !copy_nonempty_c_string(input.network, next.network, sizeof(next.network)) ||
        !copy_nonempty_c_string(input.recipient, next.recipient, sizeof(next.recipient)) ||
        !copy_nonempty_c_string(input.asset, next.asset, sizeof(next.asset)) ||
        !copy_nonempty_c_string(input.amount, next.amount, sizeof(next.amount)) ||
        !copy_nonempty_c_string(input.gas_budget, next.gas_budget, sizeof(next.gas_budget)) ||
        !copy_nonempty_c_string(input.gas_price, next.gas_price, sizeof(next.gas_price)) ||
        !copy_nonempty_c_string(input.payload_digest, next.payload_digest, sizeof(next.payload_digest)) ||
        !copy_nonempty_c_string(input.policy_hash, next.policy_hash, sizeof(next.policy_hash)) ||
        !copy_nonempty_c_string(input.rule_ref, next.rule_ref, sizeof(next.rule_ref))) {
        return AgentQMethodSigningRequestTransitionResult::invalid_argument;
    }
    memcpy(next.signable_payload, input.signable_payload, input.signable_payload_size);
    next.signable_payload_size = input.signable_payload_size;
    next.stage = AgentQMethodSigningRequestStage::awaiting_user;
    next.policy_decision = input.policy_decision;
    next.deadline = input.deadline;
    g_state = next;
    next.clear();
    return AgentQMethodSigningRequestTransitionResult::began;
}

bool method_signing_request_flow_deadline_reached(TickType_t now)
{
    return g_state.stage == AgentQMethodSigningRequestStage::awaiting_user &&
           tick_reached(now, g_state.deadline);
}

AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_user_approved(
    const char* session_id,
    TickType_t now)
{
    if (g_state.stage == AgentQMethodSigningRequestStage::inactive) {
        return AgentQMethodSigningRequestTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodSigningRequestTransitionResult::terminal_pending;
    }
    if (g_state.stage != AgentQMethodSigningRequestStage::awaiting_user) {
        return AgentQMethodSigningRequestTransitionResult::busy;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodSigningRequestTransitionResult::session_mismatch;
    }
    if (tick_reached(now, g_state.deadline)) {
        return record_terminal(AgentQMethodSigningRequestTerminalResult::user_timeout);
    }
    g_state.stage = AgentQMethodSigningRequestStage::awaiting_history;
    return AgentQMethodSigningRequestTransitionResult::user_approved_waiting_history;
}

AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_history_durable(
    const char* session_id)
{
    if (g_state.stage == AgentQMethodSigningRequestStage::inactive) {
        return AgentQMethodSigningRequestTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodSigningRequestTransitionResult::terminal_pending;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodSigningRequestTransitionResult::session_mismatch;
    }
    if (g_state.stage != AgentQMethodSigningRequestStage::awaiting_history) {
        return AgentQMethodSigningRequestTransitionResult::busy;
    }
    g_state.stage = AgentQMethodSigningRequestStage::signing_critical_section;
    return AgentQMethodSigningRequestTransitionResult::history_durable;
}

bool method_signing_request_flow_copy_signable_payload(
    uint8_t* output,
    size_t output_size,
    size_t* copied_size)
{
    if (copied_size != nullptr) {
        *copied_size = 0;
    }
    if (g_state.stage != AgentQMethodSigningRequestStage::signing_critical_section) {
        return false;
    }
    return copy_signable_payload(
        g_state.signable_payload,
        g_state.signable_payload_size,
        output,
        output_size,
        copied_size);
}

AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_user_rejected(
    const char* session_id,
    TickType_t now)
{
    return record_awaiting_terminal_for_session(
        session_id,
        now,
        AgentQMethodSigningRequestTerminalResult::user_rejected);
}

AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_timeout(TickType_t now)
{
    if (g_state.stage == AgentQMethodSigningRequestStage::inactive) {
        return AgentQMethodSigningRequestTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodSigningRequestTransitionResult::terminal_pending;
    }
    if (g_state.stage != AgentQMethodSigningRequestStage::awaiting_user) {
        return AgentQMethodSigningRequestTransitionResult::busy;
    }
    if (!tick_reached(now, g_state.deadline)) {
        return AgentQMethodSigningRequestTransitionResult::deadline_not_reached;
    }
    return record_terminal(AgentQMethodSigningRequestTerminalResult::user_timeout);
}

AgentQMethodSigningRequestTransitionResult method_signing_request_flow_cancel_for_disconnect(
    const char* session_id)
{
    if (g_state.stage == AgentQMethodSigningRequestStage::inactive) {
        return AgentQMethodSigningRequestTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodSigningRequestTransitionResult::terminal_pending;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodSigningRequestTransitionResult::session_mismatch;
    }
    return record_terminal(AgentQMethodSigningRequestTerminalResult::canceled);
}

AgentQMethodSigningRequestTransitionResult method_signing_request_flow_cancel_for_session_loss(
    const char* session_id)
{
    if (g_state.stage == AgentQMethodSigningRequestStage::inactive) {
        return AgentQMethodSigningRequestTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodSigningRequestTransitionResult::terminal_pending;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodSigningRequestTransitionResult::session_mismatch;
    }
    return record_terminal(AgentQMethodSigningRequestTerminalResult::session_lost);
}

AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_ui_error(
    const char* session_id)
{
    if (g_state.stage == AgentQMethodSigningRequestStage::inactive) {
        return AgentQMethodSigningRequestTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodSigningRequestTransitionResult::terminal_pending;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodSigningRequestTransitionResult::session_mismatch;
    }
    return record_terminal(AgentQMethodSigningRequestTerminalResult::ui_error);
}

AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_history_error(
    const char* session_id)
{
    if (g_state.stage == AgentQMethodSigningRequestStage::inactive) {
        return AgentQMethodSigningRequestTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodSigningRequestTransitionResult::terminal_pending;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodSigningRequestTransitionResult::session_mismatch;
    }
    if (g_state.stage != AgentQMethodSigningRequestStage::awaiting_history) {
        return AgentQMethodSigningRequestTransitionResult::busy;
    }
    return record_terminal(AgentQMethodSigningRequestTerminalResult::history_error);
}

AgentQMethodSigningRequestTransitionResult method_signing_request_flow_complete_approved(
    const char* session_id)
{
    if (g_state.stage == AgentQMethodSigningRequestStage::inactive) {
        return AgentQMethodSigningRequestTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodSigningRequestTransitionResult::terminal_pending;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodSigningRequestTransitionResult::session_mismatch;
    }
    if (g_state.stage != AgentQMethodSigningRequestStage::signing_critical_section) {
        return AgentQMethodSigningRequestTransitionResult::busy;
    }
    return record_terminal(AgentQMethodSigningRequestTerminalResult::user_approved);
}

AgentQMethodSigningRequestTransitionResult method_signing_request_flow_record_method_error(
    const char* session_id)
{
    if (g_state.stage == AgentQMethodSigningRequestStage::inactive) {
        return AgentQMethodSigningRequestTransitionResult::inactive;
    }
    if (has_terminal()) {
        return AgentQMethodSigningRequestTransitionResult::terminal_pending;
    }
    if (!session_matches(session_id)) {
        return AgentQMethodSigningRequestTransitionResult::session_mismatch;
    }
    if (g_state.stage != AgentQMethodSigningRequestStage::signing_critical_section) {
        return AgentQMethodSigningRequestTransitionResult::busy;
    }
    return record_terminal(AgentQMethodSigningRequestTerminalResult::method_error);
}

bool method_signing_request_flow_consume_terminal(
    AgentQMethodSigningRequestTerminalSnapshot* output)
{
    if (output == nullptr || !has_terminal()) {
        return false;
    }
    copy_terminal_snapshot(output);
    method_signing_request_flow_clear();
    return true;
}

}  // namespace agent_q
