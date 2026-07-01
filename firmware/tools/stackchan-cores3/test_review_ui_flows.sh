#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_review_ui_flows.sh

Compiles the StackChan CoreS3 policy-update, Sui zkLogin, and user-signing
review UI flow owners against host stubs and verifies display, accept/reject,
PIN handoff, timeout, and panel-recovery behavior without linking the USB
request server.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
CXX_BIN="${CXX:-c++}"

for required in \
  "${AGENT_Q_DIR}/agent_q_policy_update_review_ui_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_policy_update_review_ui_flow.h" \
  "${AGENT_Q_DIR}/agent_q_sui_zklogin_review_ui_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_zklogin_review_ui_flow.h" \
  "${AGENT_Q_DIR}/agent_q_modal_transition.cpp" \
  "${AGENT_Q_DIR}/agent_q_modal_transition.h" \
  "${AGENT_Q_DIR}/agent_q_user_signing_review_ui_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_user_signing_review_ui_flow.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-review-ui-flows.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/stubs/freertos" "${TMP_DIR}/stubs/lvgl" "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"

cat >"${TMP_DIR}/stubs/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
#define pdMS_TO_TICKS(ms) (static_cast<TickType_t>(ms))
H

cat >"${TMP_DIR}/stubs/lvgl.h" <<'H'
#pragma once

typedef void (*lv_event_cb_t)(void*);
typedef struct {
    int x1;
    int y1;
    int x2;
    int y2;
} lv_area_t;
typedef struct _lv_obj_t lv_obj_t;
H

cat >"${TMP_DIR}/stubs/ArduinoJson.h" <<'H'
#pragma once

struct JsonVariantConst {};
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_policy_update_review_ui_flow.h"
#include "agent_q_sui_zklogin_review_ui_flow.h"
#include "agent_q_user_signing_review_ui_flow.h"

namespace {

int failures = 0;
TickType_t g_now = 100;
uint64_t g_wall_ms = 1234;

agent_q::AgentQPolicyUpdateFlowSnapshot g_policy_snapshot = {};
agent_q::AgentQPolicyUpdateFlowTransitionResult g_policy_continue_result =
    agent_q::AgentQPolicyUpdateFlowTransitionResult::ok;
bool g_policy_draw_result = true;
bool g_policy_deadline_reached = false;
bool g_policy_panel_active = true;
bool g_protocol_pin_begin_result = true;
bool g_local_pin_begin_result = true;
bool g_local_pin_draw_result = true;
int g_policy_draw_calls = 0;
int g_policy_clear_review_calls = 0;
int g_policy_clear_review_order = 0;
int g_policy_identification_clear_calls = 0;
int g_policy_continue_calls = 0;
int g_protocol_pin_begin_calls = 0;
int g_protocol_pin_clear_calls = 0;
int g_local_pin_begin_calls = 0;
int g_local_pin_draw_calls = 0;
int g_policy_local_pin_draw_order = 0;
int g_wipe_pin_calls = 0;
int g_policy_record_timeout_calls = 0;
int g_policy_record_rejected_calls = 0;
int g_policy_record_ui_error_calls = 0;
int g_policy_finish_terminal_calls = 0;
int g_policy_finish_terminal_order = 0;
int g_policy_finish_error_calls = 0;
agent_q::AgentQPolicyUpdateFlowTerminalResult g_policy_last_terminal =
    agent_q::AgentQPolicyUpdateFlowTerminalResult::invalid_state;
char g_policy_last_error_code[48] = {};

agent_q::AgentQSuiZkLoginProposalSnapshot g_sui_snapshot = {};
agent_q::AgentQSuiZkLoginProposalTransitionResult g_sui_continue_result =
    agent_q::AgentQSuiZkLoginProposalTransitionResult::ok;
bool g_sui_draw_result = true;
bool g_sui_deadline_reached = false;
bool g_sui_panel_active = true;
bool g_sui_protocol_pin_begin_result = true;
bool g_sui_local_pin_begin_result = true;
bool g_sui_local_pin_draw_result = true;
int g_sui_draw_calls = 0;
int g_sui_clear_review_calls = 0;
int g_sui_clear_review_order = 0;
int g_sui_identification_clear_calls = 0;
int g_sui_continue_calls = 0;
int g_sui_protocol_pin_begin_calls = 0;
int g_sui_protocol_pin_clear_calls = 0;
int g_sui_local_pin_begin_calls = 0;
int g_sui_local_pin_draw_calls = 0;
int g_sui_local_pin_draw_order = 0;
int g_sui_wipe_pin_calls = 0;
int g_sui_record_timeout_calls = 0;
int g_sui_record_rejected_calls = 0;
int g_sui_record_ui_error_calls = 0;
int g_sui_finish_terminal_calls = 0;
int g_sui_finish_terminal_order = 0;
int g_sui_finish_error_calls = 0;
agent_q::AgentQSuiZkLoginProposalTerminalResult g_sui_last_terminal =
    agent_q::AgentQSuiZkLoginProposalTerminalResult::invalid_state;
char g_sui_last_error_code[48] = {};

agent_q::AgentQUserSigningFlowSnapshot g_user_snapshot = {};
agent_q::AgentQUserSigningReviewTimerState g_user_timer_state = {};
agent_q::AgentQUserSigningReviewTimerState g_user_last_draw_timer = {};
agent_q::AgentQUserSigningReviewTimerState g_user_last_timer_update = {};
bool g_user_requires_pin = false;
bool g_user_draw_result = true;
bool g_user_timer_update_result = true;
bool g_user_local_pin_draw_result = true;
bool g_user_panel_active = true;
bool g_user_terminal_pending = false;
agent_q::AgentQUserSigningTransitionResult g_user_physical_result =
    agent_q::AgentQUserSigningTransitionResult::ok;
agent_q::AgentQUserSigningConfirmationResult g_user_begin_pin_result =
    agent_q::AgentQUserSigningConfirmationResult::ok;
agent_q::AgentQUserSigningConfirmationResult g_user_reject_result =
    agent_q::AgentQUserSigningConfirmationResult::ok;
agent_q::AgentQUserSigningTransitionResult g_user_timeout_result =
    agent_q::AgentQUserSigningTransitionResult::deadline_not_reached;
agent_q::AgentQUserSigningTransitionResult g_user_pause_result =
    agent_q::AgentQUserSigningTransitionResult::ok;
agent_q::AgentQUserSigningTransitionResult g_user_resume_result =
    agent_q::AgentQUserSigningTransitionResult::ok;
bool g_user_timeout_resumes_timer = false;
int g_user_build_calls = 0;
int g_user_draw_calls = 0;
int g_user_clear_review_calls = 0;
int g_user_clear_pin_calls = 0;
int g_user_physical_calls = 0;
int g_user_begin_pin_calls = 0;
int g_user_reject_calls = 0;
int g_user_timeout_calls = 0;
int g_user_pause_calls = 0;
int g_user_resume_calls = 0;
int g_user_timer_update_calls = 0;
int g_user_clear_flow_calls = 0;
int g_user_cancel_pin_loss_calls = 0;
int g_user_local_pin_draw_calls = 0;
int g_user_local_pin_draw_order = 0;
int g_user_write_error_calls = 0;
int g_user_display_error_calls = 0;
int g_user_execute_calls = 0;
int g_user_finish_terminal_calls = 0;
int g_user_finish_terminal_order = 0;
int g_user_finish_error_calls = 0;
int g_user_order_counter = 0;
int g_user_execute_order = 0;
int g_user_clear_review_order = 0;
char g_user_last_error_code[48] = {};

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void reset_policy()
{
    g_now = 100;
    g_wall_ms = 1234;
    g_policy_snapshot = {};
    g_policy_snapshot.active = true;
    g_policy_snapshot.stage = agent_q::AgentQPolicyUpdateFlowStage::reviewing;
    g_policy_snapshot.request_id = "policy-1";
    g_policy_snapshot.session_id = "session-1";
    g_policy_snapshot.review_window = {10, 200};
    g_policy_snapshot.policy_hash = "hash";
    g_policy_snapshot.blockchain_count = 1;
    g_policy_snapshot.network_count = 1;
    g_policy_snapshot.policy_count = 2;
    g_policy_snapshot.condition_count = 3;
    g_policy_snapshot.default_action = "reject";
    g_policy_snapshot.highest_action = "sign";
    g_policy_snapshot.scope_summary = "scopes=1/1 policies=2 conditions=3";
    g_policy_snapshot.review_summary = "summary";
    g_policy_continue_result = agent_q::AgentQPolicyUpdateFlowTransitionResult::ok;
    g_policy_draw_result = true;
    g_policy_deadline_reached = false;
    g_policy_panel_active = true;
    g_protocol_pin_begin_result = true;
    g_local_pin_begin_result = true;
    g_local_pin_draw_result = true;
    g_policy_draw_calls = 0;
    g_policy_clear_review_calls = 0;
    g_policy_clear_review_order = 0;
    g_policy_identification_clear_calls = 0;
    g_policy_continue_calls = 0;
    g_protocol_pin_begin_calls = 0;
    g_protocol_pin_clear_calls = 0;
    g_local_pin_begin_calls = 0;
    g_local_pin_draw_calls = 0;
    g_policy_local_pin_draw_order = 0;
    g_wipe_pin_calls = 0;
    g_policy_record_timeout_calls = 0;
    g_policy_record_rejected_calls = 0;
    g_policy_record_ui_error_calls = 0;
    g_policy_finish_terminal_calls = 0;
    g_policy_finish_terminal_order = 0;
    g_policy_finish_error_calls = 0;
    g_user_order_counter = 0;
    g_policy_last_terminal = agent_q::AgentQPolicyUpdateFlowTerminalResult::invalid_state;
    g_policy_last_error_code[0] = '\0';
}

void reset_sui()
{
    g_now = 100;
    g_sui_snapshot = {};
    g_sui_snapshot.active = true;
    g_sui_snapshot.stage = agent_q::AgentQSuiZkLoginProposalStage::reviewing;
    g_sui_snapshot.request_id = "sui-zklogin-1";
    g_sui_snapshot.session_id = "session-1";
    g_sui_snapshot.request_window = {10, 200};
    g_sui_snapshot.address = "0x2222222222222222222222222222222222222222222222222222222222222222";
    g_sui_snapshot.network = "testnet";
    g_sui_snapshot.issuer = "https://accounts.google.com";
    g_sui_snapshot.max_epoch = "123";
    g_sui_snapshot.proof_hash = "sha256:abcdef";
    g_sui_continue_result = agent_q::AgentQSuiZkLoginProposalTransitionResult::ok;
    g_sui_draw_result = true;
    g_sui_deadline_reached = false;
    g_sui_panel_active = true;
    g_sui_protocol_pin_begin_result = true;
    g_sui_local_pin_begin_result = true;
    g_sui_local_pin_draw_result = true;
    g_sui_draw_calls = 0;
    g_sui_clear_review_calls = 0;
    g_sui_clear_review_order = 0;
    g_sui_identification_clear_calls = 0;
    g_sui_continue_calls = 0;
    g_sui_protocol_pin_begin_calls = 0;
    g_sui_protocol_pin_clear_calls = 0;
    g_sui_local_pin_begin_calls = 0;
    g_sui_local_pin_draw_calls = 0;
    g_sui_local_pin_draw_order = 0;
    g_sui_wipe_pin_calls = 0;
    g_sui_record_timeout_calls = 0;
    g_sui_record_rejected_calls = 0;
    g_sui_record_ui_error_calls = 0;
    g_sui_finish_terminal_calls = 0;
    g_sui_finish_terminal_order = 0;
    g_sui_finish_error_calls = 0;
    g_user_order_counter = 0;
    g_sui_last_terminal = agent_q::AgentQSuiZkLoginProposalTerminalResult::invalid_state;
    g_sui_last_error_code[0] = '\0';
}

void reset_user()
{
    g_now = 100;
    g_user_snapshot = {};
    g_user_snapshot.active = true;
    g_user_snapshot.stage = agent_q::AgentQUserSigningStage::reviewing;
    snprintf(g_user_snapshot.request_id, sizeof(g_user_snapshot.request_id), "%s", "sign-1");
    g_user_snapshot.request_window = {10, 200};
    g_user_timer_state = {};
    g_user_timer_state.available = true;
    g_user_timer_state.display_window = {10, 200};
    g_user_timer_state.display_tick = g_now;
    g_user_last_draw_timer = {};
    g_user_last_timer_update = {};
    g_user_requires_pin = false;
    g_user_draw_result = true;
    g_user_timer_update_result = true;
    g_user_local_pin_draw_result = true;
    g_user_panel_active = true;
    g_user_terminal_pending = false;
    g_user_physical_result = agent_q::AgentQUserSigningTransitionResult::ok;
    g_user_begin_pin_result = agent_q::AgentQUserSigningConfirmationResult::ok;
    g_user_reject_result = agent_q::AgentQUserSigningConfirmationResult::ok;
    g_user_timeout_result =
        agent_q::AgentQUserSigningTransitionResult::deadline_not_reached;
    g_user_pause_result = agent_q::AgentQUserSigningTransitionResult::ok;
    g_user_resume_result = agent_q::AgentQUserSigningTransitionResult::ok;
    g_user_timeout_resumes_timer = false;
    g_user_build_calls = 0;
    g_user_draw_calls = 0;
    g_user_clear_review_calls = 0;
    g_user_clear_pin_calls = 0;
    g_user_physical_calls = 0;
    g_user_begin_pin_calls = 0;
    g_user_reject_calls = 0;
    g_user_timeout_calls = 0;
    g_user_pause_calls = 0;
    g_user_resume_calls = 0;
    g_user_timer_update_calls = 0;
    g_user_clear_flow_calls = 0;
    g_user_cancel_pin_loss_calls = 0;
    g_user_local_pin_draw_calls = 0;
    g_user_local_pin_draw_order = 0;
    g_user_write_error_calls = 0;
    g_user_display_error_calls = 0;
    g_user_execute_calls = 0;
    g_user_finish_terminal_calls = 0;
    g_user_finish_terminal_order = 0;
    g_user_finish_error_calls = 0;
    g_user_order_counter = 0;
    g_user_execute_order = 0;
    g_user_clear_review_order = 0;
    g_user_last_error_code[0] = '\0';
}

TickType_t now() { return g_now; }
uint64_t wall_ms() { return g_wall_ms; }

agent_q::AgentQPolicyUpdateFlowSnapshot policy_snapshot()
{
    return g_policy_snapshot;
}

bool draw_policy_review(
    const agent_q::AgentQPolicyUpdateReviewViewModel& model,
    agent_q::AgentQTimeoutWindow window)
{
    ++g_policy_draw_calls;
    expect(strcmp(model.policy_hash, "hash") == 0, "policy show passes hash");
    expect(model.blockchain_count == 1, "policy show passes blockchain count");
    expect(model.network_count == 1, "policy show passes network count");
    expect(model.policy_count == 2, "policy show passes policy count");
    expect(model.condition_count == 3, "policy show passes condition count");
    expect(strcmp(model.scope_summary, "scopes=1/1 policies=2 conditions=3") == 0, "policy show passes scope summary");
    expect(window.deadline == 200, "policy show passes review window");
    return g_policy_draw_result;
}

bool clear_panel(agent_q::AgentQUiPanelKind kind, agent_q::SensitiveUiClearPolicy policy)
{
    expect(policy == agent_q::SensitiveUiClearPolicy::preserve, "review clear preserves scratch");
    if (kind == agent_q::AgentQUiPanelKind::policy_update_review) {
        ++g_policy_clear_review_calls;
        g_policy_clear_review_order = ++g_user_order_counter;
    }
    if (kind == agent_q::AgentQUiPanelKind::sui_zklogin_review) {
        ++g_sui_clear_review_calls;
        g_sui_clear_review_order = ++g_user_order_counter;
    }
    if (kind == agent_q::AgentQUiPanelKind::user_signing_review) {
        ++g_user_clear_review_calls;
        g_user_clear_review_order = ++g_user_order_counter;
    }
    if (kind == agent_q::AgentQUiPanelKind::local_pin_auth) {
        ++g_user_clear_pin_calls;
    }
    return true;
}

bool policy_panel_active() { return g_policy_panel_active; }
void identification_clear() { ++g_policy_identification_clear_calls; }
agent_q::AgentQPolicyUpdateFlowTransitionResult continue_to_pin(TickType_t tick)
{
    expect(tick == g_now, "policy continue receives current tick");
    ++g_policy_continue_calls;
    return g_policy_continue_result;
}
bool protocol_pin_begin(
    const char* request_id,
    const char* session_id,
    TickType_t now,
    agent_q::AgentQTimeoutWindow window)
{
    expect(now == g_now, "policy protocol PIN begin receives current tick");
    expect(strcmp(request_id, "policy-1") == 0, "policy PIN begin uses request id");
    expect(strcmp(session_id, "session-1") == 0, "policy PIN begin uses session id");
    expect(window.started_at == g_now, "policy PIN window starts now");
    ++g_protocol_pin_begin_calls;
    return g_protocol_pin_begin_result;
}
void protocol_pin_clear() { ++g_protocol_pin_clear_calls; }
bool local_pin_begin(TickType_t now, agent_q::AgentQTimeoutWindow)
{
    expect(now == g_now, "policy local PIN begin receives current tick");
    ++g_local_pin_begin_calls;
    return g_local_pin_begin_result;
}
agent_q::AgentQPolicyUpdateFlowTerminalResult policy_timeout(uint64_t uptime_ms);
agent_q::AgentQPolicyUpdateReviewPinBeginResult policy_begin_pin_from_review(
    const agent_q::AgentQPolicyUpdateFlowSnapshot& current,
    TickType_t tick,
    agent_q::AgentQTimeoutWindow window,
    uint64_t uptime_ms)
{
    const agent_q::AgentQPolicyUpdateFlowTransitionResult transition =
        continue_to_pin(tick);
    if (transition == agent_q::AgentQPolicyUpdateFlowTransitionResult::timed_out) {
        return agent_q::AgentQPolicyUpdateReviewPinBeginResult{
            agent_q::AgentQPolicyUpdateReviewPinBeginStatus::timed_out,
            policy_timeout(uptime_ms)};
    }
    if (transition != agent_q::AgentQPolicyUpdateFlowTransitionResult::ok) {
        return agent_q::AgentQPolicyUpdateReviewPinBeginResult{
            agent_q::AgentQPolicyUpdateReviewPinBeginStatus::unavailable,
            agent_q::AgentQPolicyUpdateFlowTerminalResult::invalid_state};
    }
    if (!protocol_pin_begin(current.request_id, current.session_id, tick, window)) {
        return agent_q::AgentQPolicyUpdateReviewPinBeginResult{
            agent_q::AgentQPolicyUpdateReviewPinBeginStatus::unavailable,
            agent_q::AgentQPolicyUpdateFlowTerminalResult::invalid_state};
    }
    if (!local_pin_begin(tick, window)) {
        protocol_pin_clear();
        return agent_q::AgentQPolicyUpdateReviewPinBeginResult{
            agent_q::AgentQPolicyUpdateReviewPinBeginStatus::pin_unavailable,
            agent_q::AgentQPolicyUpdateFlowTerminalResult::invalid_state};
    }
    return agent_q::AgentQPolicyUpdateReviewPinBeginResult{
        agent_q::AgentQPolicyUpdateReviewPinBeginStatus::started,
        agent_q::AgentQPolicyUpdateFlowTerminalResult::invalid_state};
}
bool draw_local_pin()
{
    ++g_local_pin_draw_calls;
    g_policy_local_pin_draw_order = ++g_user_order_counter;
    ++g_user_local_pin_draw_calls;
    g_user_local_pin_draw_order = g_policy_local_pin_draw_order;
    return g_local_pin_draw_result && g_user_local_pin_draw_result;
}
void wipe_pin(const char*) { ++g_wipe_pin_calls; }
bool policy_deadline(TickType_t tick)
{
    expect(tick == g_now, "policy deadline receives current tick");
    return g_policy_deadline_reached;
}
agent_q::AgentQPolicyUpdateFlowTerminalResult policy_timeout(uint64_t uptime_ms)
{
    expect(uptime_ms == g_wall_ms, "policy timeout uses wall clock");
    ++g_policy_record_timeout_calls;
    return agent_q::AgentQPolicyUpdateFlowTerminalResult::timed_out;
}
agent_q::AgentQPolicyUpdateFlowTerminalResult policy_rejected(uint64_t uptime_ms)
{
    expect(uptime_ms == g_wall_ms, "policy reject uses wall clock");
    ++g_policy_record_rejected_calls;
    return agent_q::AgentQPolicyUpdateFlowTerminalResult::rejected;
}
agent_q::AgentQPolicyUpdateFlowTerminalResult policy_ui_error()
{
    ++g_policy_record_ui_error_calls;
    return agent_q::AgentQPolicyUpdateFlowTerminalResult::ui_error;
}
void policy_finish_terminal(
    const char* request_id,
    agent_q::AgentQPolicyUpdateFlowTerminalResult result)
{
    expect(strcmp(request_id, "policy-1") == 0, "policy terminal uses request id");
    ++g_policy_finish_terminal_calls;
    g_policy_finish_terminal_order = ++g_user_order_counter;
    g_policy_last_terminal = result;
}
void policy_finish_error(
    const char*,
    const char* error_code,
    const char*,
    const char*)
{
    ++g_policy_finish_error_calls;
    snprintf(g_policy_last_error_code, sizeof(g_policy_last_error_code), "%s", error_code);
}

agent_q::AgentQSuiZkLoginProposalSnapshot sui_snapshot()
{
    return g_sui_snapshot;
}

bool draw_sui_review(
    const agent_q::AgentQSuiZkLoginReviewViewModel& model,
    agent_q::AgentQTimeoutWindow window)
{
    ++g_sui_draw_calls;
    expect(strcmp(model.network, "testnet") == 0, "Sui zkLogin show passes network");
    expect(strcmp(model.address, g_sui_snapshot.address) == 0, "Sui zkLogin show passes address");
    expect(strcmp(model.issuer, "https://accounts.google.com") == 0, "Sui zkLogin show passes issuer");
    expect(strcmp(model.max_epoch, "123") == 0, "Sui zkLogin show passes max epoch");
    expect(strcmp(model.proof_hash, "sha256:abcdef") == 0, "Sui zkLogin show passes proof hash");
    expect(model.effect_summary != nullptr && model.effect_summary[0] != '\0',
           "Sui zkLogin show passes effect summary");
    expect(window.deadline == 200, "Sui zkLogin show passes review window");
    return g_sui_draw_result;
}

bool sui_panel_active() { return g_sui_panel_active; }
void sui_identification_clear() { ++g_sui_identification_clear_calls; }
agent_q::AgentQSuiZkLoginProposalTransitionResult sui_continue_to_pin(TickType_t tick)
{
    expect(tick == g_now, "Sui zkLogin continue receives current tick");
    ++g_sui_continue_calls;
    return g_sui_continue_result;
}
bool sui_protocol_pin_begin(
    const char* request_id,
    const char* session_id,
    TickType_t now,
    agent_q::AgentQTimeoutWindow window)
{
    expect(now == g_now, "Sui zkLogin protocol PIN begin receives current tick");
    expect(strcmp(request_id, "sui-zklogin-1") == 0, "Sui zkLogin PIN begin uses request id");
    expect(strcmp(session_id, "session-1") == 0, "Sui zkLogin PIN begin uses session id");
    expect(window.deadline == 200, "Sui zkLogin PIN uses proposal window");
    ++g_sui_protocol_pin_begin_calls;
    return g_sui_protocol_pin_begin_result;
}
void sui_protocol_pin_clear() { ++g_sui_protocol_pin_clear_calls; }
bool sui_local_pin_begin(TickType_t now, agent_q::AgentQTimeoutWindow window)
{
    expect(now == g_now, "Sui zkLogin local PIN begin receives current tick");
    expect(window.deadline == 200, "Sui zkLogin local PIN uses proposal window");
    ++g_sui_local_pin_begin_calls;
    return g_sui_local_pin_begin_result;
}
agent_q::AgentQSuiZkLoginProposalTerminalResult sui_timeout();
agent_q::AgentQSuiZkLoginReviewPinBeginResult sui_begin_pin_from_review(
    const agent_q::AgentQSuiZkLoginProposalSnapshot& current,
    TickType_t tick)
{
    const agent_q::AgentQSuiZkLoginProposalTransitionResult transition =
        sui_continue_to_pin(tick);
    if (transition == agent_q::AgentQSuiZkLoginProposalTransitionResult::timed_out) {
        return agent_q::AgentQSuiZkLoginReviewPinBeginResult{
            agent_q::AgentQSuiZkLoginReviewPinBeginStatus::timed_out,
            sui_timeout()};
    }
    if (transition != agent_q::AgentQSuiZkLoginProposalTransitionResult::ok) {
        return agent_q::AgentQSuiZkLoginReviewPinBeginResult{
            agent_q::AgentQSuiZkLoginReviewPinBeginStatus::unavailable,
            agent_q::AgentQSuiZkLoginProposalTerminalResult::invalid_state};
    }
    if (!sui_protocol_pin_begin(
            current.request_id,
            current.session_id,
            tick,
            current.request_window)) {
        return agent_q::AgentQSuiZkLoginReviewPinBeginResult{
            agent_q::AgentQSuiZkLoginReviewPinBeginStatus::pin_unavailable,
            agent_q::AgentQSuiZkLoginProposalTerminalResult::invalid_state};
    }
    if (!sui_local_pin_begin(tick, current.request_window)) {
        sui_protocol_pin_clear();
        return agent_q::AgentQSuiZkLoginReviewPinBeginResult{
            agent_q::AgentQSuiZkLoginReviewPinBeginStatus::pin_unavailable,
            agent_q::AgentQSuiZkLoginProposalTerminalResult::invalid_state};
    }
    return agent_q::AgentQSuiZkLoginReviewPinBeginResult{
        agent_q::AgentQSuiZkLoginReviewPinBeginStatus::started,
        agent_q::AgentQSuiZkLoginProposalTerminalResult::invalid_state};
}
bool draw_sui_local_pin(const char* notice)
{
    expect(strcmp(notice, "Approve Sui zkLogin") == 0, "Sui zkLogin PIN notice is explicit");
    ++g_sui_local_pin_draw_calls;
    g_sui_local_pin_draw_order = ++g_user_order_counter;
    return g_sui_local_pin_draw_result;
}
void sui_wipe_pin(const char*) { ++g_sui_wipe_pin_calls; }
bool sui_deadline(TickType_t tick)
{
    expect(tick == g_now, "Sui zkLogin deadline receives current tick");
    return g_sui_deadline_reached;
}
agent_q::AgentQSuiZkLoginProposalTerminalResult sui_timeout()
{
    ++g_sui_record_timeout_calls;
    return agent_q::AgentQSuiZkLoginProposalTerminalResult::timed_out;
}
agent_q::AgentQSuiZkLoginProposalTerminalResult sui_rejected()
{
    ++g_sui_record_rejected_calls;
    return agent_q::AgentQSuiZkLoginProposalTerminalResult::rejected;
}
agent_q::AgentQSuiZkLoginProposalTerminalResult sui_ui_error()
{
    ++g_sui_record_ui_error_calls;
    return agent_q::AgentQSuiZkLoginProposalTerminalResult::ui_error;
}
void sui_finish_terminal(
    const char* request_id,
    agent_q::AgentQSuiZkLoginProposalTerminalResult result)
{
    expect(strcmp(request_id, "sui-zklogin-1") == 0, "Sui zkLogin terminal uses request id");
    ++g_sui_finish_terminal_calls;
    g_sui_finish_terminal_order = ++g_user_order_counter;
    g_sui_last_terminal = result;
}
void sui_finish_error(
    const char*,
    const char* error_code,
    const char*,
    const char*)
{
    ++g_sui_finish_error_calls;
    snprintf(g_sui_last_error_code, sizeof(g_sui_last_error_code), "%s", error_code);
}

bool user_snapshot(agent_q::AgentQUserSigningFlowSnapshot* output)
{
    if (output == nullptr) {
        return false;
    }
    *output = g_user_snapshot;
    return true;
}

agent_q::AgentQUserSigningFlowCoreSnapshot user_core_snapshot()
{
    return g_user_snapshot;
}

agent_q::AgentQUserSigningReviewTimerState user_timer_state(TickType_t tick)
{
    expect(tick == g_now, "user timer state receives current tick");
    return g_user_timer_state;
}

agent_q::AgentQUserSigningReviewBuildResult build_user_model(
    const agent_q::AgentQUserSigningFlowSnapshot& snapshot,
    agent_q::AgentQUserSigningReviewViewModel* output)
{
    ++g_user_build_calls;
    expect(strcmp(snapshot.request_id, "sign-1") == 0, "user build receives snapshot");
    if (output != nullptr) {
        snprintf(output->title, sizeof(output->title), "%s", "title");
    }
    return agent_q::AgentQUserSigningReviewBuildResult::ok;
}

bool draw_user_review(
    const agent_q::AgentQUserSigningReviewViewModel& model,
    agent_q::AgentQUserSigningReviewTimerState timer)
{
    ++g_user_draw_calls;
    g_user_last_draw_timer = timer;
    expect(strcmp(model.title, "title") == 0, "user show passes model");
    expect(timer.available && timer.display_window.deadline == 200,
           "user show passes review timer state");
    return g_user_draw_result;
}

bool user_panel_active() { return g_user_panel_active; }
bool requires_pin() { return g_user_requires_pin; }
agent_q::AgentQUserSigningTransitionResult physical_confirm(
    TickType_t tick,
    agent_q::AgentQUserSigningHistoryWriteFn,
    void*)
{
    expect(tick == g_now, "physical confirm receives current tick");
    ++g_user_physical_calls;
    return g_user_physical_result;
}
agent_q::AgentQUserSigningConfirmationResult begin_user_pin(
    TickType_t tick,
    agent_q::AgentQTimeoutWindow window)
{
    expect(tick == g_now, "user PIN begin receives current tick");
    expect(window.started_at == g_now, "user PIN window starts now");
    ++g_user_begin_pin_calls;
    return g_user_begin_pin_result;
}
agent_q::AgentQUserSigningConfirmationResult record_user_rejected()
{
    ++g_user_reject_calls;
    return g_user_reject_result;
}
agent_q::AgentQUserSigningTransitionResult user_timeout(TickType_t tick)
{
    expect(tick == g_now, "user timeout receives current tick");
    ++g_user_timeout_calls;
    if (g_user_timeout_resumes_timer) {
        g_user_timer_state.paused = false;
        g_user_timer_state.display_tick = tick;
    }
    return g_user_timeout_result;
}
agent_q::AgentQUserSigningTransitionResult pause_user_review(TickType_t tick)
{
    expect(tick == g_now, "user scroll start receives current tick");
    ++g_user_pause_calls;
    return g_user_pause_result;
}
agent_q::AgentQUserSigningTransitionResult resume_user_review(TickType_t tick)
{
    expect(tick == g_now, "user scroll finish receives current tick");
    ++g_user_resume_calls;
    return g_user_resume_result;
}
bool draw_user_review_timer(agent_q::AgentQUserSigningReviewTimerState timer)
{
    ++g_user_timer_update_calls;
    g_user_last_timer_update = timer;
    return g_user_timer_update_result;
}
agent_q::AgentQUserSigningTransitionResult clear_user_flow()
{
    ++g_user_clear_flow_calls;
    return agent_q::AgentQUserSigningTransitionResult::ok;
}
bool user_terminal_pending() { return g_user_terminal_pending; }
void cancel_pin_loss() { ++g_user_cancel_pin_loss_calls; }
bool write_error(const char*, const char* code){
    ++g_user_write_error_calls;
    snprintf(g_user_last_error_code, sizeof(g_user_last_error_code), "%s", code);
    return true;
}
void show_display_error() { ++g_user_display_error_calls; }
bool dummy_history_write(const agent_q::AgentQUserSigningFlowCoreSnapshot&, void*) { return true; }
void execute_signing(const char* request_id)
{
    expect(strcmp(request_id, "sign-1") == 0, "execute uses request id");
    ++g_user_execute_calls;
    g_user_execute_order = ++g_user_order_counter;
}
void finish_user_terminal(const char* request_id)
{
    expect(strcmp(request_id, "sign-1") == 0, "user terminal uses request id");
    ++g_user_finish_terminal_calls;
    g_user_finish_terminal_order = ++g_user_order_counter;
}
void finish_user_error(const char*, const char* code, const char*, const char*)
{
    ++g_user_finish_error_calls;
    snprintf(g_user_last_error_code, sizeof(g_user_last_error_code), "%s", code);
}
void log_warn(const char*) {}

agent_q::AgentQPolicyUpdateReviewUiFlowOps policy_ops()
{
    return {
        now,
        wall_ms,
        policy_snapshot,
        draw_policy_review,
        clear_panel,
        policy_panel_active,
        identification_clear,
        policy_begin_pin_from_review,
        draw_local_pin,
        wipe_pin,
        policy_deadline,
        policy_timeout,
        policy_rejected,
        policy_ui_error,
        policy_finish_terminal,
        policy_finish_error,
        log_warn,
        300,
    };
}

agent_q::AgentQSuiZkLoginReviewUiFlowOps sui_ops()
{
    return {
        now,
        sui_snapshot,
        draw_sui_review,
        clear_panel,
        sui_panel_active,
        sui_identification_clear,
        sui_begin_pin_from_review,
        draw_sui_local_pin,
        sui_wipe_pin,
        sui_deadline,
        sui_timeout,
        sui_rejected,
        sui_ui_error,
        sui_finish_terminal,
        sui_finish_error,
        log_warn,
    };
}

agent_q::AgentQUserSigningReviewUiFlowOps user_ops()
{
    return {
        now,
        user_core_snapshot,
        user_timer_state,
        user_snapshot,
        build_user_model,
        draw_user_review,
        draw_user_review_timer,
        clear_panel,
        user_panel_active,
        requires_pin,
        physical_confirm,
        begin_user_pin,
        record_user_rejected,
        user_timeout,
        pause_user_review,
        resume_user_review,
        clear_user_flow,
        user_terminal_pending,
        cancel_pin_loss,
        draw_local_pin,
        write_error,
        show_display_error,
        dummy_history_write,
        execute_signing,
        finish_user_terminal,
        finish_user_error,
        log_warn,
        300,
    };
}

void test_policy_continue_to_pin()
{
    reset_policy();
    agent_q::policy_update_review_ui_continue(policy_ops());
    expect(g_policy_identification_clear_calls == 1, "policy continue clears identification");
    expect(g_policy_continue_calls == 1, "policy continue advances flow");
    expect(g_protocol_pin_begin_calls == 1, "policy continue begins protocol PIN");
    expect(g_local_pin_begin_calls == 1, "policy continue begins local PIN");
    expect(g_local_pin_draw_calls == 1, "policy continue draws local PIN");
    expect(g_policy_clear_review_calls == 1, "policy continue clears review");
    expect(g_policy_local_pin_draw_order < g_policy_clear_review_order,
           "policy continue prepares PIN panel before clearing review");
    expect(g_policy_finish_error_calls == 0, "policy continue has no error");
}

void test_policy_reject_and_timeout()
{
    reset_policy();
    agent_q::policy_update_review_ui_reject(policy_ops());
    expect(g_policy_clear_review_calls == 1, "policy reject clears review panel");
    expect(g_policy_record_rejected_calls == 1, "policy reject records rejection");
    expect(g_policy_finish_terminal_calls == 1, "policy reject finishes terminal");
    expect(g_policy_finish_terminal_order < g_policy_clear_review_order,
           "policy reject prepares terminal result before clearing review");

    reset_policy();
    g_policy_deadline_reached = true;
    agent_q::policy_update_review_ui_reject(policy_ops());
    expect(g_policy_record_timeout_calls == 1, "policy reject after deadline records timeout");
    expect(g_policy_record_rejected_calls == 0, "policy reject after deadline skips rejection");
    expect(g_policy_finish_terminal_order < g_policy_clear_review_order,
           "policy reject timeout prepares terminal result before clearing review");
}

void test_policy_recovery_and_display_failure()
{
    reset_policy();
    expect(agent_q::policy_update_review_ui_show(policy_ops()), "policy show succeeds");
    expect(g_policy_draw_calls == 1, "policy show draws review");

    reset_policy();
    g_policy_panel_active = false;
    agent_q::policy_update_review_ui_clear_if_needed(policy_ops());
    expect(g_policy_draw_calls == 1, "policy maintenance redraws missing panel");

    reset_policy();
    g_policy_panel_active = false;
    g_policy_draw_result = false;
    agent_q::policy_update_review_ui_clear_if_needed(policy_ops());
    expect(g_policy_record_ui_error_calls == 1, "policy redraw failure records ui_error");
    expect(g_policy_last_terminal == agent_q::AgentQPolicyUpdateFlowTerminalResult::ui_error,
           "policy redraw failure finishes ui_error");
}

void test_sui_review_continue_reject_and_recovery()
{
    reset_sui();
    expect(agent_q::sui_zklogin_review_ui_show(sui_ops()), "Sui zkLogin show succeeds");
    expect(g_sui_draw_calls == 1, "Sui zkLogin show draws review");

    reset_sui();
    agent_q::sui_zklogin_review_ui_continue(sui_ops());
    expect(g_sui_identification_clear_calls == 1, "Sui zkLogin continue clears identification");
    expect(g_sui_continue_calls == 1, "Sui zkLogin continue advances flow");
    expect(g_sui_protocol_pin_begin_calls == 1, "Sui zkLogin continue begins protocol PIN");
    expect(g_sui_local_pin_begin_calls == 1, "Sui zkLogin continue begins local PIN");
    expect(g_sui_local_pin_draw_calls == 1, "Sui zkLogin continue draws local PIN");
    expect(g_sui_clear_review_calls == 1, "Sui zkLogin continue clears review");
    expect(g_sui_local_pin_draw_order < g_sui_clear_review_order,
           "Sui zkLogin continue prepares PIN panel before clearing review");

    reset_sui();
    agent_q::sui_zklogin_review_ui_reject(sui_ops());
    expect(g_sui_record_rejected_calls == 1, "Sui zkLogin reject records rejection");
    expect(g_sui_finish_terminal_calls == 1, "Sui zkLogin reject finishes terminal");
    expect(g_sui_finish_terminal_order < g_sui_clear_review_order,
           "Sui zkLogin reject prepares terminal result before clearing review");

    reset_sui();
    g_sui_deadline_reached = true;
    agent_q::sui_zklogin_review_ui_reject(sui_ops());
    expect(g_sui_record_timeout_calls == 1, "Sui zkLogin reject after deadline records timeout");
    expect(g_sui_record_rejected_calls == 0, "Sui zkLogin reject after deadline skips rejection");

    reset_sui();
    g_sui_panel_active = false;
    agent_q::sui_zklogin_review_ui_clear_if_needed(sui_ops());
    expect(g_sui_draw_calls == 1, "Sui zkLogin maintenance redraws missing panel");

    reset_sui();
    g_sui_panel_active = false;
    g_sui_draw_result = false;
    agent_q::sui_zklogin_review_ui_clear_if_needed(sui_ops());
    expect(g_sui_record_ui_error_calls == 1, "Sui zkLogin redraw failure records ui_error");
    expect(g_sui_last_terminal == agent_q::AgentQSuiZkLoginProposalTerminalResult::ui_error,
           "Sui zkLogin redraw failure finishes ui_error");
}

void test_user_accept_reject_and_pin()
{
    reset_user();
    agent_q::user_signing_review_ui_accept(user_ops());
    expect(g_user_physical_calls == 1, "user no-PIN accept records physical confirmation");
    expect(g_user_clear_review_calls == 1, "user no-PIN accept clears review");
    expect(g_user_execute_calls == 1, "user no-PIN accept executes signing");
    expect(g_user_execute_order < g_user_clear_review_order,
           "user no-PIN accept keeps review panel until signing work completes");

    reset_user();
    g_user_requires_pin = true;
    agent_q::user_signing_review_ui_accept(user_ops());
    expect(g_user_begin_pin_calls == 1, "user PIN accept begins PIN");
    expect(g_user_clear_review_calls == 1, "user PIN accept clears review");
    expect(g_user_local_pin_draw_calls == 1, "user PIN accept draws local PIN");
    expect(g_user_local_pin_draw_order < g_user_clear_review_order,
           "user PIN accept prepares PIN panel before clearing review");

    reset_user();
    agent_q::user_signing_review_ui_reject(user_ops());
    expect(g_user_reject_calls == 1, "user reject records rejection");
    expect(g_user_finish_terminal_calls == 1, "user reject finishes terminal");
    expect(g_user_finish_terminal_order < g_user_clear_review_order,
           "user reject prepares terminal result before clearing review");
}

void test_user_scroll_events()
{
    reset_user();
    g_user_timer_state.paused = true;
    g_user_timer_state.display_tick = g_now;
    agent_q::user_signing_review_ui_scroll_started(user_ops());
    expect(g_user_pause_calls == 1, "user scroll start delegates pause to flow");
    expect(g_user_timer_update_calls == 1 &&
               g_user_last_timer_update.paused &&
               g_user_last_timer_update.display_tick == g_now,
           "user scroll start redraws timer from paused state projection");
    expect(g_user_resume_calls == 0, "user scroll start does not resume timer");

    g_user_timer_state.paused = false;
    g_user_timer_state.display_tick = g_now;
    agent_q::user_signing_review_ui_scroll_finished(user_ops());
    expect(g_user_resume_calls == 1, "user scroll finish delegates resume to flow");
    expect(g_user_timer_update_calls == 2 &&
               !g_user_last_timer_update.paused,
           "user scroll finish redraws timer from resumed state projection");

    reset_user();
    g_user_snapshot.stage = agent_q::AgentQUserSigningStage::pin_entry;
    agent_q::user_signing_review_ui_scroll_started(user_ops());
    expect(g_user_pause_calls == 0 &&
               g_user_timer_update_calls == 0 &&
               g_user_finish_terminal_calls == 0,
           "stale user scroll start does not touch state or timer display");

    reset_user();
    g_user_panel_active = false;
    agent_q::user_signing_review_ui_scroll_started(user_ops());
    expect(g_user_pause_calls == 0 &&
               g_user_timer_update_calls == 0 &&
               g_user_finish_terminal_calls == 0,
           "inactive user review panel scroll start does not touch state or timer display");

    reset_user();
    g_user_pause_result = agent_q::AgentQUserSigningTransitionResult::deadline_expired;
    g_user_terminal_pending = true;
    agent_q::user_signing_review_ui_scroll_started(user_ops());
    expect(g_user_pause_calls == 1 &&
               g_user_timer_update_calls == 0 &&
               g_user_finish_terminal_calls == 1,
           "expired user scroll start finishes terminal without timer display update");

    reset_user();
    g_user_resume_result = agent_q::AgentQUserSigningTransitionResult::wrong_stage;
    agent_q::user_signing_review_ui_scroll_finished(user_ops());
    expect(g_user_resume_calls == 1 &&
               g_user_timer_update_calls == 0 &&
               g_user_finish_terminal_calls == 0,
           "stale user scroll finish result does not touch timer display or terminal");

    reset_user();
    g_user_timer_update_result = false;
    agent_q::user_signing_review_ui_scroll_started(user_ops());
    expect(g_user_finish_error_calls == 1 &&
               strcmp(g_user_last_error_code, "ui_error") == 0,
           "timer update failure fails closed with display error");
}

void test_user_recovery_timeout_and_pin_display_failure()
{
    reset_user();
    expect(agent_q::user_signing_review_ui_show(user_ops()), "user show succeeds");
    expect(g_user_build_calls == 1 && g_user_draw_calls == 1, "user show builds and draws");

    reset_user();
    g_user_snapshot.request_window = {};
    g_user_timer_state.paused = true;
    g_user_timer_state.display_window = {10, 200};
    g_user_timer_state.display_tick = g_now;
    expect(agent_q::user_signing_review_ui_show(user_ops()),
           "user show succeeds while review timer is paused");
    expect(g_user_last_draw_timer.paused &&
               g_user_last_draw_timer.display_window.deadline == 200 &&
               g_user_last_draw_timer.display_tick == g_now,
           "user show uses state-owned timer instead of raw snapshot window");

    reset_user();
    g_user_panel_active = false;
    agent_q::user_signing_review_ui_clear_if_needed(user_ops());
    expect(g_user_timeout_calls == 1, "user maintenance records timeout check");
    expect(g_user_draw_calls == 1, "user maintenance redraws missing panel");

    reset_user();
    g_user_timer_state.paused = true;
    g_user_timer_state.display_tick = g_now;
    g_user_timeout_result =
        agent_q::AgentQUserSigningTransitionResult::deadline_not_reached;
    agent_q::user_signing_review_ui_clear_if_needed(user_ops());
    expect(g_user_timer_update_calls == 0,
           "maintenance does not redraw timer while pause remains active");

    reset_user();
    g_user_timer_state.paused = true;
    g_user_timer_state.display_tick = g_now;
    g_user_timeout_result =
        agent_q::AgentQUserSigningTransitionResult::deadline_not_reached;
    g_user_timeout_calls = 0;
    g_user_timer_update_calls = 0;
    g_user_last_timer_update = {};
    g_user_timeout_resumes_timer = true;
    agent_q::user_signing_review_ui_clear_if_needed(user_ops());
    expect(g_user_timer_update_calls == 1 &&
               !g_user_last_timer_update.paused,
           "maintenance redraws timer after abandoned pause fallback resumes state");

    reset_user();
    g_user_panel_active = false;
    g_user_draw_result = false;
    agent_q::user_signing_review_ui_clear_if_needed(user_ops());
    expect(g_user_clear_flow_calls == 1, "user redraw failure clears flow");
    expect(g_user_write_error_calls == 1, "user redraw failure writes error");
    expect(g_user_display_error_calls == 1, "user redraw failure displays error");

    reset_user();
    g_user_timeout_result = agent_q::AgentQUserSigningTransitionResult::ok;
    agent_q::user_signing_review_ui_clear_if_needed(user_ops());
    expect(g_user_finish_terminal_calls == 1, "user timeout finishes terminal");
    expect(g_user_finish_terminal_order < g_user_clear_review_order,
           "user timeout prepares terminal result before clearing review");

    reset_user();
    g_user_requires_pin = true;
    g_user_local_pin_draw_result = false;
    agent_q::user_signing_review_ui_accept(user_ops());
    expect(g_user_cancel_pin_loss_calls == 1, "user PIN display failure cancels PIN");
    expect(g_user_clear_pin_calls == 1, "user PIN display failure clears PIN panel");
    expect(g_user_finish_error_calls == 1, "user PIN display failure finishes error");
    expect(strcmp(g_user_last_error_code, "ui_error") == 0,
           "user PIN display failure emits ui_error");
}

}  // namespace

int main()
{
    test_policy_continue_to_pin();
    test_policy_reject_and_timeout();
    test_policy_recovery_and_display_failure();
    test_sui_review_continue_reject_and_recovery();
    test_user_accept_reject_and_pin();
    test_user_scroll_events();
    test_user_recovery_timeout_and_pin_display_failure();
    return failures == 0 ? 0 : 1;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}/stubs/lvgl" \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${REPO_ROOT}/firmware/src/common" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_modal_transition.cpp" \
  "${AGENT_Q_DIR}/agent_q_policy_update_review_ui_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_zklogin_review_ui_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_user_signing_review_ui_flow.cpp" \
  -o "${TMP_DIR}/review_ui_flows_test"

"${TMP_DIR}/review_ui_flows_test"
