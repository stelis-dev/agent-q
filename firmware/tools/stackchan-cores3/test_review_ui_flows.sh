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
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CXX_BIN="${CXX:-c++}"

for required in \
  "${RUNTIME_DIR}/policy_update_review_ui_flow.cpp" \
  "${RUNTIME_DIR}/policy_update_review_ui_flow.h" \
  "${RUNTIME_DIR}/sui_zklogin_review_ui_flow.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_review_ui_flow.h" \
  "${RUNTIME_DIR}/modal_transition.cpp" \
  "${RUNTIME_DIR}/modal_transition.h" \
  "${RUNTIME_DIR}/user_signing_review_ui_flow.cpp" \
  "${RUNTIME_DIR}/user_signing_review_ui_flow.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-review-ui-flows.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/stubs/freertos" "${TMP_DIR}/stubs/lvgl" "${TMP_DIR}/firmware_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/firmware_common/sui"

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

#include "policy_update_review_ui_flow.h"
#include "sui_zklogin_review_ui_flow.h"
#include "user_signing_review_ui_flow.h"

namespace {

int failures = 0;
TickType_t g_now = 100;
uint64_t g_wall_ms = 1234;

signing::PolicyUpdateFlowSnapshot g_policy_snapshot = {};
signing::PolicyUpdateFlowTransitionResult g_policy_continue_result =
    signing::PolicyUpdateFlowTransitionResult::ok;
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
signing::PolicyUpdateFlowTerminalResult g_policy_last_terminal =
    signing::PolicyUpdateFlowTerminalResult::invalid_state;
char g_policy_last_error_code[48] = {};

signing::SuiZkLoginProposalSnapshot g_sui_snapshot = {};
signing::SuiZkLoginProposalTransitionResult g_sui_continue_result =
    signing::SuiZkLoginProposalTransitionResult::ok;
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
signing::SuiZkLoginProposalTerminalResult g_sui_last_terminal =
    signing::SuiZkLoginProposalTerminalResult::invalid_state;
char g_sui_last_error_code[48] = {};

signing::UserSigningFlowSnapshot g_user_snapshot = {};
signing::UserSigningReviewTimerState g_user_timer_state = {};
signing::UserSigningReviewTimerState g_user_last_draw_timer = {};
signing::UserSigningReviewTimerState g_user_last_timer_update = {};
bool g_user_requires_pin = false;
bool g_user_draw_result = true;
bool g_user_timer_update_result = true;
bool g_user_local_pin_draw_result = true;
bool g_user_panel_active = true;
bool g_user_terminal_pending = false;
signing::UserSigningReviewAcceptResult g_user_physical_result =
    signing::UserSigningReviewAcceptResult::execute;
signing::UserSigningReviewPinBeginResult g_user_begin_pin_result =
    signing::UserSigningReviewPinBeginResult::started;
signing::UserSigningReviewRejectResult g_user_reject_result =
    signing::UserSigningReviewRejectResult::finish_terminal;
signing::UserSigningTransitionResult g_user_timeout_result =
    signing::UserSigningTransitionResult::deadline_not_reached;
signing::UserSigningTransitionResult g_user_pause_result =
    signing::UserSigningTransitionResult::ok;
signing::UserSigningTransitionResult g_user_resume_result =
    signing::UserSigningTransitionResult::ok;
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
    g_policy_snapshot.stage = signing::PolicyUpdateFlowStage::reviewing;
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
    g_policy_continue_result = signing::PolicyUpdateFlowTransitionResult::ok;
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
    g_policy_last_terminal = signing::PolicyUpdateFlowTerminalResult::invalid_state;
    g_policy_last_error_code[0] = '\0';
}

void reset_sui()
{
    g_now = 100;
    g_sui_snapshot = {};
    g_sui_snapshot.active = true;
    g_sui_snapshot.stage = signing::SuiZkLoginProposalStage::reviewing;
    g_sui_snapshot.request_id = "sui-zklogin-1";
    g_sui_snapshot.session_id = "session-1";
    g_sui_snapshot.request_window = {10, 200};
    g_sui_snapshot.address = "0x2222222222222222222222222222222222222222222222222222222222222222";
    g_sui_snapshot.network = "testnet";
    g_sui_snapshot.issuer = "https://accounts.google.com";
    g_sui_snapshot.max_epoch = "123";
    g_sui_snapshot.proof_hash = "sha256:abcdef";
    g_sui_continue_result = signing::SuiZkLoginProposalTransitionResult::ok;
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
    g_sui_last_terminal = signing::SuiZkLoginProposalTerminalResult::invalid_state;
    g_sui_last_error_code[0] = '\0';
}

void reset_user()
{
    g_now = 100;
    g_user_snapshot = {};
    g_user_snapshot.active = true;
    g_user_snapshot.stage = signing::UserSigningStage::reviewing;
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
    g_user_physical_result = signing::UserSigningReviewAcceptResult::execute;
    g_user_begin_pin_result = signing::UserSigningReviewPinBeginResult::started;
    g_user_reject_result = signing::UserSigningReviewRejectResult::finish_terminal;
    g_user_timeout_result =
        signing::UserSigningTransitionResult::deadline_not_reached;
    g_user_pause_result = signing::UserSigningTransitionResult::ok;
    g_user_resume_result = signing::UserSigningTransitionResult::ok;
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

signing::PolicyUpdateFlowSnapshot policy_snapshot()
{
    return g_policy_snapshot;
}

bool draw_policy_review(
    const signing::PolicyUpdateReviewViewModel& model,
    signing::TimeoutWindow window)
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

bool clear_panel(signing::UiPanelKind kind, signing::SensitiveUiClearPolicy policy)
{
    expect(policy == signing::SensitiveUiClearPolicy::preserve, "review clear preserves scratch");
    if (kind == signing::UiPanelKind::policy_update_review) {
        ++g_policy_clear_review_calls;
        g_policy_clear_review_order = ++g_user_order_counter;
    }
    if (kind == signing::UiPanelKind::sui_zklogin_review) {
        ++g_sui_clear_review_calls;
        g_sui_clear_review_order = ++g_user_order_counter;
    }
    if (kind == signing::UiPanelKind::user_signing_review) {
        ++g_user_clear_review_calls;
        g_user_clear_review_order = ++g_user_order_counter;
    }
    if (kind == signing::UiPanelKind::local_pin_auth) {
        ++g_user_clear_pin_calls;
    }
    return true;
}

bool policy_panel_active() { return g_policy_panel_active; }
void identification_clear() { ++g_policy_identification_clear_calls; }
signing::PolicyUpdateFlowTransitionResult continue_to_pin(TickType_t tick)
{
    expect(tick == g_now, "policy continue receives current tick");
    ++g_policy_continue_calls;
    return g_policy_continue_result;
}
bool protocol_pin_begin(
    const char* request_id,
    const char* session_id,
    TickType_t now,
    signing::TimeoutWindow window)
{
    expect(now == g_now, "policy protocol PIN begin receives current tick");
    expect(strcmp(request_id, "policy-1") == 0, "policy PIN begin uses request id");
    expect(strcmp(session_id, "session-1") == 0, "policy PIN begin uses session id");
    expect(window.started_at == g_now, "policy PIN window starts now");
    ++g_protocol_pin_begin_calls;
    return g_protocol_pin_begin_result;
}
void protocol_pin_clear() { ++g_protocol_pin_clear_calls; }
bool local_pin_begin(TickType_t now, signing::TimeoutWindow)
{
    expect(now == g_now, "policy local PIN begin receives current tick");
    ++g_local_pin_begin_calls;
    return g_local_pin_begin_result;
}
signing::PolicyUpdateFlowTerminalResult policy_timeout(uint64_t uptime_ms);
signing::PolicyUpdateReviewPinBeginResult policy_begin_pin_from_review(
    const signing::PolicyUpdateFlowSnapshot& current,
    TickType_t tick,
    signing::TimeoutWindow window,
    uint64_t uptime_ms)
{
    const signing::PolicyUpdateFlowTransitionResult transition =
        continue_to_pin(tick);
    if (transition == signing::PolicyUpdateFlowTransitionResult::timed_out) {
        return signing::PolicyUpdateReviewPinBeginResult{
            signing::PolicyUpdateReviewPinBeginStatus::timed_out,
            policy_timeout(uptime_ms)};
    }
    if (transition != signing::PolicyUpdateFlowTransitionResult::ok) {
        return signing::PolicyUpdateReviewPinBeginResult{
            signing::PolicyUpdateReviewPinBeginStatus::unavailable,
            signing::PolicyUpdateFlowTerminalResult::invalid_state};
    }
    if (!protocol_pin_begin(current.request_id, current.session_id, tick, window)) {
        return signing::PolicyUpdateReviewPinBeginResult{
            signing::PolicyUpdateReviewPinBeginStatus::unavailable,
            signing::PolicyUpdateFlowTerminalResult::invalid_state};
    }
    if (!local_pin_begin(tick, window)) {
        protocol_pin_clear();
        return signing::PolicyUpdateReviewPinBeginResult{
            signing::PolicyUpdateReviewPinBeginStatus::pin_unavailable,
            signing::PolicyUpdateFlowTerminalResult::invalid_state};
    }
    return signing::PolicyUpdateReviewPinBeginResult{
        signing::PolicyUpdateReviewPinBeginStatus::started,
        signing::PolicyUpdateFlowTerminalResult::invalid_state};
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
signing::PolicyUpdateFlowTerminalResult policy_timeout(uint64_t uptime_ms)
{
    expect(uptime_ms == g_wall_ms, "policy timeout uses wall clock");
    ++g_policy_record_timeout_calls;
    return signing::PolicyUpdateFlowTerminalResult::timed_out;
}
signing::PolicyUpdateFlowTerminalResult policy_rejected(uint64_t uptime_ms)
{
    expect(uptime_ms == g_wall_ms, "policy reject uses wall clock");
    ++g_policy_record_rejected_calls;
    return signing::PolicyUpdateFlowTerminalResult::rejected;
}
signing::PolicyUpdateFlowTerminalResult policy_ui_error()
{
    ++g_policy_record_ui_error_calls;
    return signing::PolicyUpdateFlowTerminalResult::ui_error;
}
void policy_finish_terminal(
    const char* request_id,
    signing::PolicyUpdateFlowTerminalResult result)
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

signing::SuiZkLoginProposalSnapshot sui_snapshot()
{
    return g_sui_snapshot;
}

bool draw_sui_review(
    const signing::SuiZkLoginReviewViewModel& model,
    signing::TimeoutWindow window)
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
signing::SuiZkLoginProposalTransitionResult sui_continue_to_pin(TickType_t tick)
{
    expect(tick == g_now, "Sui zkLogin continue receives current tick");
    ++g_sui_continue_calls;
    return g_sui_continue_result;
}
bool sui_protocol_pin_begin(
    const char* request_id,
    const char* session_id,
    TickType_t now,
    signing::TimeoutWindow window)
{
    expect(now == g_now, "Sui zkLogin protocol PIN begin receives current tick");
    expect(strcmp(request_id, "sui-zklogin-1") == 0, "Sui zkLogin PIN begin uses request id");
    expect(strcmp(session_id, "session-1") == 0, "Sui zkLogin PIN begin uses session id");
    expect(window.deadline == 200, "Sui zkLogin PIN uses proposal window");
    ++g_sui_protocol_pin_begin_calls;
    return g_sui_protocol_pin_begin_result;
}
void sui_protocol_pin_clear() { ++g_sui_protocol_pin_clear_calls; }
bool sui_local_pin_begin(TickType_t now, signing::TimeoutWindow window)
{
    expect(now == g_now, "Sui zkLogin local PIN begin receives current tick");
    expect(window.deadline == 200, "Sui zkLogin local PIN uses proposal window");
    ++g_sui_local_pin_begin_calls;
    return g_sui_local_pin_begin_result;
}
signing::SuiZkLoginProposalTerminalResult sui_timeout();
signing::SuiZkLoginReviewPinBeginResult sui_begin_pin_from_review(
    const signing::SuiZkLoginProposalSnapshot& current,
    TickType_t tick)
{
    const signing::SuiZkLoginProposalTransitionResult transition =
        sui_continue_to_pin(tick);
    if (transition == signing::SuiZkLoginProposalTransitionResult::timed_out) {
        return signing::SuiZkLoginReviewPinBeginResult{
            signing::SuiZkLoginReviewPinBeginStatus::timed_out,
            sui_timeout()};
    }
    if (transition != signing::SuiZkLoginProposalTransitionResult::ok) {
        return signing::SuiZkLoginReviewPinBeginResult{
            signing::SuiZkLoginReviewPinBeginStatus::unavailable,
            signing::SuiZkLoginProposalTerminalResult::invalid_state};
    }
    if (!sui_protocol_pin_begin(
            current.request_id,
            current.session_id,
            tick,
            current.request_window)) {
        return signing::SuiZkLoginReviewPinBeginResult{
            signing::SuiZkLoginReviewPinBeginStatus::pin_unavailable,
            signing::SuiZkLoginProposalTerminalResult::invalid_state};
    }
    if (!sui_local_pin_begin(tick, current.request_window)) {
        sui_protocol_pin_clear();
        return signing::SuiZkLoginReviewPinBeginResult{
            signing::SuiZkLoginReviewPinBeginStatus::pin_unavailable,
            signing::SuiZkLoginProposalTerminalResult::invalid_state};
    }
    return signing::SuiZkLoginReviewPinBeginResult{
        signing::SuiZkLoginReviewPinBeginStatus::started,
        signing::SuiZkLoginProposalTerminalResult::invalid_state};
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
signing::SuiZkLoginProposalTerminalResult sui_timeout()
{
    ++g_sui_record_timeout_calls;
    return signing::SuiZkLoginProposalTerminalResult::timed_out;
}
signing::SuiZkLoginProposalTerminalResult sui_rejected()
{
    ++g_sui_record_rejected_calls;
    return signing::SuiZkLoginProposalTerminalResult::rejected;
}
signing::SuiZkLoginProposalTerminalResult sui_ui_error()
{
    ++g_sui_record_ui_error_calls;
    return signing::SuiZkLoginProposalTerminalResult::ui_error;
}
void sui_finish_terminal(
    const char* request_id,
    signing::SuiZkLoginProposalTerminalResult result)
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

bool user_snapshot(signing::UserSigningFlowSnapshot* output)
{
    if (output == nullptr) {
        return false;
    }
    *output = g_user_snapshot;
    return true;
}

signing::UserSigningFlowCoreSnapshot user_core_snapshot()
{
    return g_user_snapshot;
}

signing::UserSigningReviewTimerState user_timer_state(TickType_t tick)
{
    expect(tick == g_now, "user timer state receives current tick");
    return g_user_timer_state;
}

signing::UserSigningReviewBuildResult build_user_model(
    const signing::UserSigningFlowSnapshot& snapshot,
    signing::UserSigningReviewViewModel* output)
{
    ++g_user_build_calls;
    expect(strcmp(snapshot.request_id, "sign-1") == 0, "user build receives snapshot");
    if (output != nullptr) {
        snprintf(output->title, sizeof(output->title), "%s", "title");
    }
    return signing::UserSigningReviewBuildResult::ok;
}

bool draw_user_review(
    const signing::UserSigningReviewViewModel& model,
    signing::UserSigningReviewTimerState timer)
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
signing::UserSigningReviewAcceptResult physical_confirm(TickType_t tick)
{
    expect(tick == g_now, "physical confirm receives current tick");
    ++g_user_physical_calls;
    return g_user_physical_result;
}
signing::UserSigningReviewPinBeginResult begin_user_pin(
    TickType_t tick,
    signing::TimeoutWindow window)
{
    expect(tick == g_now, "user PIN begin receives current tick");
    expect(window.started_at == g_now, "user PIN window starts now");
    ++g_user_begin_pin_calls;
    return g_user_begin_pin_result;
}
signing::UserSigningReviewRejectResult record_user_rejected()
{
    ++g_user_reject_calls;
    return g_user_reject_result;
}
signing::UserSigningTransitionResult user_timeout(TickType_t tick)
{
    expect(tick == g_now, "user timeout receives current tick");
    ++g_user_timeout_calls;
    if (g_user_timeout_resumes_timer) {
        g_user_timer_state.paused = false;
        g_user_timer_state.display_tick = tick;
    }
    return g_user_timeout_result;
}
signing::UserSigningTransitionResult pause_user_review(TickType_t tick)
{
    expect(tick == g_now, "user scroll start receives current tick");
    ++g_user_pause_calls;
    return g_user_pause_result;
}
signing::UserSigningTransitionResult resume_user_review(TickType_t tick)
{
    expect(tick == g_now, "user scroll finish receives current tick");
    ++g_user_resume_calls;
    return g_user_resume_result;
}
bool draw_user_review_timer(signing::UserSigningReviewTimerState timer)
{
    ++g_user_timer_update_calls;
    g_user_last_timer_update = timer;
    return g_user_timer_update_result;
}
signing::UserSigningTransitionResult clear_user_flow()
{
    ++g_user_clear_flow_calls;
    return signing::UserSigningTransitionResult::ok;
}
bool user_terminal_pending() { return g_user_terminal_pending; }
void cancel_pin_loss() { ++g_user_cancel_pin_loss_calls; }
bool write_error(const char*, const char* code){
    ++g_user_write_error_calls;
    snprintf(g_user_last_error_code, sizeof(g_user_last_error_code), "%s", code);
    return true;
}
void show_display_error() { ++g_user_display_error_calls; }
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

signing::PolicyUpdateReviewUiFlowOps policy_ops()
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

signing::SuiZkLoginReviewUiFlowOps sui_ops()
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

signing::UserSigningReviewUiFlowOps user_ops()
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
    signing::policy_update_review_ui_continue(policy_ops());
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
    signing::policy_update_review_ui_reject(policy_ops());
    expect(g_policy_clear_review_calls == 1, "policy reject clears review panel");
    expect(g_policy_record_rejected_calls == 1, "policy reject records rejection");
    expect(g_policy_finish_terminal_calls == 1, "policy reject finishes terminal");
    expect(g_policy_finish_terminal_order < g_policy_clear_review_order,
           "policy reject prepares terminal result before clearing review");

    reset_policy();
    g_policy_deadline_reached = true;
    signing::policy_update_review_ui_reject(policy_ops());
    expect(g_policy_record_timeout_calls == 1, "policy reject after deadline records timeout");
    expect(g_policy_record_rejected_calls == 0, "policy reject after deadline skips rejection");
    expect(g_policy_finish_terminal_order < g_policy_clear_review_order,
           "policy reject timeout prepares terminal result before clearing review");
}

void test_policy_recovery_and_display_failure()
{
    reset_policy();
    expect(signing::policy_update_review_ui_show(policy_ops()), "policy show succeeds");
    expect(g_policy_draw_calls == 1, "policy show draws review");

    reset_policy();
    g_policy_panel_active = false;
    signing::policy_update_review_ui_clear_if_needed(policy_ops());
    expect(g_policy_draw_calls == 1, "policy maintenance redraws missing panel");

    reset_policy();
    g_policy_panel_active = false;
    g_policy_draw_result = false;
    signing::policy_update_review_ui_clear_if_needed(policy_ops());
    expect(g_policy_record_ui_error_calls == 1, "policy redraw failure records ui_error");
    expect(g_policy_last_terminal == signing::PolicyUpdateFlowTerminalResult::ui_error,
           "policy redraw failure finishes ui_error");
}

void test_sui_review_continue_reject_and_recovery()
{
    reset_sui();
    expect(signing::sui_zklogin_review_ui_show(sui_ops()), "Sui zkLogin show succeeds");
    expect(g_sui_draw_calls == 1, "Sui zkLogin show draws review");

    reset_sui();
    signing::sui_zklogin_review_ui_continue(sui_ops());
    expect(g_sui_identification_clear_calls == 1, "Sui zkLogin continue clears identification");
    expect(g_sui_continue_calls == 1, "Sui zkLogin continue advances flow");
    expect(g_sui_protocol_pin_begin_calls == 1, "Sui zkLogin continue begins protocol PIN");
    expect(g_sui_local_pin_begin_calls == 1, "Sui zkLogin continue begins local PIN");
    expect(g_sui_local_pin_draw_calls == 1, "Sui zkLogin continue draws local PIN");
    expect(g_sui_clear_review_calls == 1, "Sui zkLogin continue clears review");
    expect(g_sui_local_pin_draw_order < g_sui_clear_review_order,
           "Sui zkLogin continue prepares PIN panel before clearing review");

    reset_sui();
    signing::sui_zklogin_review_ui_reject(sui_ops());
    expect(g_sui_record_rejected_calls == 1, "Sui zkLogin reject records rejection");
    expect(g_sui_finish_terminal_calls == 1, "Sui zkLogin reject finishes terminal");
    expect(g_sui_finish_terminal_order < g_sui_clear_review_order,
           "Sui zkLogin reject prepares terminal result before clearing review");

    reset_sui();
    g_sui_deadline_reached = true;
    signing::sui_zklogin_review_ui_reject(sui_ops());
    expect(g_sui_record_timeout_calls == 1, "Sui zkLogin reject after deadline records timeout");
    expect(g_sui_record_rejected_calls == 0, "Sui zkLogin reject after deadline skips rejection");

    reset_sui();
    g_sui_panel_active = false;
    signing::sui_zklogin_review_ui_clear_if_needed(sui_ops());
    expect(g_sui_draw_calls == 1, "Sui zkLogin maintenance redraws missing panel");

    reset_sui();
    g_sui_panel_active = false;
    g_sui_draw_result = false;
    signing::sui_zklogin_review_ui_clear_if_needed(sui_ops());
    expect(g_sui_record_ui_error_calls == 1, "Sui zkLogin redraw failure records ui_error");
    expect(g_sui_last_terminal == signing::SuiZkLoginProposalTerminalResult::ui_error,
           "Sui zkLogin redraw failure finishes ui_error");
}

void test_user_accept_reject_and_pin()
{
    reset_user();
    signing::user_signing_review_ui_accept(user_ops());
    expect(g_user_physical_calls == 1, "user no-PIN accept records physical confirmation");
    expect(g_user_clear_review_calls == 1, "user no-PIN accept clears review");
    expect(g_user_execute_calls == 1, "user no-PIN accept executes signing");
    expect(g_user_execute_order < g_user_clear_review_order,
           "user no-PIN accept keeps review panel until signing work completes");

    reset_user();
    g_user_physical_result = signing::UserSigningReviewAcceptResult::history_error;
    signing::user_signing_review_ui_accept(user_ops());
    expect(g_user_finish_error_calls == 1 &&
               strcmp(g_user_last_error_code, "history_unavailable") == 0,
           "user no-PIN history failure emits history_unavailable");
    expect(g_user_execute_calls == 0 &&
               g_user_finish_terminal_calls == 0,
           "user no-PIN history failure does not execute or finish terminal");

    reset_user();
    g_user_physical_result = signing::UserSigningReviewAcceptResult::finish_terminal;
    signing::user_signing_review_ui_accept(user_ops());
    expect(g_user_finish_terminal_calls == 1 &&
               g_user_execute_calls == 0 &&
               g_user_finish_error_calls == 0,
           "user no-PIN terminal result finishes terminal without signing work");

    reset_user();
    g_user_physical_result = signing::UserSigningReviewAcceptResult::unavailable;
    signing::user_signing_review_ui_accept(user_ops());
    expect(g_user_finish_error_calls == 1 &&
               strcmp(g_user_last_error_code, "invalid_state") == 0,
           "user no-PIN unavailable result emits invalid_state");

    reset_user();
    g_user_requires_pin = true;
    signing::user_signing_review_ui_accept(user_ops());
    expect(g_user_begin_pin_calls == 1, "user PIN accept begins PIN");
    expect(g_user_clear_review_calls == 1, "user PIN accept clears review");
    expect(g_user_local_pin_draw_calls == 1, "user PIN accept draws local PIN");
    expect(g_user_local_pin_draw_order < g_user_clear_review_order,
           "user PIN accept prepares PIN panel before clearing review");

    reset_user();
    g_user_requires_pin = true;
    g_user_begin_pin_result = signing::UserSigningReviewPinBeginResult::busy;
    signing::user_signing_review_ui_accept(user_ops());
    expect(g_user_finish_error_calls == 1 &&
               strcmp(g_user_last_error_code, "busy") == 0,
           "user PIN busy result emits busy");
    expect(g_user_local_pin_draw_calls == 0 &&
               g_user_clear_review_calls == 0,
           "user PIN busy result does not draw PIN or clear review");

    reset_user();
    g_user_requires_pin = true;
    g_user_begin_pin_result = signing::UserSigningReviewPinBeginResult::finish_terminal;
    signing::user_signing_review_ui_accept(user_ops());
    expect(g_user_finish_terminal_calls == 1 &&
               g_user_finish_error_calls == 0,
           "user PIN terminal result finishes terminal");

    reset_user();
    g_user_requires_pin = true;
    g_user_begin_pin_result = signing::UserSigningReviewPinBeginResult::unavailable;
    signing::user_signing_review_ui_accept(user_ops());
    expect(g_user_finish_error_calls == 1 &&
               strcmp(g_user_last_error_code, "invalid_state") == 0,
           "user PIN unavailable result emits invalid_state");

    reset_user();
    signing::user_signing_review_ui_reject(user_ops());
    expect(g_user_reject_calls == 1, "user reject records rejection");
    expect(g_user_finish_terminal_calls == 1, "user reject finishes terminal");
    expect(g_user_finish_terminal_order < g_user_clear_review_order,
           "user reject prepares terminal result before clearing review");

    reset_user();
    g_user_reject_result = signing::UserSigningReviewRejectResult::unavailable;
    signing::user_signing_review_ui_reject(user_ops());
    expect(g_user_finish_error_calls == 1 &&
               strcmp(g_user_last_error_code, "invalid_state") == 0,
           "user reject unavailable result emits invalid_state");
}

void test_user_scroll_events()
{
    reset_user();
    g_user_timer_state.paused = true;
    g_user_timer_state.display_tick = g_now;
    signing::user_signing_review_ui_scroll_started(user_ops());
    expect(g_user_pause_calls == 1, "user scroll start delegates pause to flow");
    expect(g_user_timer_update_calls == 1 &&
               g_user_last_timer_update.paused &&
               g_user_last_timer_update.display_tick == g_now,
           "user scroll start redraws timer from paused state projection");
    expect(g_user_resume_calls == 0, "user scroll start does not resume timer");

    g_user_timer_state.paused = false;
    g_user_timer_state.display_tick = g_now;
    signing::user_signing_review_ui_scroll_finished(user_ops());
    expect(g_user_resume_calls == 1, "user scroll finish delegates resume to flow");
    expect(g_user_timer_update_calls == 2 &&
               !g_user_last_timer_update.paused,
           "user scroll finish redraws timer from resumed state projection");

    reset_user();
    g_user_snapshot.stage = signing::UserSigningStage::pin_entry;
    signing::user_signing_review_ui_scroll_started(user_ops());
    expect(g_user_pause_calls == 0 &&
               g_user_timer_update_calls == 0 &&
               g_user_finish_terminal_calls == 0,
           "stale user scroll start does not touch state or timer display");

    reset_user();
    g_user_panel_active = false;
    signing::user_signing_review_ui_scroll_started(user_ops());
    expect(g_user_pause_calls == 0 &&
               g_user_timer_update_calls == 0 &&
               g_user_finish_terminal_calls == 0,
           "inactive user review panel scroll start does not touch state or timer display");

    reset_user();
    g_user_pause_result = signing::UserSigningTransitionResult::deadline_expired;
    g_user_terminal_pending = true;
    signing::user_signing_review_ui_scroll_started(user_ops());
    expect(g_user_pause_calls == 1 &&
               g_user_timer_update_calls == 0 &&
               g_user_finish_terminal_calls == 1,
           "expired user scroll start finishes terminal without timer display update");

    reset_user();
    g_user_resume_result = signing::UserSigningTransitionResult::wrong_stage;
    signing::user_signing_review_ui_scroll_finished(user_ops());
    expect(g_user_resume_calls == 1 &&
               g_user_timer_update_calls == 0 &&
               g_user_finish_terminal_calls == 0,
           "stale user scroll finish result does not touch timer display or terminal");

    reset_user();
    g_user_timer_update_result = false;
    signing::user_signing_review_ui_scroll_started(user_ops());
    expect(g_user_finish_error_calls == 1 &&
               strcmp(g_user_last_error_code, "ui_error") == 0,
           "timer update failure fails closed with display error");
}

void test_user_recovery_timeout_and_pin_display_failure()
{
    reset_user();
    expect(signing::user_signing_review_ui_show(user_ops()), "user show succeeds");
    expect(g_user_build_calls == 1 && g_user_draw_calls == 1, "user show builds and draws");

    reset_user();
    g_user_snapshot.request_window = {};
    g_user_timer_state.paused = true;
    g_user_timer_state.display_window = {10, 200};
    g_user_timer_state.display_tick = g_now;
    expect(signing::user_signing_review_ui_show(user_ops()),
           "user show succeeds while review timer is paused");
    expect(g_user_last_draw_timer.paused &&
               g_user_last_draw_timer.display_window.deadline == 200 &&
               g_user_last_draw_timer.display_tick == g_now,
           "user show uses state-owned timer instead of raw snapshot window");

    reset_user();
    g_user_panel_active = false;
    signing::user_signing_review_ui_clear_if_needed(user_ops());
    expect(g_user_timeout_calls == 1, "user maintenance records timeout check");
    expect(g_user_draw_calls == 1, "user maintenance redraws missing panel");

    reset_user();
    g_user_timer_state.paused = true;
    g_user_timer_state.display_tick = g_now;
    g_user_timeout_result =
        signing::UserSigningTransitionResult::deadline_not_reached;
    signing::user_signing_review_ui_clear_if_needed(user_ops());
    expect(g_user_timer_update_calls == 0,
           "maintenance does not redraw timer while pause remains active");

    reset_user();
    g_user_timer_state.paused = true;
    g_user_timer_state.display_tick = g_now;
    g_user_timeout_result =
        signing::UserSigningTransitionResult::deadline_not_reached;
    g_user_timeout_calls = 0;
    g_user_timer_update_calls = 0;
    g_user_last_timer_update = {};
    g_user_timeout_resumes_timer = true;
    signing::user_signing_review_ui_clear_if_needed(user_ops());
    expect(g_user_timer_update_calls == 1 &&
               !g_user_last_timer_update.paused,
           "maintenance redraws timer after abandoned pause fallback resumes state");

    reset_user();
    g_user_panel_active = false;
    g_user_draw_result = false;
    signing::user_signing_review_ui_clear_if_needed(user_ops());
    expect(g_user_clear_flow_calls == 1, "user redraw failure clears flow");
    expect(g_user_write_error_calls == 1, "user redraw failure writes error");
    expect(g_user_display_error_calls == 1, "user redraw failure displays error");

    reset_user();
    g_user_timeout_result = signing::UserSigningTransitionResult::ok;
    signing::user_signing_review_ui_clear_if_needed(user_ops());
    expect(g_user_finish_terminal_calls == 1, "user timeout finishes terminal");
    expect(g_user_finish_terminal_order < g_user_clear_review_order,
           "user timeout prepares terminal result before clearing review");

    reset_user();
    g_user_requires_pin = true;
    g_user_local_pin_draw_result = false;
    signing::user_signing_review_ui_accept(user_ops());
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
  -I"${RUNTIME_DIR}" \
  -I"${REPO_ROOT}/firmware/src/common" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/modal_transition.cpp" \
  "${RUNTIME_DIR}/policy_update_review_ui_flow.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_review_ui_flow.cpp" \
  "${RUNTIME_DIR}/user_signing_review_ui_flow.cpp" \
  -o "${TMP_DIR}/review_ui_flows_test"

"${TMP_DIR}/review_ui_flows_test"
