#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_connect_review_response_flow.sh

Compiles the StackChan CoreS3 connect-review response flow against host stubs
and verifies connect approval choice, timeout, PIN handoff, terminal response,
session creation, and review-UI recovery behavior without linking the USB
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
CXX_BIN="${CXX:-c++}"

for required in \
  "${AGENT_Q_DIR}/agent_q_connect_review_response_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_connect_review_response_flow.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-connect-review-response-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/stubs/freertos" "${TMP_DIR}/stubs/lvgl"

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

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_connect_review_response_flow.h"

namespace {

int failures = 0;
TickType_t g_now = 100;
bool g_local_pin_flow_active = false;
bool g_has_choice_event = false;
bool g_awaiting_choice = false;
bool g_requires_pin = false;
bool g_deadline_reached = false;
bool g_replace_session_result = true;
bool g_write_approved_response = true;
bool g_write_rejected_response = true;
bool g_review_panel_visible = true;
agent_q::AgentQConnectApprovalChoice g_choice_event =
    agent_q::AgentQConnectApprovalChoice::none;
agent_q::AgentQConnectApprovalSnapshot g_snapshot = {};
int g_reset_choice_calls = 0;
int g_receive_calls = 0;
int g_begin_pin_calls = 0;
int g_choose_calls = 0;
int g_clear_calls = 0;
int g_replace_session_calls = 0;
int g_write_error_calls = 0;
int g_write_approved_calls = 0;
int g_write_rejected_calls = 0;
int g_log_info_calls = 0;
int g_log_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_log_recovered_calls = 0;
int g_show_result_calls = 0;
int g_show_review_calls = 0;
agent_q::AgentQConnectApprovalChoice g_last_chosen =
    agent_q::AgentQConnectApprovalChoice::none;
agent_q::AgentQMessageKind g_last_result_kind = agent_q::AgentQMessageKind::info;
char g_last_result_message[80] = {};
char g_last_response_code[80] = {};
char g_last_response_message[120] = {};

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void reset_harness()
{
    g_now = 100;
    g_local_pin_flow_active = false;
    g_has_choice_event = false;
    g_awaiting_choice = false;
    g_requires_pin = false;
    g_deadline_reached = false;
    g_replace_session_result = true;
    g_write_approved_response = true;
    g_write_rejected_response = true;
    g_review_panel_visible = true;
    g_choice_event = agent_q::AgentQConnectApprovalChoice::none;
    g_snapshot = {
        true,
        "req-1",
        "client",
        {},
        agent_q::AgentQConnectApprovalChoice::none,
    };
    g_reset_choice_calls = 0;
    g_receive_calls = 0;
    g_begin_pin_calls = 0;
    g_choose_calls = 0;
    g_clear_calls = 0;
    g_replace_session_calls = 0;
    g_write_error_calls = 0;
    g_write_approved_calls = 0;
    g_write_rejected_calls = 0;
    g_log_info_calls = 0;
    g_log_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_log_recovered_calls = 0;
    g_show_result_calls = 0;
    g_show_review_calls = 0;
    g_last_chosen = agent_q::AgentQConnectApprovalChoice::none;
    g_last_result_kind = agent_q::AgentQMessageKind::info;
    g_last_result_message[0] = '\0';
    g_last_response_code[0] = '\0';
    g_last_response_message[0] = '\0';
}

TickType_t now() { return g_now; }
bool local_pin_flow_active() { return g_local_pin_flow_active; }
void reset_choices() { ++g_reset_choice_calls; }
bool receive_choice(agent_q::AgentQConnectApprovalChoice* choice)
{
    ++g_receive_calls;
    if (!g_has_choice_event) {
        return false;
    }
    g_has_choice_event = false;
    if (choice != nullptr) {
        *choice = g_choice_event;
    }
    return true;
}
bool awaiting_choice() { return g_awaiting_choice; }
bool requires_pin() { return g_requires_pin; }
bool begin_pin(TickType_t tick)
{
    expect(tick == g_now, "PIN handoff receives current tick");
    ++g_begin_pin_calls;
    return true;
}
bool choose(agent_q::AgentQConnectApprovalChoice choice, TickType_t tick)
{
    expect(tick == g_now, "choice receives current tick");
    ++g_choose_calls;
    g_last_chosen = choice;
    g_snapshot.choice = choice;
    return true;
}
agent_q::AgentQConnectApprovalSnapshot snapshot() { return g_snapshot; }
bool deadline_reached(TickType_t tick)
{
    expect(tick == g_now, "deadline check receives current tick");
    return g_deadline_reached;
}
bool request_id(char* output, size_t output_size)
{
    snprintf(output, output_size, "%s", g_snapshot.request_id);
    return true;
}
void clear_approval()
{
    ++g_clear_calls;
    g_snapshot.active = false;
    g_snapshot.choice = agent_q::AgentQConnectApprovalChoice::none;
}
bool replace_session()
{
    ++g_replace_session_calls;
    return g_replace_session_result;
}
bool write_error(const char*, const char* code)
{
    ++g_write_error_calls;
    snprintf(g_last_response_code, sizeof(g_last_response_code), "%s", code);
    g_last_response_message[0] = '\0';
    return true;
}
bool write_approved(const char*)
{
    ++g_write_approved_calls;
    return g_write_approved_response;
}
bool write_rejected(const char*, const char* code)
{
    ++g_write_rejected_calls;
    snprintf(g_last_response_code, sizeof(g_last_response_code), "%s", code);
    g_last_response_message[0] = '\0';
    return g_write_rejected_response;
}
void log_info(const char*, const char*) { ++g_log_info_calls; }
void log_error(const char*, const char*) { ++g_log_error_calls; }
void log_write_failure(const char*, const char*) { ++g_log_write_failure_calls; }
void log_recovered(const char*) { ++g_log_recovered_calls; }
void show_result(const char* message, agent_q::AgentQMessageKind kind)
{
    ++g_show_result_calls;
    snprintf(g_last_result_message, sizeof(g_last_result_message), "%s", message);
    g_last_result_kind = kind;
}
bool review_panel_visible() { return g_review_panel_visible; }
void show_review() { ++g_show_review_calls; }

const agent_q::AgentQConnectReviewResponseFlowOps& ops()
{
    static const agent_q::AgentQConnectReviewResponseFlowOps value = {
        now,
        local_pin_flow_active,
        reset_choices,
        receive_choice,
        awaiting_choice,
        requires_pin,
        begin_pin,
        choose,
        snapshot,
        deadline_reached,
        request_id,
        clear_approval,
        replace_session,
        write_error,
        write_approved,
        write_rejected,
        log_info,
        log_error,
        log_write_failure,
        log_recovered,
        show_result,
        review_panel_visible,
        show_review,
    };
    return value;
}

}  // namespace

int main()
{
    using agent_q::AgentQConnectApprovalChoice;
    using agent_q::AgentQMessageKind;

    reset_harness();
    g_local_pin_flow_active = true;
    g_has_choice_event = true;
    g_choice_event = AgentQConnectApprovalChoice::approved;
    agent_q::connect_review_response_flow_run(ops());
    expect(g_reset_choice_calls == 1, "active connect PIN flow resets stale choices");
    expect(g_receive_calls == 0, "active connect PIN flow skips choice receive");
    expect(g_show_result_calls == 0, "active connect PIN flow has no terminal result");

    reset_harness();
    g_has_choice_event = true;
    g_choice_event = AgentQConnectApprovalChoice::approved;
    g_awaiting_choice = true;
    g_requires_pin = true;
    agent_q::connect_review_response_flow_run(ops());
    expect(g_begin_pin_calls == 1, "approved choice with PIN requirement starts PIN auth");
    expect(g_reset_choice_calls == 1, "PIN handoff resets choice queue");
    expect(g_choose_calls == 0, "PIN handoff does not choose terminal approval yet");
    expect(g_show_result_calls == 0, "PIN handoff has no terminal result");

    reset_harness();
    g_has_choice_event = true;
    g_choice_event = AgentQConnectApprovalChoice::rejected;
    g_awaiting_choice = true;
    agent_q::connect_review_response_flow_run(ops());
    expect(g_choose_calls == 1, "rejected choice is recorded");
    expect(g_last_chosen == AgentQConnectApprovalChoice::rejected, "rejected choice value");
    expect(g_reset_choice_calls == 1, "terminal choice resets choice queue");
    expect(g_clear_calls == 1, "terminal rejected connect clears approval state");
    expect(g_write_rejected_calls == 1, "terminal rejected connect writes rejected response");
    expect(strcmp(g_last_response_code, "user_rejected") == 0, "rejected response code");
    expect(g_show_result_calls == 1, "terminal rejected connect shows result");
    expect(strcmp(g_last_result_message, "Connection rejected") == 0, "rejected result message");
    expect(g_last_result_kind == AgentQMessageKind::rejected, "rejected result kind");

    reset_harness();
    g_deadline_reached = true;
    agent_q::connect_review_response_flow_run(ops());
    expect(g_clear_calls == 1, "timeout clears approval state before result");
    expect(g_write_rejected_calls == 1, "timeout writes rejected response");
    expect(strcmp(g_last_response_code, "timeout") == 0, "timeout response code");
    expect(g_show_result_calls == 1, "timeout shows result");
    expect(strcmp(g_last_result_message, "Connection timed out") == 0, "timeout result message");
    expect(g_last_result_kind == AgentQMessageKind::timeout, "timeout result kind");

    reset_harness();
    g_snapshot.choice = AgentQConnectApprovalChoice::approved;
    agent_q::connect_review_response_flow_run(ops());
    expect(g_clear_calls == 1, "approved connect clears approval state");
    expect(g_replace_session_calls == 1, "approved connect creates session");
    expect(g_write_approved_calls == 1, "approved connect writes approved response");
    expect(g_show_result_calls == 1, "approved connect shows result");
    expect(strcmp(g_last_result_message, "Connected") == 0, "approved result message");
    expect(g_last_result_kind == AgentQMessageKind::success, "approved result kind");

    reset_harness();
    g_snapshot.choice = AgentQConnectApprovalChoice::approved;
    g_replace_session_result = false;
    agent_q::connect_review_response_flow_run(ops());
    expect(g_write_error_calls == 1, "session creation failure writes public error");
    expect(strcmp(g_last_response_code, "rng_unavailable") == 0, "session failure code");
    expect(g_log_error_calls == 1, "session creation failure logs error");
    expect(strcmp(g_last_result_message, "RNG error") == 0, "session failure result");
    expect(g_last_result_kind == AgentQMessageKind::error, "session failure result kind");

    reset_harness();
    g_snapshot.choice = AgentQConnectApprovalChoice::approved;
    g_write_approved_response = false;
    agent_q::connect_review_response_flow_run(ops());
    expect(g_log_write_failure_calls == 1, "approved response write failure is logged");
    expect(g_show_result_calls == 1, "approved response write failure still shows terminal result");

    reset_harness();
    g_awaiting_choice = true;
    g_review_panel_visible = false;
    agent_q::connect_review_response_flow_run(ops());
    expect(g_show_review_calls == 1, "missing connect review panel is recovered");
    expect(g_log_recovered_calls == 1, "connect review recovery logs recovery warning");

    reset_harness();
    g_awaiting_choice = true;
    g_review_panel_visible = true;
    agent_q::connect_review_response_flow_run(ops());
    expect(g_show_review_calls == 0, "visible connect review panel is not redrawn");

    if (failures != 0) {
        fprintf(stderr, "%d connect review response flow test(s) failed\n", failures);
        return 1;
    }
    printf("Connect review response flow tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_connect_review_response_flow.cpp" \
  -o "${TMP_DIR}/connect_review_response_flow_test"

"${TMP_DIR}/connect_review_response_flow_test"
