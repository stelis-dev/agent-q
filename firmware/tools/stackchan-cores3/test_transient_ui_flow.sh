#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_transient_ui_flow.sh

Compiles the StackChan CoreS3 transient UI-flow controller against host stubs
and verifies temporary identification, welcome overlay, and message-expiry
behavior without linking the USB request server.
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
  "${AGENT_Q_DIR}/agent_q_transient_ui_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_transient_ui_flow.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-transient-ui-flow.XXXXXX")"
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

#include "agent_q_transient_ui_flow.h"

namespace {

int failures = 0;
TickType_t g_now = 100;
bool g_welcome_available = false;
bool g_identification_deadline_reached = false;
bool g_message_deadline_reached = false;
bool g_show_message_result = true;
agent_q::AgentQUiMode g_overlay_mode = agent_q::AgentQUiMode::none;
int g_clear_request_calls = 0;
int g_identification_begin_calls = 0;
int g_identification_clear_calls = 0;
int g_overlay_clear_calls = 0;
int g_show_message_calls = 0;
int g_setup_callback_calls = 0;
int g_log_warn_calls = 0;
TickType_t g_last_identification_deadline = 0;
char g_last_message[80] = {};
agent_q::AgentQMessageKind g_last_kind = agent_q::AgentQMessageKind::info;
agent_q::AgentQUiMode g_last_mode = agent_q::AgentQUiMode::none;
uint32_t g_last_duration_ms = 0;
lv_event_cb_t g_last_callback = nullptr;

void setup_clicked(void*) {}

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
    g_welcome_available = false;
    g_identification_deadline_reached = false;
    g_message_deadline_reached = false;
    g_show_message_result = true;
    g_overlay_mode = agent_q::AgentQUiMode::none;
    g_clear_request_calls = 0;
    g_identification_begin_calls = 0;
    g_identification_clear_calls = 0;
    g_overlay_clear_calls = 0;
    g_show_message_calls = 0;
    g_setup_callback_calls = 0;
    g_log_warn_calls = 0;
    g_last_identification_deadline = 0;
    g_last_message[0] = '\0';
    g_last_kind = agent_q::AgentQMessageKind::info;
    g_last_mode = agent_q::AgentQUiMode::none;
    g_last_duration_ms = 0;
    g_last_callback = nullptr;
}

TickType_t now() { return g_now; }
bool welcome_available() { return g_welcome_available; }
void clear_request() { ++g_clear_request_calls; }
void identification_begin(TickType_t deadline)
{
    ++g_identification_begin_calls;
    g_last_identification_deadline = deadline;
}
bool identification_deadline_reached(TickType_t tick)
{
    expect(tick == g_now, "identification deadline check receives current tick");
    return g_identification_deadline_reached;
}
void identification_clear() { ++g_identification_clear_calls; }
agent_q::AgentQUiMode overlay_mode() { return g_overlay_mode; }
void overlay_clear() { ++g_overlay_clear_calls; }
bool message_deadline_reached(TickType_t tick)
{
    expect(tick == g_now, "message deadline check receives current tick");
    return g_message_deadline_reached;
}
bool show_message(
    const char* message,
    agent_q::AgentQMessageKind kind,
    agent_q::AgentQUiMode mode,
    uint32_t duration_ms,
    lv_event_cb_t callback)
{
    ++g_show_message_calls;
    snprintf(g_last_message, sizeof(g_last_message), "%s", message != nullptr ? message : "");
    g_last_kind = kind;
    g_last_mode = mode;
    g_last_duration_ms = duration_ms;
    g_last_callback = callback;
    return g_show_message_result;
}
lv_event_cb_t setup_callback()
{
    ++g_setup_callback_calls;
    return setup_clicked;
}
void log_warn(const char*) { ++g_log_warn_calls; }

const agent_q::AgentQTransientUiFlowOps& ops()
{
    static const agent_q::AgentQTransientUiFlowOps value = {
        now,
        welcome_available,
        clear_request,
        identification_begin,
        identification_deadline_reached,
        identification_clear,
        overlay_mode,
        overlay_clear,
        message_deadline_reached,
        show_message,
        setup_callback,
        log_warn,
    };
    return value;
}

}  // namespace

int main()
{
    using agent_q::AgentQMessageKind;
    using agent_q::AgentQUiMode;

    expect(agent_q::transient_ui_identification_code_safe("1234"),
           "four digits are a safe identification code");
    expect(!agent_q::transient_ui_identification_code_safe(nullptr),
           "null identification code is rejected");
    expect(!agent_q::transient_ui_identification_code_safe("123"),
           "short identification code is rejected");
    expect(!agent_q::transient_ui_identification_code_safe("12345"),
           "long identification code is rejected");
    expect(!agent_q::transient_ui_identification_code_safe("12a4"),
           "non-digit identification code is rejected");

    reset_harness();
    agent_q::transient_ui_show_identification_code("1234", 30000, ops());
    expect(g_clear_request_calls == 1, "identification clears request UI first");
    expect(g_identification_begin_calls == 1, "identification display begins");
    expect(g_last_identification_deadline == 30100,
           "identification deadline uses current tick plus duration");
    expect(strcmp(g_last_message, "Device code: 1234") == 0,
           "identification message includes the code");
    expect(g_last_kind == AgentQMessageKind::info, "identification message kind is info");
    expect(g_last_mode == AgentQUiMode::identification,
           "identification message uses identification overlay mode");
    expect(g_last_duration_ms == 30000, "identification message duration is passed through");
    expect(g_log_warn_calls == 0, "successful identification display does not warn");

    reset_harness();
    g_show_message_result = false;
    agent_q::transient_ui_show_identification_code("1234", 30000, ops());
    expect(g_log_warn_calls == 1, "failed identification display logs a warning");

    reset_harness();
    g_welcome_available = true;
    agent_q::transient_ui_show_provisioning_welcome_if_available(ops());
    expect(g_show_message_calls == 1, "welcome display is shown when available");
    expect(strcmp(g_last_message, "Set up Agent-Q") == 0, "welcome message text");
    expect(g_last_mode == AgentQUiMode::identification, "welcome uses identification overlay mode");
    expect(g_last_duration_ms == 0, "welcome display has no timeout");
    expect(g_setup_callback_calls == 1, "welcome display requests setup callback");
    expect(g_last_callback == setup_clicked, "welcome display installs setup callback");

    reset_harness();
    agent_q::transient_ui_show_provisioning_welcome_if_available(ops());
    expect(g_show_message_calls == 0, "welcome display is skipped when unavailable");

    reset_harness();
    agent_q::transient_ui_clear_identification_if_needed(ops());
    expect(g_identification_clear_calls == 0, "non-expired identification remains active");
    expect(g_overlay_clear_calls == 0, "non-expired identification keeps overlay");

    reset_harness();
    g_identification_deadline_reached = true;
    g_overlay_mode = AgentQUiMode::result;
    agent_q::transient_ui_clear_identification_if_needed(ops());
    expect(g_identification_clear_calls == 1, "expired identification clears display state");
    expect(g_overlay_clear_calls == 0, "expired identification does not clear another overlay mode");
    expect(g_show_message_calls == 0, "expired hidden identification does not show welcome");

    reset_harness();
    g_identification_deadline_reached = true;
    g_overlay_mode = AgentQUiMode::identification;
    g_welcome_available = true;
    agent_q::transient_ui_clear_identification_if_needed(ops());
    expect(g_identification_clear_calls == 1, "visible expired identification clears display state");
    expect(g_overlay_clear_calls == 1, "visible expired identification clears overlay");
    expect(g_show_message_calls == 1, "visible expired identification restores welcome when available");

    reset_harness();
    agent_q::transient_ui_clear_message_if_needed(ops());
    expect(g_overlay_clear_calls == 0, "non-expired message keeps overlay");

    reset_harness();
    g_message_deadline_reached = true;
    g_welcome_available = true;
    agent_q::transient_ui_clear_message_if_needed(ops());
    expect(g_overlay_clear_calls == 1, "expired message clears overlay");
    expect(g_show_message_calls == 1, "expired message restores welcome when available");

    if (failures != 0) {
        fprintf(stderr, "%d transient UI flow test(s) failed\n", failures);
        return 1;
    }
    printf("Transient UI flow tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_transient_ui_flow.cpp" \
  -o "${TMP_DIR}/transient_ui_flow_test"

"${TMP_DIR}/transient_ui_flow_test"
