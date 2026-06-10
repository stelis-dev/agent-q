#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_protocol_pin_approval.sh

Compiles the StackChan CoreS3 protocol-backed local PIN approval state owner
against host stubs and verifies request id, session id, purpose, and deadline
ownership. This test uses only a host C++ compiler and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
LOCAL_PIN_AUTH_UI_SOURCE="${AGENT_Q_DIR}/agent_q_local_pin_auth_ui_flow.cpp"
CXX_BIN="${CXX:-c++}"

check_local_pin_ui_deadline_order() {
  local deadline_line
  local lockout_line

  deadline_line="$(awk '
    /void local_pin_auth_ui_clear_if_needed\(/ { in_fn = 1 }
    in_fn && /request_backed_local_pin_input_deadline_reached/ { print NR; exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}")"
  lockout_line="$(awk '
    /void local_pin_auth_ui_clear_if_needed\(/ { in_fn = 1 }
    in_fn && /local_pin_auth_release_lockout_if_elapsed/ { print NR; exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}")"

  if [[ -z "${deadline_line}" || -z "${lockout_line}" || "${deadline_line}" -ge "${lockout_line}" ]]; then
    echo "FAILED: protocol-backed PIN input timeout must be handled before lockout retry UI recovery" >&2
    echo "deadline_line=${deadline_line:-missing} lockout_line=${lockout_line:-missing}" >&2
    exit 1
  fi
}

check_local_pin_ui_handler_timeout_order() {
  local function_name="$1"
  local second_pattern="$2"
  local label="$3"
  local snippet="${TMP_DIR}/${function_name}.cpp"
  local timeout_line
  local second_line

  awk -v fn="${function_name}" '
    $0 ~ "void " fn "\\(" { in_fn = 1 }
    in_fn { print }
    in_fn && /^}/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${snippet}"

  timeout_line="$(grep -En 'finish_request_backed_local_pin_input_timeout_if_reached' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  second_line="$(grep -En "${second_pattern}" "${snippet}" | head -n 1 | cut -d: -f1 || true)"

  if [[ -z "${timeout_line}" || -z "${second_line}" || "${timeout_line}" -ge "${second_line}" ]]; then
    echo "FAILED: ${label}" >&2
    echo "timeout_line=${timeout_line:-missing} second_line=${second_line:-missing}" >&2
    exit 1
  fi
}

check_local_pin_worker_timeout_order() {
  local snippet="${TMP_DIR}/handle_local_pin_auth_verify_worker_result.cpp"
  local timeout_line
  local complete_line

  awk '
    /void local_pin_auth_ui_handle_verify_worker_result\(/ { in_fn = 1 }
    in_fn { print }
    in_fn && /^}/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${snippet}"

  complete_line="$(grep -En 'local_pin_auth_complete_verify_job\(' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  timeout_line="$(grep -En 'finish_request_backed_local_pin_input_timeout_if_reached' "${snippet}" | awk -F: -v complete="${complete_line:-0}" '$1 < complete { line = $1 } END { print line }')"

  if [[ -z "${timeout_line}" || -z "${complete_line}" || "${timeout_line}" -ge "${complete_line}" ]]; then
    echo "FAILED: protocol-backed PIN worker completion must check input timeout before local PIN verify result" >&2
    echo "timeout_line=${timeout_line:-missing} complete_line=${complete_line:-missing}" >&2
    exit 1
  fi
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-protocol-pin-approval.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/protocol_pin_approval_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_protocol_pin_approval.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

bool random_bytes(void* output, size_t size, void*)
{
    if (output == nullptr) {
        return false;
    }
    unsigned char* bytes = static_cast<unsigned char*>(output);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = static_cast<unsigned char>(index + 1);
    }
    return true;
}

agent_q::AgentQTimeoutWindow timeout_window(TickType_t started_at, TickType_t deadline)
{
    return agent_q::timeout_window_from_deadline(started_at, deadline);
}

}  // namespace

namespace agent_q {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

}  // namespace agent_q

int main()
{
    using Purpose = agent_q::AgentQProtocolPinApprovalPurpose;
    using LocalPurpose = agent_q::AgentQLocalPinAuthPurpose;
    using SessionValidation = agent_q::AgentQSessionValidationResult;

    agent_q::session_init();
    agent_q::protocol_pin_approval_clear();
    expect(!agent_q::protocol_pin_approval_active(), "clear leaves state inactive");
    char request_id[agent_q::kAgentQProtocolPinRequestIdSize] = {};
    expect(!agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
               LocalPurpose::connect,
               request_id,
               sizeof(request_id)),
           "inactive state has no connect request id");
    expect(request_id[0] == '\0', "inactive request id output is cleared");
    expect(agent_q::protocol_pin_approval_begin_connect("connect-1", timeout_window(10, 100)),
           "connect protocol PIN approval begins");
    agent_q::AgentQProtocolPinApprovalSnapshot snapshot =
        agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.active, "connect snapshot is active");
    expect(snapshot.purpose == Purpose::connect, "connect snapshot purpose");
    expect(strcmp(snapshot.request_id, "connect-1") == 0, "connect request id stored");
    expect(snapshot.session_id[0] == '\0', "connect stores no session id");
    expect(snapshot.request_window.started_at == 10 &&
               snapshot.request_window.deadline == 100,
           "connect request window stored");
    expect(snapshot.pin_input_window.started_at == 10 &&
               snapshot.pin_input_window.deadline == 100,
           "connect PIN input window stored");
    expect(agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
               LocalPurpose::connect,
               request_id,
               sizeof(request_id)) &&
               strcmp(request_id, "connect-1") == 0,
           "connect request id maps from local PIN purpose");
    expect(!agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
               LocalPurpose::policy_update,
               request_id,
               sizeof(request_id)),
           "connect state does not map policy update purpose");
    expect(!agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               99),
           "deadline not reached before deadline");
    expect(agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               100),
           "deadline reached at deadline");
    expect(agent_q::protocol_pin_approval_pause_deadline_for_local_pin_purpose(
               LocalPurpose::connect,
               90),
           "connect local PIN verification pauses PIN input deadline");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.request_window.deadline == 100, "connect request admission window remains recorded while PIN verifies");
    expect(snapshot.pin_input_window.started_at == 0 &&
               snapshot.pin_input_window.deadline == 0,
           "connect PIN input deadline is hidden while verification runs");
    expect(!agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               1000),
           "paused connect PIN input deadline does not keep request deadline running");
    expect(agent_q::protocol_pin_approval_refresh_deadline_for_local_pin_purpose(
               LocalPurpose::connect,
               120),
           "connect local PIN retry resumes after processing");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.pin_input_window.started_at == 40 &&
               snapshot.pin_input_window.deadline == 130,
           "connect retry resumes remaining time without resetting timer fill");
    expect(!agent_q::protocol_pin_approval_refresh_deadline_for_local_pin_purpose(
               LocalPurpose::connect,
               121),
           "connect retry cannot resume twice without a new pause");
    expect(agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               130),
           "resumed connect retry expires after remaining input time");
    expect(agent_q::protocol_pin_approval_pause_deadline_for_local_pin_purpose(
               LocalPurpose::connect,
               125),
           "connect local PIN verification can pause a resumed input window");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.request_window.deadline == 100, "connect request window remains immutable");
    expect(snapshot.pin_input_window.deadline == 0, "connect paused PIN input deadline stored");
    expect(!agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               1000),
           "paused connect PIN input deadline stays paused after resumed retry");

    char too_long[agent_q::kAgentQProtocolPinRequestIdSize + 4] = {};
    memset(too_long, 'a', sizeof(too_long) - 1);
    expect(!agent_q::protocol_pin_approval_begin_connect(too_long, timeout_window(20, 200)),
           "overlong request id is rejected");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(strcmp(snapshot.request_id, "connect-1") == 0,
           "failed begin does not overwrite existing state");
    expect(!agent_q::protocol_pin_approval_begin_policy_update(
               "policy-overwrite",
               "session_aaaaaaaaaaaaaaaa",
               timeout_window(20, 225)),
           "active protocol PIN approval cannot be overwritten");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.purpose == Purpose::connect &&
               strcmp(snapshot.request_id, "connect-1") == 0,
           "rejected active overwrite leaves current state intact");

    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session starts");
    const char* session_id = agent_q::session_id();
    agent_q::protocol_pin_approval_clear();
    expect(agent_q::protocol_pin_approval_begin_policy_update(
               "policy-1",
               session_id,
               timeout_window(20, 250)),
           "policy update protocol PIN approval begins");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.active, "policy update snapshot is active");
    expect(snapshot.purpose == Purpose::policy_update, "policy update snapshot purpose");
    expect(strcmp(snapshot.request_id, "policy-1") == 0, "policy update request id stored");
    expect(strcmp(snapshot.session_id, session_id) == 0, "policy update session id stored");
    expect(snapshot.request_window.started_at == 20 &&
               snapshot.request_window.deadline == 250,
           "policy update stores request window");
    expect(snapshot.pin_input_window.started_at == 20 &&
               snapshot.pin_input_window.deadline == 250,
           "policy update stores PIN input window");
    expect(agent_q::protocol_pin_approval_policy_update_session_matches(session_id),
           "matching policy update session recognized");
    expect(!agent_q::protocol_pin_approval_policy_update_session_matches(
               "session_aaaaaaaaaaaaaaaa"),
           "mismatched policy update session rejected");
    expect(agent_q::protocol_pin_approval_policy_update_request_id(
               request_id,
               sizeof(request_id)) &&
               strcmp(request_id, "policy-1") == 0,
           "policy update request id is available");
    expect(agent_q::protocol_pin_approval_validate_policy_update_session() ==
               SessionValidation::ok,
           "active matching session validates");
    agent_q::session_clear();
    expect(agent_q::protocol_pin_approval_validate_policy_update_session() ==
               SessionValidation::missing,
           "cleared session invalidates pending policy update");

    agent_q::protocol_pin_approval_clear();
    expect(!agent_q::protocol_pin_approval_policy_update_request_id(
               request_id,
               sizeof(request_id)),
           "cleared state has no policy update request id");
    expect(!agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               1000),
           "cleared state has no reached protocol deadline");

    if (failures != 0) {
        fprintf(stderr, "%d protocol PIN approval test(s) failed\n", failures);
        return 1;
    }
    printf("Protocol PIN approval tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/protocol_pin_approval_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_protocol_pin_approval.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  -o "${TMP_DIR}/protocol_pin_approval_test"

"${TMP_DIR}/protocol_pin_approval_test"
check_local_pin_ui_deadline_order
check_local_pin_ui_handler_timeout_order \
  local_pin_auth_ui_handle_digit \
  'local_pin_auth_add_digit' \
  "request-backed PIN digit handler must timeout before local PIN mutation"
check_local_pin_ui_handler_timeout_order \
  local_pin_auth_ui_handle_clear \
  'local_pin_auth_clear_pin' \
  "request-backed PIN clear handler must timeout before local PIN mutation"
check_local_pin_ui_handler_timeout_order \
  local_pin_auth_ui_handle_backspace \
  'local_pin_auth_backspace_pin' \
  "request-backed PIN backspace handler must timeout before local PIN mutation"
check_local_pin_ui_handler_timeout_order \
  local_pin_auth_ui_handle_submit \
  'local_pin_auth_submit' \
  "request-backed PIN submit handler must timeout before verification start"
check_local_pin_ui_handler_timeout_order \
  local_pin_auth_ui_cancel \
  'policy_update_flow_return_to_review|usb_response_write_connect_rejected|user_signing_confirmation_return_to_review_from_pin' \
  "request-backed PIN cancel handler must timeout before cancel/back action"
check_local_pin_worker_timeout_order
