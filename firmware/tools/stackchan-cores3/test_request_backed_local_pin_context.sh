#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_request_backed_local_pin_context.sh

Compiles the StackChan CoreS3 request-backed local PIN context boundary against
host stubs and verifies owner selection, request id lookup, deadline capping,
pause/resume delegation, and deadline checks. This test uses only a host C++
compiler and does NOT require ESP-IDF.
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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-request-backed-local-pin.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos" "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
H

cat >"${TMP_DIR}/freertos/task.h" <<'H'
#pragma once
#include "freertos/FreeRTOS.h"
H

cat >"${TMP_DIR}/ArduinoJson.h" <<'H'
#pragma once
class JsonVariantConst {};
H

cat >"${TMP_DIR}/request_backed_local_pin_context_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_policy_update_flow.h"
#include "agent_q_protocol_pin_approval.h"
#include "agent_q_request_backed_local_pin_context.h"
#include "agent_q_user_signing_confirmation.h"
#include "agent_q_user_signing_flow.h"

namespace {

int failures = 0;

agent_q::AgentQProtocolPinApprovalSnapshot g_protocol_snapshot = {};
agent_q::AgentQUserSigningFlowSnapshot g_user_snapshot = {};
bool g_protocol_request_id_result = false;
bool g_protocol_refresh_result = false;
bool g_protocol_pause_result = false;
bool g_protocol_deadline_reached = false;
agent_q::AgentQUserSigningTransitionResult g_user_refresh_result =
    agent_q::AgentQUserSigningTransitionResult::inactive;
agent_q::AgentQUserSigningConfirmationResult g_user_pause_result =
    agent_q::AgentQUserSigningConfirmationResult::inactive;
bool g_user_deadline_reached = false;
agent_q::AgentQPolicyUpdateFlowTransitionResult g_policy_mark_result =
    agent_q::AgentQPolicyUpdateFlowTransitionResult::ok;
agent_q::AgentQLocalPinAuthPurpose g_last_protocol_request_id_purpose =
    agent_q::AgentQLocalPinAuthPurpose::none;
agent_q::AgentQLocalPinAuthPurpose g_last_protocol_refresh_purpose =
    agent_q::AgentQLocalPinAuthPurpose::none;
agent_q::AgentQLocalPinAuthPurpose g_last_protocol_pause_purpose =
    agent_q::AgentQLocalPinAuthPurpose::none;
agent_q::AgentQLocalPinAuthPurpose g_last_protocol_deadline_purpose =
    agent_q::AgentQLocalPinAuthPurpose::none;
TickType_t g_last_protocol_refresh_now = 0;
TickType_t g_last_protocol_pause_now = 0;
TickType_t g_last_protocol_deadline_now = 0;
TickType_t g_last_user_refresh_now = 0;
TickType_t g_last_user_pause_now = 0;
TickType_t g_last_user_deadline_now = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

agent_q::AgentQTimeoutWindow window(TickType_t started_at, TickType_t deadline)
{
    return agent_q::timeout_window_from_deadline(started_at, deadline);
}

}  // namespace

namespace agent_q {

AgentQProtocolPinApprovalSnapshot protocol_pin_approval_snapshot()
{
    return g_protocol_snapshot;
}

bool protocol_pin_approval_request_id_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    char* output,
    size_t output_size)
{
    g_last_protocol_request_id_purpose = purpose;
    if (!g_protocol_request_id_result || output == nullptr || output_size == 0) {
        return false;
    }
    snprintf(output, output_size, "%s", g_protocol_snapshot.request_id);
    return true;
}

bool protocol_pin_approval_refresh_deadline_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    g_last_protocol_refresh_purpose = purpose;
    g_last_protocol_refresh_now = now;
    return g_protocol_refresh_result;
}

bool protocol_pin_approval_pause_deadline_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    g_last_protocol_pause_purpose = purpose;
    g_last_protocol_pause_now = now;
    return g_protocol_pause_result;
}

bool protocol_pin_approval_deadline_reached_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    g_last_protocol_deadline_purpose = purpose;
    g_last_protocol_deadline_now = now;
    return g_protocol_deadline_reached;
}

AgentQUserSigningFlowSnapshot user_signing_flow_snapshot()
{
    return g_user_snapshot;
}

AgentQUserSigningTransitionResult user_signing_flow_refresh_pin_deadline(TickType_t now)
{
    g_last_user_refresh_now = now;
    return g_user_refresh_result;
}

bool user_signing_flow_deadline_reached(TickType_t now)
{
    g_last_user_deadline_now = now;
    return g_user_deadline_reached;
}

AgentQUserSigningConfirmationResult
user_signing_confirmation_mark_pin_verification_started(TickType_t now)
{
    g_last_user_pause_now = now;
    return g_user_pause_result;
}

AgentQPolicyUpdateFlowTransitionResult policy_update_flow_mark_pin_verifying()
{
    return g_policy_mark_result;
}

}  // namespace agent_q

int main()
{
    using Purpose = agent_q::AgentQLocalPinAuthPurpose;
    using Owner = agent_q::AgentQRequestBackedLocalPinOwner;

    expect(agent_q::request_backed_local_pin_owner_for_purpose(Purpose::connect) ==
               Owner::protocol_pin_approval,
           "connect is owned by protocol PIN approval");
    expect(agent_q::request_backed_local_pin_owner_for_purpose(Purpose::policy_update) ==
               Owner::protocol_pin_approval,
           "policy update is owned by protocol PIN approval");
    expect(agent_q::request_backed_local_pin_owner_for_purpose(Purpose::user_signing) ==
               Owner::user_signing,
           "user signing is owned by user signing flow");
    expect(agent_q::request_backed_local_pin_owner_for_purpose(Purpose::settings_signing_mode) ==
               Owner::none,
           "settings PIN action is not request backed");
    expect(agent_q::request_backed_local_pin_purpose(Purpose::user_signing),
           "user signing is request backed");
    expect(!agent_q::request_backed_local_pin_purpose(Purpose::settings_change_pin),
           "settings change PIN is not request backed");

    char request_id[32] = "unchanged";
    expect(!agent_q::request_backed_local_pin_request_id(
               Purpose::settings_change_pin,
               request_id,
               sizeof(request_id)),
           "non-request-backed purpose has no request id");
    expect(request_id[0] == '\0', "non-request-backed request id output clears");

    g_protocol_snapshot = agent_q::AgentQProtocolPinApprovalSnapshot{
        true,
        agent_q::AgentQProtocolPinApprovalPurpose::connect,
        "connect-1",
        "",
        window(10, 100),
        window(10, 90),
    };
    g_protocol_request_id_result = true;
    expect(agent_q::request_backed_local_pin_request_id(
               Purpose::connect,
               request_id,
               sizeof(request_id)) &&
               strcmp(request_id, "connect-1") == 0,
           "protocol-backed request id delegates to protocol owner");
    expect(g_last_protocol_request_id_purpose == Purpose::connect,
           "protocol request id receives local PIN purpose");

    g_user_snapshot = {};
    expect(!agent_q::request_backed_local_pin_request_id(
               Purpose::user_signing,
               request_id,
               sizeof(request_id)),
           "inactive user signing flow has no request id");
    g_user_snapshot.active = true;
    snprintf(g_user_snapshot.request_id, sizeof(g_user_snapshot.request_id), "%s", "sign-1");
    g_user_snapshot.request_window = window(20, 80);
    expect(agent_q::request_backed_local_pin_request_id(
               Purpose::user_signing,
               request_id,
               sizeof(request_id)) &&
               strcmp(request_id, "sign-1") == 0,
           "user-signing request id comes from user signing flow");

    agent_q::AgentQTimeoutWindow capped =
        agent_q::request_backed_local_pin_cap_input_window(
            Purpose::connect,
            window(30, 150));
    expect(capped.started_at == 30 && capped.deadline == 100,
           "protocol-backed PIN input deadline caps to request window");
    capped = agent_q::request_backed_local_pin_cap_input_window(
        Purpose::user_signing,
        window(40, 120));
    expect(capped.started_at == 40 && capped.deadline == 80,
           "user-signing PIN input deadline caps to request window");
    capped = agent_q::request_backed_local_pin_cap_input_window(
        Purpose::settings_signing_mode,
        window(40, 120));
    expect(!agent_q::timeout_window_valid(capped),
           "non-request-backed purpose cannot cap request window");

    g_protocol_refresh_result = true;
    expect(agent_q::request_backed_local_pin_resume_input_window(Purpose::policy_update, 55),
           "protocol-backed resume delegates to protocol owner");
    expect(g_last_protocol_refresh_purpose == Purpose::policy_update &&
               g_last_protocol_refresh_now == 55,
           "protocol resume receives purpose and tick");
    g_user_refresh_result = agent_q::AgentQUserSigningTransitionResult::ok;
    expect(agent_q::request_backed_local_pin_resume_input_window(Purpose::user_signing, 56),
           "user-signing resume delegates to user signing flow");
    expect(g_last_user_refresh_now == 56, "user resume receives tick");

    g_policy_mark_result = agent_q::AgentQPolicyUpdateFlowTransitionResult::inactive;
    expect(!agent_q::request_backed_local_pin_pause_input_window(Purpose::policy_update, 60),
           "policy update pause fails before protocol pause when policy stage transition fails");
    g_policy_mark_result = agent_q::AgentQPolicyUpdateFlowTransitionResult::ok;
    g_protocol_pause_result = true;
    expect(agent_q::request_backed_local_pin_pause_input_window(Purpose::policy_update, 61),
           "policy update pause marks policy stage then pauses protocol owner");
    expect(g_last_protocol_pause_purpose == Purpose::policy_update &&
               g_last_protocol_pause_now == 61,
           "policy update pause delegates protocol purpose and tick");
    g_user_pause_result = agent_q::AgentQUserSigningConfirmationResult::ok;
    expect(agent_q::request_backed_local_pin_pause_input_window(Purpose::user_signing, 62),
           "user-signing pause delegates to confirmation flow");
    expect(g_last_user_pause_now == 62, "user pause receives tick");
    expect(agent_q::request_backed_local_pin_pause_input_window(Purpose::settings_change_pin, 63),
           "non-request-backed pause is a no-op success");

    g_protocol_deadline_reached = true;
    expect(agent_q::request_backed_local_pin_deadline_reached(Purpose::connect, 70),
           "protocol-backed deadline delegates to protocol owner");
    expect(g_last_protocol_deadline_purpose == Purpose::connect &&
               g_last_protocol_deadline_now == 70,
           "protocol deadline receives purpose and tick");
    g_user_deadline_reached = true;
    expect(agent_q::request_backed_local_pin_deadline_reached(Purpose::user_signing, 71),
           "user-signing deadline delegates to user signing flow");
    expect(g_last_user_deadline_now == 71, "user deadline receives tick");
    expect(!agent_q::request_backed_local_pin_deadline_reached(Purpose::settings_signing_mode, 72),
           "non-request-backed deadline is never reached");

    if (failures != 0) {
        fprintf(stderr, "%d request-backed local PIN context test(s) failed\n", failures);
        return 1;
    }
    printf("Request-backed local PIN context tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${TMP_DIR}" \
  "${TMP_DIR}/request_backed_local_pin_context_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_backed_local_pin_context.cpp" \
  -o "${TMP_DIR}/request_backed_local_pin_context_test"

"${TMP_DIR}/request_backed_local_pin_context_test"
