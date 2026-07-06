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
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-request-backed-local-pin.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos" "${TMP_DIR}/firmware_common"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/firmware_common/sui"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"
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

#include "policy/policy_update_flow.h"
#include "protocol_pin_approval.h"
#include "request_backed_local_pin_context.h"
#include "sui_zklogin_proposal_flow.h"
#include "user_signing_confirmation.h"
#include "signing/user_signing_flow.h"

namespace {

int failures = 0;

signing::ProtocolPinApprovalSnapshot g_protocol_snapshot = {};
signing::UserSigningFlowSnapshot g_user_snapshot = {};
bool g_protocol_request_id_result = false;
bool g_protocol_refresh_result = false;
bool g_protocol_pause_result = false;
bool g_protocol_deadline_reached = false;
signing::UserSigningTransitionResult g_user_refresh_result =
    signing::UserSigningTransitionResult::inactive;
signing::UserSigningTransitionResult g_user_prepare_pin_result =
    signing::UserSigningTransitionResult::inactive;
signing::TimeoutWindow g_user_prepare_pin_output = {};
signing::UserSigningConfirmationResult g_user_pause_result =
    signing::UserSigningConfirmationResult::inactive;
bool g_user_deadline_reached = false;
signing::PolicyUpdateFlowTransitionResult g_policy_mark_result =
    signing::PolicyUpdateFlowTransitionResult::ok;
signing::SuiZkLoginProposalTransitionResult g_sui_zklogin_mark_result =
    signing::SuiZkLoginProposalTransitionResult::ok;
signing::LocalPinAuthPurpose g_last_protocol_request_id_purpose =
    signing::LocalPinAuthPurpose::none;
signing::LocalPinAuthPurpose g_last_protocol_refresh_purpose =
    signing::LocalPinAuthPurpose::none;
signing::LocalPinAuthPurpose g_last_protocol_pause_purpose =
    signing::LocalPinAuthPurpose::none;
signing::LocalPinAuthPurpose g_last_protocol_deadline_purpose =
    signing::LocalPinAuthPurpose::none;
TickType_t g_last_protocol_refresh_now = 0;
TickType_t g_last_protocol_pause_now = 0;
TickType_t g_last_protocol_deadline_now = 0;
TickType_t g_last_user_refresh_now = 0;
TickType_t g_last_user_pause_now = 0;
TickType_t g_last_user_deadline_now = 0;
TickType_t g_last_user_prepare_pin_now = 0;
signing::TimeoutWindow g_last_user_prepare_pin_input = {};

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

signing::TimeoutWindow window(TickType_t started_at, TickType_t deadline)
{
    return signing::timeout_window_from_deadline(started_at, deadline);
}

}  // namespace

namespace signing {

ProtocolPinApprovalSnapshot protocol_pin_approval_snapshot()
{
    return g_protocol_snapshot;
}

bool protocol_pin_approval_request_id_for_local_pin_purpose(
    LocalPinAuthPurpose purpose,
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
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    g_last_protocol_refresh_purpose = purpose;
    g_last_protocol_refresh_now = now;
    return g_protocol_refresh_result;
}

bool protocol_pin_approval_pause_deadline_for_local_pin_purpose(
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    g_last_protocol_pause_purpose = purpose;
    g_last_protocol_pause_now = now;
    return g_protocol_pause_result;
}

bool protocol_pin_approval_deadline_reached_for_local_pin_purpose(
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    g_last_protocol_deadline_purpose = purpose;
    g_last_protocol_deadline_now = now;
    return g_protocol_deadline_reached;
}

UserSigningFlowSnapshot user_signing_flow_snapshot()
{
    return g_user_snapshot;
}

UserSigningFlowCoreSnapshot user_signing_flow_core_snapshot()
{
    return g_user_snapshot;
}

UserSigningTransitionResult user_signing_flow_cap_request_backed_pin_input_window(
    TickType_t now,
    TimeoutWindow pin_input_window,
    TimeoutWindow* output)
{
    g_last_user_prepare_pin_now = now;
    g_last_user_prepare_pin_input = pin_input_window;
    if (output != nullptr) {
        *output = g_user_prepare_pin_output;
    }
    return g_user_prepare_pin_result;
}

UserSigningTransitionResult user_signing_flow_refresh_pin_deadline(TickType_t now)
{
    g_last_user_refresh_now = now;
    return g_user_refresh_result;
}

bool user_signing_flow_apply_deadline_transition(TickType_t now)
{
    g_last_user_deadline_now = now;
    return g_user_deadline_reached;
}

UserSigningConfirmationResult
user_signing_confirmation_mark_pin_verification_started(TickType_t now)
{
    g_last_user_pause_now = now;
    return g_user_pause_result;
}

PolicyUpdateFlowTransitionResult policy_update_flow_mark_pin_verifying()
{
    return g_policy_mark_result;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_flow_mark_pin_verifying()
{
    return g_sui_zklogin_mark_result;
}

}  // namespace signing

int main()
{
    using Purpose = signing::LocalPinAuthPurpose;
    using Owner = signing::RequestBackedLocalPinOwner;

    expect(signing::request_backed_local_pin_owner_for_purpose(Purpose::connect) ==
               Owner::protocol_pin_approval,
           "connect is owned by protocol PIN approval");
    expect(signing::request_backed_local_pin_owner_for_purpose(Purpose::policy_update) ==
               Owner::protocol_pin_approval,
           "policy update is owned by protocol PIN approval");
    expect(signing::request_backed_local_pin_owner_for_purpose(Purpose::sui_zklogin_proposal) ==
               Owner::protocol_pin_approval,
           "Sui zkLogin proposal is owned by protocol PIN approval");
    expect(signing::request_backed_local_pin_owner_for_purpose(Purpose::user_signing) ==
               Owner::user_signing,
           "user signing is owned by user signing flow");
    expect(signing::request_backed_local_pin_owner_for_purpose(Purpose::settings_signing_mode) ==
               Owner::none,
           "settings PIN action is not request backed");
    expect(signing::request_backed_local_pin_purpose(Purpose::user_signing),
           "user signing is request backed");
    expect(signing::request_backed_local_pin_purpose(Purpose::sui_zklogin_proposal),
           "Sui zkLogin proposal is request backed");
    expect(!signing::request_backed_local_pin_purpose(Purpose::settings_change_pin),
           "settings change PIN is not request backed");

    char request_id[32] = "unchanged";
    expect(!signing::request_backed_local_pin_request_id(
               Purpose::settings_change_pin,
               request_id,
               sizeof(request_id)),
           "non-request-backed purpose has no request id");
    expect(request_id[0] == '\0', "non-request-backed request id output clears");

    g_protocol_snapshot = signing::ProtocolPinApprovalSnapshot{
        true,
        signing::ProtocolPinApprovalPurpose::connect,
        "connect-1",
        "",
        window(10, 100),
        window(10, 90),
    };
    g_protocol_request_id_result = true;
    expect(signing::request_backed_local_pin_request_id(
               Purpose::connect,
               request_id,
               sizeof(request_id)) &&
               strcmp(request_id, "connect-1") == 0,
           "protocol-backed request id delegates to protocol owner");
    expect(g_last_protocol_request_id_purpose == Purpose::connect,
           "protocol request id receives local PIN purpose");

    g_user_snapshot = {};
    expect(!signing::request_backed_local_pin_request_id(
               Purpose::user_signing,
               request_id,
               sizeof(request_id)),
           "inactive user signing flow has no request id");
    g_user_snapshot.active = true;
    snprintf(g_user_snapshot.request_id, sizeof(g_user_snapshot.request_id), "%s", "sign-1");
    g_user_snapshot.request_window = window(20, 80);
    expect(signing::request_backed_local_pin_request_id(
               Purpose::user_signing,
               request_id,
               sizeof(request_id)) &&
               strcmp(request_id, "sign-1") == 0,
           "user-signing request id comes from user signing flow");
    g_user_prepare_pin_result = signing::UserSigningTransitionResult::ok;
    g_user_prepare_pin_output = window(40, 80);

    signing::TimeoutWindow capped =
        signing::request_backed_local_pin_cap_input_window(
            Purpose::connect,
            30,
            window(30, 150));
    expect(capped.started_at == 30 && capped.deadline == 100,
           "protocol-backed PIN input deadline caps to request window");
    capped = signing::request_backed_local_pin_cap_input_window(
        Purpose::user_signing,
        40,
        window(40, 120));
    expect(capped.started_at == 40 && capped.deadline == 80,
           "user-signing PIN input deadline delegates to user signing flow");
    expect(g_last_user_prepare_pin_now == 40 &&
               g_last_user_prepare_pin_input.started_at == 40 &&
               g_last_user_prepare_pin_input.deadline == 120,
           "user-signing PIN cap passes tick and requested window to state owner");
    g_user_prepare_pin_result = signing::UserSigningTransitionResult::inactive;
    capped = signing::request_backed_local_pin_cap_input_window(
        Purpose::settings_signing_mode,
        40,
        window(40, 120));
    expect(!signing::timeout_window_valid(capped),
           "non-request-backed purpose cannot cap request window");
    capped = signing::request_backed_local_pin_cap_input_window(
        Purpose::connect,
        70,
        window(30, 60));
    expect(!signing::timeout_window_valid(capped),
           "request-backed PIN cap rejects stale input windows");
    capped = signing::request_backed_local_pin_cap_input_window(
        Purpose::connect,
        70,
        window(90, 120));
    expect(!signing::timeout_window_valid(capped),
           "request-backed PIN cap rejects future input windows");

    g_protocol_refresh_result = true;
    expect(signing::request_backed_local_pin_resume_input_window(Purpose::policy_update, 55),
           "protocol-backed resume delegates to protocol owner");
    expect(g_last_protocol_refresh_purpose == Purpose::policy_update &&
               g_last_protocol_refresh_now == 55,
           "protocol resume receives purpose and tick");
    g_user_refresh_result = signing::UserSigningTransitionResult::ok;
    expect(signing::request_backed_local_pin_resume_input_window(Purpose::user_signing, 56),
           "user-signing resume delegates to user signing flow");
    expect(g_last_user_refresh_now == 56, "user resume receives tick");

    g_policy_mark_result = signing::PolicyUpdateFlowTransitionResult::inactive;
    expect(!signing::request_backed_local_pin_pause_input_window(Purpose::policy_update, 60),
           "policy update pause fails before protocol pause when policy stage transition fails");
    g_policy_mark_result = signing::PolicyUpdateFlowTransitionResult::ok;
    g_protocol_pause_result = true;
    expect(signing::request_backed_local_pin_pause_input_window(Purpose::policy_update, 61),
           "policy update pause marks policy stage then pauses protocol owner");
    expect(g_last_protocol_pause_purpose == Purpose::policy_update &&
               g_last_protocol_pause_now == 61,
           "policy update pause delegates protocol purpose and tick");
    g_sui_zklogin_mark_result = signing::SuiZkLoginProposalTransitionResult::wrong_stage;
    expect(!signing::request_backed_local_pin_pause_input_window(Purpose::sui_zklogin_proposal, 62),
           "Sui zkLogin pause fails before protocol pause when proposal stage transition fails");
    g_sui_zklogin_mark_result = signing::SuiZkLoginProposalTransitionResult::ok;
    g_protocol_pause_result = true;
    expect(signing::request_backed_local_pin_pause_input_window(Purpose::sui_zklogin_proposal, 63),
           "Sui zkLogin pause marks proposal stage then pauses protocol owner");
    expect(g_last_protocol_pause_purpose == Purpose::sui_zklogin_proposal &&
               g_last_protocol_pause_now == 63,
           "Sui zkLogin pause delegates protocol purpose and tick");
    g_user_pause_result = signing::UserSigningConfirmationResult::ok;
    expect(signing::request_backed_local_pin_pause_input_window(Purpose::user_signing, 64),
           "user-signing pause delegates to confirmation flow");
    expect(g_last_user_pause_now == 64, "user pause receives tick");
    expect(signing::request_backed_local_pin_pause_input_window(Purpose::settings_change_pin, 65),
           "non-request-backed pause is a no-op success");

    g_protocol_deadline_reached = true;
    expect(signing::request_backed_local_pin_deadline_reached(Purpose::connect, 70),
           "protocol-backed deadline delegates to protocol owner");
    expect(g_last_protocol_deadline_purpose == Purpose::connect &&
               g_last_protocol_deadline_now == 70,
           "protocol deadline receives purpose and tick");
    g_user_deadline_reached = true;
    expect(signing::request_backed_local_pin_deadline_reached(Purpose::user_signing, 71),
           "user-signing deadline delegates to user signing flow");
    expect(g_last_user_deadline_now == 71, "user deadline receives tick");
    expect(!signing::request_backed_local_pin_deadline_reached(Purpose::settings_signing_mode, 72),
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
  -I"${RUNTIME_DIR}" \
  -I"${TMP_DIR}" \
  "${TMP_DIR}/request_backed_local_pin_context_test.cpp" \
  "${RUNTIME_DIR}/request_backed_local_pin_context.cpp" \
  -o "${TMP_DIR}/request_backed_local_pin_context_test"

"${TMP_DIR}/request_backed_local_pin_context_test"
