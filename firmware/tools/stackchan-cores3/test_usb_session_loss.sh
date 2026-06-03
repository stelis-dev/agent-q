#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_session_loss.sh

Compiles the StackChan CoreS3 USB session-loss cleanup classifier against host
stubs and verifies which session-bound volatile states are affected by USB host
SOF loss. This test uses only a host C++ compiler and does NOT require ESP-IDF.
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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-session-loss.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/usb_session_loss_test.cpp" <<'CPP'
#include <stdio.h>

#include "agent_q_usb_session_loss.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

agent_q::AgentQUsbSessionLossPlan plan(
    bool session_active,
    bool connect_approval_active,
    agent_q::AgentQUsbSessionLossProtocolPinPurpose protocol_pin,
    agent_q::AgentQUsbSessionLossLocalPinPurpose local_pin,
    bool method_signing_active = false)
{
    return agent_q::usb_session_loss_plan(agent_q::AgentQUsbSessionLossInput{
        session_active,
        connect_approval_active,
        protocol_pin,
        local_pin,
        method_signing_active,
    });
}

}  // namespace

int main()
{
    using ProtocolPurpose = agent_q::AgentQUsbSessionLossProtocolPinPurpose;
    using LocalPurpose = agent_q::AgentQUsbSessionLossLocalPinPurpose;

    agent_q::AgentQUsbSessionLossPlan p =
        plan(false, false, ProtocolPurpose::none, LocalPurpose::none);
    expect(!p.relevant, "idle state is not USB-session-loss relevant");
    expect(!p.clear_session && !p.clear_connect_approval && !p.clear_protocol_pin &&
               !p.wipe_local_pin_auth && !p.clear_policy_update_flow &&
               !p.clear_method_signing_flow && !p.clear_decision_panel &&
               !p.clear_local_pin_panel,
           "idle plan has no cleanup actions");

    p = plan(true, false, ProtocolPurpose::none, LocalPurpose::none);
    expect(p.relevant && p.clear_session, "active session is cleared");
    expect(!p.clear_connect_approval && !p.clear_protocol_pin &&
               !p.wipe_local_pin_auth && !p.clear_policy_update_flow &&
               !p.clear_method_signing_flow,
           "session-only loss does not clear unrelated owners");

    p = plan(false, true, ProtocolPurpose::none, LocalPurpose::none);
    expect(p.relevant && p.clear_connect_approval && p.clear_decision_panel,
           "physical connect approval is cleared with decision panel");
    expect(!p.clear_session && !p.clear_protocol_pin && !p.wipe_local_pin_auth,
           "physical connect approval does not imply other cleanup");

    p = plan(false, false, ProtocolPurpose::connect, LocalPurpose::none);
    expect(p.relevant && p.clear_protocol_pin,
           "protocol connect PIN approval is cleared");
    expect(!p.clear_policy_update_flow && !p.wipe_local_pin_auth,
           "protocol connect PIN does not clear policy update or local PIN");

    p = plan(false, false, ProtocolPurpose::policy_update, LocalPurpose::none);
    expect(p.relevant && p.clear_protocol_pin && p.clear_policy_update_flow,
           "protocol policy-update PIN clears protocol and policy update flow");
    expect(!p.wipe_local_pin_auth, "protocol-only policy update does not imply local PIN wipe");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::connect);
    expect(p.relevant && p.wipe_local_pin_auth && p.clear_local_pin_panel,
           "local connect PIN is wiped with local PIN panel");
    expect(!p.clear_policy_update_flow && !p.clear_protocol_pin,
           "local connect PIN does not clear policy update flow");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::policy_update);
    expect(p.relevant && p.wipe_local_pin_auth && p.clear_policy_update_flow &&
               p.clear_local_pin_panel,
           "local policy-update PIN wipes local PIN and policy update flow");
    expect(!p.clear_protocol_pin, "local-only policy update does not imply protocol cleanup");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::method_signing);
    expect(p.relevant && p.wipe_local_pin_auth && p.clear_method_signing_flow &&
               p.clear_local_pin_panel,
           "local method-signing PIN wipes local PIN and method signing flow");
    expect(!p.clear_policy_update_flow && !p.clear_protocol_pin,
           "local method-signing PIN does not clear policy update flow or protocol PIN");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::none, true);
    expect(p.relevant && p.clear_method_signing_flow,
           "method signing flow is cleared after local PIN is gone");
    expect(!p.wipe_local_pin_auth && !p.clear_policy_update_flow,
           "method signing flow alone does not wipe unrelated owners");

    p = plan(true, true, ProtocolPurpose::policy_update, LocalPurpose::policy_update);
    expect(p.relevant && p.clear_session && p.clear_connect_approval &&
               p.clear_protocol_pin && p.wipe_local_pin_auth &&
               p.clear_policy_update_flow && !p.clear_method_signing_flow &&
               p.clear_decision_panel &&
               p.clear_local_pin_panel,
           "combined session-bound state plans all relevant cleanup");

    p = plan(false, false, ProtocolPurpose::other, LocalPurpose::other);
    expect(!p.relevant, "unknown or non-session-bound local/protocol purposes are ignored");

    if (failures != 0) {
        fprintf(stderr, "%d USB session-loss test(s) failed\n", failures);
        return 1;
    }
    printf("USB session-loss tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/usb_session_loss_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_session_loss.cpp" \
  -o "${TMP_DIR}/usb_session_loss_test"

"${TMP_DIR}/usb_session_loss_test"
