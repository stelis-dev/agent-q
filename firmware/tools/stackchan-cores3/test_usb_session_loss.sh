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
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-session-loss.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/usb_session_loss_test.cpp" <<'CPP'
#include <stdio.h>

#include "usb_session_loss.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

signing::UsbSessionLossPlan plan(
    bool session_active,
    bool connect_approval_active,
    signing::UsbSessionLossProtocolPinPurpose protocol_pin,
    signing::UsbSessionLossLocalPinPurpose local_pin,
    bool policy_update_active = false,
    bool sui_zklogin_proposal_active = false,
    bool user_signing_active = false,
    bool user_signing_critical = false)
{
    return signing::usb_session_loss_plan(signing::UsbSessionLossInput{
        session_active,
        connect_approval_active,
        protocol_pin,
        local_pin,
        policy_update_active,
        sui_zklogin_proposal_active,
        user_signing_active,
        user_signing_critical,
    });
}

}  // namespace

int main()
{
    using ProtocolPurpose = signing::UsbSessionLossProtocolPinPurpose;
    using LocalPurpose = signing::UsbSessionLossLocalPinPurpose;

    signing::UsbSessionLossPlan p =
        plan(false, false, ProtocolPurpose::none, LocalPurpose::none);
    expect(!p.relevant, "idle state is not USB-session-loss relevant");
    expect(!p.clear_session && !p.clear_connect_approval && !p.clear_protocol_pin &&
               !p.wipe_local_pin_auth && !p.clear_policy_update_flow &&
               !p.clear_sui_zklogin_proposal_flow && !p.cancel_user_signing &&
               !p.clear_connect_review_panel && !p.clear_local_pin_panel &&
               !p.clear_policy_update_review_panel &&
               !p.clear_sui_zklogin_review_panel && !p.clear_user_signing_review_panel,
           "idle plan has no cleanup actions");

    p = plan(true, false, ProtocolPurpose::none, LocalPurpose::none);
    expect(p.relevant && p.clear_session, "active session is cleared");
    expect(!p.clear_connect_approval && !p.clear_protocol_pin &&
               !p.wipe_local_pin_auth && !p.clear_policy_update_flow,
           "session-only loss does not clear unrelated owners");

    p = plan(false, true, ProtocolPurpose::none, LocalPurpose::none);
    expect(p.relevant && p.clear_connect_approval && p.clear_connect_review_panel,
           "physical connect approval is cleared with review panel");
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

    p = plan(false, false, ProtocolPurpose::sui_zklogin_proposal, LocalPurpose::none);
    expect(p.relevant && p.clear_protocol_pin && p.clear_sui_zklogin_proposal_flow,
           "protocol Sui zkLogin PIN clears protocol and proposal flow");
    expect(!p.clear_policy_update_flow && !p.wipe_local_pin_auth,
           "protocol-only Sui zkLogin PIN does not clear policy update or local PIN");

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

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::sui_zklogin_proposal);
    expect(p.relevant && p.wipe_local_pin_auth && p.clear_sui_zklogin_proposal_flow &&
               p.clear_local_pin_panel,
           "local Sui zkLogin PIN wipes local PIN and proposal flow");
    expect(!p.clear_protocol_pin && !p.clear_policy_update_flow,
           "local-only Sui zkLogin PIN does not imply protocol or policy cleanup");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::none, true);
    expect(p.relevant && p.clear_policy_update_flow && p.clear_policy_update_review_panel,
           "policy update review clears pending proposal and review panel");
    expect(!p.clear_protocol_pin && !p.wipe_local_pin_auth && !p.clear_local_pin_panel,
           "policy update review does not imply protocol or PIN cleanup");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::none, false, true);
    expect(p.relevant && p.clear_sui_zklogin_proposal_flow &&
               p.clear_sui_zklogin_review_panel,
           "active Sui zkLogin proposal flow clears on session loss with review panel");
    expect(!p.clear_policy_update_flow && !p.clear_protocol_pin && !p.wipe_local_pin_auth,
           "active Sui zkLogin proposal flow does not imply policy or PIN cleanup");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::none, false, false, true, false);
    expect(p.relevant && p.cancel_user_signing && p.clear_user_signing_review_panel,
           "pre-critical user_signing is canceled with user_signing review cleanup");
    expect(!p.wipe_local_pin_auth && !p.clear_policy_update_flow,
           "user_signing review cleanup does not imply unrelated PIN or policy cleanup");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::user_signing, false, false, true, false);
    expect(p.relevant && p.wipe_local_pin_auth && p.cancel_user_signing &&
               p.clear_local_pin_panel && p.clear_user_signing_review_panel,
           "user_signing PIN cleanup wipes local PIN and cancels pre-critical user_signing");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::none, false, false, true, true);
    expect(p.relevant && !p.wipe_local_pin_auth && !p.cancel_user_signing &&
               !p.clear_local_pin_panel && !p.clear_user_signing_review_panel,
           "signature critical section is not cancelable by USB session-loss cleanup");

    p = plan(true, true, ProtocolPurpose::sui_zklogin_proposal, LocalPurpose::sui_zklogin_proposal);
    expect(p.relevant && p.clear_session && p.clear_connect_approval &&
               p.clear_protocol_pin && p.wipe_local_pin_auth &&
               p.clear_sui_zklogin_proposal_flow && p.clear_connect_review_panel &&
               p.clear_local_pin_panel,
           "combined Sui zkLogin session-bound state plans all relevant cleanup");

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
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/usb_session_loss_test.cpp" \
  "${RUNTIME_DIR}/usb_session_loss.cpp" \
  -o "${TMP_DIR}/usb_session_loss_test"

"${TMP_DIR}/usb_session_loss_test"
