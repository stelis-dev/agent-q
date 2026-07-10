#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/common/test_protocol_transport_loss.sh

Compiles the common protocol-transport loss classifier and verifies which
session-bound volatile states each target must clear or preserve after its
originating transport is lost. This test uses only a host C++ compiler and does
NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_SIGNING_DIR="${REPO_ROOT}/firmware/src/common/signing"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/protocol-transport-loss.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/protocol_transport_loss_test.cpp" <<'CPP'
#include <stdio.h>

#include "protocol_transport_loss.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

signing::ProtocolTransportLossPlan plan(
    bool session_active,
    bool connect_approval_active,
    signing::ProtocolPinLossPurpose protocol_pin,
    signing::LocalPinLossPurpose local_pin,
    bool policy_update_active = false,
    bool credential_preparation_active = false,
    bool credential_proposal_active = false,
    bool user_signing_active = false,
    bool user_signing_critical = false)
{
    signing::ProtocolTransportLossState state = {};
    state.lost_transport = signing::ProtocolTransport::usb;
    state.session = {session_active, signing::ProtocolTransport::usb};
    state.connect_approval = {
        connect_approval_active,
        signing::ProtocolTransport::usb,
    };
    state.protocol_pin = protocol_pin;
    state.protocol_pin_transport = signing::ProtocolTransport::usb;
    state.local_pin = local_pin;
    state.local_pin_transport = signing::ProtocolTransport::usb;
    state.policy_update = {
        policy_update_active,
        signing::ProtocolTransport::usb,
    };
    state.credential_preparation = {
        credential_preparation_active,
        signing::ProtocolTransport::usb,
    };
    state.credential_proposal = {
        credential_proposal_active,
        signing::ProtocolTransport::usb,
    };
    state.user_signing = {
        user_signing_active,
        signing::ProtocolTransport::usb,
    };
    state.user_signing_critical = user_signing_critical;
    return signing::protocol_transport_loss_plan(state);
}

}  // namespace

int main()
{
    using ProtocolPurpose = signing::ProtocolPinLossPurpose;
    using LocalPurpose = signing::LocalPinLossPurpose;

    signing::ProtocolTransportLossPlan p =
        plan(false, false, ProtocolPurpose::none, LocalPurpose::none);
    expect(!p.relevant, "idle state is not transport-loss relevant");
    expect(!p.clear_session && !p.clear_connect_approval && !p.clear_protocol_pin &&
               !p.clear_local_pin_auth && !p.clear_policy_update_flow &&
               !p.clear_credential_preparation &&
               !p.clear_credential_proposal_flow && !p.cancel_user_signing &&
               !p.clear_connect_review_panel && !p.clear_local_pin_panel &&
               !p.clear_policy_update_review_panel &&
               !p.clear_credential_review_panel && !p.clear_user_signing_review_panel,
           "idle plan has no cleanup actions");

    p = plan(true, false, ProtocolPurpose::none, LocalPurpose::none);
    expect(p.relevant && p.clear_session, "active session is cleared");
    expect(!p.clear_connect_approval && !p.clear_protocol_pin &&
               !p.clear_local_pin_auth && !p.clear_policy_update_flow,
           "session-only loss does not clear unrelated owners");

    p = plan(false, true, ProtocolPurpose::none, LocalPurpose::none);
    expect(p.relevant && p.clear_connect_approval && p.clear_connect_review_panel,
           "physical connect approval is cleared with review panel");
    expect(!p.clear_session && !p.clear_protocol_pin && !p.clear_local_pin_auth,
           "physical connect approval does not imply other cleanup");

    p = plan(false, false, ProtocolPurpose::connect, LocalPurpose::none);
    expect(p.relevant && p.clear_protocol_pin,
           "protocol connect PIN approval is cleared");
    expect(!p.clear_policy_update_flow && !p.clear_local_pin_auth,
           "protocol connect PIN does not clear policy update or local PIN");

    p = plan(false, false, ProtocolPurpose::policy_update, LocalPurpose::none);
    expect(p.relevant && p.clear_protocol_pin && p.clear_policy_update_flow,
           "protocol policy-update PIN clears protocol and policy update flow");
    expect(!p.clear_local_pin_auth, "protocol-only policy update does not imply local PIN wipe");

    p = plan(false, false, ProtocolPurpose::credential_proposal, LocalPurpose::none);
    expect(p.relevant && p.clear_protocol_pin && p.clear_credential_proposal_flow,
           "protocol credential PIN clears protocol and proposal flow");
    expect(!p.clear_policy_update_flow && !p.clear_local_pin_auth,
           "protocol-only credential PIN does not clear policy update or local PIN");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::connect);
    expect(p.relevant && p.clear_local_pin_auth && p.clear_local_pin_panel,
           "local connect PIN is wiped with local PIN panel");
    expect(!p.clear_policy_update_flow && !p.clear_protocol_pin,
           "local connect PIN does not clear policy update flow");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::policy_update);
    expect(p.relevant && p.clear_local_pin_auth && p.clear_policy_update_flow &&
               p.clear_local_pin_panel,
           "local policy-update PIN wipes local PIN and policy update flow");
    expect(!p.clear_protocol_pin, "local-only policy update does not imply protocol cleanup");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::credential_proposal);
    expect(p.relevant && p.clear_local_pin_auth && p.clear_credential_proposal_flow &&
               p.clear_local_pin_panel,
           "local credential PIN wipes local PIN and proposal flow");
    expect(!p.clear_protocol_pin && !p.clear_policy_update_flow,
           "local-only credential PIN does not imply protocol or policy cleanup");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::none, true);
    expect(p.relevant && p.clear_policy_update_flow && p.clear_policy_update_review_panel,
           "policy update review clears pending proposal and review panel");
    expect(!p.clear_protocol_pin && !p.clear_local_pin_auth && !p.clear_local_pin_panel,
           "policy update review does not imply protocol or PIN cleanup");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::none, false, true);
    expect(p.relevant && p.clear_credential_preparation &&
               !p.clear_credential_proposal_flow,
           "active credential preparation clears without implying a proposal");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::none, false, false, true);
    expect(p.relevant && p.clear_credential_proposal_flow &&
               p.clear_credential_review_panel,
           "active credential proposal flow clears on transport loss with review panel");
    expect(!p.clear_policy_update_flow && !p.clear_protocol_pin && !p.clear_local_pin_auth,
           "active credential proposal flow does not imply policy or PIN cleanup");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::none, false, false, false, true, false);
    expect(p.relevant && p.cancel_user_signing && p.clear_user_signing_review_panel,
           "pre-critical user_signing is canceled with user_signing review cleanup");
    expect(!p.clear_local_pin_auth && !p.clear_policy_update_flow,
           "user_signing review cleanup does not imply unrelated PIN or policy cleanup");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::user_signing, false, false, false, true, false);
    expect(p.relevant && p.clear_local_pin_auth && p.cancel_user_signing &&
               p.clear_local_pin_panel && p.clear_user_signing_review_panel,
           "user_signing PIN cleanup wipes local PIN and cancels pre-critical user_signing");

    p = plan(false, false, ProtocolPurpose::none, LocalPurpose::none, false, false, false, true, true);
    expect(p.relevant && !p.clear_local_pin_auth && !p.cancel_user_signing &&
               !p.clear_local_pin_panel && !p.clear_user_signing_review_panel,
           "signature critical section is not cancelable by transport-loss cleanup");

    p = plan(true, true, ProtocolPurpose::credential_proposal, LocalPurpose::credential_proposal);
    expect(p.relevant && p.clear_session && p.clear_connect_approval &&
               p.clear_protocol_pin && p.clear_local_pin_auth &&
               p.clear_credential_proposal_flow && p.clear_connect_review_panel &&
               p.clear_local_pin_panel,
           "combined credential session-bound state plans all relevant cleanup");

    p = plan(false, false, ProtocolPurpose::other, LocalPurpose::other);
    expect(!p.relevant, "unknown or non-session-bound local/protocol purposes are ignored");

    signing::ProtocolTransportLossState cross_transport = {};
    cross_transport.lost_transport = signing::ProtocolTransport::usb;
    cross_transport.session = {true, signing::ProtocolTransport::local_transport};
    cross_transport.connect_approval = {
        true,
        signing::ProtocolTransport::local_transport,
    };
    cross_transport.policy_update = {
        true,
        signing::ProtocolTransport::local_transport,
    };
    cross_transport.credential_preparation = {
        true,
        signing::ProtocolTransport::local_transport,
    };
    cross_transport.credential_proposal = {
        true,
        signing::ProtocolTransport::local_transport,
    };
    cross_transport.user_signing = {
        true,
        signing::ProtocolTransport::local_transport,
    };
    p = signing::protocol_transport_loss_plan(cross_transport);
    expect(!p.relevant,
           "USB loss preserves every state owned by local transport");

    cross_transport.lost_transport = signing::ProtocolTransport::local_transport;
    p = signing::protocol_transport_loss_plan(cross_transport);
    expect(p.relevant && p.clear_session && p.clear_connect_approval &&
               p.clear_policy_update_flow && p.clear_credential_preparation &&
               p.clear_credential_proposal_flow && p.cancel_user_signing,
           "local-transport loss clears every state owned by local transport");

    cross_transport.lost_transport = signing::ProtocolTransport::none;
    p = signing::protocol_transport_loss_plan(cross_transport);
    expect(!p.relevant,
           "an unspecified transport never claims state ownership");

    if (failures != 0) {
        fprintf(stderr, "%d protocol transport-loss test(s) failed\n", failures);
        return 1;
    }
    printf("Protocol transport-loss tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_SIGNING_DIR}" \
  "${TMP_DIR}/protocol_transport_loss_test.cpp" \
  "${COMMON_SIGNING_DIR}/protocol_transport_loss.cpp" \
  -o "${TMP_DIR}/protocol_transport_loss_test"

"${TMP_DIR}/protocol_transport_loss_test"
