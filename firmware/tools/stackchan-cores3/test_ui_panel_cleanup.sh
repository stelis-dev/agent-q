#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_ui_panel_cleanup.sh

Compiles the StackChan CoreS3 UI panel cleanup classifier against host stubs
and verifies panel-deletion routing between drawing-surface events and explicit
state owners. This test uses only a host C++ compiler and does NOT require
ESP-IDF.
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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-ui-panel-cleanup.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/stubs/freertos"

cat >"${TMP_DIR}/stubs/lvgl.h" <<'H'
#pragma once

#include <stdint.h>

struct _lv_obj_t;
typedef _lv_obj_t lv_obj_t;

typedef struct {
    int32_t x1;
    int32_t y1;
    int32_t x2;
    int32_t y2;
} lv_area_t;
H

cat >"${TMP_DIR}/stubs/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
H

cat >"${TMP_DIR}/ui_panel_cleanup_test.cpp" <<'CPP'
#include <stdio.h>

#include "agent_q_ui_panel_cleanup.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

agent_q::AgentQUiPanelCleanupPlan plan(
    agent_q::AgentQUiPanelKind kind,
	    agent_q::AgentQUiPanelCleanupEvent event,
	    bool reset_matches = false,
	    bool pin_matches = false,
	    bool policy_update_review_matches = false,
	    bool user_signing_review_matches = false,
	    bool sui_zklogin_review_matches = false)
{
    return agent_q::ui_panel_cleanup_plan(agent_q::AgentQUiPanelCleanupInput{
        kind,
        event,
	        reset_matches,
	        pin_matches,
	        policy_update_review_matches,
	        sui_zklogin_review_matches,
	        user_signing_review_matches,
	    });
}

}  // namespace

int main()
{
    using Event = agent_q::AgentQUiPanelCleanupEvent;
    using Panel = agent_q::AgentQUiPanelKind;
    using ProvisioningPanel = agent_q::AgentQProvisioningFlowPanel;

    agent_q::AgentQUiPanelCleanupPlan p =
        plan(Panel::setup_choice, Event::external_delete);
    expect(p.route_provisioning_panel_deleted, "setup delete routes to provisioning owner");
    expect(p.provisioning_panel == ProvisioningPanel::setup_choice, "setup panel maps to setup choice");
    expect(!p.wipe_setup_if_unhandled, "external setup delete does not fallback wipe");

    p = plan(Panel::backup_phrase_display, Event::external_delete);
    expect(p.route_provisioning_panel_deleted, "phrase delete routes to provisioning owner");
    expect(p.provisioning_panel == ProvisioningPanel::backup_phrase_display, "phrase panel maps");

    p = plan(Panel::import_word_entry, Event::external_delete);
    expect(p.route_provisioning_panel_deleted, "import entry delete routes to provisioning owner");
    expect(p.provisioning_panel == ProvisioningPanel::import_word_entry, "import entry maps");

    p = plan(Panel::pin_entry, Event::explicit_clear);
    expect(p.route_provisioning_panel_deleted, "explicit setup PIN clear routes to provisioning owner");
    expect(p.provisioning_panel == ProvisioningPanel::pin_entry, "setup PIN panel maps");
    expect(p.wipe_setup_if_unhandled, "explicit setup clear fallback wipes setup scratch");

    p = plan(Panel::reset_pin_entry, Event::external_delete, true, false);
    expect(p.wipe_local_reset, "matching reset panel delete wipes local reset owner");
    expect(!p.route_provisioning_panel_deleted && !p.wipe_local_pin_auth,
           "reset route does not touch other owners");

    p = plan(Panel::reset_pin_entry, Event::external_delete, false, false);
    expect(!p.wipe_local_reset && !p.route_provisioning_panel_deleted &&
               !p.wipe_local_pin_auth,
           "nonmatching reset panel delete is no-op");

    p = plan(Panel::local_pin_auth, Event::external_delete, false, false);
    expect(p.recover_local_pin_auth_panel, "external local PIN panel delete requests state-loop recovery");
    expect(!p.wipe_local_pin_auth, "external local PIN panel delete does not wipe directly");

    p = plan(Panel::local_pin_auth, Event::explicit_clear, false, true);
    expect(p.wipe_local_pin_auth, "explicit local PIN clear wipes matching local PIN owner");
    expect(!p.recover_local_pin_auth_panel, "explicit local PIN clear does not request recovery");

    p = plan(Panel::local_pin_auth, Event::explicit_clear, false, false);
    expect(!p.wipe_local_pin_auth && !p.recover_local_pin_auth_panel,
           "explicit local PIN clear without owner match is no-op");

    p = plan(Panel::user_signing_review, Event::external_delete);
    expect(p.recover_user_signing_review_panel, "external user_signing review delete requests state-loop recovery");
    expect(!p.wipe_user_signing, "external user_signing review delete does not wipe directly");

	    p = plan(Panel::policy_update_review, Event::external_delete);
	    expect(p.recover_policy_update_review_panel, "external policy update review delete requests state-loop recovery");
	    expect(!p.wipe_local_pin_auth && !p.wipe_user_signing,
	           "external policy update review delete does not wipe unrelated owners");

	    p = plan(Panel::sui_zklogin_review, Event::external_delete);
	    expect(p.recover_sui_zklogin_review_panel, "external Sui zkLogin review delete requests state-loop recovery");
	    expect(!p.wipe_local_pin_auth && !p.wipe_user_signing &&
	               !p.recover_policy_update_review_panel,
	           "external Sui zkLogin review delete does not wipe unrelated owners");

	    p = plan(Panel::user_signing_review, Event::explicit_clear, false, false, false, true);
	    expect(p.wipe_user_signing, "explicit user_signing review clear wipes matching signing owner");
	    expect(!p.recover_user_signing_review_panel, "explicit user_signing review clear does not request recovery");

    p = plan(Panel::user_signing_review, Event::explicit_clear, false, false, false);
    expect(!p.wipe_user_signing && !p.recover_user_signing_review_panel,
           "explicit user_signing review clear without owner match is no-op");

	    p = plan(Panel::settings_menu, Event::external_delete);
	    expect(!p.route_provisioning_panel_deleted && !p.wipe_setup_if_unhandled &&
	               !p.wipe_local_reset && !p.wipe_local_pin_auth &&
	               !p.recover_local_pin_auth_panel &&
	               !p.recover_policy_update_review_panel &&
	               !p.recover_sui_zklogin_review_panel && !p.wipe_user_signing &&
	               !p.recover_user_signing_review_panel,
	           "idle settings panel delete has no state cleanup");

	    p = plan(Panel::sui_settings, Event::external_delete, true);
	    expect(p.wipe_local_reset, "matching Sui settings panel delete wipes local settings owner");

	    p = plan(Panel::connect_review, Event::external_delete);
	    expect(!p.route_provisioning_panel_deleted && !p.wipe_local_reset &&
	               !p.wipe_local_pin_auth && !p.recover_local_pin_auth_panel &&
	               !p.recover_policy_update_review_panel &&
	               !p.recover_sui_zklogin_review_panel &&
	               !p.wipe_user_signing && !p.recover_user_signing_review_panel,
	           "connect review delete does not decide or cancel");

    if (failures != 0) {
        fprintf(stderr, "%d UI panel cleanup test(s) failed\n", failures);
        return 1;
    }
    printf("UI panel cleanup tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/ui_panel_cleanup_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_ui_panel_cleanup.cpp" \
  -o "${TMP_DIR}/ui_panel_cleanup_test"

"${TMP_DIR}/ui_panel_cleanup_test"
