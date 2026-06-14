#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_Q_DIR="${SCRIPT_DIR}/../../src/stackchan-cores3/agent_q"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
CXX_BIN="${CXX:-c++}"

# Minimal FreeRTOS stub: the grace module only needs TickType_t.
mkdir -p "${TMP_DIR}/freertos"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'STUB'
#pragma once
#include <stdint.h>
typedef uint32_t TickType_t;
STUB

cat >"${TMP_DIR}/usb_session_grace_test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>

#include "agent_q_usb_session_grace.h"

using namespace agent_q;

int main()
{
    const TickType_t grace = 100;

    // A transient drop that reconnects within the window resumes (session survives).
    {
        AgentQUsbGraceState s;
        assert(usb_session_grace_step(AgentQUsbLinkEvent::disconnected, 1000, grace, s) == AgentQUsbGraceAction::suspend);
        assert(s.pending);
        assert(usb_session_grace_step(AgentQUsbLinkEvent::unchanged_disconnected, 1050, grace, s) == AgentQUsbGraceAction::none);
        assert(s.pending);
        assert(usb_session_grace_step(AgentQUsbLinkEvent::connected, 1080, grace, s) == AgentQUsbGraceAction::resume);
        assert(!s.pending);
    }

    // A sustained drop past the window confirms the loss exactly once.
    {
        AgentQUsbGraceState s;
        assert(usb_session_grace_step(AgentQUsbLinkEvent::disconnected, 2000, grace, s) == AgentQUsbGraceAction::suspend);
        assert(usb_session_grace_step(AgentQUsbLinkEvent::unchanged_disconnected, 2099, grace, s) == AgentQUsbGraceAction::none);
        assert(usb_session_grace_step(AgentQUsbLinkEvent::unchanged_disconnected, 2100, grace, s) == AgentQUsbGraceAction::confirm);
        assert(!s.pending);
        assert(usb_session_grace_step(AgentQUsbLinkEvent::unchanged_disconnected, 2200, grace, s) == AgentQUsbGraceAction::none);
    }

    // Flapping: each disconnect edge reopens the window.
    {
        AgentQUsbGraceState s;
        assert(usb_session_grace_step(AgentQUsbLinkEvent::disconnected, 3000, grace, s) == AgentQUsbGraceAction::suspend);
        assert(usb_session_grace_step(AgentQUsbLinkEvent::connected, 3010, grace, s) == AgentQUsbGraceAction::resume);
        assert(usb_session_grace_step(AgentQUsbLinkEvent::disconnected, 3020, grace, s) == AgentQUsbGraceAction::suspend);
        assert(s.pending && s.pending_since == 3020);
    }

    // A fresh connect / steady states without a pending window are no-ops for the grace.
    {
        AgentQUsbGraceState s;
        assert(usb_session_grace_step(AgentQUsbLinkEvent::connected, 4000, grace, s) == AgentQUsbGraceAction::none);
        assert(usb_session_grace_step(AgentQUsbLinkEvent::unchanged_connected, 4000, grace, s) == AgentQUsbGraceAction::none);
        assert(usb_session_grace_step(AgentQUsbLinkEvent::not_due, 4000, grace, s) == AgentQUsbGraceAction::none);
        assert(usb_session_grace_step(AgentQUsbLinkEvent::unchanged_disconnected, 5000, grace, s) == AgentQUsbGraceAction::none);
    }

    printf("USB session grace tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/usb_session_grace_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_session_grace.cpp" \
  -o "${TMP_DIR}/usb_session_grace_test"

"${TMP_DIR}/usb_session_grace_test"
