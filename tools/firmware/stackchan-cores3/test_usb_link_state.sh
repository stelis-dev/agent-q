#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_usb_link_state.sh

Compiles the StackChan CoreS3 USB host link polling state owner against host
stubs and verifies poll deadline, initial observation, edge, clear, and
wrap-safe behavior. This test uses only a host C++ compiler and does NOT
require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/products/firmware/src/stackchan-cores3/agent_q"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-link-state.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
H

cat >"${TMP_DIR}/usb_link_state_test.cpp" <<'CPP'
#include <stdio.h>

#include "agent_q_usb_link_state.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

}  // namespace

int main()
{
    using Event = agent_q::AgentQUsbLinkEvent;

    agent_q::usb_link_state_clear();
    agent_q::AgentQUsbLinkStateSnapshot snapshot =
        agent_q::usb_link_state_snapshot();
    expect(!snapshot.known && !snapshot.connected && snapshot.next_poll == 0,
           "clear resets link state");

    expect(agent_q::usb_link_state_observe(true, 10, 5) == Event::initial_observed,
           "first due observation initializes state");
    snapshot = agent_q::usb_link_state_snapshot();
    expect(snapshot.known && snapshot.connected && snapshot.next_poll == 15,
           "initial observation stores connection and next poll");
    expect(agent_q::usb_link_state_observe(false, 14, 5) == Event::not_due,
           "observation before next poll is not due");
    snapshot = agent_q::usb_link_state_snapshot();
    expect(snapshot.connected && snapshot.next_poll == 15,
           "not-due observation leaves state untouched");

    expect(agent_q::usb_link_state_observe(true, 15, 5) == Event::unchanged_connected,
           "same connected state is unchanged connected");
    expect(agent_q::usb_link_state_observe(false, 20, 5) == Event::disconnected,
           "connected to disconnected edge is reported");
    snapshot = agent_q::usb_link_state_snapshot();
    expect(snapshot.known && !snapshot.connected && snapshot.next_poll == 25,
           "disconnected edge stores disconnected state");
    expect(agent_q::usb_link_state_observe(false, 25, 5) == Event::unchanged_disconnected,
           "same disconnected state is unchanged disconnected");
    expect(agent_q::usb_link_state_observe(true, 30, 5) == Event::connected,
           "disconnected to connected edge is reported");

    agent_q::usb_link_state_clear();
    expect(agent_q::usb_link_state_observe(false, 1, 5) == Event::initial_observed,
           "clear makes next observation initial again");
    snapshot = agent_q::usb_link_state_snapshot();
    expect(snapshot.known && !snapshot.connected && snapshot.next_poll == 6,
           "initial disconnected observation is stored");

    agent_q::usb_link_state_clear();
    expect(agent_q::usb_link_state_observe(true, 0xFFFFFFF0u, 20) == Event::initial_observed,
           "large initial tick initializes state");
    expect(agent_q::usb_link_state_observe(true, 3, 20) == Event::not_due,
           "deadline comparison stays not-due before wrapped deadline");
    expect(agent_q::usb_link_state_observe(true, 4, 20) == Event::unchanged_connected,
           "deadline comparison is wrap-safe after overflow");

    if (failures != 0) {
        fprintf(stderr, "%d USB link state test(s) failed\n", failures);
        return 1;
    }
    printf("USB link state tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/usb_link_state_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_link_state.cpp" \
  -o "${TMP_DIR}/usb_link_state_test"

"${TMP_DIR}/usb_link_state_test"
