#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_local_settings_touch_entry.sh

Compiles the StackChan CoreS3 local Settings touch-entry state owner against
host stubs and verifies touch start, hold, cancel, clear, and wrap-safe elapsed
behavior. This test uses only a host C++ compiler and does NOT require ESP-IDF.
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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-local-settings-touch-entry.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
H

cat >"${TMP_DIR}/local_settings_touch_entry_test.cpp" <<'CPP'
#include <stdio.h>

#include "agent_q_local_settings_touch_entry.h"

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
    agent_q::local_settings_touch_entry_clear();
    expect(!agent_q::local_settings_touch_entry_active(),
           "clear leaves touch entry inactive");
    expect(!agent_q::local_settings_touch_entry_update(false, 100, 10),
           "outside touch does not trigger entry");
    expect(!agent_q::local_settings_touch_entry_active(),
           "outside touch leaves entry inactive");

    expect(!agent_q::local_settings_touch_entry_update(true, 100, 10),
           "first inside touch arms entry");
    agent_q::AgentQLocalSettingsTouchEntrySnapshot snapshot =
        agent_q::local_settings_touch_entry_snapshot();
    expect(snapshot.active && snapshot.started_at == 100,
           "inside touch stores start tick");
    expect(!agent_q::local_settings_touch_entry_update(true, 109, 10),
           "hold below threshold does not trigger entry");
    expect(agent_q::local_settings_touch_entry_active(),
           "below-threshold hold remains active");

    expect(!agent_q::local_settings_touch_entry_update(false, 110, 10),
           "leaving corner cancels entry");
    expect(!agent_q::local_settings_touch_entry_active(),
           "leaving corner clears state");

    expect(!agent_q::local_settings_touch_entry_update(true, 200, 10),
           "second inside touch arms entry");
    expect(agent_q::local_settings_touch_entry_update(true, 210, 10),
           "hold threshold triggers entry");
    expect(!agent_q::local_settings_touch_entry_active(),
           "trigger clears entry state");
    expect(!agent_q::local_settings_touch_entry_update(true, 210, 10),
           "post-trigger same tick starts a new hold instead of retriggering");
    expect(agent_q::local_settings_touch_entry_active(),
           "post-trigger touch is a new active hold");

    agent_q::local_settings_touch_entry_clear();
    expect(!agent_q::local_settings_touch_entry_update(true, 0xfffffff0u, 5),
           "wrapped-tick scenario arms entry");
    expect(agent_q::local_settings_touch_entry_update(true, 0xfffffff5u, 5),
           "elapsed calculation handles unsigned tick values");

    agent_q::local_settings_touch_entry_clear();
    expect(!agent_q::local_settings_touch_entry_update(true, 300, 0),
           "zero hold first touch arms entry");
    expect(agent_q::local_settings_touch_entry_update(true, 300, 0),
           "zero hold triggers on the next observed inside touch");

    if (failures != 0) {
        fprintf(stderr, "%d local settings touch-entry test(s) failed\n", failures);
        return 1;
    }
    printf("Local settings touch-entry tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/local_settings_touch_entry_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_settings_touch_entry.cpp" \
  -o "${TMP_DIR}/local_settings_touch_entry_test"

"${TMP_DIR}/local_settings_touch_entry_test"
