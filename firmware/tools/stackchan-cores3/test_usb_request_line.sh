#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_Q_DIR="${SCRIPT_DIR}/../../src/stackchan-cores3/agent_q"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
CXX_BIN="${CXX:-c++}"

cat >"${TMP_DIR}/usb_request_line_test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_usb_request_line.h"

using namespace agent_q;

int main()
{
    char buf[8];
    size_t size = 0;
    bool discarding = false;
    auto feed = [&](char c) { return usb_request_line_feed(c, buf, sizeof(buf), &size, &discarding); };

    // A normal line yields line_ready with the NUL-terminated content; state resets.
    size = 0;
    discarding = false;
    assert(feed('a') == AgentQUsbLineFeedResult::none);
    assert(feed('b') == AgentQUsbLineFeedResult::none);
    assert(feed('c') == AgentQUsbLineFeedResult::none);
    assert(feed('\n') == AgentQUsbLineFeedResult::line_ready);
    assert(strcmp(buf, "abc") == 0 && size == 0 && !discarding);

    // An empty line is not delivered.
    assert(feed('\n') == AgentQUsbLineFeedResult::none);

    // Carriage returns are ignored.
    assert(feed('a') == AgentQUsbLineFeedResult::none);
    assert(feed('\r') == AgentQUsbLineFeedResult::none);
    assert(feed('b') == AgentQUsbLineFeedResult::none);
    assert(feed('\n') == AgentQUsbLineFeedResult::line_ready);
    assert(strcmp(buf, "ab") == 0);

    // A NUL byte rejects the line; the rest is discarded; the next line resyncs cleanly.
    assert(feed('x') == AgentQUsbLineFeedResult::none);
    assert(feed('\0') == AgentQUsbLineFeedResult::rejected_nul);
    assert(discarding);
    assert(feed('y') == AgentQUsbLineFeedResult::none);
    assert(feed('\n') == AgentQUsbLineFeedResult::none);
    assert(!discarding);
    assert(feed('o') == AgentQUsbLineFeedResult::none);
    assert(feed('k') == AgentQUsbLineFeedResult::none);
    assert(feed('\n') == AgentQUsbLineFeedResult::line_ready);
    assert(strcmp(buf, "ok") == 0);

    // An over-long line (>= capacity) is rejected and discarded; the next line resyncs.
    for (int i = 0; i < 7; ++i) {
        assert(feed('z') == AgentQUsbLineFeedResult::none);
    }
    assert(size == 7);
    assert(feed('z') == AgentQUsbLineFeedResult::rejected_too_long);
    assert(discarding);
    assert(feed('z') == AgentQUsbLineFeedResult::none);
    assert(feed('\n') == AgentQUsbLineFeedResult::none);
    assert(!discarding);
    assert(feed('h') == AgentQUsbLineFeedResult::none);
    assert(feed('i') == AgentQUsbLineFeedResult::none);
    assert(feed('\n') == AgentQUsbLineFeedResult::line_ready);
    assert(strcmp(buf, "hi") == 0);

    printf("USB request line tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/usb_request_line_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_request_line.cpp" \
  -o "${TMP_DIR}/usb_request_line_test"

"${TMP_DIR}/usb_request_line_test"
