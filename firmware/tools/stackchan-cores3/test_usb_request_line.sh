#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="${SCRIPT_DIR}/../../src/stackchan-cores3/runtime"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
CXX_BIN="${CXX:-c++}"

cat >"${TMP_DIR}/usb_request_line_test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "usb_request_line.h"

using namespace signing;

int main()
{
    char buf[8];
    size_t size = 0;
    bool discarding = false;
    auto feed = [&](char c) { return usb_request_line_feed(c, buf, sizeof(buf), &size, &discarding); };

    // A normal line yields line_ready with the NUL-terminated content; state resets.
    size = 0;
    discarding = false;
    assert(feed('a') == UsbLineFeedResult::none);
    assert(feed('b') == UsbLineFeedResult::none);
    assert(feed('c') == UsbLineFeedResult::none);
    assert(feed('\n') == UsbLineFeedResult::line_ready);
    assert(strcmp(buf, "abc") == 0 && size == 0 && !discarding);

    // An empty line is not delivered.
    assert(feed('\n') == UsbLineFeedResult::none);

    // Carriage returns are ignored.
    assert(feed('a') == UsbLineFeedResult::none);
    assert(feed('\r') == UsbLineFeedResult::none);
    assert(feed('b') == UsbLineFeedResult::none);
    assert(feed('\n') == UsbLineFeedResult::line_ready);
    assert(strcmp(buf, "ab") == 0);

    // A NUL byte rejects the line; the rest is discarded; the next line resyncs cleanly.
    assert(feed('x') == UsbLineFeedResult::none);
    assert(feed('\0') == UsbLineFeedResult::rejected_nul);
    assert(discarding);
    assert(feed('y') == UsbLineFeedResult::none);
    assert(feed('\n') == UsbLineFeedResult::none);
    assert(!discarding);
    assert(feed('o') == UsbLineFeedResult::none);
    assert(feed('k') == UsbLineFeedResult::none);
    assert(feed('\n') == UsbLineFeedResult::line_ready);
    assert(strcmp(buf, "ok") == 0);

    // An over-long line (>= capacity) is rejected and discarded; the next line resyncs.
    for (int i = 0; i < 7; ++i) {
        assert(feed('z') == UsbLineFeedResult::none);
    }
    assert(size == 7);
    assert(feed('z') == UsbLineFeedResult::rejected_too_long);
    assert(discarding);
    assert(feed('z') == UsbLineFeedResult::none);
    assert(feed('\n') == UsbLineFeedResult::none);
    assert(!discarding);
    assert(feed('h') == UsbLineFeedResult::none);
    assert(feed('i') == UsbLineFeedResult::none);
    assert(feed('\n') == UsbLineFeedResult::line_ready);
    assert(strcmp(buf, "hi") == 0);

    printf("USB request line tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/usb_request_line_test.cpp" \
  "${RUNTIME_DIR}/usb_request_line.cpp" \
  -o "${TMP_DIR}/usb_request_line_test"

"${TMP_DIR}/usb_request_line_test"
