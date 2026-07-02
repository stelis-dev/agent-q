#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
CXX_BIN="${CXX:-c++}"

cat >"${TMP_DIR}/request_line_test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/request_line.h"

using namespace signing;

int main()
{
    char buf[8];
    size_t size = 0;
    bool discarding = false;
    auto feed = [&](char c) { return request_line_feed(c, buf, sizeof(buf), &size, &discarding); };

    // A normal line yields line_ready with the NUL-terminated content; state resets.
    size = 0;
    discarding = false;
    assert(feed('a') == RequestLineFeedResult::none);
    assert(feed('b') == RequestLineFeedResult::none);
    assert(feed('c') == RequestLineFeedResult::none);
    assert(feed('\n') == RequestLineFeedResult::line_ready);
    assert(strcmp(buf, "abc") == 0 && size == 0 && !discarding);

    // An empty line is not delivered.
    assert(feed('\n') == RequestLineFeedResult::none);

    // Carriage returns are ignored.
    assert(feed('a') == RequestLineFeedResult::none);
    assert(feed('\r') == RequestLineFeedResult::none);
    assert(feed('b') == RequestLineFeedResult::none);
    assert(feed('\n') == RequestLineFeedResult::line_ready);
    assert(strcmp(buf, "ab") == 0);

    // A NUL byte rejects the line; the rest is discarded; the next line resyncs cleanly.
    assert(feed('x') == RequestLineFeedResult::none);
    assert(feed('\0') == RequestLineFeedResult::rejected_nul);
    assert(discarding);
    assert(feed('y') == RequestLineFeedResult::none);
    assert(feed('\n') == RequestLineFeedResult::none);
    assert(!discarding);
    assert(feed('o') == RequestLineFeedResult::none);
    assert(feed('k') == RequestLineFeedResult::none);
    assert(feed('\n') == RequestLineFeedResult::line_ready);
    assert(strcmp(buf, "ok") == 0);

    // An over-long line (>= capacity) is rejected and discarded; the next line resyncs.
    for (int i = 0; i < 7; ++i) {
        assert(feed('z') == RequestLineFeedResult::none);
    }
    assert(size == 7);
    assert(feed('z') == RequestLineFeedResult::rejected_too_long);
    assert(discarding);
    assert(feed('z') == RequestLineFeedResult::none);
    assert(feed('\n') == RequestLineFeedResult::none);
    assert(!discarding);
    assert(feed('h') == RequestLineFeedResult::none);
    assert(feed('i') == RequestLineFeedResult::none);
    assert(feed('\n') == RequestLineFeedResult::line_ready);
    assert(strcmp(buf, "hi") == 0);

    printf("request line tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/request_line_test.cpp" \
  "${COMMON_ROOT}/protocol/request_line.cpp" \
  -o "${TMP_DIR}/request_line_test"

"${TMP_DIR}/request_line_test"
