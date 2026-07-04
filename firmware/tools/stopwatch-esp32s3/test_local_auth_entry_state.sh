#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stopwatch-esp32s3/test_local_auth_entry_state.sh

Compiles the StopWatch target-local volatile local-authentication entry state
with a host C++ compiler. This test does not require ESP-IDF or hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime"

for required in \
  "${RUNTIME_DIR}/local_auth.cpp" \
  "${RUNTIME_DIR}/local_auth.h" \
  "${RUNTIME_DIR}/local_auth_entry_state.cpp" \
  "${RUNTIME_DIR}/local_auth_entry_state.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-local-auth-entry.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "local_auth_entry_state.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void expect_text(const char* actual, const char* expected, const char* label)
{
    expect(actual != nullptr && strcmp(actual, expected) == 0, label);
}

}  // namespace

int main()
{
    using namespace stopwatch_target;

    LocalAuthEntryState entry;
    expect(entry.length() == 0, "starts empty");
    expect(!entry.timed_out(1000), "empty entry cannot time out");
    expect(entry.append('1', 1000), "appends first digit");
    expect_text(entry.code(), "1", "code stores digit");
    expect(entry.length() == 1, "length increments");
    expect(entry.digit_at(0) == '1', "digit_at returns digit");
    expect(entry.digit_visible(0, 1000), "captured digit starts visible");
    expect(entry.digit_visible(0, 1849), "captured digit remains visible before deadline");
    expect(!entry.digit_visible(0, 1850), "captured digit hides at deadline");
    expect(!entry.timed_out(999), "same-loop stale timestamp cannot underflow into timeout");
    expect(!entry.timed_out(30999), "input waits below timeout");
    expect(entry.timed_out(31000), "input times out at timeout");

    expect(entry.append('2', 1100), "appends second digit");
    expect(entry.append('3', 1200), "appends third digit");
    expect(entry.append('4', 1300), "appends fourth digit");
    expect(!entry.append('5', 1400), "rejects fifth digit");
    expect_text(entry.code(), "1234", "max-length code is stable");
    expect(!entry.append('x', 1400), "rejects non-digit");

    expect(entry.delete_last(1500), "delete removes one digit");
    expect_text(entry.code(), "123", "delete updates code");
    expect(entry.length() == 3, "delete updates length");
    entry.clear();
    expect(entry.length() == 0, "clear resets length");
    expect_text(entry.code(), "", "clear wipes visible code string");
    expect(!entry.timed_out(999999), "cleared entry cannot time out");

    if (failures != 0) {
        fprintf(stderr, "StopWatch local auth entry state tests failed: %d\n", failures);
        return 1;
    }

    printf("StopWatch local auth entry state tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -DSTOPWATCH_LOCAL_AUTH_HOST_TEST \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/local_auth.cpp" \
  "${RUNTIME_DIR}/local_auth_entry_state.cpp" \
  -o "${TMP_DIR}/test_local_auth_entry_state"

"${TMP_DIR}/test_local_auth_entry_state"
