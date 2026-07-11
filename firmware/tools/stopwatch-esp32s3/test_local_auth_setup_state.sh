#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stopwatch-esp32s3/test_local_auth_setup_state.sh

Compiles the StopWatch target-local setup-confirm scratch state with a host C++
compiler. This test does not require ESP-IDF or hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime"
COMMON_DIR="${REPO_ROOT}/firmware/src/common"

for required in \
  "${RUNTIME_DIR}/local_auth.h" \
  "${RUNTIME_DIR}/local_auth_setup_state.cpp" \
  "${RUNTIME_DIR}/local_auth_setup_state.h" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-local-auth-setup.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <stdio.h>

#include "local_auth_setup_state.h"

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
    using namespace stopwatch_target;

    LocalAuthSetupState setup;
    expect(setup.length() == 0, "starts empty");
    expect(!setup.matches("1", 1), "empty setup cannot match");
    expect(!setup.set_first_entry("", 0), "rejects empty first entry");
    expect(!setup.set_first_entry("12345", 5), "rejects five-digit first entry");
    expect(setup.set_first_entry("1", 1), "stores one-digit first entry");
    expect(setup.length() == 1, "stores one-digit length");
    expect(setup.contains_for_test("1"), "test seam observes first entry before clear");
    expect(setup.matches("1", 1), "matching one-digit second entry accepted");
    expect(!setup.matches("2", 1), "different one-digit second entry rejected");
    setup.clear();
    expect(setup.length() == 0, "clear resets first length");
    expect(!setup.contains_for_test("1"), "clear wipes first entry bytes");
    expect(!setup.matches("1", 1), "cleared setup cannot match old entry");
    expect(setup.set_first_entry("1234", 4), "stores four-digit first entry");
    expect(setup.matches("1234", 4), "matching four-digit second entry accepted");

    if (failures != 0) {
        fprintf(stderr, "StopWatch local auth setup state tests failed: %d\n", failures);
        return 1;
    }

    printf("StopWatch local auth setup state tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -DSTOPWATCH_LOCAL_AUTH_HOST_TEST \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/local_auth_setup_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  -o "${TMP_DIR}/test_local_auth_setup_state"

"${TMP_DIR}/test_local_auth_setup_state"
