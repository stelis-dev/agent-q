#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stopwatch-esp32s3/test_state_projection.sh

Compiles the StopWatch target-local status projection rules with a host C++
compiler. This test uses only pure state projection code and does not require
ESP-IDF or hardware.
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
  "${RUNTIME_DIR}/state_projection.cpp" \
  "${RUNTIME_DIR}/state_projection.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-state-projection.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "state_projection.h"

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

    expect_text(
        stopwatch_device_state(StateProjectionInput{
            LocalAuthProjectionStatus::missing,
            CredentialProjectionStatus::missing,
            false,
            false,
        }),
        "idle",
        "first-run setup waits as idle");
    expect_text(
        stopwatch_provisioning_state(StateProjectionInput{
            LocalAuthProjectionStatus::missing,
            CredentialProjectionStatus::missing,
            false,
            false,
        }),
        "unprovisioned",
        "missing local auth is externally unprovisioned");
    expect_text(
        stopwatch_device_state(StateProjectionInput{
            LocalAuthProjectionStatus::active,
            CredentialProjectionStatus::missing,
            false,
            false,
        }),
        "locked",
        "configured auth without volatile unlock is locked");
    expect_text(
        stopwatch_device_state(StateProjectionInput{
            LocalAuthProjectionStatus::active,
            CredentialProjectionStatus::missing,
            true,
            false,
        }),
        "idle",
        "configured auth with volatile unlock and no pending work is idle");
    expect_text(
        stopwatch_device_state(StateProjectionInput{
            LocalAuthProjectionStatus::locked,
            CredentialProjectionStatus::active,
            true,
            true,
        }),
        "locked",
        "time lock has priority over busy UI");
    expect_text(
        stopwatch_provisioning_state(StateProjectionInput{
            LocalAuthProjectionStatus::locked,
            CredentialProjectionStatus::active,
            false,
            false,
        }),
        "provisioned",
        "active proof remains externally provisioned while locked");
    expect_text(
        stopwatch_device_state(StateProjectionInput{
            LocalAuthProjectionStatus::active,
            CredentialProjectionStatus::missing,
            true,
            true,
        }),
        "busy",
        "explicit processing projects busy");
    expect_text(
        stopwatch_device_state(StateProjectionInput{
            LocalAuthProjectionStatus::active,
            CredentialProjectionStatus::storage_error,
            true,
            false,
        }),
        "error",
        "credential storage error projects device error");
    expect_text(
        stopwatch_provisioning_state(StateProjectionInput{
            LocalAuthProjectionStatus::active,
            CredentialProjectionStatus::invalid,
            true,
            false,
        }),
        "error",
        "credential invalid record projects provisioning error");
    expect_text(
        stopwatch_device_state(StateProjectionInput{
            LocalAuthProjectionStatus::invalid,
            CredentialProjectionStatus::missing,
            true,
            true,
        }),
        "error",
        "invalid local auth record projects error");
    expect_text(
        stopwatch_provisioning_state(StateProjectionInput{
            LocalAuthProjectionStatus::storage_error,
            CredentialProjectionStatus::missing,
            true,
            false,
        }),
        "error",
        "storage error projects provisioning error");
    if (failures != 0) {
        fprintf(stderr, "StopWatch state projection tests failed: %d\n", failures);
        return 1;
    }

    printf("StopWatch state projection tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/state_projection.cpp" \
  -o "${TMP_DIR}/test_state_projection"

"${TMP_DIR}/test_state_projection"
