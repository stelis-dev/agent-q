#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_identification_display.sh

Compiles the StackChan CoreS3 temporary identification display state owner
against host stubs and verifies active/deadline/clear behavior. This test uses
only a host C++ compiler and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-identification-display.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
H

cat >"${TMP_DIR}/identification_display_test.cpp" <<'CPP'
#include <stdio.h>

#include "identification_display.h"

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
    signing::identification_display_clear();
    expect(!signing::identification_display_active(), "clear leaves state inactive");
    expect(!signing::identification_display_deadline_reached(1),
           "inactive state has no reached deadline");

    signing::identification_display_begin(100);
    signing::IdentificationDisplaySnapshot snapshot =
        signing::identification_display_snapshot();
    expect(snapshot.active, "begin activates state");
    expect(snapshot.deadline == 100, "begin stores deadline");
    expect(!signing::identification_display_deadline_reached(99),
           "deadline is not reached before deadline");
    expect(signing::identification_display_deadline_reached(100),
           "deadline is reached at deadline");
    expect(signing::identification_display_deadline_reached(101),
           "deadline stays reached after deadline");

    signing::identification_display_begin(250);
    snapshot = signing::identification_display_snapshot();
    expect(snapshot.active && snapshot.deadline == 250,
           "begin overwrites temporary identification display state");
    expect(!signing::identification_display_deadline_reached(100),
           "overwritten deadline is used");

    signing::identification_display_clear();
    expect(!signing::identification_display_active(), "final clear leaves state inactive");

    signing::identification_display_begin(0);
    expect(signing::identification_display_active(), "zero deadline can still mark display active");
    expect(signing::identification_display_deadline_reached(0),
           "zero deadline is a valid reached tick value");

    if (failures != 0) {
        fprintf(stderr, "%d identification display test(s) failed\n", failures);
        return 1;
    }
    printf("Identification display tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/identification_display_test.cpp" \
  "${RUNTIME_DIR}/identification_display.cpp" \
  -o "${TMP_DIR}/identification_display_test"

"${TMP_DIR}/identification_display_test"
