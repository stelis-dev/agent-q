#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-session-state.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

CXX_BIN="${CXX:-c++}"

cat >"${TMP_DIR}/session_state_test.cpp" <<'CPP'
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "session_state.h"

using namespace stopwatch_target;

namespace {

bool fill_counter_random(void* output, size_t size, void* context)
{
    uint8_t* cursor = static_cast<uint8_t*>(output);
    uint8_t* value = static_cast<uint8_t*>(context);
    if (cursor == nullptr || value == nullptr) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        cursor[index] = static_cast<uint8_t>((*value)++);
    }
    return true;
}

bool failing_random(void*, size_t, void*)
{
    return false;
}

}  // namespace

int main()
{
    session_state_init();
    assert(!session_state_active());
    assert(strcmp(session_state_id(), "") == 0);

    assert(!session_id_format_valid(nullptr));
    assert(!session_id_format_valid(""));
    assert(!session_id_format_valid("not_session_0000000000000000"));
    assert(!session_id_format_valid("session_"));
    assert(session_id_format_valid("session_0"));
    assert(session_id_format_valid("session_000102030405060"));
    assert(!session_id_format_valid("session_000000000000000g"));
    assert(session_id_format_valid("session_00010203040506070"));
    assert(!session_id_format_valid("session_00000000000000000000000000000000"));
    assert(!session_id_format_valid("session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert(!session_id_format_valid("session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert(session_id_format_valid("session_0001020304050607"));

    assert(session_state_validate("session_0001020304050607") == SessionValidationResult::missing);

    uint8_t counter = 0;
    assert(session_state_replace(fill_counter_random, &counter) == SessionStartResult::ok);
    assert(session_state_active());
    assert(strcmp(session_state_id(), "session_0001020304050607") == 0);
    assert(session_state_validate("bad") == SessionValidationResult::invalid_format);
    assert(session_state_validate("session_08090a0b0c0d0e0f") == SessionValidationResult::mismatch);
    assert(session_state_validate("session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == SessionValidationResult::invalid_format);
    assert(session_state_validate("session_0001020304050607") == SessionValidationResult::ok);

    assert(session_state_replace(fill_counter_random, &counter) == SessionStartResult::ok);
    assert(strcmp(session_state_id(), "session_08090a0b0c0d0e0f") == 0);
    assert(session_state_validate("session_0001020304050607") == SessionValidationResult::mismatch);
    assert(session_state_validate("session_08090a0b0c0d0e0f") == SessionValidationResult::ok);

    session_state_clear();
    assert(!session_state_active());
    assert(session_state_replace(failing_random, nullptr) == SessionStartResult::rng_error);
    assert(!session_state_active());

    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/session_state_test.cpp" \
  "${RUNTIME_DIR}/session_state.cpp" \
  -o "${TMP_DIR}/session_state_test"

"${TMP_DIR}/session_state_test"
echo "StopWatch session state tests passed"
