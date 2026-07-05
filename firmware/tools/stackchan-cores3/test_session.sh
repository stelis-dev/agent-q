#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_session.sh

Compiles the StackChan CoreS3 Firmware session core against host stubs and
verifies session id generation, validation, mismatch handling, and link-bound
session lifetime. This test uses only a host C++ compiler and does NOT require
ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-session.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/session_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "session.h"

namespace {

int failures = 0;
bool g_rng_fails = false;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

bool random_bytes(void* output, size_t size, void*)
{
    if (g_rng_fails || output == nullptr) {
        return false;
    }
    unsigned char* bytes = static_cast<unsigned char*>(output);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = static_cast<unsigned char>(index + 1);
    }
    return true;
}

}  // namespace

namespace signing {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

}  // namespace signing

int main()
{
    using Result = signing::SessionValidationResult;

    signing::session_init();
    expect(!signing::session_active(), "session init clears session");
    expect(signing::kSessionAdvertisedTtlMs == 0xffffffffu,
           "link-bound target advertises maximum session ttl");
    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "session replace succeeds with random bytes");
    char id[signing::kSessionIdSize] = {};
    snprintf(id, sizeof(id), "%s", signing::session_id());
    expect(strcmp(id, "session_0102030405060708") == 0,
           "session id is generated from random bytes");
    expect(signing::session_id_format_valid(id),
           "generated session id satisfies public format helper");
    expect(!signing::session_id_format_valid("x"),
           "format helper rejects wrong prefix");
    expect(!signing::session_id_format_valid("session_AAAAAAAAAAAAAAAA"),
           "format helper rejects uppercase hex");
    expect(!signing::session_id_format_valid("session_"),
           "format helper rejects empty suffix");
    expect(!signing::session_id_format_valid(
               "session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
           "format helper rejects ids beyond the current session buffer");
    expect(!signing::session_id_format_valid(
               "session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
           "format helper rejects previously proposed 128-hex ids");
    expect(!signing::session_id_format_valid(
               "session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
           "format helper rejects ids beyond the public maximum");
    expect(signing::session_validate(id) == Result::ok,
           "matching session validates");
    expect(signing::session_validate("not-a-session") == Result::invalid_format,
           "invalid session format is rejected distinctly");
    expect(signing::session_validate("session_aaaaaaaaaaaaaaaa") == Result::mismatch,
           "mismatched session is rejected without clearing active session");
    expect(signing::session_validate("session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == Result::invalid_format,
           "overlong mismatched sessions are rejected before active-session comparison");
    expect(signing::session_active(), "mismatch does not clear session");
    signing::session_clear();
    expect(!signing::session_active(), "explicit clear ends session");
    expect(signing::session_validate(id) == Result::missing,
           "cleared session rejects previous id");

    signing::session_init();
    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "second session starts");
    expect(signing::session_active(), "session remains active until explicit cleanup");

    signing::session_init();
    g_rng_fails = true;
    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::rng_error,
           "rng failure is reported without creating session");
    expect(!signing::session_active(), "rng failure leaves session inactive");

    if (failures != 0) {
        fprintf(stderr, "%d session test(s) failed\n", failures);
        return 1;
    }
    printf("Session tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/session_test.cpp" \
  "${RUNTIME_DIR}/session.cpp" \
  -o "${TMP_DIR}/session_test"

"${TMP_DIR}/session_test"
