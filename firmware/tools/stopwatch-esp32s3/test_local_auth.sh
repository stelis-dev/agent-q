#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stopwatch-esp32s3/test_local_auth.sh

Compiles the StopWatch target-local local-authentication verifier and persistent
lock state with host test storage. This test uses only a host C++ compiler and
does not require ESP-IDF or hardware.
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
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-local-auth.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "local_auth.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void expect_status(stopwatch_target::LocalAuthStoreStatus actual, stopwatch_target::LocalAuthStoreStatus expected, const char* label)
{
    expect(actual == expected, label);
}

void expect_verify(stopwatch_target::LocalAuthVerifyResult actual, stopwatch_target::LocalAuthVerifyResult expected, const char* label)
{
    expect(actual == expected, label);
}

}  // namespace

int main()
{
    using namespace stopwatch_target;

    local_auth_test_reset_store();
    local_auth_init(0);
    expect_status(local_auth_snapshot(0).status, LocalAuthStoreStatus::missing, "missing store starts missing");
    expect(local_auth_test_read_count() == 1, "init reads missing store once");
    local_auth_snapshot(1);
    local_auth_snapshot(2);
    expect(local_auth_test_read_count() == 1, "missing snapshot is cached without repeated storage reads");

    expect(!local_auth_code_shape_valid("", 0), "rejects empty code");
    expect(!local_auth_code_shape_valid("12345", 5), "rejects too long");
    expect(!local_auth_code_shape_valid("12a4", 4), "rejects non-digit");
    expect(local_auth_code_shape_valid("1", 1), "accepts one-digit code");
    expect(local_auth_code_shape_valid("119", 3), "accepts short code");
    expect(local_auth_code_shape_valid("1111", 4), "accepts repeated four-digit code");
    expect(local_auth_code_shape_valid("1234", 4), "accepts four-digit code");

    expect(local_auth_store_new_code("119", 3), "stores short accepted code");
    LocalAuthSnapshot snapshot = local_auth_snapshot(1000);
    expect_status(snapshot.status, LocalAuthStoreStatus::active, "stored record active");
    expect(snapshot.code_length == 3, "stored length is 3");
    expect(!snapshot.locked, "new record unlocked");
    expect(!local_auth_test_record_contains("119"), "raw code not stored");
    const uint32_t reads_after_store = local_auth_test_read_count();
    local_auth_snapshot(1001);
    local_auth_snapshot(1002);
    expect(local_auth_test_read_count() == reads_after_store, "active snapshot is cached without repeated storage reads");

    for (int attempt = 1; attempt <= 4; ++attempt) {
        expect_verify(
            local_auth_verify_code("000", 3, 1000 + attempt),
            LocalAuthVerifyResult::rejected,
            "first four wrong attempts reject without lock");
    }
    expect_verify(local_auth_verify_code("000", 3, 2000), LocalAuthVerifyResult::locked, "fifth wrong attempt locks");
    snapshot = local_auth_snapshot(2000);
    expect(snapshot.locked, "snapshot reports lock");
    expect(snapshot.failed_attempts == 5, "failed attempts persisted");
    expect(snapshot.lock_tier == 1, "first lock tier persisted");
    expect(snapshot.lock_remaining_ms == 5ULL * 60ULL * 1000ULL, "first lock duration is 5 minutes");

    expect_verify(local_auth_verify_code("119", 3, 10000), LocalAuthVerifyResult::locked, "correct code blocked during lock");
    expect(local_auth_snapshot(0).locked, "power-cycle-style low monotonic time does not clear lock");
    local_auth_init(0);
    snapshot = local_auth_snapshot(0);
    expect(snapshot.locked, "boot re-anchors persistent lock");
    expect(snapshot.lock_remaining_ms == 5ULL * 60ULL * 1000ULL, "boot re-anchor uses tier duration");

    expect_verify(local_auth_verify_code("119", 3, 302001), LocalAuthVerifyResult::verified, "correct code verifies after lock deadline");
    snapshot = local_auth_snapshot(302001);
    expect(!snapshot.locked, "correct code clears lock");
    expect(snapshot.failed_attempts == 0, "correct code clears failed attempts");
    expect(snapshot.lock_tier == 0, "correct code clears lock tier");

    local_auth_test_reset_store();
    expect(local_auth_store_new_code("119", 3), "stores code for high-uptime lock re-anchor");
    const uint64_t high_uptime_ms = 7ULL * 60ULL * 60ULL * 1000ULL;
    for (int attempt = 1; attempt <= 5; ++attempt) {
        local_auth_verify_code("000", 3, high_uptime_ms + static_cast<uint64_t>(attempt));
    }
    snapshot = local_auth_snapshot(high_uptime_ms + 5);
    expect(snapshot.locked, "high-uptime lock is active");
    expect(snapshot.lock_remaining_ms == 5ULL * 60ULL * 1000ULL, "high-uptime lock starts with tier duration");
    local_auth_init(0);
    snapshot = local_auth_snapshot(0);
    expect(snapshot.locked, "restart keeps high-uptime lock active");
    expect(snapshot.lock_remaining_ms == 5ULL * 60ULL * 1000ULL, "restart does not preserve stale high-uptime deadline");
    expect_verify(local_auth_verify_code("119", 3, 299999), LocalAuthVerifyResult::locked, "re-anchored lock blocks before full duration");
    expect_verify(local_auth_verify_code("119", 3, 300001), LocalAuthVerifyResult::verified, "re-anchored lock releases after full powered uptime");

    local_auth_test_reset_store();
    expect(local_auth_store_new_code("119", 3), "stores code for tier accumulation");
    for (int attempt = 1; attempt <= 10; ++attempt) {
        const uint64_t now = 400000ULL + static_cast<uint64_t>(attempt) * 31ULL * 60ULL * 1000ULL;
        local_auth_verify_code("111", 3, now);
    }
    snapshot = local_auth_snapshot(400000ULL + 10ULL * 31ULL * 60ULL * 1000ULL);
    expect(snapshot.failed_attempts == 10, "failed attempts accumulate across released locks");
    expect(snapshot.lock_tier == 2, "tenth failure reaches 30-minute tier");
    expect(snapshot.lock_remaining_ms == 30ULL * 60ULL * 1000ULL, "second tier lock duration is 30 minutes");

    local_auth_test_set_write_failure(true);
    snapshot = local_auth_snapshot(400000ULL + 10ULL * 31ULL * 60ULL * 1000ULL + 31ULL * 60ULL * 1000ULL);
    expect_status(snapshot.status, LocalAuthStoreStatus::storage_error, "expired lock cleanup failure is storage error");
    expect_verify(
        local_auth_verify_code("119", 3, 400000ULL + 10ULL * 31ULL * 60ULL * 1000ULL + 31ULL * 60ULL * 1000ULL),
        LocalAuthVerifyResult::storage_error,
        "expired lock cleanup failure blocks verification");
    local_auth_test_set_write_failure(false);

    local_auth_test_corrupt_record();
    expect_status(local_auth_snapshot(0).status, LocalAuthStoreStatus::invalid, "corrupt record is invalid");
    expect_verify(local_auth_verify_code("119", 3, 0), LocalAuthVerifyResult::invalid, "corrupt record fails closed");

    local_auth_test_reset_store();
    expect(local_auth_store_new_code("1234", 4), "stores replacement code");
    local_auth_test_set_write_failure(true);
    expect_verify(local_auth_verify_code("1234", 4, 0), LocalAuthVerifyResult::storage_error, "verified code does not unlock if persistence fails");
    local_auth_test_set_write_failure(false);
    expect(local_auth_clear(), "clear succeeds");
    expect_status(local_auth_snapshot(0).status, LocalAuthStoreStatus::missing, "clear removes record");

    if (failures != 0) {
        fprintf(stderr, "StopWatch local auth tests failed: %d\n", failures);
        return 1;
    }

    printf("StopWatch local auth tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -DSTOPWATCH_LOCAL_AUTH_HOST_TEST \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/local_auth.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  -o "${TMP_DIR}/test_local_auth"

"${TMP_DIR}/test_local_auth"
