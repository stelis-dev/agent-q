#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stopwatch-esp32s3/test_local_auth.sh

Compiles the StopWatch target-local non-secret lockout metadata state with host
test storage. Common encrypted-keystore tests own PIN KDF and record crypto.
This test uses only a host C++ compiler and does not require ESP-IDF or hardware.
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
  "${RUNTIME_DIR}/local_auth.cpp" \
  "${RUNTIME_DIR}/local_auth.h" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.h" \
  "${RUNTIME_DIR}/stopwatch_keystore.h" \
  "${COMMON_DIR}/keystore/encrypted_keystore.h"; do
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

#include "local_auth.h"
#include "stopwatch_keystore.h"

namespace stopwatch_target {

signing::KeystoreState g_test_keystore_state = signing::KeystoreState::absent;
uint32_t g_test_keystore_lock_count = 0;

signing::KeystoreState stopwatch_keystore_state()
{
    return g_test_keystore_state;
}

signing::KeystoreOperationStatus stopwatch_keystore_lock()
{
    ++g_test_keystore_lock_count;
    if (g_test_keystore_state != signing::KeystoreState::absent &&
        g_test_keystore_state != signing::KeystoreState::invalid &&
        g_test_keystore_state != signing::KeystoreState::storage_error) {
        g_test_keystore_state = signing::KeystoreState::locked;
    }
    return signing::KeystoreOperationStatus::success;
}

}  // namespace stopwatch_target

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void expect_status(
    stopwatch_target::LocalAuthStoreStatus actual,
    stopwatch_target::LocalAuthStoreStatus expected,
    const char* label)
{
    expect(actual == expected, label);
}

void expect_verify(
    stopwatch_target::LocalAuthVerifyResult actual,
    stopwatch_target::LocalAuthVerifyResult expected,
    const char* label)
{
    expect(actual == expected, label);
}

void set_keystore_state(signing::KeystoreState state)
{
    stopwatch_target::g_test_keystore_state = state;
}

}  // namespace

int main()
{
    using namespace signing;
    using namespace stopwatch_target;

    local_auth_test_reset_store();
    set_keystore_state(KeystoreState::absent);
    local_auth_init(0);
    expect_status(
        local_auth_snapshot(0).status,
        LocalAuthStoreStatus::missing,
        "absent keyslot and metadata start missing");
    expect(local_auth_test_read_count() == 1, "init reads missing metadata once");
    local_auth_snapshot(1);
    local_auth_snapshot(2);
    expect(
        local_auth_test_read_count() == 1,
        "missing metadata projection is cached");

    expect(!local_auth_code_shape_valid("", 0), "rejects empty PIN");
    expect(!local_auth_code_shape_valid("12345", 5), "rejects five digits");
    expect(!local_auth_code_shape_valid("12a4", 4), "rejects non-digit PIN");
    expect(
        !local_auth_code_shape_valid("12345", 4),
        "rejects a non-terminated four-byte prefix");
    expect(local_auth_code_shape_valid("1", 1), "accepts one digit");
    expect(local_auth_code_shape_valid("12", 2), "accepts two digits");
    expect(local_auth_code_shape_valid("123", 3), "accepts three digits");
    expect(local_auth_code_shape_valid("1234", 4), "accepts four digits");

    set_keystore_state(KeystoreState::unlocked);
    expect(local_auth_store_initial_metadata(), "stores initial non-secret metadata");
    LocalAuthSnapshot snapshot = local_auth_snapshot(1000);
    expect_status(snapshot.status, LocalAuthStoreStatus::active, "complete setup is active");
    expect(!snapshot.locked, "new metadata is not locked");
    expect(snapshot.failed_attempts == 0, "new metadata has no failed attempts");
    const uint32_t reads_after_store = local_auth_test_read_count();
    local_auth_snapshot(1001);
    local_auth_snapshot(1002);
    expect(
        local_auth_test_read_count() == reads_after_store,
        "active metadata projection is cached");

    for (int attempt = 1; attempt <= 4; ++attempt) {
        set_keystore_state(KeystoreState::unlocked);
        expect_verify(
            local_auth_record_keystore_result(
                KeystoreOperationStatus::wrong_pin,
                1000 + static_cast<uint64_t>(attempt)),
            LocalAuthVerifyResult::rejected,
            "first four wrong PINs reject without lockout");
    }
    set_keystore_state(KeystoreState::unlocked);
    expect_verify(
        local_auth_record_keystore_result(
            KeystoreOperationStatus::wrong_pin,
            2000),
        LocalAuthVerifyResult::locked,
        "fifth wrong PIN starts lockout");
    expect(g_test_keystore_state == KeystoreState::locked, "lockout locks master key");
    snapshot = local_auth_snapshot(2000);
    expect(snapshot.locked, "projection reports lockout");
    expect(snapshot.failed_attempts == 5, "failed attempts persist");
    expect(snapshot.lock_tier == 1, "fifth failure selects first tier");
    expect(
        snapshot.lock_remaining_ms == 5ULL * 60ULL * 1000ULL,
        "first lockout lasts five minutes");

    local_auth_init(0);
    snapshot = local_auth_snapshot(0);
    expect(snapshot.locked, "boot keeps persistent lockout active");
    expect(
        snapshot.lock_remaining_ms == 5ULL * 60ULL * 1000ULL,
        "boot re-anchors full tier duration");

    set_keystore_state(KeystoreState::unlocked);
    expect_verify(
        local_auth_record_keystore_result(
            KeystoreOperationStatus::success,
            300001),
        LocalAuthVerifyResult::verified,
        "successful unlock clears expired lockout");
    snapshot = local_auth_snapshot(300001);
    expect(!snapshot.locked, "success clears lockout projection");
    expect(snapshot.failed_attempts == 0, "success clears failed attempts");
    expect(snapshot.lock_tier == 0, "success clears lock tier");

    local_auth_test_reset_store();
    set_keystore_state(KeystoreState::unlocked);
    expect(local_auth_store_initial_metadata(), "stores metadata for tier accumulation");
    uint64_t now_ms = 400000;
    for (int attempt = 1; attempt <= 10; ++attempt) {
        set_keystore_state(KeystoreState::unlocked);
        const LocalAuthVerifyResult result = local_auth_record_keystore_result(
            KeystoreOperationStatus::wrong_pin,
            now_ms);
        if (attempt < 5) {
            expect_verify(result, LocalAuthVerifyResult::rejected, "non-tier failure rejects");
        } else {
            expect_verify(result, LocalAuthVerifyResult::locked, "tiered failure starts lockout");
            if (attempt < 10) {
                now_ms += 5ULL * 60ULL * 1000ULL + 1;
                set_keystore_state(KeystoreState::locked);
                expect(
                    !local_auth_snapshot(now_ms).locked,
                    "first-tier lockout expires before the next attempt");
            }
        }
        ++now_ms;
    }
    snapshot = local_auth_snapshot(now_ms - 1);
    expect(snapshot.failed_attempts == 10, "failed attempts accumulate across lockout release");
    expect(snapshot.lock_tier == 2, "tenth failure selects second tier");
    expect(
        snapshot.lock_remaining_ms == 30ULL * 60ULL * 1000ULL,
        "second lockout lasts thirty minutes");

    local_auth_test_set_write_failure(true);
    const uint64_t after_second_tier = now_ms + 30ULL * 60ULL * 1000ULL;
    snapshot = local_auth_snapshot(after_second_tier);
    expect_status(
        snapshot.status,
        LocalAuthStoreStatus::storage_error,
        "failed expired-lock cleanup is storage error");
    expect(
        g_test_keystore_state == KeystoreState::locked,
        "storage error never leaves master key unlocked");
    local_auth_test_set_write_failure(false);

    local_auth_test_corrupt_record();
    set_keystore_state(KeystoreState::locked);
    expect_status(
        local_auth_snapshot(0).status,
        LocalAuthStoreStatus::invalid,
        "corrupt current metadata fails closed");

    local_auth_test_reset_store();
    set_keystore_state(KeystoreState::unlocked);
    expect(local_auth_store_initial_metadata(), "stores metadata for persistence failure");
    local_auth_test_set_write_failure(true);
    expect_verify(
        local_auth_record_keystore_result(
            KeystoreOperationStatus::success,
            0),
        LocalAuthVerifyResult::storage_error,
        "successful PIN cannot authorize when metadata commit fails");
    expect(g_test_keystore_state == KeystoreState::locked, "commit failure locks master key");
    local_auth_test_set_write_failure(false);

    expect(local_auth_clear(), "metadata clear succeeds");
    set_keystore_state(KeystoreState::absent);
    expect_status(
        local_auth_snapshot(0).status,
        LocalAuthStoreStatus::missing,
        "clear plus absent keyslot returns to setup");

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
  -I"${COMMON_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/local_auth.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  -o "${TMP_DIR}/test_local_auth"

"${TMP_DIR}/test_local_auth"

WORKER_SOURCE="${RUNTIME_DIR}/local_auth_worker.cpp"
APP_SOURCE="${RUNTIME_DIR}/app.cpp"

cancel_block="$(sed -n '/bool local_auth_worker_cancel(/,/bool local_auth_worker_poll_result(/p' "${WORKER_SOURCE}")"
if ! awk '
  /wipe_sensitive_buffer\(g_pending_pin/ { wipe = NR }
  /g_cancelled_job_id = job_id/ { cancel = NR }
  END { exit !(wipe > 0 && cancel > wipe) }
' <<<"${cancel_block}"; then
  echo "Worker cancellation must wipe queued PIN scratch before recording cancellation" >&2
  exit 1
fi

lock_block="$(sed -n '/void RuntimeApp::lock_local_auth()/,/bool RuntimeApp::unlocked_material_valid()/p' "${APP_SOURCE}")"
if ! grep -Fq 'if (local_auth_job_id_ == 0)' <<<"${lock_block}" ||
   ! grep -Fq 'stopwatch_keystore_lock();' <<<"${lock_block}"; then
  echo "App must defer direct keystore locking while the KDF worker owns a job" >&2
  exit 1
fi

for cancellation_owner in \
  "$(sed -n '/void RuntimeApp::poll_local_auth_worker(/,/void RuntimeApp::relock()/p' "${APP_SOURCE}")" \
  "$(sed -n '/void RuntimeApp::relock()/,/void RuntimeApp::clear_entry()/p' "${APP_SOURCE}")"; do
  if ! awk '
    /local_auth_cancel_requested_ = true/ { intent = NR }
    /local_auth_worker_cancel\(local_auth_job_id_\)/ {
      if (intent > 0 && intent < NR) found = 1
    }
    END { exit !found }
  ' <<<"${cancellation_owner}"; then
    echo "Cancellation owner must record intent before best-effort worker cancellation" >&2
    exit 1
  fi
done
