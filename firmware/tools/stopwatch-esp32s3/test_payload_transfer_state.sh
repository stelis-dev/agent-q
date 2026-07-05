#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-payload-transfer.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

CXX_BIN="${CXX:-c++}"

cat >"${TMP_DIR}/payload_transfer_state_test.cpp" <<'CPP'
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "payload_transfer_state.h"

using namespace stopwatch_target;

namespace {

bool simple_digest(const uint8_t* data, size_t size, char out[kPayloadDigestSize])
{
    if (data == nullptr || out == nullptr) {
        return false;
    }
    uint8_t acc = 0;
    for (size_t index = 0; index < size; ++index) {
        acc = static_cast<uint8_t>(acc + data[index]);
    }
    snprintf(out,
             kPayloadDigestSize,
             "sha256:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             acc, acc, acc, acc, acc, acc, acc, acc,
             acc, acc, acc, acc, acc, acc, acc, acc,
             acc, acc, acc, acc, acc, acc, acc, acc,
             acc, acc, acc, acc, acc, acc, acc, acc);
    return true;
}

bool failing_digest(const uint8_t*, size_t, char[kPayloadDigestSize])
{
    return false;
}

}  // namespace

int main()
{
    payload_transfer_state_init();
    uint32_t now = 1000;
    assert(payload_transfer_snapshot(now).status == PayloadTransferStatus::idle);
    PayloadTransferAdmissionDecision admission =
        payload_transfer_admit_operation(now, PayloadTransferAdmissionOperation::sign_transaction);
    assert(admission.result == PayloadTransferAdmissionResult::ok);
    assert(admission.reason == PayloadTransferAdmissionReason::idle_passthrough);
    admission =
        payload_transfer_admit_operation(now, PayloadTransferAdmissionOperation::payload_transfer_chunk);
    assert(admission.result == PayloadTransferAdmissionResult::unknown_request);
    assert(admission.reason == PayloadTransferAdmissionReason::missing_active_payload);

    PayloadTransferBeginOutput begin = {};
    assert(payload_transfer_begin(now,
               "bad",
               3,
               "sha256:0606060606060606060606060606060606060606060606060606060606060606",
               &begin) == PayloadTransferResult::invalid_session);
    assert(payload_transfer_begin(now,
               "session_0",
               0,
               "sha256:0606060606060606060606060606060606060606060606060606060606060606",
               &begin) == PayloadTransferResult::payload_too_large);
    assert(payload_transfer_begin(now,
               "session_0011223344556677",
               0,
               "sha256:0606060606060606060606060606060606060606060606060606060606060606",
               &begin) == PayloadTransferResult::payload_too_large);
    assert(payload_transfer_begin(now,
               "session_0011223344556677",
               3,
               "not-a-digest",
               &begin) == PayloadTransferResult::invalid_payload_digest);

    assert(payload_transfer_begin(now,
               "session_0011223344556677",
               3,
               "sha256:0606060606060606060606060606060606060606060606060606060606060606",
               &begin) == PayloadTransferResult::ok);
    admission =
        payload_transfer_admit_operation(now, PayloadTransferAdmissionOperation::safe_read);
    assert(admission.result == PayloadTransferAdmissionResult::ok);
    assert(admission.reason == PayloadTransferAdmissionReason::receiving_safe_read);
    admission =
        payload_transfer_admit_operation(now, PayloadTransferAdmissionOperation::sign_transaction);
    assert(admission.result == PayloadTransferAdmissionResult::busy);
    assert(admission.reason == PayloadTransferAdmissionReason::blocked_incomplete_transfer);
    assert(payload_transfer_admission_blocks_sensitive_flow(admission));
    admission =
        payload_transfer_admit_operation(now, PayloadTransferAdmissionOperation::payload_transfer_chunk);
    assert(admission.result == PayloadTransferAdmissionResult::ok);
    assert(admission.reason == PayloadTransferAdmissionReason::receiving_transfer_continue);
    assert(strcmp(begin.transfer_id, "transfer_0000000000000001") == 0);
    assert(begin.received_bytes == 0);
    assert(begin.chunk_max_bytes == kPayloadTransferChunkMaxBytes);
    assert(begin.chunk_max_bytes == 2700);

    const uint8_t first[] = {1, 2};
    size_t received = 0;
    assert(payload_transfer_append_chunk(now,
               "session_8899aabbccddeeff",
               begin.transfer_id,
               0,
               first,
               sizeof(first),
               &received) == PayloadTransferResult::invalid_session);
    assert(payload_transfer_append_chunk(now,
               "session_0011223344556677",
               "not_transfer",
               0,
               first,
               sizeof(first),
               &received) == PayloadTransferResult::invalid_transfer_id);
    assert(payload_transfer_append_chunk(now,
               "session_0011223344556677",
               "transfer_0123456789abcdef01234567",
               0,
               first,
               sizeof(first),
               &received) == PayloadTransferResult::not_found);
    assert(payload_transfer_append_chunk(now,
               "session_0011223344556677",
               begin.transfer_id,
               1,
               first,
               sizeof(first),
               &received) == PayloadTransferResult::offset_mismatch);
    assert(payload_transfer_snapshot(now).status == PayloadTransferStatus::idle);

    assert(payload_transfer_begin(now,
               "session_0011223344556677",
               3,
               "sha256:0606060606060606060606060606060606060606060606060606060606060606",
               &begin) == PayloadTransferResult::ok);
    assert(strcmp(begin.transfer_id, "transfer_0000000000000002") == 0);
    assert(payload_transfer_append_chunk(now,
               "session_0011223344556677",
               begin.transfer_id,
               0,
               first,
               sizeof(first),
               &received) == PayloadTransferResult::ok);
    assert(received == 2);
    const uint8_t second[] = {3};
    assert(payload_transfer_append_chunk(now,
               "session_0011223344556677",
               begin.transfer_id,
               2,
               second,
               sizeof(second),
               &received) == PayloadTransferResult::ok);
    assert(received == 3);

    PayloadTransferFinishOutput finish = {};
    assert(payload_transfer_finish(now,
               "session_0011223344556677",
               begin.transfer_id,
               failing_digest,
               &finish) == PayloadTransferResult::digest_error);
    assert(payload_transfer_snapshot(now).status == PayloadTransferStatus::idle);

    assert(payload_transfer_begin(now,
               "session_0011223344556677",
               3,
               "sha256:0606060606060606060606060606060606060606060606060606060606060606",
               &begin) == PayloadTransferResult::ok);
    assert(payload_transfer_append_chunk(now,
               "session_0011223344556677",
               begin.transfer_id,
               0,
               first,
               sizeof(first),
               &received) == PayloadTransferResult::ok);
    assert(payload_transfer_append_chunk(now,
               "session_0011223344556677",
               begin.transfer_id,
               2,
               second,
               sizeof(second),
               &received) == PayloadTransferResult::ok);
    assert(payload_transfer_finish(now,
               "session_0011223344556677",
               begin.transfer_id,
               simple_digest,
               &finish) == PayloadTransferResult::ok);
    admission =
        payload_transfer_admit_operation(now, PayloadTransferAdmissionOperation::safe_read);
    assert(admission.result == PayloadTransferAdmissionResult::ok);
    assert(admission.reason == PayloadTransferAdmissionReason::finalized_safe_read);
    admission =
        payload_transfer_admit_operation(now, PayloadTransferAdmissionOperation::sign_transaction);
    assert(admission.result == PayloadTransferAdmissionResult::busy);
    assert(admission.reason == PayloadTransferAdmissionReason::blocked_unrelated_sensitive_flow);
    assert(payload_transfer_admission_blocks_sensitive_flow(admission));
    admission =
        payload_transfer_admit_operation(now, PayloadTransferAdmissionOperation::payload_transfer_finish);
    assert(admission.result == PayloadTransferAdmissionResult::busy);
    assert(admission.reason == PayloadTransferAdmissionReason::blocked_pending_finalized_payload);
    admission =
        payload_transfer_admit_operation(now, PayloadTransferAdmissionOperation::payload_transfer_abort);
    assert(admission.result == PayloadTransferAdmissionResult::ok);
    assert(admission.reason == PayloadTransferAdmissionReason::finalized_transfer_abort);
    assert(strcmp(finish.payload_ref, "payload_0000000000000001") == 0);
    assert(finish.size_bytes == 3);
    assert(strcmp(finish.payload_digest, "sha256:0606060606060606060606060606060606060606060606060606060606060606") == 0);

    PayloadTransferView view = {};
    assert(payload_transfer_resolve(now,
               "session_0011223344556677",
               finish.payload_ref,
               &view) == PayloadTransferResult::ok);
    assert(view.size_bytes == 3);
    assert(view.bytes[0] == 1 && view.bytes[1] == 2 && view.bytes[2] == 3);

    PayloadTransferOwnedPayload owned = {};
    assert(payload_transfer_take(now,
               "session_0011223344556677",
               finish.payload_ref,
               &owned) == PayloadTransferResult::ok);
    assert(owned.size_bytes == 3);
    assert(owned.bytes != nullptr);
    assert(owned.bytes[0] == 1 && owned.bytes[1] == 2 && owned.bytes[2] == 3);
    payload_transfer_wipe_owned_payload(&owned);
    assert(owned.bytes == nullptr);
    assert(owned.size_bytes == 0);
    assert(payload_transfer_snapshot(now).status == PayloadTransferStatus::idle);
    assert(payload_transfer_resolve(now,
               "session_0011223344556677",
               finish.payload_ref,
               &view) == PayloadTransferResult::not_found);
    assert(payload_transfer_abort(now,
               "session_0011223344556677",
               "transfer_0000000000000002",
               nullptr) == PayloadTransferResult::not_found);

    assert(payload_transfer_begin(now,
               "session_0011223344556677",
               3,
               "sha256:0606060606060606060606060606060606060606060606060606060606060606",
               &begin) == PayloadTransferResult::ok);
    assert(payload_transfer_append_chunk(now,
               "session_0011223344556677",
               begin.transfer_id,
               0,
               first,
               sizeof(first),
               &received) == PayloadTransferResult::ok);
    assert(payload_transfer_append_chunk(now,
               "session_0011223344556677",
               begin.transfer_id,
               2,
               second,
               sizeof(second),
               &received) == PayloadTransferResult::ok);
    assert(payload_transfer_finish(now,
               "session_0011223344556677",
               begin.transfer_id,
               simple_digest,
               &finish) == PayloadTransferResult::ok);

    assert(payload_transfer_abort(now,
               "session_0011223344556677",
               nullptr,
               "payload_0") == PayloadTransferResult::not_found);
    assert(payload_transfer_abort(now,
               "session_0011223344556677",
               nullptr,
               finish.payload_ref) == PayloadTransferResult::ok);
    assert(payload_transfer_snapshot(now).status == PayloadTransferStatus::idle);

    assert(payload_transfer_begin(now,
               "session_0011223344556677",
               3,
               "sha256:0000000000000000000000000000000000000000000000000000000000000000",
               &begin) == PayloadTransferResult::ok);
    assert(payload_transfer_clear_for_session("session_0011223344556677"));
    assert(payload_transfer_snapshot(now).status == PayloadTransferStatus::idle);

    assert(payload_transfer_begin(now,
               "session_0011223344556677",
               kPayloadTransferChunkMaxBytes + 1,
               "sha256:0000000000000000000000000000000000000000000000000000000000000000",
               &begin) == PayloadTransferResult::ok);
    uint8_t too_large[kPayloadTransferChunkMaxBytes + 1] = {};
    assert(payload_transfer_append_chunk(now,
               "session_8899aabbccddeeff",
               begin.transfer_id,
               0,
               too_large,
               sizeof(too_large),
               &received) == PayloadTransferResult::invalid_session);
    assert(payload_transfer_snapshot(now).status == PayloadTransferStatus::receiving);
    assert(payload_transfer_reject_chunk_too_large(now,
               "session_8899aabbccddeeff",
               begin.transfer_id) == PayloadTransferResult::invalid_session);
    assert(payload_transfer_snapshot(now).status == PayloadTransferStatus::receiving);
    assert(payload_transfer_reject_chunk_too_large(now,
               "session_0011223344556677",
               begin.transfer_id) == PayloadTransferResult::chunk_too_large);
    assert(payload_transfer_snapshot(now).status == PayloadTransferStatus::idle);

    assert(payload_transfer_begin(now,
               "session_0011223344556677",
               3,
               "sha256:0000000000000000000000000000000000000000000000000000000000000000",
               &begin) == PayloadTransferResult::ok);
    PayloadTransferSnapshot snapshot = payload_transfer_snapshot(now);
    assert(snapshot.status == PayloadTransferStatus::receiving);
    assert(snapshot.started_at_ms == now);
    assert(snapshot.deadline_ms > now);
    now = snapshot.deadline_ms;
    assert(payload_transfer_snapshot(now).status == PayloadTransferStatus::idle);
    assert(payload_transfer_append_chunk(now,
               "session_0011223344556677",
               begin.transfer_id,
               0,
               first,
               sizeof(first),
               &received) == PayloadTransferResult::not_found);

    const uint32_t zero_deadline_start =
        static_cast<uint32_t>(0u - (kPayloadTransferBaseWindowMs + kPayloadTransferPerChunkWindowMs));
    assert(payload_transfer_begin(zero_deadline_start,
               "session_0011223344556677",
               1,
               "sha256:0000000000000000000000000000000000000000000000000000000000000000",
               &begin) == PayloadTransferResult::invalid_argument);
    assert(payload_transfer_snapshot(zero_deadline_start).status == PayloadTransferStatus::idle);

    const uint32_t wrapped_deadline_start = UINT32_MAX - 10;
    assert(payload_transfer_begin(wrapped_deadline_start,
               "session_0011223344556677",
               1,
               "sha256:0000000000000000000000000000000000000000000000000000000000000000",
               &begin) == PayloadTransferResult::ok);
    snapshot = payload_transfer_snapshot(UINT32_MAX);
    assert(snapshot.status == PayloadTransferStatus::receiving);
    assert(snapshot.deadline_ms != 0);
    assert(payload_transfer_snapshot(snapshot.deadline_ms).status == PayloadTransferStatus::idle);
    assert(payload_transfer_append_chunk(snapshot.deadline_ms,
               "session_0011223344556677",
               begin.transfer_id,
               0,
               first,
               1,
               &received) == PayloadTransferResult::not_found);

    payload_transfer_state_init();
    now = 1000;
    assert(payload_transfer_begin(now,
               "session_0011223344556677",
               3,
               "sha256:0606060606060606060606060606060606060606060606060606060606060606",
               &begin) == PayloadTransferResult::ok);
    assert(strcmp(begin.transfer_id, "transfer_0000000000000001") == 0);
    assert(payload_transfer_append_chunk(now,
               "session_0011223344556677",
               begin.transfer_id,
               0,
               first,
               sizeof(first),
               &received) == PayloadTransferResult::ok);
    assert(payload_transfer_append_chunk(now,
               "session_0011223344556677",
               begin.transfer_id,
               2,
               second,
               sizeof(second),
               &received) == PayloadTransferResult::ok);
    assert(payload_transfer_finish(now,
               "session_0011223344556677",
               begin.transfer_id,
               simple_digest,
               &finish) == PayloadTransferResult::ok);
    assert(strcmp(finish.payload_ref, "payload_0000000000000001") == 0);
    payload_transfer_clear_all();
    assert(payload_transfer_begin(now,
               "session_0011223344556677",
               3,
               "sha256:0606060606060606060606060606060606060606060606060606060606060606",
               &begin) == PayloadTransferResult::ok);
    assert(strcmp(begin.transfer_id, "transfer_0000000000000002") == 0);

    assert(strcmp(signing::payload_delivery_transfer_error_code(PayloadTransferResult::ok), "internal_output_error") == 0);
    assert(strcmp(signing::payload_delivery_transfer_error_code(PayloadTransferResult::invalid_state), "busy") == 0);
    assert(strcmp(signing::payload_delivery_transfer_error_code(PayloadTransferResult::not_found), "unknown_request") == 0);
    assert(strcmp(signing::payload_delivery_transfer_error_code(PayloadTransferResult::invalid_transfer_id), "invalid_params") == 0);
    assert(strcmp(signing::payload_delivery_transfer_error_code(PayloadTransferResult::invalid_payload_ref), "invalid_params") == 0);
    assert(strcmp(signing::payload_delivery_transfer_error_code(PayloadTransferResult::size_mismatch), "invalid_params") == 0);
    assert(strcmp(signing::payload_delivery_transfer_error_code(PayloadTransferResult::digest_error), "internal_output_error") == 0);

    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/payload_transfer_state_test.cpp" \
  "${RUNTIME_DIR}/payload_transfer_state.cpp" \
  "${RUNTIME_DIR}/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_admission.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_primitives.cpp" \
  -o "${TMP_DIR}/payload_transfer_state_test"

"${TMP_DIR}/payload_transfer_state_test"
echo "StopWatch payload transfer state tests passed"
