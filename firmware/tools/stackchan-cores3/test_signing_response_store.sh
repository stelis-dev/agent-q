#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${SCRIPT_DIR}/../../src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
CXX_BIN="${CXX:-c++}"

cat >"${TMP_DIR}/signing_response_store_test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/signing_response_store.h"
#include "signing_retry_delivery.h"

using namespace signing;

int main()
{
    signing_response_clear_all();
    char out[64];
    size_t out_len = 0;
    uint8_t identity[kSignRequestIdentitySize] = {};
    uint8_t conflicting_identity[kSignRequestIdentitySize] = {};
    conflicting_identity[0] = 1;
    const auto store_response = [&](const char* session_id,
                                  const char* request_id,
                                  const char* response,
                                  size_t response_size) {
        return signing_response_store(
            session_id,
            request_id,
            identity,
            sizeof(identity),
            response,
            response_size);
    };

    // store + find round-trip
    assert(store_response("sess_a", "req_1", "RESPONSE_1", strlen("RESPONSE_1")) == ResponseStoreOutcome::stored);
    assert(signing_response_find("sess_a", "req_1", out, sizeof(out), &out_len));
    assert(out_len == strlen("RESPONSE_1") && strcmp(out, "RESPONSE_1") == 0);

    // idempotency: same (session,request) keeps the original
    assert(store_response("sess_a", "req_1", "RESPONSE_X", strlen("RESPONSE_X")) == ResponseStoreOutcome::duplicate);
    assert(signing_response_store(
               "sess_a",
               "req_1",
               conflicting_identity,
               sizeof(conflicting_identity),
               "RESPONSE_X",
               strlen("RESPONSE_X")) == ResponseStoreOutcome::conflict);
    assert(signing_response_find_for_retry(
               "sess_a",
               "req_1",
               conflicting_identity,
               sizeof(conflicting_identity),
               out,
               sizeof(out),
               &out_len) == ResponseRetryLookup::conflict);
    assert(signing_response_find_for_retry(
               "sess_a",
               "req_1",
               identity,
               sizeof(identity),
               out,
               sizeof(out),
               &out_len) == ResponseRetryLookup::match);
    assert(signing_response_find("sess_a", "req_1", out, sizeof(out), &out_len));
    assert(strcmp(out, "RESPONSE_1") == 0);
    char retry_out[64] = {};
    size_t retry_out_len = 0;
    const RetryDeliveryResult retry_match =
        evaluate_signing_retry_delivery(
            "sess_a",
            "req_1",
            identity,
            sizeof(identity),
            retry_out,
            sizeof(retry_out));
    assert(retry_match.status == RetryDeliveryStatus::match);
    assert(retry_match.stored_response_len == strlen("RESPONSE_1") && strcmp(retry_out, "RESPONSE_1") == 0);
    assert(retry_match.error_code == nullptr);
    const RetryDeliveryResult retry_conflict =
        evaluate_signing_retry_delivery(
            "sess_a",
            "req_1",
            conflicting_identity,
            sizeof(conflicting_identity),
            retry_out,
            sizeof(retry_out));
    assert(retry_conflict.status == RetryDeliveryStatus::request_id_conflict);
    assert(retry_out[0] == '\0');
    assert(strcmp(retry_conflict.error_code, "request_id_conflict") == 0);
    const RetryDeliveryResult retry_not_found =
        evaluate_signing_retry_delivery(
            "sess_a",
            "req_missing",
            identity,
            sizeof(identity),
            retry_out,
            sizeof(retry_out));
    assert(retry_not_found.status == RetryDeliveryStatus::not_found);
    assert(retry_not_found.error_code == nullptr && retry_not_found.stored_response_len == 0);
    assert(retry_out[0] == '\0');
    const RetryDeliveryResult retry_invalid =
        evaluate_signing_retry_delivery(
            "sess_a",
            "req_1",
            identity,
            sizeof(identity) - 1,
            retry_out,
            sizeof(retry_out));
    assert(retry_invalid.status == RetryDeliveryStatus::lookup_error);
    assert(strcmp(retry_invalid.error_code, "internal_output_error") == 0);
    assert(retry_out[0] == '\0');

    const RetryDeliveryResult retry_small =
        evaluate_signing_retry_delivery(
            "sess_a",
            "req_1",
            identity,
            sizeof(identity),
            retry_out,
            4);
    assert(retry_small.status == RetryDeliveryStatus::lookup_error);
    assert(strcmp(retry_small.error_code, "internal_output_error") == 0);
    retry_out_len = retry_small.stored_response_len;
    assert(retry_out_len == 0);

    // session-scoping: same request_id under a different session is a distinct entry
    assert(store_response("sess_b", "req_1", "RESPONSE_B", strlen("RESPONSE_B")) == ResponseStoreOutcome::stored);
    assert(signing_response_find("sess_b", "req_1", out, sizeof(out), &out_len) && strcmp(out, "RESPONSE_B") == 0);
    assert(signing_response_find("sess_a", "req_1", out, sizeof(out), &out_len) && strcmp(out, "RESPONSE_1") == 0);

    // ack releases; second ack is a no-op
    assert(signing_response_ack("sess_a", "req_1"));
    assert(!signing_response_find("sess_a", "req_1", out, sizeof(out), &out_len));
    assert(!signing_response_ack("sess_a", "req_1"));
    assert(signing_response_store(
               "sess_a",
               "req_1",
               conflicting_identity,
               sizeof(conflicting_identity),
               "RESPONSE_AFTER_ACK",
               strlen("RESPONSE_AFTER_ACK")) == ResponseStoreOutcome::stored);
    assert(signing_response_find_for_retry(
               "sess_a",
               "req_1",
               conflicting_identity,
               sizeof(conflicting_identity),
               out,
               sizeof(out),
               &out_len) == ResponseRetryLookup::match);
    assert(out_len == strlen("RESPONSE_AFTER_ACK") && strcmp(out, "RESPONSE_AFTER_ACK") == 0);

    // not found / invalid / too large
    assert(!signing_response_find("sess_a", "nope", out, sizeof(out), &out_len));
    char big[kResponseMaxSize];
    memset(big, 'x', sizeof(big));
    assert(store_response("sess_a", "req_big", big, sizeof(big)) == ResponseStoreOutcome::too_large);
    assert(store_response(nullptr, "req", "r", 1) == ResponseStoreOutcome::invalid);
    assert(store_response("sess", "", "r", 1) == ResponseStoreOutcome::invalid);

    // out buffer too small -> false (no truncation)
    assert(store_response("sess_c", "req_c", "0123456789", 10) == ResponseStoreOutcome::stored);
    char small[5];
    assert(!signing_response_find("sess_c", "req_c", small, sizeof(small), &out_len));

    // LRU eviction: a fifth store drops the oldest entry
    signing_response_clear_all();
    assert(store_response("s", "e1", "1", 1) == ResponseStoreOutcome::stored);
    assert(store_response("s", "e2", "2", 1) == ResponseStoreOutcome::stored);
    assert(store_response("s", "e3", "3", 1) == ResponseStoreOutcome::stored);
    assert(store_response("s", "e4", "4", 1) == ResponseStoreOutcome::stored);
    assert(store_response("s", "e5", "5", 1) == ResponseStoreOutcome::stored);
    assert(!signing_response_find("s", "e1", out, sizeof(out), &out_len));
    assert(signing_response_find("s", "e5", out, sizeof(out), &out_len));

    // clear_session drops only that session
    signing_response_clear_all();
    assert(store_response("sx", "r1", "a", 1) == ResponseStoreOutcome::stored);
    assert(store_response("sy", "r1", "b", 1) == ResponseStoreOutcome::stored);
    signing_response_clear_session("sx");
    assert(!signing_response_find("sx", "r1", out, sizeof(out), &out_len));
    assert(signing_response_find("sy", "r1", out, sizeof(out), &out_len));
    assert(signing_response_store(
               "sx",
               "r1",
               conflicting_identity,
               sizeof(conflicting_identity),
               "c",
               1) == ResponseStoreOutcome::stored);
    assert(signing_response_find_for_retry(
               "sx",
               "r1",
               conflicting_identity,
               sizeof(conflicting_identity),
               out,
               sizeof(out),
               &out_len) == ResponseRetryLookup::match);

    printf("Signing response store tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/signing_response_store_test.cpp" \
  "${COMMON_ROOT}/protocol/signing_response_store.cpp" \
  "${RUNTIME_DIR}/signing_retry_delivery.cpp" \
  -o "${TMP_DIR}/signing_response_store_test"

"${TMP_DIR}/signing_response_store_test"
