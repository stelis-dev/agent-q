#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_Q_DIR="${SCRIPT_DIR}/../../src/stackchan-cores3/agent_q"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
CXX_BIN="${CXX:-c++}"

cat >"${TMP_DIR}/signing_result_store_test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_signing_result_store.h"

using namespace agent_q;

int main()
{
    signing_result_clear_all();
    char out[64];
    size_t out_len = 0;

    // store + find round-trip
    assert(signing_result_store("sess_a", "req_1", "RESULT_1", 8) == SigningResultStoreOutcome::stored);
    assert(signing_result_find("sess_a", "req_1", out, sizeof(out), &out_len));
    assert(out_len == 8 && strcmp(out, "RESULT_1") == 0);

    // idempotency: same (session,request) keeps the original
    assert(signing_result_store("sess_a", "req_1", "RESULT_X", 8) == SigningResultStoreOutcome::duplicate);
    assert(signing_result_find("sess_a", "req_1", out, sizeof(out), &out_len));
    assert(strcmp(out, "RESULT_1") == 0);

    // session-scoping: same request_id under a different session is a distinct entry
    assert(signing_result_store("sess_b", "req_1", "RESULT_B", 8) == SigningResultStoreOutcome::stored);
    assert(signing_result_find("sess_b", "req_1", out, sizeof(out), &out_len) && strcmp(out, "RESULT_B") == 0);
    assert(signing_result_find("sess_a", "req_1", out, sizeof(out), &out_len) && strcmp(out, "RESULT_1") == 0);

    // ack releases; second ack is a no-op
    assert(signing_result_ack("sess_a", "req_1"));
    assert(!signing_result_find("sess_a", "req_1", out, sizeof(out), &out_len));
    assert(!signing_result_ack("sess_a", "req_1"));

    // not found / invalid / too large
    assert(!signing_result_find("sess_a", "nope", out, sizeof(out), &out_len));
    char big[1100];
    memset(big, 'x', sizeof(big));
    assert(signing_result_store("sess_a", "req_big", big, 1100) == SigningResultStoreOutcome::too_large);
    assert(signing_result_store(nullptr, "req", "r", 1) == SigningResultStoreOutcome::invalid);
    assert(signing_result_store("sess", "", "r", 1) == SigningResultStoreOutcome::invalid);

    // out buffer too small -> false (no truncation)
    assert(signing_result_store("sess_c", "req_c", "0123456789", 10) == SigningResultStoreOutcome::stored);
    char small[5];
    assert(!signing_result_find("sess_c", "req_c", small, sizeof(small), &out_len));

    // LRU eviction: a fifth store drops the oldest entry
    signing_result_clear_all();
    assert(signing_result_store("s", "e1", "1", 1) == SigningResultStoreOutcome::stored);
    assert(signing_result_store("s", "e2", "2", 1) == SigningResultStoreOutcome::stored);
    assert(signing_result_store("s", "e3", "3", 1) == SigningResultStoreOutcome::stored);
    assert(signing_result_store("s", "e4", "4", 1) == SigningResultStoreOutcome::stored);
    assert(signing_result_store("s", "e5", "5", 1) == SigningResultStoreOutcome::stored);
    assert(!signing_result_find("s", "e1", out, sizeof(out), &out_len));
    assert(signing_result_find("s", "e5", out, sizeof(out), &out_len));

    // clear_session drops only that session
    signing_result_clear_all();
    assert(signing_result_store("sx", "r1", "a", 1) == SigningResultStoreOutcome::stored);
    assert(signing_result_store("sy", "r1", "b", 1) == SigningResultStoreOutcome::stored);
    signing_result_clear_session("sx");
    assert(!signing_result_find("sx", "r1", out, sizeof(out), &out_len));
    assert(signing_result_find("sy", "r1", out, sizeof(out), &out_len));

    printf("Signing result store tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/signing_result_store_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_result_store.cpp" \
  -o "${TMP_DIR}/signing_result_store_test"

"${TMP_DIR}/signing_result_store_test"
