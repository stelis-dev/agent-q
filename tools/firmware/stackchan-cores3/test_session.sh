#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_session.sh

Compiles the StackChan CoreS3 Firmware session core against host stubs and
verifies session id generation, validation, mismatch handling, expiry, and
scheduled expiry cleanup. This test uses only a host C++ compiler and does NOT
require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/products/firmware/src/stackchan-cores3/agent_q"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-session.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/stubs/freertos"

cat >"${TMP_DIR}/stubs/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;

#define pdMS_TO_TICKS(ms) (static_cast<TickType_t>(ms))
H

cat >"${TMP_DIR}/session_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_session.h"

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

namespace agent_q {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

}  // namespace agent_q

int main()
{
    using Result = agent_q::AgentQSessionValidationResult;

    agent_q::session_init();
    expect(!agent_q::session_active(), "session init clears session");
    expect(agent_q::session_replace(100, random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "session replace succeeds with random bytes");
    char id[agent_q::kAgentQSessionIdSize] = {};
    snprintf(id, sizeof(id), "%s", agent_q::session_id());
    expect(strcmp(id, "session_0102030405060708") == 0,
           "session id is generated from random bytes");
    expect(agent_q::session_validate(id, 100) == Result::ok,
           "matching session validates");
    expect(agent_q::session_validate("not-a-session", 100) == Result::invalid_format,
           "invalid session format is rejected distinctly");
    expect(agent_q::session_validate("session_aaaaaaaaaaaaaaaa", 100) == Result::mismatch,
           "mismatched session is rejected without clearing active session");
    expect(agent_q::session_active(), "mismatch does not clear session");
    expect(agent_q::session_validate(id, 100 + agent_q::kAgentQSessionTtlMs) == Result::expired,
           "expired session is rejected");
    expect(!agent_q::session_active(), "expired validation clears session");
    expect(agent_q::session_validate(id, 101 + agent_q::kAgentQSessionTtlMs) == Result::missing,
           "missing session is rejected after expiry clear");

    agent_q::session_init();
    expect(agent_q::session_replace(200, random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "second session starts");
    expect(!agent_q::session_expire_if_needed(200), "scheduled check before interval does not clear");
    expect(!agent_q::session_expire_if_needed(200 + agent_q::kAgentQSessionExpiryCheckMs),
           "scheduled check before ttl keeps session");
    expect(agent_q::session_active(), "session remains active before ttl");
    expect(agent_q::session_expire_if_needed(200 + agent_q::kAgentQSessionTtlMs),
           "scheduled expiry clears expired session");
    expect(!agent_q::session_active(), "scheduled expiry leaves no active session");

    agent_q::session_init();
    g_rng_fails = true;
    expect(agent_q::session_replace(300, random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::rng_error,
           "rng failure is reported without creating session");
    expect(!agent_q::session_active(), "rng failure leaves session inactive");

    if (failures != 0) {
        fprintf(stderr, "%d session test(s) failed\n", failures);
        return 1;
    }
    printf("Session tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/session_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  -o "${TMP_DIR}/session_test"

"${TMP_DIR}/session_test"
