#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_protocol_pin_approval.sh

Compiles the StackChan CoreS3 protocol-backed local PIN approval state owner
against host stubs and verifies request id, session id, purpose, and deadline
ownership. This test uses only a host C++ compiler and does NOT require ESP-IDF.
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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-protocol-pin-approval.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/protocol_pin_approval_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_protocol_pin_approval.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

bool random_bytes(void* output, size_t size, void*)
{
    if (output == nullptr) {
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
    using Purpose = agent_q::AgentQProtocolPinApprovalPurpose;
    using LocalPurpose = agent_q::AgentQLocalPinAuthPurpose;
    using SessionValidation = agent_q::AgentQSessionValidationResult;

    agent_q::session_init();
    agent_q::protocol_pin_approval_clear();
    expect(!agent_q::protocol_pin_approval_active(), "clear leaves state inactive");
    char request_id[agent_q::kAgentQProtocolPinRequestIdSize] = {};
    expect(!agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
               LocalPurpose::connect,
               request_id,
               sizeof(request_id)),
           "inactive state has no connect request id");
    expect(request_id[0] == '\0', "inactive request id output is cleared");
    expect(agent_q::protocol_pin_approval_retry_deadline_for_local_pin_purpose(
               LocalPurpose::connect,
               77) == 77,
           "inactive state returns fallback deadline");

    expect(agent_q::protocol_pin_approval_begin_connect("connect-1", 100),
           "connect protocol PIN approval begins");
    agent_q::AgentQProtocolPinApprovalSnapshot snapshot =
        agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.active, "connect snapshot is active");
    expect(snapshot.purpose == Purpose::connect, "connect snapshot purpose");
    expect(strcmp(snapshot.request_id, "connect-1") == 0, "connect request id stored");
    expect(snapshot.session_id[0] == '\0', "connect stores no session id");
    expect(snapshot.deadline == 100, "connect deadline stored");
    expect(agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
               LocalPurpose::connect,
               request_id,
               sizeof(request_id)) &&
               strcmp(request_id, "connect-1") == 0,
           "connect request id maps from local PIN purpose");
    expect(!agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
               LocalPurpose::policy_update,
               request_id,
               sizeof(request_id)),
           "connect state does not map policy update purpose");
    expect(!agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               99),
           "deadline not reached before deadline");
    expect(agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               100),
           "deadline reached at deadline");

    char too_long[agent_q::kAgentQProtocolPinRequestIdSize + 4] = {};
    memset(too_long, 'a', sizeof(too_long) - 1);
    expect(!agent_q::protocol_pin_approval_begin_connect(too_long, 200),
           "overlong request id is rejected");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(strcmp(snapshot.request_id, "connect-1") == 0,
           "failed begin does not overwrite existing state");
    expect(!agent_q::protocol_pin_approval_begin_policy_update(
               "policy-overwrite",
               "session_aaaaaaaaaaaaaaaa",
               225),
           "active protocol PIN approval cannot be overwritten");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.purpose == Purpose::connect &&
               strcmp(snapshot.request_id, "connect-1") == 0,
           "rejected active overwrite leaves current state intact");

    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session starts");
    const char* session_id = agent_q::session_id();
    agent_q::protocol_pin_approval_clear();
    expect(agent_q::protocol_pin_approval_begin_policy_update(
               "policy-1",
               session_id,
               250),
           "policy update protocol PIN approval begins");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.active, "policy update snapshot is active");
    expect(snapshot.purpose == Purpose::policy_update, "policy update snapshot purpose");
    expect(strcmp(snapshot.request_id, "policy-1") == 0, "policy update request id stored");
    expect(strcmp(snapshot.session_id, session_id) == 0, "policy update session id stored");
    expect(agent_q::protocol_pin_approval_policy_update_session_matches(session_id),
           "matching policy update session recognized");
    expect(!agent_q::protocol_pin_approval_policy_update_session_matches(
               "session_aaaaaaaaaaaaaaaa"),
           "mismatched policy update session rejected");
    expect(agent_q::protocol_pin_approval_policy_update_request_id(
               request_id,
               sizeof(request_id)) &&
               strcmp(request_id, "policy-1") == 0,
           "policy update request id is available");
    expect(agent_q::protocol_pin_approval_validate_policy_update_session() ==
               SessionValidation::ok,
           "active matching session validates");
    agent_q::session_clear();
    expect(agent_q::protocol_pin_approval_validate_policy_update_session() ==
               SessionValidation::missing,
           "cleared session invalidates pending policy update");

    agent_q::protocol_pin_approval_clear();
    expect(!agent_q::protocol_pin_approval_policy_update_request_id(
               request_id,
               sizeof(request_id)),
           "cleared state has no policy update request id");
    expect(!agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               1000),
           "cleared state has no reached protocol deadline");

    if (failures != 0) {
        fprintf(stderr, "%d protocol PIN approval test(s) failed\n", failures);
        return 1;
    }
    printf("Protocol PIN approval tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/protocol_pin_approval_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_protocol_pin_approval.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  -o "${TMP_DIR}/protocol_pin_approval_test"

"${TMP_DIR}/protocol_pin_approval_test"
