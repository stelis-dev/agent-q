#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_connect_approval.sh

Compiles the StackChan CoreS3 physical connect approval state owner against
host stubs and verifies request id, client name, deadline, choice, and clear
ownership. This test uses only a host C++ compiler and does NOT require ESP-IDF.
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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-connect-approval.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/connect_approval_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "connect_approval.h"

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
    using Choice = signing::ConnectApprovalChoice;

    signing::connect_approval_clear();
    expect(!signing::connect_approval_active(), "clear leaves state inactive");
    expect(!signing::connect_approval_awaiting_choice(), "inactive state is not awaiting choice");
    char request_id[signing::kConnectApprovalRequestIdSize] = {};
    expect(!signing::connect_approval_request_id(request_id, sizeof(request_id)),
           "inactive state has no request id");
    expect(request_id[0] == '\0', "inactive request id output is cleared");
    expect(!signing::connect_approval_choose(Choice::approved, 0),
           "cleared state ignores stale approve choice");

    expect(signing::connect_approval_begin("connect-1", "Agent-Q", 10, {10, 100}),
           "connect approval begins");
    signing::ConnectApprovalSnapshot snapshot =
        signing::connect_approval_snapshot();
    expect(snapshot.active, "snapshot active");
    expect(strcmp(snapshot.request_id, "connect-1") == 0, "request id stored");
    expect(strcmp(snapshot.client_name, "Agent-Q") == 0, "client name stored");
    expect(snapshot.approval_window.started_at == 10, "approval window start stored");
    expect(snapshot.approval_window.deadline == 100, "approval window deadline stored");
    expect(snapshot.choice == Choice::none, "initial choice is none");
    expect(signing::connect_approval_awaiting_choice(), "active state awaits choice");
    expect(!signing::connect_approval_deadline_reached(99), "deadline not reached before deadline");
    expect(signing::connect_approval_deadline_reached(100), "deadline reached at deadline");
    expect(signing::connect_approval_request_id(request_id, sizeof(request_id)) &&
               strcmp(request_id, "connect-1") == 0,
           "request id is copied for response writer");
    expect(signing::connect_approval_review_action_available(99),
           "review action is available before deadline");
    expect(!signing::connect_approval_review_action_available(100),
           "review action is unavailable at deadline");

    expect(!signing::connect_approval_begin("connect-2", "Other Agent-Q", 25, {25, 125}),
           "active approval cannot be overwritten");
    snapshot = signing::connect_approval_snapshot();
    expect(strcmp(snapshot.request_id, "connect-1") == 0 &&
               strcmp(snapshot.client_name, "Agent-Q") == 0,
           "rejected overwrite leaves state intact");

    expect(!signing::connect_approval_choose(Choice::none, 50),
           "none choice is rejected");
    expect(signing::connect_approval_choose(Choice::approved, 50),
           "approve choice is recorded");
    expect(!signing::connect_approval_awaiting_choice(),
           "approved state no longer awaits choice");
    expect(!signing::connect_approval_choose(Choice::rejected, 51),
           "recorded choice cannot be overwritten");
    snapshot = signing::connect_approval_snapshot();
    expect(snapshot.choice == Choice::approved, "approved choice retained");
    expect(!signing::connect_approval_return_to_review(50, {30, 40}),
           "return to review rejects stale approval window at state owner boundary");
    expect(!signing::connect_approval_return_to_review(20, {30, 130}),
           "return to review rejects future approval window at state owner boundary");
    expect(signing::connect_approval_return_to_review(60, {60, 160}),
           "return to review stores fresh approval window");
    snapshot = signing::connect_approval_snapshot();
    expect(snapshot.choice == Choice::none &&
               snapshot.approval_window.started_at == 60 &&
               snapshot.approval_window.deadline == 160,
           "return to review resets choice and stores window");

    signing::connect_approval_clear();
    char too_long_id[signing::kConnectApprovalRequestIdSize + 4] = {};
    memset(too_long_id, 'a', sizeof(too_long_id) - 1);
    expect(!signing::connect_approval_begin(too_long_id, "Agent-Q", 20, {20, 200}),
           "overlong request id is rejected");
    expect(!signing::connect_approval_active(), "overlong request id does not activate state");

    char too_long_client[signing::kConnectApprovalClientNameSize + 4] = {};
    memset(too_long_client, 'b', sizeof(too_long_client) - 1);
    expect(!signing::connect_approval_begin("connect-3", too_long_client, 20, {20, 200}),
           "overlong client name is rejected");
    expect(!signing::connect_approval_active(), "overlong client name does not activate state");
    expect(!signing::connect_approval_begin("connect-3", "", 20, {20, 200}),
           "empty client name is rejected");
    expect(!signing::connect_approval_begin("", "Agent-Q", 20, {20, 200}),
           "empty request id is rejected");
    expect(!signing::connect_approval_begin("connect-3", "Agent-Q", 200, {200, 200}),
           "already expired approval window is rejected");
    expect(!signing::connect_approval_begin("connect-3", "Agent-Q", 20, {20, 0}),
           "zero approval deadline is rejected");
    expect(!signing::connect_approval_begin("connect-3", "Agent-Q", 30, {10, 20}),
           "stale approval window is rejected at state owner boundary");
    expect(!signing::connect_approval_begin("connect-3", "Agent-Q", 10, {20, 40}),
           "future approval window is rejected at state owner boundary");

    expect(signing::connect_approval_begin("connect-expired-choice", "Agent-Q", 30, {30, 90}),
           "connect approval can begin for expired-choice test");
    expect(!signing::connect_approval_choose(Choice::approved, 90),
           "approve choice at deadline is rejected");
    snapshot = signing::connect_approval_snapshot();
    expect(snapshot.choice == Choice::none, "expired approve leaves choice unset");
    expect(signing::connect_approval_awaiting_choice(),
           "expired approve keeps state awaiting timeout response");
    signing::connect_approval_clear();

    expect(signing::connect_approval_begin("connect-4", "Agent-Q", 30, {30, 300}),
           "connect approval can begin after clear");
    char small_request_id[4] = {};
    expect(!signing::connect_approval_request_id(small_request_id, sizeof(small_request_id)),
           "too-small request id output is rejected");
    expect(small_request_id[0] == '\0', "too-small request id output is cleared");
    expect(signing::connect_approval_choose(Choice::rejected, 40),
           "reject choice is recorded");
    snapshot = signing::connect_approval_snapshot();
    expect(snapshot.choice == Choice::rejected, "rejected choice retained");

    signing::connect_approval_clear();
    expect(!signing::connect_approval_active(), "final clear leaves state inactive");

    if (failures != 0) {
        fprintf(stderr, "%d connect approval test(s) failed\n", failures);
        return 1;
    }
    printf("Connect approval tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/connect_approval_test.cpp" \
  "${RUNTIME_DIR}/connect_approval.cpp" \
  -o "${TMP_DIR}/connect_approval_test"

"${TMP_DIR}/connect_approval_test"
