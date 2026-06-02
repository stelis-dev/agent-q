#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_method_approval_flow.sh

Compiles the StackChan CoreS3 method approval state owner against host stubs
and verifies request id, session id, method metadata, deadline, critical
section, and terminal-result ownership. This test uses only a host C++ compiler
and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_POLICY_DIR="${REPO_ROOT}/firmware/src/common/agent_q/policy"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-method-approval-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos" "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_POLICY_DIR}" "${TMP_DIR}/agent_q_common/policy"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/method_approval_flow_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_method_approval_flow.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

agent_q::AgentQMethodApprovalBeginInput valid_input(const char* request_id = "method-1",
                                                    const char* session_id = "session_abcdefghijklmnop")
{
    return agent_q::AgentQMethodApprovalBeginInput{
        request_id,
        session_id,
        "sui",
        "sign_transaction",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "ask_rule",
        agent_q::AgentQMethodApprovalPolicyDecision::ask,
        100,
    };
}

void begin_valid()
{
    expect(agent_q::method_approval_flow_begin(valid_input()) ==
               agent_q::AgentQMethodApprovalTransitionResult::began,
           "valid method approval begins");
}

}  // namespace

int main()
{
    using Stage = agent_q::AgentQMethodApprovalStage;
    using Terminal = agent_q::AgentQMethodApprovalTerminalResult;
    using Result = agent_q::AgentQMethodApprovalTransitionResult;

    agent_q::method_approval_flow_clear();
    expect(!agent_q::method_approval_flow_active(), "clear leaves method approval inactive");
    agent_q::AgentQMethodApprovalSnapshot snapshot =
        agent_q::method_approval_flow_snapshot();
    expect(!snapshot.active && snapshot.stage == Stage::inactive, "inactive snapshot");

    begin_valid();
    snapshot = agent_q::method_approval_flow_snapshot();
    expect(snapshot.active, "snapshot is active after begin");
    expect(snapshot.stage == Stage::awaiting_user, "begin enters awaiting user stage");
    expect(strcmp(snapshot.request_id, "method-1") == 0, "request id stored");
    expect(strcmp(snapshot.session_id, "session_abcdefghijklmnop") == 0, "session id stored");
    expect(strcmp(snapshot.chain, "sui") == 0, "chain stored");
    expect(strcmp(snapshot.method, "sign_transaction") == 0, "method stored");
    expect(strcmp(snapshot.rule_ref, "ask_rule") == 0, "rule ref stored");
    expect(!agent_q::method_approval_flow_deadline_reached(99), "deadline not reached before deadline");
    expect(agent_q::method_approval_flow_deadline_reached(100), "deadline reached at deadline");

    expect(agent_q::method_approval_flow_begin(valid_input("method-2")) == Result::active,
           "active approval cannot be overwritten");
    snapshot = agent_q::method_approval_flow_snapshot();
    expect(strcmp(snapshot.request_id, "method-1") == 0, "rejected duplicate leaves state intact");
    expect(agent_q::method_approval_flow_approve_for_signing("session_wrong", 90) ==
               Result::session_mismatch,
           "wrong session approval is ignored");
    snapshot = agent_q::method_approval_flow_snapshot();
    expect(snapshot.stage == Stage::awaiting_user, "wrong session leaves approval awaiting");

    expect(agent_q::method_approval_flow_record_timeout(99) == Result::deadline_not_reached,
           "timeout before deadline does not terminalize");
    expect(agent_q::method_approval_flow_record_user_rejected(
               "session_abcdefghijklmnop",
               90) == Result::terminal_user_rejected,
           "matching user rejection terminalizes");
    expect(agent_q::method_approval_flow_record_timeout(100) == Result::terminal_pending,
           "stale event cannot overwrite terminal result");
    agent_q::AgentQMethodApprovalTerminalSnapshot terminal = {};
    expect(agent_q::method_approval_flow_consume_terminal(&terminal),
           "terminal result is consumable");
    expect(terminal.result == Terminal::user_rejected, "terminal records user rejection");
    expect(strcmp(terminal.request_id, "method-1") == 0, "terminal preserves request id");
    expect(strcmp(terminal.payload_digest,
                  "sha256:1111111111111111111111111111111111111111111111111111111111111111") == 0,
           "terminal preserves payload digest");
    expect(!agent_q::method_approval_flow_consume_terminal(&terminal),
           "terminal result is one-shot");
    expect(!agent_q::method_approval_flow_active(), "consume clears method approval state");

    begin_valid();
    expect(agent_q::method_approval_flow_record_timeout(100) ==
               Result::terminal_user_timeout,
           "deadline timeout terminalizes approval");
    expect(agent_q::method_approval_flow_consume_terminal(&terminal),
           "timeout terminal is consumable");
    expect(terminal.result == Terminal::user_timeout, "terminal records timeout");

    begin_valid();
    expect(agent_q::method_approval_flow_cancel_for_disconnect("session_wrong") ==
               Result::session_mismatch,
           "mismatched disconnect does not cancel");
    expect(agent_q::method_approval_flow_cancel_for_disconnect(
               "session_abcdefghijklmnop") == Result::terminal_canceled,
           "matching disconnect cancels before critical section");
    expect(agent_q::method_approval_flow_consume_terminal(&terminal),
           "disconnect terminal is consumable");
    expect(terminal.result == Terminal::canceled, "terminal records cancellation");

    begin_valid();
    expect(agent_q::method_approval_flow_cancel_for_session_loss(
               "session_abcdefghijklmnop") == Result::terminal_session_lost,
           "matching session loss terminalizes");
    expect(agent_q::method_approval_flow_consume_terminal(&terminal),
           "session-loss terminal is consumable");
    expect(terminal.result == Terminal::session_lost, "terminal records session loss");

    begin_valid();
    expect(agent_q::method_approval_flow_record_ui_error(
               "session_abcdefghijklmnop") == Result::terminal_ui_error,
           "UI failure terminalizes while awaiting user");
    expect(agent_q::method_approval_flow_consume_terminal(&terminal),
           "UI-error terminal is consumable");
    expect(terminal.result == Terminal::ui_error, "terminal records UI error");

    begin_valid();
    expect(agent_q::method_approval_flow_approve_for_signing(
               "session_abcdefghijklmnop",
               100) == Result::terminal_user_timeout,
           "approval at deadline records timeout instead of signing");
    expect(agent_q::method_approval_flow_consume_terminal(&terminal),
           "deadline approval terminal is consumable");
    expect(terminal.result == Terminal::user_timeout, "deadline approval records timeout");

    begin_valid();
    expect(agent_q::method_approval_flow_approve_for_signing(
               "session_abcdefghijklmnop",
               90) == Result::approved_for_signing,
           "matching approval enters critical section");
    snapshot = agent_q::method_approval_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section,
           "approval enters signing critical section");
    expect(agent_q::method_approval_flow_cancel_for_disconnect(
               "session_abcdefghijklmnop") == Result::busy,
           "disconnect cannot cancel critical section");
    expect(agent_q::method_approval_flow_record_ui_error(
               "session_abcdefghijklmnop") == Result::busy,
           "UI error cannot rewrite critical section");
    expect(agent_q::method_approval_flow_complete_approved(
               "session_wrong") == Result::session_mismatch,
           "wrong session cannot complete approval");
    expect(agent_q::method_approval_flow_complete_approved(
               "session_abcdefghijklmnop") == Result::terminal_user_approved,
           "approved critical section terminalizes");
    expect(agent_q::method_approval_flow_consume_terminal(&terminal),
           "approved terminal is consumable");
    expect(terminal.result == Terminal::user_approved, "terminal records approved result");

    begin_valid();
    expect(agent_q::method_approval_flow_approve_for_signing(
               "session_abcdefghijklmnop",
               90) == Result::approved_for_signing,
           "approval enters critical section before method error");
    expect(agent_q::method_approval_flow_record_method_error(
               "session_abcdefghijklmnop") == Result::terminal_method_error,
           "method error terminalizes critical section");
    expect(agent_q::method_approval_flow_consume_terminal(&terminal),
           "method-error terminal is consumable");
    expect(terminal.result == Terminal::method_error, "terminal records method error");

    agent_q::method_approval_flow_clear();
    expect(agent_q::method_approval_flow_record_timeout(100) == Result::inactive,
           "inactive timeout is ignored");
    expect(agent_q::method_approval_flow_begin(valid_input("", "session_abcdefghijklmnop")) ==
               Result::invalid_argument,
           "empty request id is rejected");
    char too_long[agent_q::kAgentQMethodApprovalRequestIdSize + 4] = {};
    memset(too_long, 'a', sizeof(too_long) - 1);
    expect(agent_q::method_approval_flow_begin(valid_input(too_long, "session_abcdefghijklmnop")) ==
               Result::invalid_argument,
           "overlong request id is rejected");
    expect(!agent_q::method_approval_flow_active(), "invalid begin leaves state inactive");

    if (failures != 0) {
        fprintf(stderr, "%d method approval flow test(s) failed\n", failures);
        return 1;
    }
    printf("Method approval flow tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/method_approval_flow_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_method_approval_flow.cpp" \
  -o "${TMP_DIR}/method_approval_flow_test"

"${TMP_DIR}/method_approval_flow_test"
