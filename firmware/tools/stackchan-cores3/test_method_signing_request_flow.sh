#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_method_signing_request_flow.sh

Compiles the StackChan CoreS3 method signing request state owner against host
stubs and verifies request id, session id, method metadata, bounded signable
payload scratch, deadline, history durability gate, critical section,
terminal-result ownership, and payload wipe on terminal transitions. This test
uses only a host C++ compiler and does NOT require ESP-IDF.
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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-method-signing-request-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos" "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_POLICY_DIR}" "${TMP_DIR}/agent_q_common/policy"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/method_signing_request_flow_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_method_signing_request_flow.h"

namespace {

int failures = 0;

constexpr uint8_t kPayload[] = {0x01, 0x02, 0x03, 0x04};

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

agent_q::AgentQMethodSigningRequestBeginInput valid_input(
    const char* request_id = "method-1",
    const char* session_id = "session_abcdefghijklmnop",
    const uint8_t* payload = kPayload,
    size_t payload_size = sizeof(kPayload))
{
    return agent_q::AgentQMethodSigningRequestBeginInput{
        request_id,
        session_id,
        "sui",
        "sign_transaction",
        payload,
        payload_size,
        "devnet",
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "0x2::sui::SUI",
        "1000000",
        "50000000",
        "1000",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "ask_rule",
        agent_q::AgentQMethodSigningRequestPolicyDecision::ask,
        100,
    };
}

void begin_valid()
{
    expect(agent_q::method_signing_request_flow_begin(valid_input()) ==
               agent_q::AgentQMethodSigningRequestTransitionResult::began,
           "valid method signing request begins");
}

void expect_payload_copy_unavailable(const char* label)
{
    uint8_t output[sizeof(kPayload)] = {0xaa, 0xaa, 0xaa, 0xaa};
    size_t copied_size = 99;
    expect(!agent_q::method_signing_request_flow_copy_signable_payload(
               output,
               sizeof(output),
               &copied_size),
           label);
    expect(copied_size == 0, "unavailable payload copy resets copied size");
}

}  // namespace

int main()
{
    using Stage = agent_q::AgentQMethodSigningRequestStage;
    using Terminal = agent_q::AgentQMethodSigningRequestTerminalResult;
    using Result = agent_q::AgentQMethodSigningRequestTransitionResult;

    agent_q::method_signing_request_flow_clear();
    expect(!agent_q::method_signing_request_flow_active(), "clear leaves signing request inactive");
    agent_q::AgentQMethodSigningRequestSnapshot snapshot =
        agent_q::method_signing_request_flow_snapshot();
    expect(!snapshot.active && snapshot.stage == Stage::inactive, "inactive snapshot");
    expect_payload_copy_unavailable("inactive state does not expose payload");

    begin_valid();
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.active, "snapshot is active after begin");
    expect(snapshot.stage == Stage::awaiting_user, "begin enters awaiting user stage");
    expect(strcmp(snapshot.request_id, "method-1") == 0, "request id stored");
    expect(strcmp(snapshot.session_id, "session_abcdefghijklmnop") == 0, "session id stored");
    expect(strcmp(snapshot.chain, "sui") == 0, "chain stored");
    expect(strcmp(snapshot.method, "sign_transaction") == 0, "method stored");
    expect(strcmp(snapshot.network, "devnet") == 0, "network stored");
    expect(strcmp(snapshot.recipient,
                  "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0,
           "recipient stored");
    expect(strcmp(snapshot.asset, "0x2::sui::SUI") == 0, "asset stored");
    expect(strcmp(snapshot.amount, "1000000") == 0, "amount stored");
    expect(strcmp(snapshot.gas_budget, "50000000") == 0, "gas budget stored");
    expect(strcmp(snapshot.gas_price, "1000") == 0, "gas price stored");
    expect(strcmp(snapshot.rule_ref, "ask_rule") == 0, "rule ref stored");
    expect(snapshot.signable_payload_size == sizeof(kPayload), "payload size stored");
    expect(!agent_q::method_signing_request_flow_deadline_reached(99),
           "deadline not reached before deadline");
    expect(agent_q::method_signing_request_flow_deadline_reached(100),
           "deadline reached at deadline");
    expect_payload_copy_unavailable("awaiting user state does not expose payload");

    expect(agent_q::method_signing_request_flow_begin(valid_input("method-2")) ==
               Result::active,
           "active signing request cannot be overwritten");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(strcmp(snapshot.request_id, "method-1") == 0, "rejected duplicate leaves state intact");
    expect(agent_q::method_signing_request_flow_record_user_approved("session_wrong", 90) ==
               Result::session_mismatch,
           "wrong session approval is ignored");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.stage == Stage::awaiting_user, "wrong session leaves request awaiting");

    expect(agent_q::method_signing_request_flow_record_timeout(99) ==
               Result::deadline_not_reached,
           "timeout before deadline does not terminalize");
    expect(agent_q::method_signing_request_flow_record_user_rejected(
               "session_abcdefghijklmnop",
               90) == Result::terminal_user_rejected,
           "matching user rejection terminalizes");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.signable_payload_size == 0, "user rejection wipes payload size");
    expect_payload_copy_unavailable("terminal user rejection does not expose payload");
    expect(agent_q::method_signing_request_flow_record_timeout(100) == Result::terminal_pending,
           "stale event cannot overwrite terminal result");
    agent_q::AgentQMethodSigningRequestTerminalSnapshot terminal = {};
    expect(agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "terminal result is consumable");
    expect(terminal.result == Terminal::user_rejected, "terminal records user rejection");
    expect(strcmp(terminal.request_id, "method-1") == 0, "terminal preserves request id");
    expect(strcmp(terminal.payload_digest,
                  "sha256:1111111111111111111111111111111111111111111111111111111111111111") == 0,
           "terminal preserves payload digest");
    expect(!agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "terminal result is one-shot");
    expect(!agent_q::method_signing_request_flow_active(), "consume clears signing request state");

    begin_valid();
    expect(agent_q::method_signing_request_flow_record_timeout(100) ==
               Result::terminal_user_timeout,
           "deadline timeout terminalizes request");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.signable_payload_size == 0, "timeout wipes payload size");
    expect_payload_copy_unavailable("timeout does not expose payload");
    expect(agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "timeout terminal is consumable");
    expect(terminal.result == Terminal::user_timeout, "terminal records timeout");

    begin_valid();
    expect(agent_q::method_signing_request_flow_cancel_for_disconnect("session_wrong") ==
               Result::session_mismatch,
           "mismatched disconnect does not cancel");
    expect(agent_q::method_signing_request_flow_cancel_for_disconnect(
               "session_abcdefghijklmnop") == Result::terminal_canceled,
           "matching disconnect cancels before critical section");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.signable_payload_size == 0, "disconnect wipes payload size");
    expect(agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "disconnect terminal is consumable");
    expect(terminal.result == Terminal::canceled, "terminal records cancellation");

    begin_valid();
    expect(agent_q::method_signing_request_flow_cancel_for_session_loss(
               "session_abcdefghijklmnop") == Result::terminal_session_lost,
           "matching session loss terminalizes");
    expect(agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "session-loss terminal is consumable");
    expect(terminal.result == Terminal::session_lost, "terminal records session loss");

    begin_valid();
    expect(agent_q::method_signing_request_flow_record_ui_error(
               "session_abcdefghijklmnop") == Result::terminal_ui_error,
           "UI failure terminalizes while awaiting user");
    expect(agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "UI-error terminal is consumable");
    expect(terminal.result == Terminal::ui_error, "terminal records UI error");

    begin_valid();
    expect(agent_q::method_signing_request_flow_record_user_approved(
               "session_abcdefghijklmnop",
               90) == Result::user_approved_waiting_history,
           "user approval waits for history before disconnect test");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.stage == Stage::awaiting_history,
           "approved request waits for history before disconnect test");
    expect_payload_copy_unavailable("history-pending request does not expose payload");
    expect(agent_q::method_signing_request_flow_cancel_for_disconnect(
               "session_abcdefghijklmnop") == Result::terminal_canceled,
           "disconnect before durable history cancels and wipes payload");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.signable_payload_size == 0, "history-pending disconnect wipes payload size");
    expect_payload_copy_unavailable("history-pending disconnect terminal does not expose payload");
    expect(agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "history-pending disconnect terminal is consumable");
    expect(terminal.result == Terminal::canceled,
           "terminal records history-pending disconnect cancellation");

    begin_valid();
    expect(agent_q::method_signing_request_flow_record_user_approved(
               "session_abcdefghijklmnop",
               90) == Result::user_approved_waiting_history,
           "user approval waits for history before history-error test");
    expect(agent_q::method_signing_request_flow_record_history_error("session_wrong") ==
               Result::session_mismatch,
           "wrong session cannot record history error");
    expect(agent_q::method_signing_request_flow_record_history_error(
               "session_abcdefghijklmnop") == Result::terminal_history_error,
           "history error terminalizes and wipes payload");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.signable_payload_size == 0, "history error wipes payload size");
    expect_payload_copy_unavailable("history-error terminal does not expose payload");
    expect(agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "history-error terminal is consumable");
    expect(terminal.result == Terminal::history_error, "terminal records history error");

    begin_valid();
    expect(agent_q::method_signing_request_flow_record_user_approved(
               "session_abcdefghijklmnop",
               100) == Result::terminal_user_timeout,
           "approval at deadline records timeout instead of signing");
    expect_payload_copy_unavailable("deadline approval timeout does not expose payload");
    expect(agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "deadline approval terminal is consumable");
    expect(terminal.result == Terminal::user_timeout, "deadline approval records timeout");

    begin_valid();
    expect(agent_q::method_signing_request_flow_record_user_approved(
               "session_abcdefghijklmnop",
               90) == Result::user_approved_waiting_history,
           "matching approval waits for durable history");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.stage == Stage::awaiting_history,
           "approval enters history durability stage");
    expect_payload_copy_unavailable("approval before durable history does not expose payload");
    expect(agent_q::method_signing_request_flow_record_history_durable("session_wrong") ==
               Result::session_mismatch,
           "wrong session cannot mark history durable");
    expect(agent_q::method_signing_request_flow_record_history_durable(
               "session_abcdefghijklmnop") == Result::history_durable,
           "durable history enters signing critical section");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section,
           "history durability enters signing critical section");
    uint8_t copied_payload[sizeof(kPayload)] = {};
    size_t copied_size = 0;
    expect(agent_q::method_signing_request_flow_copy_signable_payload(
               copied_payload,
               sizeof(copied_payload),
               &copied_size),
           "critical section exposes payload copy");
    expect(copied_size == sizeof(kPayload), "critical section reports payload size");
    expect(memcmp(copied_payload, kPayload, sizeof(kPayload)) == 0,
           "critical section copies payload bytes");
    uint8_t short_payload[sizeof(kPayload) - 1] = {};
    copied_size = 99;
    expect(!agent_q::method_signing_request_flow_copy_signable_payload(
               short_payload,
               sizeof(short_payload),
               &copied_size),
           "short output buffer rejects payload copy");
    expect(copied_size == 0, "short output payload copy resets copied size");
    expect(agent_q::method_signing_request_flow_cancel_for_disconnect(
               "session_abcdefghijklmnop") == Result::terminal_canceled,
           "disconnect cancels critical section and wipes payload");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.signable_payload_size == 0, "critical disconnect wipes payload size");
    expect_payload_copy_unavailable("critical disconnect terminal does not expose payload");
    expect(agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "critical disconnect terminal is consumable");
    expect(terminal.result == Terminal::canceled, "terminal records critical cancellation");

    begin_valid();
    expect(agent_q::method_signing_request_flow_record_user_approved(
               "session_abcdefghijklmnop",
               90) == Result::user_approved_waiting_history,
           "approval waits for durable history before method error");
    expect(agent_q::method_signing_request_flow_record_history_durable(
               "session_abcdefghijklmnop") == Result::history_durable,
           "history durable enters critical before method error");
    expect(agent_q::method_signing_request_flow_record_method_error(
               "session_abcdefghijklmnop") == Result::terminal_method_error,
           "method error terminalizes critical section");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.signable_payload_size == 0, "method error wipes payload size");
    expect_payload_copy_unavailable("method-error terminal does not expose payload");
    expect(agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "method-error terminal is consumable");
    expect(terminal.result == Terminal::method_error, "terminal records method error");

    begin_valid();
    expect(agent_q::method_signing_request_flow_record_user_approved(
               "session_abcdefghijklmnop",
               90) == Result::user_approved_waiting_history,
           "approval waits for durable history before session-loss test");
    expect(agent_q::method_signing_request_flow_record_history_durable(
               "session_abcdefghijklmnop") == Result::history_durable,
           "history durable enters critical before session-loss test");
    expect(agent_q::method_signing_request_flow_cancel_for_session_loss(
               "session_abcdefghijklmnop") == Result::terminal_session_lost,
           "session loss cancels critical section and wipes payload");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.signable_payload_size == 0, "critical session loss wipes payload size");
    expect_payload_copy_unavailable("critical session loss terminal does not expose payload");
    expect(agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "critical session-loss terminal is consumable");
    expect(terminal.result == Terminal::session_lost, "terminal records critical session loss");

    begin_valid();
    expect(agent_q::method_signing_request_flow_record_user_approved(
               "session_abcdefghijklmnop",
               90) == Result::user_approved_waiting_history,
           "approval waits for durable history before approved completion");
    expect(agent_q::method_signing_request_flow_record_history_durable(
               "session_abcdefghijklmnop") == Result::history_durable,
           "history durable enters critical before approved completion");
    expect(agent_q::method_signing_request_flow_complete_approved(
               "session_wrong") == Result::session_mismatch,
           "wrong session cannot complete approval");
    expect(agent_q::method_signing_request_flow_complete_approved(
               "session_abcdefghijklmnop") == Result::terminal_user_approved,
           "approved critical section terminalizes");
    snapshot = agent_q::method_signing_request_flow_snapshot();
    expect(snapshot.signable_payload_size == 0, "approved completion wipes payload size");
    expect_payload_copy_unavailable("approved terminal does not expose payload");
    expect(agent_q::method_signing_request_flow_consume_terminal(&terminal),
           "approved terminal is consumable");
    expect(terminal.result == Terminal::user_approved, "terminal records approved result");

    agent_q::method_signing_request_flow_clear();
    expect(agent_q::method_signing_request_flow_record_timeout(100) == Result::inactive,
           "inactive timeout is ignored");
    expect(agent_q::method_signing_request_flow_begin(
               valid_input("", "session_abcdefghijklmnop")) == Result::invalid_argument,
           "empty request id is rejected");
    char too_long[agent_q::kAgentQMethodSigningRequestIdSize + 4] = {};
    memset(too_long, 'a', sizeof(too_long) - 1);
    expect(agent_q::method_signing_request_flow_begin(
               valid_input(too_long, "session_abcdefghijklmnop")) == Result::invalid_argument,
           "overlong request id is rejected");
    expect(agent_q::method_signing_request_flow_begin(
               valid_input("method-null", "session_abcdefghijklmnop", nullptr, sizeof(kPayload))) ==
               Result::invalid_argument,
           "null payload is rejected");
    expect(agent_q::method_signing_request_flow_begin(
               valid_input("method-empty", "session_abcdefghijklmnop", kPayload, 0)) ==
               Result::invalid_argument,
           "empty payload is rejected");
    uint8_t oversized_payload[agent_q::kAgentQMethodSigningRequestPayloadMaxBytes + 1] = {};
    expect(agent_q::method_signing_request_flow_begin(
               valid_input(
                   "method-oversized",
                   "session_abcdefghijklmnop",
                   oversized_payload,
                   sizeof(oversized_payload))) == Result::invalid_argument,
           "oversized payload is rejected");
    expect(!agent_q::method_signing_request_flow_active(), "invalid begin leaves state inactive");

    if (failures != 0) {
        fprintf(stderr, "%d method signing request flow test(s) failed\n", failures);
        return 1;
    }
    printf("Method signing request flow tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/method_signing_request_flow_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_method_signing_request_flow.cpp" \
  -o "${TMP_DIR}/method_signing_request_flow_test"

"${TMP_DIR}/method_signing_request_flow_test"
