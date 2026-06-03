#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_signature_request_flow.sh

Compiles the StackChan CoreS3 device-confirmed signature request flow owner
against host stubs and verifies pending state, session ownership, terminal
cleanup, and signable payload one-shot consumption. This test uses only a host
C++ compiler and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-signature-request-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/signature_request_flow_test.cpp" <<'CPP'
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "agent_q_signature_request_flow.h"
#include "agent_q_sui_account_store.h"

namespace {

int failures = 0;
bool g_digest_result = true;
int g_digest_calls = 0;
agent_q::SuiAccountDerivationResult g_account_result =
    agent_q::SuiAccountDerivationResult::ok;
char g_account_address[agent_q::kSuiAddressBufferSize] =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
bool g_history_write_result = true;
bool g_history_write_clears_session = false;
bool g_history_write_clears_flow = false;
bool g_history_write_restarts_flow = false;
int g_history_write_calls = 0;

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
    uint8_t* bytes = static_cast<uint8_t*>(output);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = static_cast<uint8_t>(index + 1);
    }
    return true;
}

std::string read_file(const char* path)
{
    FILE* file = fopen(path, "rb");
    if (file == nullptr) {
        fprintf(stderr, "Could not open %s\n", path);
        exit(1);
    }
    std::string data;
    char buffer[4096];
    while (true) {
        const size_t read = fread(buffer, 1, sizeof(buffer), file);
        if (read != 0) {
            data.append(buffer, read);
        }
        if (read < sizeof(buffer)) {
            if (ferror(file)) {
                fprintf(stderr, "Could not read %s\n", path);
                fclose(file);
                exit(1);
            }
            break;
        }
    }
    fclose(file);
    return data;
}

int hex_value(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return 10 + value - 'a';
    }
    if (value >= 'A' && value <= 'F') {
        return 10 + value - 'A';
    }
    return -1;
}

std::vector<uint8_t> read_hex_fixture(const char* path)
{
    const std::string raw = read_file(path);
    std::string hex;
    for (char ch : raw) {
        if (!isspace(static_cast<unsigned char>(ch))) {
            hex.push_back(ch);
        }
    }
    if (hex.size() % 2 != 0) {
        fprintf(stderr, "Odd-length hex fixture: %s\n", path);
        exit(1);
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t index = 0; index < hex.size(); index += 2) {
        const int high = hex_value(hex[index]);
        const int low = hex_value(hex[index + 1]);
        if (high < 0 || low < 0) {
            fprintf(stderr, "Invalid hex fixture: %s\n", path);
            exit(1);
        }
        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return bytes;
}

const std::vector<uint8_t>& valid_payload()
{
    static const std::vector<uint8_t> payload =
        read_hex_fixture(AGENT_Q_TEST_VALID_SUI_TRANSFER_TX_HEX);
    return payload;
}

constexpr const char* kDefaultStoredSigner =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

agent_q::AgentQSignatureRequestBeginInput make_valid_input(
    const char* request_id,
    const char* session_id,
    const uint8_t* payload,
    size_t payload_size)
{
    return agent_q::AgentQSignatureRequestBeginInput{
        request_id,
        session_id,
        "sui",
        "sign_transaction",
        "devnet",
        payload,
        payload_size,
        100,
    };
}

void reset_account_stub()
{
    g_account_result = agent_q::SuiAccountDerivationResult::ok;
    snprintf(g_account_address, sizeof(g_account_address), "%s", kDefaultStoredSigner);
}

void reset_history_writer_stub()
{
    g_history_write_result = true;
    g_history_write_clears_session = false;
    g_history_write_clears_flow = false;
    g_history_write_restarts_flow = false;
    g_history_write_calls = 0;
}

bool write_confirmation_history(
    const agent_q::AgentQSignatureRequestFlowSnapshot& snapshot,
    void*)
{
    ++g_history_write_calls;
    expect(snapshot.stage == agent_q::AgentQSignatureRequestStage::history_write,
           "history writer receives history_write snapshot");
    expect(snapshot.signable_payload_available,
           "history writer runs before payload handoff");
    if (g_history_write_clears_session) {
        agent_q::session_clear();
    }
    if (g_history_write_clears_flow) {
        expect(agent_q::signature_request_flow_clear() ==
                   agent_q::AgentQSignatureRequestTransitionResult::ok,
               "history writer can clear pre-critical flow in misuse test");
    }
    if (g_history_write_restarts_flow) {
        expect(agent_q::signature_request_flow_clear() ==
                   agent_q::AgentQSignatureRequestTransitionResult::ok,
               "history writer can clear before reentrant begin in misuse test");
        const std::vector<uint8_t>& payload = valid_payload();
        expect(agent_q::signature_request_flow_begin(
                   make_valid_input(
                       "req_reentrant_writer",
                       agent_q::session_id(),
                       payload.data(),
                       payload.size())) ==
                   agent_q::AgentQSignatureRequestFlowBeginResult::ok,
               "history writer can start a different request in misuse test");
    }
    return g_history_write_result;
}

bool begin_valid_flow(const char* request_id = "req_signature_1")
{
    const std::vector<uint8_t>& payload = valid_payload();
    return agent_q::signature_request_flow_begin(
               make_valid_input(request_id, agent_q::session_id(), payload.data(), payload.size())) ==
           agent_q::AgentQSignatureRequestFlowBeginResult::ok;
}

}  // namespace

namespace agent_q {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool approval_history_digest_payload(
    const uint8_t* payload,
    size_t payload_size,
    char* output,
    size_t output_size)
{
    ++g_digest_calls;
    if (!g_digest_result ||
        payload == nullptr ||
        payload_size == 0 ||
        output == nullptr ||
        output_size != kAgentQApprovalHistoryDigestSize) {
        return false;
    }
    strlcpy(output, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", output_size);
    return true;
}

SuiAccountDerivationResult derive_sui_ed25519_account_from_stored_root(
    uint8_t public_key_out[kSuiEd25519PublicKeyBytes],
    char* address_out,
    size_t address_out_size)
{
    if (public_key_out != nullptr) {
        memset(public_key_out, 0x42, kSuiEd25519PublicKeyBytes);
    }
    if (address_out != nullptr && address_out_size > 0) {
        address_out[0] = '\0';
    }
    if (g_account_result != SuiAccountDerivationResult::ok ||
        address_out == nullptr ||
        address_out_size < kSuiAddressBufferSize) {
        return g_account_result;
    }
    snprintf(address_out, address_out_size, "%s", g_account_address);
    return SuiAccountDerivationResult::ok;
}

}  // namespace agent_q

int main()
{
    using Begin = agent_q::AgentQSignatureRequestFlowBeginResult;
    using Stage = agent_q::AgentQSignatureRequestStage;
    using Transition = agent_q::AgentQSignatureRequestTransitionResult;
    using Terminal = agent_q::AgentQSignatureRequestTerminalResult;
    using SessionValidation = agent_q::AgentQSessionValidationResult;

    agent_q::session_init();
    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session starts");

    expect(agent_q::signature_request_flow_clear() == Transition::inactive,
           "clear on inactive flow reports inactive");
    expect(!agent_q::signature_request_flow_active(), "clear leaves flow inactive");
    expect(agent_q::signature_request_flow_validate_session() == SessionValidation::missing,
           "inactive flow has no session");

    const std::vector<uint8_t>& payload = valid_payload();
    expect(agent_q::signature_request_flow_begin(
               make_valid_input("req_signature_1", agent_q::session_id(), payload.data(), payload.size())) ==
               Begin::ok,
           "valid request begins in reviewing stage");
    agent_q::AgentQSignatureRequestFlowSnapshot snapshot =
        agent_q::signature_request_flow_snapshot();
    expect(snapshot.active, "snapshot is active");
    expect(snapshot.stage == Stage::reviewing, "begin starts at reviewing");
    expect(strcmp(snapshot.request_id, "req_signature_1") == 0, "request id stored");
    expect(strcmp(snapshot.session_id, agent_q::session_id()) == 0, "session id stored");
    expect(strcmp(snapshot.chain, "sui") == 0, "chain stored");
    expect(strcmp(snapshot.method, "sign_transaction") == 0, "method stored");
    expect(strcmp(snapshot.network, "devnet") == 0, "network stored");
    expect(strcmp(snapshot.payload_digest, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0,
           "payload digest stored");
    expect(snapshot.signable_payload_available, "payload initially available to owner");
    expect(snapshot.signable_payload_size == payload.size(), "payload size stored");
    expect(strcmp(snapshot.sui_transfer.sender, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0,
           "summary sender is parsed from payload");
    expect(strcmp(snapshot.sui_transfer.gas_owner, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0,
           "summary gas owner is parsed from payload");
    expect(strcmp(snapshot.sui_transfer.recipient, "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0,
           "summary recipient is parsed from payload");
    expect(strcmp(snapshot.sui_transfer.amount, "1000000") == 0, "summary amount is parsed from payload");
    expect(strcmp(snapshot.sui_transfer.gas_budget, "50000000") == 0, "summary gas budget is parsed from payload");
    expect(strcmp(snapshot.sui_transfer.gas_price, "1000") == 0, "summary gas price is parsed from payload");
    expect(agent_q::signature_request_flow_validate_session() == SessionValidation::ok,
           "matching active session validates");
    expect(agent_q::signature_request_flow_session_matches(agent_q::session_id()),
           "session match helper recognizes owner session");
    agent_q::AgentQSignatureRequestFlowSnapshot retained_snapshot = snapshot;
    expect(agent_q::signature_request_flow_clear() == Transition::ok,
           "clear before critical section succeeds");
    expect(strcmp(retained_snapshot.request_id, "req_signature_1") == 0 &&
               strcmp(retained_snapshot.session_id, snapshot.session_id) == 0 &&
               strcmp(retained_snapshot.payload_digest, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0,
           "snapshot owns copied request metadata after flow clear");
    expect(!agent_q::signature_request_flow_active(), "pre-critical clear leaves flow inactive");
    expect(agent_q::signature_request_flow_begin(
               make_valid_input("req_signature_1", agent_q::session_id(), payload.data(), payload.size())) ==
               Begin::ok,
           "valid request restarts after snapshot value test");

    expect(agent_q::signature_request_flow_begin(
               make_valid_input("req_signature_2", agent_q::session_id(), payload.data(), payload.size())) ==
               Begin::active,
           "duplicate begin is rejected");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(strcmp(snapshot.request_id, "req_signature_1") == 0,
           "duplicate begin does not overwrite state");

    std::vector<uint8_t> copied(payload.size());
    size_t copied_size = 0;
    expect(agent_q::signature_request_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::wrong_stage,
           "payload cannot be consumed before history is durable");
    expect(copied_size == 0, "failed consume reports zero size");

    expect(agent_q::signature_request_flow_record_timeout(99) == Transition::deadline_not_reached,
           "timeout before deadline is rejected");
    expect(agent_q::signature_request_flow_accept_review(99, 0) == Transition::invalid_deadline,
           "zero PIN deadline is rejected");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::reviewing, "invalid PIN deadline leaves review active");
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::ok,
           "review acceptance moves to PIN entry");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::pin_entry && snapshot.deadline == 200,
           "PIN entry stage stores new deadline");
    expect(agent_q::signature_request_flow_record_pin_verified(199) == Transition::ok,
           "PIN verification moves to history write");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::history_write, "history write stage reached");
    expect(agent_q::signature_request_flow_write_confirmation_history(nullptr, nullptr) ==
               Transition::invalid_argument,
           "history writer callback is required");
    expect(agent_q::signature_request_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::wrong_stage,
           "payload cannot be consumed before history durable transition");
    expect(agent_q::signature_request_flow_write_confirmation_history(write_confirmation_history, nullptr) == Transition::ok,
           "history durable transition enters critical section");
    expect(agent_q::signature_request_flow_in_signing_critical_section(),
           "critical section helper is true");
    expect(agent_q::signature_request_flow_clear() == Transition::busy,
           "public clear cannot wipe signing critical section");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section &&
               snapshot.signable_payload_available,
           "critical section remains active after public clear");
    expect(agent_q::signature_request_flow_complete_signed() == Transition::payload_not_consumed,
           "signed terminal requires one-shot payload handoff first");
    expect(agent_q::signature_request_flow_consume_signable_payload(copied.data(), copied.size() - 1, &copied_size) ==
               Transition::output_too_small,
           "small output buffer is rejected");
    expect(agent_q::signature_request_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::ok,
           "payload is consumable after history durability");
    expect(copied_size == payload.size() && memcmp(copied.data(), payload.data(), payload.size()) == 0,
           "payload copy matches source");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(!snapshot.signable_payload_available && snapshot.signable_payload_size == 0,
           "payload scratch is wiped after one-shot consume");
    expect(agent_q::signature_request_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::payload_unavailable,
           "payload cannot be consumed twice");
    expect(agent_q::signature_request_flow_complete_signed() == Transition::ok,
           "signed terminal is recorded");
    expect(agent_q::signature_request_flow_terminal_pending(), "signed terminal is pending");
    Terminal terminal = Terminal::none;
    expect(agent_q::signature_request_flow_consume_terminal_result(&terminal) &&
               terminal == Terminal::signed_success,
           "signed terminal is one-shot consumable");
    expect(!agent_q::signature_request_flow_active(), "terminal consume clears state");
    expect(!agent_q::signature_request_flow_consume_terminal_result(&terminal),
           "terminal result cannot be consumed twice");
    expect(strcmp(agent_q::signature_request_flow_terminal_status(Terminal::signed_success), "signed") == 0 &&
               strcmp(agent_q::signature_request_flow_terminal_reason(Terminal::signed_success), "device_confirmed") == 0,
           "signed terminal mapping");

    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_reject"), "begin before reject");
    expect(agent_q::signature_request_flow_record_device_rejected() == Transition::ok,
           "device rejection terminalizes from review");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::rejected &&
               !snapshot.signable_payload_available,
           "reject terminal wipes payload");
    expect(agent_q::signature_request_flow_consume_terminal_result(&terminal) &&
               terminal == Terminal::rejected,
           "rejected terminal consumed");
    expect(strcmp(agent_q::signature_request_flow_terminal_status(Terminal::rejected), "rejected") == 0 &&
               strcmp(agent_q::signature_request_flow_terminal_reason(Terminal::rejected), "device_rejected") == 0,
           "rejected terminal mapping");

    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_timeout"), "begin before timeout");
    expect(agent_q::signature_request_flow_record_timeout(100) == Transition::ok,
           "deadline timeout terminalizes");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::timed_out &&
               !snapshot.signable_payload_available,
           "timeout terminal wipes payload");
    expect(strcmp(agent_q::signature_request_flow_terminal_status(Terminal::timed_out), "timed_out") == 0 &&
               strcmp(agent_q::signature_request_flow_terminal_reason(Terminal::timed_out), "device_timed_out") == 0,
           "timeout terminal mapping");

    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_history_error"), "begin before history error");
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::ok,
           "review before history error");
    expect(agent_q::signature_request_flow_record_pin_verified(199) == Transition::ok,
           "PIN verified before history error");
    expect(agent_q::signature_request_flow_record_device_rejected() == Transition::wrong_stage,
           "device rejection cannot reclassify confirmed request during history write");
    g_history_write_result = false;
    expect(agent_q::signature_request_flow_write_confirmation_history(write_confirmation_history, nullptr) == Transition::history_error,
           "history error terminalizes before signing");
    g_history_write_result = true;
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::history_error &&
               !snapshot.signable_payload_available,
           "history error terminal wipes payload");
    expect(strcmp(agent_q::signature_request_flow_terminal_status(Terminal::history_error), "") == 0 &&
               strcmp(agent_q::signature_request_flow_terminal_reason(Terminal::history_error), "") == 0,
           "history error is cleanup-only, not a signature_result status");

    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_disconnect"), "begin before disconnect");
    expect(agent_q::signature_request_flow_cancel_for_session_loss() == Transition::session_still_active,
           "session-loss cancellation cannot be caller-commanded while session is active");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::reviewing && snapshot.signable_payload_available,
           "active session-loss cancellation attempt leaves request active");
    expect(agent_q::signature_request_flow_cancel_for_disconnect("session_aaaaaaaaaaaaaaaa") ==
               Transition::invalid_session,
           "mismatched disconnect does not cancel");
    expect(agent_q::signature_request_flow_cancel_for_disconnect(agent_q::session_id()) ==
               Transition::ok,
           "matching disconnect cancels before critical section");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::canceled &&
               !snapshot.signable_payload_available,
           "disconnect cancel terminal wipes payload");
    expect(strcmp(agent_q::signature_request_flow_terminal_status(Terminal::canceled), "") == 0 &&
               strcmp(agent_q::signature_request_flow_terminal_reason(Terminal::canceled), "") == 0,
           "canceled is cleanup-only, not a signature_result status");

    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_signing_failed"), "begin before signing failure");
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::ok, "review before signing failure");
    expect(agent_q::signature_request_flow_record_pin_verified(199) == Transition::ok, "pin before signing failure");
    expect(agent_q::signature_request_flow_write_confirmation_history(write_confirmation_history, nullptr) == Transition::ok, "history before signing failure");
    expect(agent_q::signature_request_flow_record_signing_failed() == Transition::ok,
           "signing failure terminalizes critical section");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::signing_failed &&
               !snapshot.signable_payload_available,
           "signing failure wipes payload");
    expect(strcmp(agent_q::signature_request_flow_terminal_status(Terminal::signing_failed), "failed") == 0 &&
               strcmp(agent_q::signature_request_flow_terminal_reason(Terminal::signing_failed), "signing_failed") == 0,
           "signing failure terminal mapping");

    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_expired_review"), "begin before expired review");
    expect(agent_q::signature_request_flow_accept_review(100, 200) == Transition::deadline_expired,
           "accept review after review deadline terminalizes as timeout");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::timed_out &&
               !snapshot.signable_payload_available,
           "expired review wipes payload");

    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_expired_pin"), "begin before expired PIN");
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::ok,
           "review accepted before PIN expiry test");
    expect(agent_q::signature_request_flow_record_pin_verified(200) == Transition::deadline_expired,
           "PIN verification after PIN deadline terminalizes as timeout");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::timed_out &&
               !snapshot.signable_payload_available,
           "expired PIN wipes payload");

    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_expired_pin_deadline"), "begin before expired PIN deadline handoff");
    expect(agent_q::signature_request_flow_accept_review(99, 99) == Transition::deadline_expired,
           "expired PIN deadline handoff terminalizes as timeout");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::timed_out &&
               !snapshot.signable_payload_available,
           "expired PIN handoff wipes payload");

    agent_q::signature_request_flow_clear();
    char saved_session_id[agent_q::kAgentQSessionIdSize] = {};
    strlcpy(saved_session_id, agent_q::session_id(), sizeof(saved_session_id));
    agent_q::session_clear();
    expect(agent_q::signature_request_flow_begin(
               make_valid_input("req_missing_session", saved_session_id, payload.data(), payload.size())) ==
               Begin::invalid_session,
           "begin rejects stale session id");
    expect(!agent_q::signature_request_flow_active(), "stale session leaves flow inactive");

    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session restarts for mid-flow session loss");
    expect(begin_valid_flow("req_session_loss_review"), "begin before review session loss");
    agent_q::session_clear();
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::invalid_session,
           "review acceptance revalidates session");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::canceled &&
               !snapshot.signable_payload_available,
           "review session loss cancels and wipes payload");

    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session restarts for PIN session loss");
    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_session_loss_pin"), "begin before PIN session loss");
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::ok,
           "review accepted before PIN session loss");
    agent_q::session_clear();
    expect(agent_q::signature_request_flow_record_pin_verified(199) == Transition::invalid_session,
           "PIN verification revalidates session");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::canceled &&
               !snapshot.signable_payload_available,
           "PIN session loss cancels and wipes payload");

    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session restarts for history session loss");
    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_session_loss_history"), "begin before history session loss");
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::ok,
           "review accepted before history session loss");
    expect(agent_q::signature_request_flow_record_pin_verified(199) == Transition::ok,
           "PIN verified before history session loss");
    agent_q::session_clear();
    expect(agent_q::signature_request_flow_write_confirmation_history(write_confirmation_history, nullptr) == Transition::invalid_session,
           "history durable transition revalidates session");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::canceled &&
               !snapshot.signable_payload_available,
           "history session loss cancels and wipes payload");

    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session restarts for history writer interleave");
    agent_q::signature_request_flow_clear();
    reset_history_writer_stub();
    expect(begin_valid_flow("req_history_writer_clears_session"), "begin before writer clears session");
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::ok,
           "review accepted before writer clears session");
    expect(agent_q::signature_request_flow_record_pin_verified(199) == Transition::ok,
           "PIN verified before writer clears session");
    g_history_write_clears_session = true;
    expect(agent_q::signature_request_flow_write_confirmation_history(write_confirmation_history, nullptr) ==
               Transition::ok,
           "successful history write cannot be downgraded by post-write session loss");
    g_history_write_clears_session = false;
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section &&
               snapshot.signable_payload_available,
           "writer success enters critical section even if session disappears after write");
    expect(agent_q::signature_request_flow_record_signing_failed() == Transition::ok,
           "writer interleave flow still ends with signing terminal");

    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session restarts for history writer clear reentry");
    agent_q::signature_request_flow_clear();
    reset_history_writer_stub();
    expect(begin_valid_flow("req_history_writer_clears_flow"), "begin before writer clears flow");
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::ok,
           "review accepted before writer clears flow");
    expect(agent_q::signature_request_flow_record_pin_verified(199) == Transition::ok,
           "PIN verified before writer clears flow");
    g_history_write_clears_flow = true;
    expect(agent_q::signature_request_flow_write_confirmation_history(write_confirmation_history, nullptr) ==
               Transition::stale_state,
           "writer clear reentry cannot enter critical section");
    g_history_write_clears_flow = false;
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(!snapshot.active,
           "writer clear reentry leaves no active critical request");

    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session restarts for history writer restart reentry");
    agent_q::signature_request_flow_clear();
    reset_history_writer_stub();
    expect(begin_valid_flow("req_history_writer_restarts_flow"), "begin before writer restarts flow");
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::ok,
           "review accepted before writer restarts flow");
    expect(agent_q::signature_request_flow_record_pin_verified(199) == Transition::ok,
           "PIN verified before writer restarts flow");
    g_history_write_restarts_flow = true;
    expect(agent_q::signature_request_flow_write_confirmation_history(write_confirmation_history, nullptr) ==
               Transition::stale_state,
           "writer restart reentry cannot move a different request to critical");
    g_history_write_restarts_flow = false;
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.active &&
               snapshot.stage == Stage::reviewing &&
               strcmp(snapshot.request_id, "req_reentrant_writer") == 0,
           "writer restart reentry leaves the new request outside critical section");
    expect(agent_q::signature_request_flow_clear() == Transition::ok,
           "cleanup reentrant writer test request");

    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session restarts for critical cancel");
    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_critical_cancel"), "begin before critical cancel");
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::ok,
           "review accepted before critical cancel");
    expect(agent_q::signature_request_flow_record_pin_verified(199) == Transition::ok,
           "PIN verified before critical cancel");
    expect(agent_q::signature_request_flow_write_confirmation_history(write_confirmation_history, nullptr) == Transition::ok,
           "history durable before critical cancel");
    char critical_session_id[agent_q::kAgentQSessionIdSize] = {};
    strlcpy(critical_session_id, agent_q::session_id(), sizeof(critical_session_id));
    expect(agent_q::signature_request_flow_cancel_for_disconnect(critical_session_id) == Transition::busy,
           "matching disconnect cannot cancel signing critical section");
    expect(agent_q::signature_request_flow_cancel_for_session_loss() == Transition::busy,
           "session loss cannot cancel signing critical section");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section &&
               snapshot.signable_payload_available,
           "critical section remains active after disconnect/session loss");
    expect(agent_q::signature_request_flow_record_signing_failed() == Transition::ok,
           "critical section still requires signed or signing-failed terminal");

    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session restarts for critical consume session loss");
    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_session_loss_consume"), "begin before consume session loss");
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::ok,
           "review accepted before consume session loss");
    expect(agent_q::signature_request_flow_record_pin_verified(199) == Transition::ok,
           "PIN verified before consume session loss");
    expect(agent_q::signature_request_flow_write_confirmation_history(write_confirmation_history, nullptr) == Transition::ok,
           "history durable before consume session loss");
    agent_q::session_clear();
    expect(agent_q::signature_request_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::ok,
           "payload consume continues after durable history even if session is gone");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section &&
               !snapshot.signable_payload_available,
           "consume after session loss keeps critical section and wipes payload scratch");
    expect(agent_q::signature_request_flow_record_signing_failed() == Transition::ok,
           "consume session loss must still end as signing failed or signed");

    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session restarts for signed-complete session loss");
    agent_q::signature_request_flow_clear();
    expect(begin_valid_flow("req_session_loss_complete"), "begin before complete session loss");
    expect(agent_q::signature_request_flow_accept_review(99, 200) == Transition::ok,
           "review accepted before complete session loss");
    expect(agent_q::signature_request_flow_record_pin_verified(199) == Transition::ok,
           "PIN verified before complete session loss");
    expect(agent_q::signature_request_flow_write_confirmation_history(write_confirmation_history, nullptr) == Transition::ok,
           "history durable before complete session loss");
    expect(agent_q::signature_request_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::ok,
           "payload consumed before complete session loss");
    agent_q::session_clear();
    expect(agent_q::signature_request_flow_complete_signed() == Transition::ok,
           "signed completion reports generated signature after session loss");
    snapshot = agent_q::signature_request_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::signed_success,
           "complete session loss cannot downgrade generated signature");

    agent_q::signature_request_flow_clear();
    g_digest_result = false;
    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session restarts");
    expect(agent_q::signature_request_flow_begin(
               make_valid_input("req_digest_fail", agent_q::session_id(), payload.data(), payload.size())) ==
               Begin::digest_error,
           "digest failure prevents begin");
    expect(!agent_q::signature_request_flow_active(), "digest failure leaves flow inactive");
    g_digest_result = true;

    agent_q::AgentQSignatureRequestBeginInput invalid_deadline =
        make_valid_input("req_bad_deadline", agent_q::session_id(), payload.data(), payload.size());
    invalid_deadline.deadline = 0;
    expect(agent_q::signature_request_flow_begin(invalid_deadline) == Begin::invalid_deadline,
           "zero review deadline rejected");
    expect(!agent_q::signature_request_flow_active(), "invalid deadline leaves flow inactive");

    static const uint8_t unrelated_payload[] = {0x01, 0x02, 0x03, 0x04};
    expect(agent_q::signature_request_flow_begin(
               make_valid_input("req_unparsed_payload", agent_q::session_id(), unrelated_payload, sizeof(unrelated_payload))) ==
               Begin::invalid_transaction,
           "payload without parser-derived transfer facts is rejected");
    expect(!agent_q::signature_request_flow_active(), "invalid transaction leaves flow inactive");

    snprintf(
        g_account_address,
        sizeof(g_account_address),
        "%s",
        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    expect(agent_q::signature_request_flow_begin(
               make_valid_input("req_wrong_stored_account", agent_q::session_id(), payload.data(), payload.size())) ==
               Begin::invalid_account,
           "parsed sender must match Firmware-derived stored signer");
    expect(!agent_q::signature_request_flow_active(), "stored account mismatch leaves flow inactive");
    reset_account_stub();

    g_account_result = agent_q::SuiAccountDerivationResult::root_material_unavailable;
    expect(agent_q::signature_request_flow_begin(
               make_valid_input("req_missing_account", agent_q::session_id(), payload.data(), payload.size())) ==
               Begin::account_unavailable,
           "missing stored account prevents begin");
    expect(!agent_q::signature_request_flow_active(), "missing account leaves flow inactive");
    reset_account_stub();

    const std::vector<uint8_t> sponsored_gas_payload =
        read_hex_fixture(AGENT_Q_TEST_SPONSORED_GAS_OWNER_TX_HEX);
    expect(agent_q::signature_request_flow_begin(
               make_valid_input(
                   "req_sponsored_gas_owner",
                   agent_q::session_id(),
                   sponsored_gas_payload.data(),
                   sponsored_gas_payload.size())) ==
               Begin::invalid_account,
           "gas owner must match Firmware-derived stored signer");
    expect(!agent_q::signature_request_flow_active(), "gas owner mismatch leaves flow inactive");

    agent_q::AgentQSignatureRequestBeginInput invalid_network =
        make_valid_input("req_bad_network", agent_q::session_id(), payload.data(), payload.size());
    invalid_network.network = "staging";
    expect(agent_q::signature_request_flow_begin(invalid_network) == Begin::invalid_network,
           "unsupported network rejected");

    agent_q::AgentQSignatureRequestBeginInput unsupported_method =
        make_valid_input("req_bad_method", agent_q::session_id(), payload.data(), payload.size());
    unsupported_method.method = "sign_personal_message";
    expect(agent_q::signature_request_flow_begin(unsupported_method) == Begin::unsupported_method,
           "unsupported method rejected");

    agent_q::AgentQSignatureRequestBeginInput empty_payload =
        make_valid_input("req_empty_payload", agent_q::session_id(), payload.data(), 0);
    expect(agent_q::signature_request_flow_begin(empty_payload) == Begin::invalid_payload,
           "empty payload rejected");

    char overlong_request_id[agent_q::kAgentQSignatureRequestIdSize + 4] = {};
    memset(overlong_request_id, 'a', sizeof(overlong_request_id) - 1);
    expect(agent_q::signature_request_flow_begin(
               make_valid_input(overlong_request_id, agent_q::session_id(), payload.data(), payload.size())) ==
               Begin::invalid_argument,
           "overlong request id rejected");
    expect(!agent_q::signature_request_flow_active(), "overlong request id leaves flow inactive");

    if (failures != 0) {
        fprintf(stderr, "%d signature request flow test(s) failed\n", failures);
        return 1;
    }
    printf("Signature request flow tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -DAGENT_Q_TEST_VALID_SUI_TRANSFER_TX_HEX=\"${COMMON_ROOT}/sui/testdata/sui_transaction_facts/valid_sui_transfer_tx.bcs.hex\" \
  -DAGENT_Q_TEST_SPONSORED_GAS_OWNER_TX_HEX=\"${COMMON_ROOT}/sui/testdata/sui_transaction_facts/sponsored_gas_owner_tx.bcs.hex\" \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_ROOT}/sui" \
  "${TMP_DIR}/signature_request_flow_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_signature_request_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${COMMON_ROOT}/sui/agent_q_sui_transaction_facts.cpp" \
  "${COMMON_ROOT}/sui/agent_q_sui_bcs_reader.cpp" \
  -o "${TMP_DIR}/signature_request_flow_test"

"${TMP_DIR}/signature_request_flow_test"
