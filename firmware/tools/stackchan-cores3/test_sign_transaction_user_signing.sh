#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sign_transaction_user_signing.sh

Compiles the StackChan CoreS3 device-confirmed sign_transaction_user signing
handoff helper against host stubs. It verifies that signing only happens inside
the request flow's signing critical section, the signable payload is one-shot,
and internal signed/signing_failed terminal state is recorded. This is not a
protocol signing test and does NOT require ESP-IDF.
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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-signature-request-signing.XXXXXX")"
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

cat >"${TMP_DIR}/sign_transaction_user_signing_test.cpp" <<'CPP'
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "agent_q_sign_transaction_user_flow.h"
#include "agent_q_sign_transaction_user_signing.h"
#include "agent_q_sui_account_store.h"

namespace {

int failures = 0;
int g_digest_calls = 0;
int g_signing_calls = 0;
bool g_signing_result_ok = true;
std::vector<uint8_t> g_last_signed_payload;

agent_q::SuiAccountDerivationResult g_account_result =
    agent_q::SuiAccountDerivationResult::ok;
char g_account_address[agent_q::kSuiAddressBufferSize] =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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

agent_q::AgentQSignTransactionUserBeginInput make_valid_input(
    const char* request_id,
    const char* session_id)
{
    const std::vector<uint8_t>& payload = valid_payload();
    return agent_q::AgentQSignTransactionUserBeginInput{
        request_id,
        session_id,
        "sui",
        "sign_transaction",
        "devnet",
        payload.data(),
        payload.size(),
        100,
    };
}

bool write_confirmation_history(
    const agent_q::AgentQSignTransactionUserFlowSnapshot& snapshot,
    void*)
{
    expect(snapshot.stage == agent_q::AgentQSignTransactionUserStage::history_write,
           "history writer receives history_write snapshot");
    return true;
}

void reset_state()
{
    agent_q::sign_transaction_user_flow_clear();
    agent_q::session_clear();
    g_digest_calls = 0;
    g_signing_calls = 0;
    g_signing_result_ok = true;
    g_last_signed_payload.clear();
    g_account_result = agent_q::SuiAccountDerivationResult::ok;
    snprintf(
        g_account_address,
        sizeof(g_account_address),
        "%s",
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

void begin_reviewing_request(const char* request_id)
{
    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "session starts");
    expect(agent_q::sign_transaction_user_flow_begin(
               make_valid_input(request_id, agent_q::session_id())) ==
               agent_q::AgentQSignTransactionUserFlowBeginResult::ok,
           "sign_transaction_user begins");
}

void enter_critical_section(const char* request_id)
{
    begin_reviewing_request(request_id);
    expect(agent_q::sign_transaction_user_flow_accept_review(50, 90) ==
               agent_q::AgentQSignTransactionUserTransitionResult::ok,
           "review accepted");
    expect(agent_q::sign_transaction_user_flow_pause_pin_deadline() ==
               agent_q::AgentQSignTransactionUserTransitionResult::ok,
           "PIN submit pauses input deadline");
    expect(agent_q::sign_transaction_user_flow_record_pin_verified_and_write_confirmation_history(55,
               write_confirmation_history,
               nullptr) == agent_q::AgentQSignTransactionUserTransitionResult::ok,
           "history write enters critical section");
    expect(agent_q::sign_transaction_user_flow_snapshot().stage ==
               agent_q::AgentQSignTransactionUserStage::signing_critical_section,
           "flow is in critical section");
}

void poison_output(agent_q::AgentQSignTransactionUserSigningOutput& output)
{
    memset(output.signature, 0xCC, sizeof(output.signature));
    output.signature_size = 999;
}

bool output_is_wiped(const agent_q::AgentQSignTransactionUserSigningOutput& output)
{
    if (output.signature_size != 0) {
        return false;
    }
    for (size_t index = 0; index < sizeof(output.signature); ++index) {
        if (output.signature[index] != 0) {
            return false;
        }
    }
    return true;
}

bool output_matches_stub_signature(
    const agent_q::AgentQSignTransactionUserSigningOutput& output)
{
    if (output.signature_size != agent_q::kSuiEd25519SignatureBytes) {
        return false;
    }
    for (size_t index = 0; index < output.signature_size; ++index) {
        if (output.signature[index] != 0xA5) {
            return false;
        }
    }
    return true;
}

}  // namespace

namespace agent_q {

void wipe_sensitive_buffer(void* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool approval_history_digest_payload(
    const uint8_t* payload,
    size_t payload_size,
    char* digest_out,
    size_t digest_out_size)
{
    ++g_digest_calls;
    if (payload == nullptr || payload_size == 0 || digest_out == nullptr || digest_out_size < 9) {
        return false;
    }
    snprintf(digest_out, digest_out_size, "digest%02d", g_digest_calls);
    return true;
}

SuiAccountDerivationResult derive_sui_ed25519_account_from_stored_root(
    uint8_t public_key_out[kSuiEd25519PublicKeyBytes],
    char* address_out,
    size_t address_out_size)
{
    if (public_key_out == nullptr || address_out == nullptr || address_out_size == 0) {
        return SuiAccountDerivationResult::derivation_error;
    }
    if (g_account_result != SuiAccountDerivationResult::ok) {
        memset(public_key_out, 0, kSuiEd25519PublicKeyBytes);
        address_out[0] = '\0';
        return g_account_result;
    }
    memset(public_key_out, 0x42, kSuiEd25519PublicKeyBytes);
    snprintf(address_out, address_out_size, "%s", g_account_address);
    return SuiAccountDerivationResult::ok;
}

SuiTransactionSigningResult sign_sui_ed25519_transaction_from_stored_root(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    uint8_t signature_out[kSuiEd25519SignatureBytes])
{
    ++g_signing_calls;
    g_last_signed_payload.assign(tx_bytes, tx_bytes + tx_bytes_size);
    if (signature_out != nullptr) {
        memset(signature_out, 0xA5, kSuiEd25519SignatureBytes);
    }
    return g_signing_result_ok ? SuiTransactionSigningResult::ok
                               : SuiTransactionSigningResult::signing_error;
}

const char* sui_transaction_signing_result_to_string(SuiTransactionSigningResult result)
{
    switch (result) {
        case SuiTransactionSigningResult::ok:
            return "ok";
        case SuiTransactionSigningResult::invalid_input:
            return "invalid_input";
        case SuiTransactionSigningResult::root_material_unavailable:
            return "root_material_unavailable";
        case SuiTransactionSigningResult::mnemonic_error:
            return "mnemonic_error";
        case SuiTransactionSigningResult::signing_error:
            return "signing_error";
    }
    return "unknown";
}

}  // namespace agent_q

int main()
{
    namespace aq = agent_q;
    aq::AgentQSignTransactionUserSigningOutput output = {};

    reset_state();
    poison_output(output);
    aq::AgentQSignTransactionUserSigningHandoffReport report =
        aq::sign_transaction_user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQSignTransactionUserSigningHandoffResult::inactive,
           "inactive flow cannot sign");
    expect(g_signing_calls == 0, "inactive flow does not call signing service");
    expect(output_is_wiped(output), "inactive flow wipes output");

    reset_state();
    enter_critical_section("req_null_output");
    report = aq::sign_transaction_user_signing_execute_critical_section(nullptr);
    expect(report.result == aq::AgentQSignTransactionUserSigningHandoffResult::invalid_output,
           "null output is rejected");
    expect(g_signing_calls == 0, "null output does not call signing service");
    expect(aq::sign_transaction_user_flow_snapshot().stage ==
               aq::AgentQSignTransactionUserStage::signing_critical_section,
           "null output keeps critical flow active");
    expect(aq::sign_transaction_user_flow_record_signing_failed() ==
               aq::AgentQSignTransactionUserTransitionResult::ok,
           "test cleanup terminalizes null-output critical flow");
    aq::AgentQSignTransactionUserTerminalResult cleanup_terminal =
        aq::AgentQSignTransactionUserTerminalResult::none;
    expect(aq::sign_transaction_user_flow_consume_terminal_result(&cleanup_terminal),
           "test cleanup consumes null-output terminal");

    reset_state();
    begin_reviewing_request("req_wrong_stage");
    poison_output(output);
    report = aq::sign_transaction_user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQSignTransactionUserSigningHandoffResult::wrong_stage,
           "reviewing flow cannot sign");
    expect(g_signing_calls == 0, "wrong stage does not call signing service");
    expect(output_is_wiped(output), "wrong stage wipes output");
    expect(aq::sign_transaction_user_flow_snapshot().stage ==
               aq::AgentQSignTransactionUserStage::reviewing,
           "wrong stage keeps request active");

    reset_state();
    enter_critical_section("req_success");
    const std::vector<uint8_t> expected_payload = valid_payload();
    poison_output(output);
    report = aq::sign_transaction_user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQSignTransactionUserSigningHandoffResult::ok,
           "critical section signs successfully");
    expect(report.flow_result == aq::AgentQSignTransactionUserTransitionResult::ok,
           "successful handoff completes flow");
    expect(report.signing_result == aq::SuiTransactionSigningResult::ok,
           "signing service result is reported");
    expect(g_signing_calls == 1, "signing service called once");
    expect(g_last_signed_payload == expected_payload,
           "signing service receives exact request payload");
    expect(output_matches_stub_signature(output),
           "successful signing returns caller-owned signature output");
    aq::AgentQSignTransactionUserFlowSnapshot snapshot = aq::sign_transaction_user_flow_snapshot();
    expect(snapshot.stage == aq::AgentQSignTransactionUserStage::terminal &&
               snapshot.terminal_result == aq::AgentQSignTransactionUserTerminalResult::signed_success,
           "successful signing records signed terminal");
    aq::AgentQSignTransactionUserTerminalResult terminal =
        aq::AgentQSignTransactionUserTerminalResult::none;
    expect(aq::sign_transaction_user_flow_consume_terminal_result(&terminal),
           "signed terminal can be consumed");
    expect(terminal == aq::AgentQSignTransactionUserTerminalResult::signed_success,
           "signed terminal value is preserved");

    reset_state();
    enter_critical_section("req_failure");
    g_signing_result_ok = false;
    poison_output(output);
    report = aq::sign_transaction_user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQSignTransactionUserSigningHandoffResult::signing_failed,
           "signing service failure is reported");
    expect(report.flow_result == aq::AgentQSignTransactionUserTransitionResult::ok,
           "signing failure terminalizes flow");
    expect(report.signing_result == aq::SuiTransactionSigningResult::signing_error,
           "signing failure cause is reported");
    expect(g_signing_calls == 1, "failing signing service called once");
    snapshot = aq::sign_transaction_user_flow_snapshot();
    expect(snapshot.stage == aq::AgentQSignTransactionUserStage::terminal &&
               snapshot.terminal_result == aq::AgentQSignTransactionUserTerminalResult::signing_failed,
           "signing service failure records failed terminal");
    expect(output_is_wiped(output), "signing service failure wipes output");

    reset_state();
    enter_critical_section("req_missing_payload");
    uint8_t consumed_payload[agent_q::kAgentQSuiSignTransactionTxBytesMaxBytes] = {};
    size_t consumed_size = 0;
    expect(aq::sign_transaction_user_flow_consume_signable_payload(
               consumed_payload,
               sizeof(consumed_payload),
               &consumed_size) == aq::AgentQSignTransactionUserTransitionResult::ok,
           "test setup consumes payload");
    poison_output(output);
    report = aq::sign_transaction_user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQSignTransactionUserSigningHandoffResult::payload_unavailable,
           "missing critical payload is reported");
    expect(g_signing_calls == 0, "missing payload does not call signing service");
    expect(output_is_wiped(output), "missing payload wipes output");
    snapshot = aq::sign_transaction_user_flow_snapshot();
    expect(snapshot.stage == aq::AgentQSignTransactionUserStage::terminal &&
               snapshot.terminal_result == aq::AgentQSignTransactionUserTerminalResult::signing_failed,
           "missing critical payload records failed terminal");

    reset_state();
    enter_critical_section("req_session_loss");
    aq::session_clear();
    poison_output(output);
    report = aq::sign_transaction_user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQSignTransactionUserSigningHandoffResult::ok,
           "critical signing is not downgraded by session loss");
    expect(output_matches_stub_signature(output),
           "post-history session loss still returns signature output");
    expect(aq::sign_transaction_user_flow_snapshot().terminal_result ==
               aq::AgentQSignTransactionUserTerminalResult::signed_success,
           "post-history session loss stays signed after service success");

    expect(strcmp(
               aq::sign_transaction_user_signing_handoff_result_name(
                   aq::AgentQSignTransactionUserSigningHandoffResult::payload_unavailable),
               "payload_unavailable") == 0,
           "result names include payload_unavailable");
    expect(strcmp(
               aq::sign_transaction_user_signing_handoff_result_name(
                   aq::AgentQSignTransactionUserSigningHandoffResult::invalid_output),
               "invalid_output") == 0,
           "result names include invalid_output");

    if (failures != 0) {
        fprintf(stderr, "%d sign_transaction_user signing test(s) failed\n", failures);
        return 1;
    }
    printf("sign_transaction_user signing tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -DAGENT_Q_TEST_VALID_SUI_TRANSFER_TX_HEX=\"${COMMON_ROOT}/sui/testdata/sui_transaction_facts/valid_sui_transfer_tx.bcs.hex\" \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_ROOT}/sui" \
  "${TMP_DIR}/sign_transaction_user_signing_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_signing.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_signing_authority.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${COMMON_ROOT}/sui/agent_q_sui_transaction_facts.cpp" \
  "${COMMON_ROOT}/sui/agent_q_sui_bcs_reader.cpp" \
  -o "${TMP_DIR}/sign_transaction_user_signing_test"

"${TMP_DIR}/sign_transaction_user_signing_test"
