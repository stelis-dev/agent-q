#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_user_signing_critical_section.sh

Compiles the StackChan CoreS3 device-confirmed user_signing critical-section
helper against host stubs. It verifies that signing only happens inside the
request flow's signing critical section, the signable payload is one-shot, and
internal signed/signing_failed terminal state is recorded. This is not a
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

cat >"${TMP_DIR}/user_signing_test.cpp" <<'CPP'
#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "agent_q_user_signing_flow.h"
#include "agent_q_user_signing_critical_section.h"
#include "agent_q_sui_account_store.h"
#include "agent_q_sui_zklogin_proof_store.h"

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

agent_q::AgentQTimeoutWindow pin_window(TickType_t started_at, TickType_t deadline)
{
    return agent_q::timeout_window_from_deadline(started_at, deadline);
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

constexpr TickType_t kDefaultRequestWindowStart = 0;

agent_q::AgentQTimeoutWindow request_window(TickType_t deadline)
{
    return agent_q::timeout_window_from_deadline(kDefaultRequestWindowStart, deadline);
}

const uint8_t kRequestIdentity[agent_q::kAgentQSignRequestIdentitySize] = {};

void fill_prepared_sui_facts(
    const uint8_t* payload,
    size_t payload_size,
    agent_q::AgentQSuiPreparedSignTransaction* prepared)
{
    agent_q::SuiParsedTransactionFacts parsed = {};
    assert(agent_q::parse_sui_parsed_transaction_facts(payload, payload_size, &parsed) ==
           agent_q::SuiTransactionFactsResult::ok);
    assert(agent_q::build_sui_policy_subject_facts(parsed, &prepared->sui_policy_subject));
    assert(agent_q::build_sui_review_summary(parsed, &prepared->sui_review));
    prepared->user_mode_authorization_covered = true;
    prepared->user_authorization_outcome =
        agent_q::AgentQSuiUserAuthorizationOutcome::offline_facts_review;
}

agent_q::AgentQUserSigningTransactionBeginInput make_valid_input(
    const char* request_id,
    const char* session_id)
{
    const std::vector<uint8_t>& payload = valid_payload();
    static agent_q::AgentQSuiPreparedSignTransaction prepared = {};
    if (prepared.tx_bytes != nullptr) {
        memset(prepared.tx_bytes, 0, prepared.tx_bytes_size);
        free(prepared.tx_bytes);
    }
    prepared = {};
    prepared.route = agent_q::AgentQSupportedSignRoute::sui_sign_transaction;
    snprintf(prepared.network, sizeof(prepared.network), "%s", "devnet");
    prepared.tx_bytes = static_cast<uint8_t*>(malloc(payload.size()));
    assert(prepared.tx_bytes != nullptr);
    memcpy(prepared.tx_bytes, payload.data(), payload.size());
    prepared.tx_bytes_size = payload.size();
    snprintf(prepared.payload_digest, sizeof(prepared.payload_digest),
             "%s", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    fill_prepared_sui_facts(payload.data(), payload.size(), &prepared);
    return agent_q::AgentQUserSigningTransactionBeginInput{
        request_id,
        kRequestIdentity,
        session_id,
        agent_q::AgentQSupportedSignRoute::sui_sign_transaction,
        &prepared,
        request_window(100),
    };
}

const std::vector<uint8_t>& valid_message()
{
    static const std::vector<uint8_t> message = {
        'A', 'g', 'e', 'n', 't', '-', 'Q', ' ', 'p', 'e', 'r', 's', 'o', 'n', 'a', 'l',
        ' ', 'm', 'e', 's', 's', 'a', 'g', 'e',
    };
    return message;
}

agent_q::AgentQUserSigningPersonalMessageBeginInput make_valid_personal_message_input(
    const char* request_id,
    const char* session_id)
{
    const std::vector<uint8_t>& message = valid_message();
    static agent_q::AgentQSuiPreparedPersonalMessage prepared = {};
    prepared = {};
    prepared.route = agent_q::AgentQSupportedSignRoute::sui_sign_personal_message;
    snprintf(prepared.network, sizeof(prepared.network), "%s", "devnet");
    memcpy(prepared.message, message.data(), message.size());
    prepared.message_size = message.size();
    snprintf(prepared.payload_digest, sizeof(prepared.payload_digest),
             "%s", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    snprintf(prepared.account_address, sizeof(prepared.account_address),
             "%s", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    return agent_q::AgentQUserSigningPersonalMessageBeginInput{
        request_id,
        kRequestIdentity,
        session_id,
        agent_q::AgentQSupportedSignRoute::sui_sign_personal_message,
        &prepared,
        request_window(100),
    };
}

bool write_confirmation_history(
    const agent_q::AgentQUserSigningFlowCoreSnapshot& snapshot,
    void*)
{
    expect(snapshot.stage == agent_q::AgentQUserSigningStage::history_write,
           "history writer receives history_write snapshot");
    return true;
}

void reset_state()
{
    agent_q::user_signing_flow_clear();
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
    expect(agent_q::user_signing_flow_begin(0,
               make_valid_input(request_id, agent_q::session_id())) ==
               agent_q::AgentQUserSigningFlowBeginResult::ok,
           "user_signing begins");
}

void begin_personal_message_reviewing_request(const char* request_id)
{
    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "session starts");
    expect(agent_q::user_signing_flow_begin_personal_message(0,
               make_valid_personal_message_input(request_id, agent_q::session_id())) ==
               agent_q::AgentQUserSigningFlowBeginResult::ok,
           "sign_personal_message user flow begins");
}

void enter_critical_section(const char* request_id)
{
    begin_reviewing_request(request_id);
    expect(agent_q::user_signing_flow_accept_review(50, pin_window(50, 90)) ==
               agent_q::AgentQUserSigningTransitionResult::ok,
           "review accepted");
    expect(agent_q::user_signing_flow_pause_pin_deadline(55) ==
               agent_q::AgentQUserSigningTransitionResult::ok,
           "PIN submit pauses input deadline");
    expect(agent_q::user_signing_flow_record_pin_verified_and_write_confirmation_history(55,
               write_confirmation_history,
               nullptr) == agent_q::AgentQUserSigningTransitionResult::ok,
           "history write enters critical section");
    expect(agent_q::user_signing_flow_snapshot().stage ==
               agent_q::AgentQUserSigningStage::signing_critical_section,
           "flow is in critical section");
}

void enter_personal_message_critical_section(const char* request_id)
{
    begin_personal_message_reviewing_request(request_id);
    expect(agent_q::user_signing_flow_accept_review(50, pin_window(50, 90)) ==
               agent_q::AgentQUserSigningTransitionResult::ok,
           "personal-message review accepted");
    expect(agent_q::user_signing_flow_pause_pin_deadline(55) ==
               agent_q::AgentQUserSigningTransitionResult::ok,
           "personal-message PIN submit pauses input deadline");
    expect(agent_q::user_signing_flow_record_pin_verified_and_write_confirmation_history(55,
               write_confirmation_history,
               nullptr) == agent_q::AgentQUserSigningTransitionResult::ok,
           "personal-message history write enters critical section");
    expect(agent_q::user_signing_flow_snapshot().stage ==
               agent_q::AgentQUserSigningStage::signing_critical_section,
           "personal-message flow is in critical section");
}

void poison_output(agent_q::AgentQUserSigningOutput& output)
{
    output.signing_route = agent_q::AgentQSigningRoute::sui_sign_personal_message;
    memset(output.signature, 0xCC, sizeof(output.signature));
    output.signature_size = 999;
    memset(output.message_bytes, 0xCC, sizeof(output.message_bytes));
    output.message_bytes_size = 999;
}

bool output_is_wiped(const agent_q::AgentQUserSigningOutput& output)
{
    if (output.signing_route != agent_q::AgentQSigningRoute::unsupported ||
        output.signature_size != 0 ||
        output.message_bytes_size != 0) {
        return false;
    }
    for (size_t index = 0; index < sizeof(output.signature); ++index) {
        if (output.signature[index] != 0) {
            return false;
        }
    }
    for (size_t index = 0; index < sizeof(output.message_bytes); ++index) {
        if (output.message_bytes[index] != 0) {
            return false;
        }
    }
    return true;
}

bool output_matches_stub_signature(
    const agent_q::AgentQUserSigningOutput& output)
{
    if (output.signature_size != agent_q::kSuiEd25519SignatureBytes) {
        return false;
    }
    if (output.signature[0] != agent_q::kAgentQSuiSignatureSchemeFlagEd25519) {
        return false;
    }
    for (size_t index = 1; index < output.signature_size; ++index) {
        if (output.signature[index] != 0xA5) {
            return false;
        }
    }
    return true;
}

bool output_has_no_message_bytes(
    const agent_q::AgentQUserSigningOutput& output)
{
    if (output.message_bytes_size != 0) {
        return false;
    }
    for (size_t index = 0; index < sizeof(output.message_bytes); ++index) {
        if (output.message_bytes[index] != 0) {
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

AgentQSuiActiveIdentity resolve_active_sui_identity()
{
    AgentQSuiActiveIdentity identity = {};
    if (g_account_result != SuiAccountDerivationResult::ok) {
        identity.kind = AgentQSuiActiveIdentityKind::error;
        identity.error = AgentQSuiActiveIdentityError::native_account_unavailable;
        return identity;
    }
    identity.kind = AgentQSuiActiveIdentityKind::native;
    identity.error = AgentQSuiActiveIdentityError::none;
    snprintf(identity.address, sizeof(identity.address), "%s", g_account_address);
    identity.public_key[0] = kAgentQSuiSignatureSchemeFlagEd25519;
    memset(identity.public_key + 1, 0x42, kSuiEd25519PublicKeyBytes);
    identity.public_key_size = kSuiEd25519PublicKeyBytes + 1;
    return identity;
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
        signature_out[0] = kAgentQSuiSignatureSchemeFlagEd25519;
    }
    return g_signing_result_ok ? SuiTransactionSigningResult::ok
                               : SuiTransactionSigningResult::signing_error;
}

SuiTransactionSigningResult sign_sui_transaction_from_active_identity(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    uint8_t signature_out[kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out)
{
    ++g_signing_calls;
    g_last_signed_payload.assign(tx_bytes, tx_bytes + tx_bytes_size);
    if (signature_size_out != nullptr) {
        *signature_size_out = 0;
    }
    if (signature_out != nullptr) {
        memset(signature_out, 0, kSuiSignatureEnvelopeMaxBytes);
    }
    if (!g_signing_result_ok) {
        return SuiTransactionSigningResult::signing_error;
    }
    if (signature_out != nullptr && signature_size_out != nullptr) {
        memset(signature_out, 0xA5, kSuiEd25519SignatureBytes);
        signature_out[0] = kAgentQSuiSignatureSchemeFlagEd25519;
        *signature_size_out = kSuiEd25519SignatureBytes;
    }
    return SuiTransactionSigningResult::ok;
}

SuiTransactionSigningResult sign_sui_ed25519_personal_message_from_stored_root(
    const uint8_t* message,
    size_t message_size,
    uint8_t signature_out[kSuiEd25519SignatureBytes])
{
    (void)message;
    (void)message_size;
    (void)signature_out;
    return SuiTransactionSigningResult::signing_error;
}

SuiTransactionSigningResult sign_sui_personal_message_from_active_identity(
    const uint8_t* message,
    size_t message_size,
    uint8_t signature_out[kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out)
{
    ++g_signing_calls;
    g_last_signed_payload.assign(message, message + message_size);
    if (signature_size_out != nullptr) {
        *signature_size_out = 0;
    }
    if (!g_signing_result_ok) {
        return SuiTransactionSigningResult::signing_error;
    }
    if (signature_out != nullptr) {
        memset(signature_out, 0xA5, kSuiEd25519SignatureBytes);
        signature_out[0] = kAgentQSuiSignatureSchemeFlagEd25519;
    }
    if (signature_size_out != nullptr) {
        *signature_size_out = kSuiEd25519SignatureBytes;
    }
    return SuiTransactionSigningResult::ok;
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
        case SuiTransactionSigningResult::active_identity_unavailable:
            return "active_identity_unavailable";
        case SuiTransactionSigningResult::signature_output_too_small:
            return "signature_output_too_small";
        case SuiTransactionSigningResult::zklogin_envelope_error:
            return "zklogin_envelope_error";
    }
    return "unknown";
}

}  // namespace agent_q

int main()
{
    namespace aq = agent_q;
    aq::AgentQUserSigningOutput output = {};

    reset_state();
    poison_output(output);
    aq::AgentQUserSigningHandoffReport report =
        aq::user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQUserSigningHandoffResult::inactive,
           "inactive flow cannot sign");
    expect(g_signing_calls == 0, "inactive flow does not call signing service");
    expect(output_is_wiped(output), "inactive flow wipes output");

    reset_state();
    enter_critical_section("req_null_output");
    report = aq::user_signing_execute_critical_section(nullptr);
    expect(report.result == aq::AgentQUserSigningHandoffResult::invalid_output,
           "null output is rejected");
    expect(g_signing_calls == 0, "null output does not call signing service");
    expect(aq::user_signing_flow_snapshot().stage ==
               aq::AgentQUserSigningStage::signing_critical_section,
           "null output keeps critical flow active");
    expect(aq::user_signing_flow_record_signing_failed() ==
               aq::AgentQUserSigningTransitionResult::ok,
           "test cleanup terminalizes null-output critical flow");
    aq::AgentQUserSigningTerminalResult cleanup_terminal =
        aq::AgentQUserSigningTerminalResult::none;
    expect(aq::user_signing_flow_consume_terminal_result(&cleanup_terminal),
           "test cleanup consumes null-output terminal");

    reset_state();
    begin_reviewing_request("req_wrong_stage");
    poison_output(output);
    report = aq::user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQUserSigningHandoffResult::wrong_stage,
           "reviewing flow cannot sign");
    expect(g_signing_calls == 0, "wrong stage does not call signing service");
    expect(output_is_wiped(output), "wrong stage wipes output");
    expect(aq::user_signing_flow_snapshot().stage ==
               aq::AgentQUserSigningStage::reviewing,
           "wrong stage keeps request active");

    reset_state();
    enter_critical_section("req_success");
    const std::vector<uint8_t> expected_payload = valid_payload();
    poison_output(output);
    report = aq::user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQUserSigningHandoffResult::ok,
           "critical section signs successfully");
    expect(report.flow_result == aq::AgentQUserSigningTransitionResult::ok,
           "successful handoff completes flow");
    expect(report.signing_result == aq::SuiTransactionSigningResult::ok,
           "signing service result is reported");
    expect(g_signing_calls == 1, "signing service called once");
    expect(g_last_signed_payload == expected_payload,
           "signing service receives exact request payload");
    expect(output_matches_stub_signature(output),
           "successful signing returns caller-owned signature output");
    expect(output.signing_route == aq::AgentQSigningRoute::sui_sign_transaction,
           "transaction signing output carries verified route enum");
    expect(output_has_no_message_bytes(output),
           "transaction signing does not return messageBytes");
    aq::AgentQUserSigningFlowSnapshot snapshot = aq::user_signing_flow_snapshot();
    expect(snapshot.stage == aq::AgentQUserSigningStage::terminal &&
               snapshot.terminal_result == aq::AgentQUserSigningTerminalResult::signed_success,
           "successful signing records signed terminal");
    aq::AgentQUserSigningTerminalResult terminal =
        aq::AgentQUserSigningTerminalResult::none;
    expect(aq::user_signing_flow_consume_terminal_result(&terminal),
           "signed terminal can be consumed");
    expect(terminal == aq::AgentQUserSigningTerminalResult::signed_success,
           "signed terminal value is preserved");

    reset_state();
    enter_personal_message_critical_section("req_personal_success");
    const std::vector<uint8_t> expected_message = valid_message();
    poison_output(output);
    report = aq::user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQUserSigningHandoffResult::ok,
           "personal-message critical section signs successfully");
    expect(report.flow_result == aq::AgentQUserSigningTransitionResult::ok,
           "personal-message handoff completes flow");
    expect(report.signing_result == aq::SuiTransactionSigningResult::ok,
           "personal-message signing service result is reported");
    expect(g_signing_calls == 1, "personal-message signing service called once");
    expect(g_last_signed_payload == expected_message,
           "personal-message signing service receives exact message bytes");
    expect(output_matches_stub_signature(output),
           "personal-message signing returns caller-owned signature output");
    expect(output.signing_route == aq::AgentQSigningRoute::sui_sign_personal_message,
           "personal-message signing output carries verified route enum");
    expect(output.message_bytes_size == expected_message.size(),
           "personal-message signing returns messageBytes size");
    expect(memcmp(output.message_bytes, expected_message.data(), expected_message.size()) == 0,
           "personal-message signing returns original messageBytes");
    snapshot = aq::user_signing_flow_snapshot();
    expect(snapshot.stage == aq::AgentQUserSigningStage::terminal &&
               snapshot.terminal_result == aq::AgentQUserSigningTerminalResult::signed_success,
           "personal-message signing records signed terminal");

    reset_state();
    enter_critical_section("req_failure");
    g_signing_result_ok = false;
    poison_output(output);
    report = aq::user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQUserSigningHandoffResult::signing_failed,
           "signing service failure is reported");
    expect(report.flow_result == aq::AgentQUserSigningTransitionResult::ok,
           "signing failure terminalizes flow");
    expect(report.signing_result == aq::SuiTransactionSigningResult::signing_error,
           "signing failure cause is reported");
    expect(g_signing_calls == 1, "failing signing service called once");
    snapshot = aq::user_signing_flow_snapshot();
    expect(snapshot.stage == aq::AgentQUserSigningStage::terminal &&
               snapshot.terminal_result == aq::AgentQUserSigningTerminalResult::signing_failed,
           "signing service failure records failed terminal");
    expect(output_is_wiped(output), "signing service failure wipes output");

    reset_state();
    enter_critical_section("req_missing_payload");
    uint8_t consumed_payload[agent_q::kAgentQSuiSignTransactionTxBytesMaxBytes] = {};
    size_t consumed_size = 0;
    expect(aq::user_signing_flow_consume_signable_payload(
               consumed_payload,
               sizeof(consumed_payload),
               &consumed_size) == aq::AgentQUserSigningTransitionResult::ok,
           "test setup consumes payload");
    poison_output(output);
    report = aq::user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQUserSigningHandoffResult::payload_unavailable,
           "missing critical payload is reported");
    expect(g_signing_calls == 0, "missing payload does not call signing service");
    expect(output_is_wiped(output), "missing payload wipes output");
    snapshot = aq::user_signing_flow_snapshot();
    expect(snapshot.stage == aq::AgentQUserSigningStage::terminal &&
               snapshot.terminal_result == aq::AgentQUserSigningTerminalResult::signing_failed,
           "missing critical payload records failed terminal");

    reset_state();
    enter_critical_section("req_session_loss");
    aq::session_clear();
    poison_output(output);
    report = aq::user_signing_execute_critical_section(&output);
    expect(report.result == aq::AgentQUserSigningHandoffResult::ok,
           "critical signing is not downgraded by session loss");
    expect(output_matches_stub_signature(output),
           "post-history session loss still returns signature output");
    expect(aq::user_signing_flow_snapshot().terminal_result ==
               aq::AgentQUserSigningTerminalResult::signed_success,
           "post-history session loss stays signed after service success");

    expect(strcmp(
               aq::user_signing_handoff_result_name(
                   aq::AgentQUserSigningHandoffResult::payload_unavailable),
               "payload_unavailable") == 0,
           "result names include payload_unavailable");
    expect(strcmp(
               aq::user_signing_handoff_result_name(
                   aq::AgentQUserSigningHandoffResult::invalid_output),
               "invalid_output") == 0,
           "result names include invalid_output");

    if (failures != 0) {
        fprintf(stderr, "%d user_signing signing test(s) failed\n", failures);
        return 1;
    }
    printf("user_signing critical-section tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -DAGENT_Q_TEST_VALID_SUI_TRANSFER_TX_HEX=\"${COMMON_ROOT}/sui/testdata/sui_transaction_facts/valid_sui_transfer_tx.bcs.hex\" \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_ROOT}/sui" \
  "${TMP_DIR}/user_signing_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_user_signing_critical_section.cpp" \
  "${AGENT_Q_DIR}/agent_q_user_signing_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_signing_authority.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${COMMON_ROOT}/sui/agent_q_sui_sign_transaction_adapter.cpp" \
  "${COMMON_ROOT}/sui/agent_q_sui_transaction_facts.cpp" \
  "${COMMON_ROOT}/sui/agent_q_sui_bcs_reader.cpp" \
  -o "${TMP_DIR}/user_signing_test"

"${TMP_DIR}/user_signing_test"
