#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_signature_request_confirmation.sh

Compiles the StackChan CoreS3 signature request confirmation
coordinator against host stubs and verifies review-to-PIN-to-history handoff
without USB protocol ingress. This test uses only a host C++ compiler and does
NOT require ESP-IDF.
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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-signature-request-confirmation.XXXXXX")"
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

cat >"${TMP_DIR}/freertos/task.h" <<'H'
#pragma once
#include "freertos/FreeRTOS.h"
extern "C" TickType_t xTaskGetTickCount(void);
H

cat >"${TMP_DIR}/signature_request_confirmation_test.cpp" <<'CPP'
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "agent_q_local_auth.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_local_pin_auth.h"
#include "agent_q_signature_request_confirmation.h"
#include "agent_q_sui_account_store.h"
#include "freertos/FreeRTOS.h"

namespace {

int failures = 0;
TickType_t g_now = 1;
int g_history_write_calls = 0;
bool g_history_write_result = true;
bool g_history_write_clears_flow = false;
char g_current_pin[agent_q::kLocalPinBufferSize] = "123456";
char g_account_address[agent_q::kSuiAddressBufferSize] =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
uint32_t g_last_worker_job_id = 0;

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

void enter_pin(const char* pin, TickType_t deadline)
{
    for (size_t index = 0; pin[index] != '\0'; ++index) {
        expect(agent_q::local_pin_auth_add_digit(pin[index], deadline) ==
                   agent_q::AgentQLocalPinAuthInputResult::accepted,
               "PIN digit accepted");
    }
}

agent_q::AgentQLocalAuthWorkerResult make_verify_result(bool verified)
{
    agent_q::AgentQLocalAuthWorkerResult worker_result = {};
    worker_result.job_id = g_last_worker_job_id;
    worker_result.owner = agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth;
    worker_result.operation = agent_q::AgentQLocalAuthWorkerOperation::verify_pin;
    worker_result.status = agent_q::AgentQLocalAuthWorkerStatus::ok;
    worker_result.verified = verified;
    return worker_result;
}

bool write_confirmation_history(
    const agent_q::AgentQSignatureRequestFlowSnapshot& snapshot,
    void*)
{
    ++g_history_write_calls;
    expect(snapshot.active, "history writer receives active snapshot");
    expect(snapshot.stage == agent_q::AgentQSignatureRequestStage::history_write,
           "history writer receives history_write stage");
    expect(snapshot.signable_payload_available,
           "history writer runs before payload handoff");
    if (g_history_write_clears_flow) {
        expect(agent_q::signature_request_flow_clear() ==
                   agent_q::AgentQSignatureRequestTransitionResult::ok,
               "history writer can clear flow in misuse test");
    }
    return g_history_write_result;
}

agent_q::AgentQSignatureRequestBeginInput make_valid_input(
    const char* request_id,
    const char* session_id,
    const char* network,
    const uint8_t* payload,
    size_t payload_size,
    TickType_t deadline = 300)
{
    return agent_q::AgentQSignatureRequestBeginInput{
        request_id,
        session_id,
        "sui",
        "sign_transaction",
        network,
        payload,
        payload_size,
        deadline,
    };
}

void reset_all()
{
    agent_q::local_pin_auth_clear_flow();
    if (agent_q::signature_request_flow_in_signing_critical_section()) {
        expect(agent_q::signature_request_flow_record_signing_failed() ==
                   agent_q::AgentQSignatureRequestTransitionResult::ok,
               "test cleanup closes critical flow");
    }
    if (agent_q::signature_request_flow_terminal_pending()) {
        agent_q::AgentQSignatureRequestTerminalResult terminal = {};
        expect(agent_q::signature_request_flow_consume_terminal_result(&terminal),
               "test cleanup consumes terminal flow");
    }
    agent_q::signature_request_flow_clear();
    agent_q::session_clear();
    g_now = 1;
    g_history_write_calls = 0;
    g_history_write_result = true;
    g_history_write_clears_flow = false;
    snprintf(g_current_pin, sizeof(g_current_pin), "%s", "123456");
    snprintf(g_account_address, sizeof(g_account_address), "%s",
             "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

bool begin_valid_flow_with_deadline(const char* request_id, TickType_t deadline)
{
    const std::vector<uint8_t>& payload = valid_payload();
    if (agent_q::session_replace(random_bytes, nullptr) !=
        agent_q::AgentQSessionStartResult::ok) {
        return false;
    }
    return agent_q::signature_request_flow_begin(
               make_valid_input(
                   request_id,
                   agent_q::session_id(),
                   "devnet",
                   payload.data(),
                   payload.size(),
                   deadline)) ==
           agent_q::AgentQSignatureRequestFlowBeginResult::ok;
}

bool begin_valid_flow(const char* request_id)
{
    return begin_valid_flow_with_deadline(request_id, 300);
}

bool begin_valid_flow_in_current_session(const char* request_id, const char* network)
{
    const std::vector<uint8_t>& payload = valid_payload();
    if (!agent_q::session_active()) {
        return false;
    }
    return agent_q::signature_request_flow_begin(
               make_valid_input(
                   request_id,
                   agent_q::session_id(),
                   network,
                   payload.data(),
                   payload.size())) ==
           agent_q::AgentQSignatureRequestFlowBeginResult::ok;
}

}  // namespace

extern "C" TickType_t xTaskGetTickCount(void)
{
    return g_now;
}

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
    if (payload == nullptr || payload_size == 0 || output == nullptr || output_size < 72) {
        return false;
    }
    snprintf(output, output_size,
             "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    return true;
}

SuiAccountDerivationResult derive_sui_ed25519_account_from_stored_root(
    uint8_t* public_key,
    char* address,
    size_t address_size)
{
    if (public_key != nullptr) {
        memset(public_key, 0x11, kSuiEd25519PublicKeyBytes);
    }
    if (address == nullptr || address_size == 0) {
        return SuiAccountDerivationResult::derivation_error;
    }
    snprintf(address, address_size, "%s", g_account_address);
    return SuiAccountDerivationResult::ok;
}

bool is_valid_local_pin(const char* pin)
{
    if (pin == nullptr || strlen(pin) != kLocalPinDigits) {
        return false;
    }
    for (size_t index = 0; index < kLocalPinDigits; ++index) {
        if (!isdigit(static_cast<unsigned char>(pin[index]))) {
            return false;
        }
    }
    return true;
}

bool verify_local_pin(const char* pin, bool* verified)
{
    if (verified == nullptr) {
        return false;
    }
    *verified = pin != nullptr && strcmp(pin, g_current_pin) == 0;
    return true;
}

bool local_auth_worker_submit_verify(
    AgentQLocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id)
{
    (void)owner;
    static uint32_t next_job_id = 1;
    if (job_id == nullptr || !is_valid_local_pin(pin)) {
        return false;
    }
    *job_id = next_job_id++;
    g_last_worker_job_id = *job_id;
    return true;
}

bool local_auth_worker_submit_prepare_verifier(
    AgentQLocalAuthWorkerOwner,
    const char*,
    uint32_t*)
{
    return false;
}

bool local_auth_worker_cancel_job(uint32_t)
{
    return true;
}

bool read_require_pin_on_connect(bool*)
{
    return false;
}

bool connect_requires_pin()
{
    return true;
}

bool store_require_pin_on_connect(bool)
{
    return false;
}

bool wipe_require_pin_on_connect()
{
    return true;
}

bool prepare_local_pin_verifier_record(const char*, AgentQLocalAuthPreparedRecord*)
{
    return false;
}

bool store_prepared_local_pin_verifier(const AgentQLocalAuthPreparedRecord*)
{
    return false;
}

void wipe_local_pin_verifier_record(AgentQLocalAuthPreparedRecord*)
{
}

bool store_local_pin_verifier(const char*)
{
    return false;
}

bool wipe_local_auth()
{
    return true;
}

AgentQLocalAuthStatus local_auth_status()
{
    return AgentQLocalAuthStatus::active;
}

}  // namespace agent_q

int main()
{
    using Confirm = agent_q::AgentQSignatureRequestConfirmationResult;
    using FlowStage = agent_q::AgentQSignatureRequestStage;
    using PinPurpose = agent_q::AgentQLocalPinAuthPurpose;
    using PinStage = agent_q::AgentQLocalPinAuthStage;

    {
        reset_all();
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 200) ==
                   Confirm::inactive,
               "cannot start signing PIN without active request");
        expect(!agent_q::signature_request_confirmation_pin_active(),
               "inactive begin does not start signing PIN");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_pin_busy"), "begin before local PIN conflict");
        agent_q::local_pin_auth_begin_connect(200);
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 200) ==
                   Confirm::local_pin_busy,
               "active unrelated local PIN blocks signing PIN");
        expect(agent_q::signature_request_flow_snapshot().stage == FlowStage::reviewing,
               "local PIN conflict leaves request in reviewing");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_pin_ok"), "begin before signing PIN");
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 200) ==
                   Confirm::ok,
               "review acceptance starts request-bound signing PIN");
        agent_q::AgentQLocalPinAuthSnapshot pin = agent_q::local_pin_auth_snapshot(100);
        expect(pin.flow_active && pin.purpose == PinPurpose::signature_request &&
                   pin.stage == PinStage::pin_entry,
               "signing PIN state is request-bound");
        expect(agent_q::signature_request_flow_snapshot().stage == FlowStage::pin_entry,
               "request flow moved to pin_entry");

        enter_pin("123456", 200);
        expect(agent_q::local_pin_auth_submit(101, 0, 200, 150) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "signing PIN submit starts verification");
        expect(agent_q::signature_request_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 101, 200, 0, nullptr, nullptr) ==
                   Confirm::invalid_argument,
               "missing history writer fails closed");
        expect(g_history_write_calls == 0,
               "missing history writer does not call history writer");
        expect(!agent_q::signature_request_confirmation_pin_active(),
               "missing history writer clears signing PIN");
        expect(agent_q::signature_request_flow_snapshot().terminal_result ==
                   agent_q::AgentQSignatureRequestTerminalResult::canceled,
               "missing history writer terminalizes request");

        reset_all();
        expect(begin_valid_flow("req_pin_ok_2"), "begin before signing PIN retry");
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 200) ==
                   Confirm::ok,
               "review acceptance starts request-bound signing PIN retry");
        enter_pin("123456", 200);
        expect(agent_q::local_pin_auth_submit(101, 0, 200, 150) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "signing PIN retry submit starts verification");
        expect(agent_q::signature_request_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 102, 200, 0, write_confirmation_history, nullptr) ==
                   Confirm::ok,
               "verified PIN completion writes history and enters critical section");
        expect(g_history_write_calls == 1, "history writer called once");
        expect(!agent_q::signature_request_confirmation_pin_active(),
               "verified PIN terminal handling clears local PIN flow");
        expect(agent_q::signature_request_flow_in_signing_critical_section(),
               "request flow entered signing critical section");

        reset_all();
        expect(begin_valid_flow("req_pin_late_verify"), "begin before late PIN verify");
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 120) ==
                   Confirm::ok,
               "review acceptance starts short signing PIN window");
        enter_pin("123456", 120);
        expect(agent_q::local_pin_auth_submit(119, 0, 120, 125) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "PIN submit starts verification before input window closes");
        expect(agent_q::signature_request_confirmation_mark_pin_verification_started() ==
                   Confirm::ok,
               "PIN verification start pauses signing request deadline");
        expect(agent_q::signature_request_flow_snapshot().deadline == 0,
               "signing request deadline is paused during PIN verification");
        expect(agent_q::signature_request_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 140, 170, 0, write_confirmation_history, nullptr) ==
                   Confirm::ok,
               "verified PIN after input deadline still enters critical section");
        expect(agent_q::signature_request_flow_in_signing_critical_section(),
               "late verified PIN is not converted to timeout");
    }

    {
        reset_all();
        expect(begin_valid_flow_with_deadline("req_pin_after_fixed_deadline", 130),
               "begin before late fixed-deadline PIN verify");
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 120) ==
                   Confirm::ok,
               "review acceptance starts short signing PIN window before fixed deadline");
        enter_pin("123456", 120);
        expect(agent_q::local_pin_auth_submit(119, 0, 120, 125) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "PIN submit starts verification before fixed deadline");
        expect(agent_q::signature_request_confirmation_mark_pin_verification_started() ==
                   Confirm::ok,
               "PIN verification start leaves fixed confirmation deadline active");
        expect(agent_q::signature_request_flow_snapshot().deadline == 0 &&
                   agent_q::signature_request_flow_snapshot().confirmation_deadline == 130,
               "local input deadline is paused but fixed confirmation deadline remains");
        expect(agent_q::signature_request_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 140, 170, 0, write_confirmation_history, nullptr) ==
                   Confirm::deadline_expired,
               "verified PIN after fixed confirmation deadline times out");
        expect(!agent_q::signature_request_confirmation_pin_active(),
               "fixed-deadline timeout clears signing PIN");
        expect(agent_q::signature_request_flow_snapshot().terminal_result ==
                   agent_q::AgentQSignatureRequestTerminalResult::timed_out,
               "fixed-deadline timeout records terminal result");
        expect(g_history_write_calls == 0,
               "fixed-deadline timeout does not write confirmation history");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_wrong_pin"), "begin before wrong PIN");
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 120) ==
                   Confirm::ok,
               "review acceptance before wrong PIN");
        enter_pin("000000", 120);
        expect(agent_q::local_pin_auth_submit(119, 0, 120, 125) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "wrong signing PIN starts verification");
        expect(agent_q::signature_request_confirmation_mark_pin_verification_started() ==
                   Confirm::ok,
               "wrong PIN verification start pauses signing request deadline");
        expect(agent_q::signature_request_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(false), 140, 170, 300, write_confirmation_history, nullptr) ==
                   Confirm::wrong_pin,
               "wrong signing PIN after input deadline starts a fresh retry window");
        expect(agent_q::signature_request_confirmation_pin_active(),
               "wrong signing PIN keeps local PIN active");
        expect(agent_q::signature_request_flow_snapshot().stage == FlowStage::pin_entry,
               "wrong signing PIN does not write history");
        expect(agent_q::signature_request_flow_snapshot().deadline == 170,
               "wrong signing PIN refreshes request flow deadline");
        expect(g_history_write_calls == 0, "wrong signing PIN does not call history writer");
    }

    {
        reset_all();
        expect(begin_valid_flow_with_deadline("req_wrong_pin_after_fixed_deadline", 130),
               "begin before wrong PIN after fixed deadline");
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 120) ==
                   Confirm::ok,
               "review acceptance before fixed-deadline wrong PIN");
        enter_pin("000000", 120);
        expect(agent_q::local_pin_auth_submit(119, 0, 120, 125) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "wrong PIN starts verification before fixed deadline");
        expect(agent_q::signature_request_confirmation_mark_pin_verification_started() ==
                   Confirm::ok,
               "wrong PIN verification start leaves fixed deadline active");
        expect(agent_q::signature_request_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(false), 140, 170, 300, write_confirmation_history, nullptr) ==
                   Confirm::deadline_expired,
               "wrong PIN after fixed confirmation deadline does not reopen input");
        expect(!agent_q::signature_request_confirmation_pin_active(),
               "wrong PIN fixed-deadline timeout clears local PIN");
        expect(agent_q::signature_request_flow_snapshot().terminal_result ==
                   agent_q::AgentQSignatureRequestTerminalResult::timed_out,
               "wrong PIN fixed-deadline timeout records terminal result");
        expect(g_history_write_calls == 0,
               "wrong PIN fixed-deadline timeout does not write history");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_auth_fail"), "begin before auth unavailable");
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 200) ==
                   Confirm::ok,
               "review acceptance before auth unavailable");
        enter_pin("123456", 200);
        expect(agent_q::local_pin_auth_submit(101, 0, 200, 150) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "PIN submit before auth unavailable");
        agent_q::AgentQLocalAuthWorkerResult worker_result = make_verify_result(true);
        worker_result.status = agent_q::AgentQLocalAuthWorkerStatus::auth_unavailable;
        expect(agent_q::signature_request_confirmation_complete_pin_verify_job_and_write_history(
                   worker_result, 102, 200, 0, write_confirmation_history, nullptr) ==
                   Confirm::auth_unavailable,
               "auth unavailable fails closed");
        expect(!agent_q::signature_request_confirmation_pin_active(),
               "auth unavailable clears signing PIN");
        expect(agent_q::signature_request_flow_snapshot().terminal_result ==
                   agent_q::AgentQSignatureRequestTerminalResult::canceled,
               "auth unavailable terminalizes request");
        expect(g_history_write_calls == 0, "auth unavailable does not call history writer");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_same_identity"), "begin before same-id stale PIN");
        const char same_session[agent_q::kAgentQSessionIdSize] = {};
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 200) ==
                   Confirm::ok,
               "review acceptance before same-id stale PIN");
        char session_copy[agent_q::kAgentQSessionIdSize] = {};
        snprintf(session_copy, sizeof(session_copy), "%s", agent_q::session_id());
        enter_pin("123456", 200);
        expect(agent_q::local_pin_auth_submit(101, 0, 200, 150) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "PIN submit before same-id stale PIN");
        expect(agent_q::signature_request_flow_clear() ==
                   agent_q::AgentQSignatureRequestTransitionResult::ok,
               "misuse clears same-id request while PIN worker is pending");
        (void)same_session;
        expect(strcmp(agent_q::session_id(), session_copy) == 0,
               "replacement keeps same session");
        expect(begin_valid_flow_in_current_session("req_same_identity", "testnet"),
               "begin replacement with same request and session but different network");
        expect(agent_q::signature_request_flow_accept_review(99, 220) ==
                   agent_q::AgentQSignatureRequestTransitionResult::ok,
               "misuse moves same-id replacement flow to pin_entry without coordinator");
        expect(agent_q::signature_request_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 104, 220, 0, write_confirmation_history, nullptr) ==
                   Confirm::wrong_stage,
               "old PIN cannot verify same-id replacement request");
        expect(g_history_write_calls == 0, "same-id stale PIN does not write history");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_history_fail"), "begin before history failure");
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 200) ==
                   Confirm::ok,
               "review acceptance before history failure");
        enter_pin("123456", 200);
        expect(agent_q::local_pin_auth_submit(101, 0, 200, 150) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "PIN submit before history failure");
        g_history_write_result = false;
        expect(agent_q::signature_request_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 102, 200, 0, write_confirmation_history, nullptr) ==
                   Confirm::history_error,
               "history failure terminalizes request");
        expect(!agent_q::signature_request_confirmation_pin_active(),
               "history failure clears local PIN");
        expect(agent_q::signature_request_flow_snapshot().terminal_result ==
                   agent_q::AgentQSignatureRequestTerminalResult::history_error,
               "history failure terminal result recorded");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_session_loss"), "begin before session loss");
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 200) ==
                   Confirm::ok,
               "review acceptance before session loss");
        enter_pin("123456", 200);
        expect(agent_q::local_pin_auth_submit(101, 0, 200, 150) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "PIN submit before session loss");
        agent_q::session_clear();
        expect(agent_q::signature_request_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 102, 200, 0, write_confirmation_history, nullptr) ==
                   Confirm::invalid_session,
               "session loss before history write cancels the active confirmation");
        expect(!agent_q::signature_request_confirmation_pin_active(),
               "session loss clears local PIN");
        expect(g_history_write_calls == 0, "session loss happens before history writer");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_stale_pin"), "begin before stale PIN misuse");
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 200) ==
                   Confirm::ok,
               "review acceptance before stale PIN misuse");
        enter_pin("123456", 200);
        expect(agent_q::local_pin_auth_submit(101, 0, 200, 150) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "PIN submit before stale PIN misuse");
        expect(agent_q::signature_request_flow_clear() ==
                   agent_q::AgentQSignatureRequestTransitionResult::ok,
               "misuse clears request flow while PIN worker is pending");
        expect(begin_valid_flow("req_stale_new"), "begin replacement flow");
        expect(agent_q::signature_request_flow_accept_review(99, 220) ==
                   agent_q::AgentQSignatureRequestTransitionResult::ok,
               "misuse moves replacement flow to pin_entry without coordinator");
        expect(agent_q::signature_request_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 104, 220, 0, write_confirmation_history, nullptr) ==
                   Confirm::wrong_stage,
               "old PIN cannot verify replacement request");
        expect(g_history_write_calls == 0, "stale PIN does not write history");
        expect(agent_q::signature_request_flow_snapshot().request_id[0] != '\0',
               "replacement flow was not cleared by stale PIN");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_reject"), "begin before reject");
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 200) ==
                   Confirm::ok,
               "review acceptance before reject");
        expect(agent_q::signature_request_confirmation_record_device_rejected() ==
                   Confirm::ok,
               "device rejection clears request");
        expect(!agent_q::signature_request_confirmation_pin_active(),
               "device rejection clears signing PIN");
        expect(agent_q::signature_request_flow_snapshot().terminal_result ==
                   agent_q::AgentQSignatureRequestTerminalResult::rejected,
               "device rejection terminal result recorded");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_callback_clear"), "begin before callback clear");
        expect(agent_q::signature_request_confirmation_accept_review_and_begin_pin(99, 200) ==
                   Confirm::ok,
               "review acceptance before callback clear");
        enter_pin("123456", 200);
        expect(agent_q::local_pin_auth_submit(101, 0, 200, 150) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "PIN submit before callback clear");
        g_history_write_clears_flow = true;
        expect(agent_q::signature_request_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 102, 200, 0, write_confirmation_history, nullptr) ==
                   Confirm::stale_state,
               "callback clear cannot enter critical section");
        expect(!agent_q::signature_request_confirmation_pin_active(),
               "callback clear clears signing PIN");
    }

    if (failures != 0) {
        fprintf(stderr, "%d signature request confirmation test(s) failed\n", failures);
        return 1;
    }
    printf("Signature request confirmation tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -DAGENT_Q_TEST_VALID_SUI_TRANSFER_TX_HEX=\"${COMMON_ROOT}/sui/testdata/sui_transaction_facts/valid_sui_transfer_tx.bcs.hex\" \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_ROOT}/sui" \
  "${TMP_DIR}/signature_request_confirmation_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_signature_request_confirmation.cpp" \
  "${AGENT_Q_DIR}/agent_q_signature_request_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_pin_auth.cpp" \
  "${AGENT_Q_DIR}/agent_q_pin_attempt.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${COMMON_ROOT}/sui/agent_q_sui_transaction_facts.cpp" \
  "${COMMON_ROOT}/sui/agent_q_sui_bcs_reader.cpp" \
  -o "${TMP_DIR}/signature_request_confirmation_test"

"${TMP_DIR}/signature_request_confirmation_test"
