#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_user_signing_confirmation.sh

Compiles the StackChan CoreS3 user_signing confirmation
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
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-signature-request-confirmation.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/firmware_common" "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/firmware_common/sui"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"

if [[ ! -f "${ARDUINOJSON_ROOT}/ArduinoJson.h" ]]; then
  echo "Missing required ArduinoJson source: ${ARDUINOJSON_ROOT}/ArduinoJson.h" >&2
  echo "Run firmware/tools/stackchan-cores3/build.sh first, or set FIRMWARE_ARDUINOJSON_ROOT." >&2
  exit 1
fi

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

cat >"${TMP_DIR}/user_signing_confirmation_test.cpp" <<'CPP'
#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "local_auth_worker.h"
#include "local_pin_auth.h"
#include "pin_attempt.h"
#include "user_signing_confirmation_test.h"
#include "signing/user_signing_flow_test.h"
#include "protocol/session_state.h"
#include "sui_account_settings.h"
#include "sui_account_store.h"
#include "sui_zklogin_proof_store.h"
#include "freertos/FreeRTOS.h"

namespace signing {

bool store_signing_authorization_mode(AuthorizationMode)
{
    return true;
}

bool store_sui_account_settings(const SuiAccountSettings&)
{
    return true;
}

}  // namespace signing

namespace {

signing::SessionValidationResult validate_flow_session(const char* session_id, void*)
{
    return signing::session_validate(session_id);
}

int failures = 0;
TickType_t g_now = 1;
int g_history_write_calls = 0;
bool g_history_write_result = true;
bool g_history_write_clears_flow = false;
char g_account_address[signing::kSuiAddressBufferSize] =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
uint32_t g_last_worker_job_id = 0;
uint32_t g_worker_cancel_attempt_count = 0;
bool g_worker_job_cancellable = false;
constexpr TickType_t kDefaultRequestWindowStart = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

signing::TimeoutWindow pin_window(TickType_t started_at, TickType_t deadline)
{
    return signing::timeout_window_from_deadline(started_at, deadline);
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
        read_hex_fixture(SUI_TEST_VALID_TRANSFER_TX_HEX);
    return payload;
}

void enter_pin(const char* pin)
{
    for (size_t index = 0; pin[index] != '\0'; ++index) {
        expect(signing::local_pin_auth_add_digit(pin[index]) ==
                   signing::LocalPinAuthInputResult::accepted,
               "PIN digit accepted");
    }
}

signing::LocalAuthWorkerResult make_verify_result(bool verified)
{
    g_worker_job_cancellable = false;
    signing::LocalAuthWorkerResult worker_result = {};
    worker_result.job_id = g_last_worker_job_id;
    worker_result.owner = signing::LocalAuthWorkerOwner::local_pin_auth;
    worker_result.operation = signing::LocalAuthWorkerOperation::authenticate_pin;
    worker_result.status = signing::LocalAuthWorkerStatus::completed;
    worker_result.operation_status = verified
        ? signing::KeystoreOperationStatus::success
        : signing::KeystoreOperationStatus::wrong_pin;
    return worker_result;
}

bool write_confirmation_history(
    const signing::UserSigningFlowCoreSnapshot& snapshot,
    void*)
{
    ++g_history_write_calls;
    expect(snapshot.active, "history writer receives active snapshot");
    expect(snapshot.stage == signing::UserSigningStage::history_write,
           "history writer receives history_write stage");
    expect(snapshot.signable_payload_available,
           "history writer runs before payload handoff");
    if (g_history_write_clears_flow) {
        expect(signing::user_signing_flow_clear() ==
                   signing::UserSigningTransitionResult::ok,
               "history writer can clear flow in misuse test");
    }
    return g_history_write_result;
}

signing::TimeoutWindow request_window(TickType_t deadline)
{
    return signing::timeout_window_from_deadline(kDefaultRequestWindowStart, deadline);
}

const uint8_t kRequestIdentity[signing::kSignRequestIdentitySize] = {};

void fill_prepared_sui_facts(
    const uint8_t* payload,
    size_t payload_size,
    signing::SuiPreparedSignTransaction* prepared)
{
    signing::SuiParsedTransactionFacts parsed = {};
    assert(signing::parse_sui_parsed_transaction_facts(payload, payload_size, &parsed) ==
           signing::SuiTransactionFactsResult::ok);
    assert(signing::build_sui_policy_subject_facts(parsed, &prepared->sui_policy_subject));
    assert(signing::build_sui_review_summary(parsed, &prepared->sui_review));
    prepared->user_mode_authorization_covered = true;
    prepared->user_authorization_outcome =
        signing::SuiUserAuthorizationOutcome::offline_facts_review;
}

signing::UserSigningTransactionBeginInput make_valid_input(
    const char* request_id,
    const char* session_id,
    const char* network,
    const uint8_t* payload,
    size_t payload_size,
    TickType_t deadline = 300)
{
    static signing::SuiPreparedSignTransaction prepared = {};
    if (prepared.tx_bytes != nullptr) {
        memset(prepared.tx_bytes, 0, prepared.tx_bytes_size);
        free(prepared.tx_bytes);
    }
    prepared = {};
    prepared.route = signing::SupportedSignRoute::sui_sign_transaction;
    snprintf(prepared.network, sizeof(prepared.network), "%s", network);
    prepared.tx_bytes = static_cast<uint8_t*>(malloc(payload_size));
    assert(prepared.tx_bytes != nullptr);
    memcpy(prepared.tx_bytes, payload, payload_size);
    prepared.tx_bytes_size = payload_size;
    snprintf(prepared.payload_digest, sizeof(prepared.payload_digest),
             "%s", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    fill_prepared_sui_facts(payload, payload_size, &prepared);
    return signing::UserSigningTransactionBeginInput{
        request_id,
        kRequestIdentity,
        session_id,
        signing::SupportedSignRoute::sui_sign_transaction,
        &prepared,
        request_window(deadline),
    };
}

void reset_all()
{
    signing::local_pin_auth_clear_flow();
    if (signing::user_signing_flow_in_signing_critical_section()) {
        expect(signing::user_signing_flow_record_signing_failed() ==
                   signing::UserSigningTransitionResult::ok,
               "test cleanup closes critical flow");
    }
    if (signing::user_signing_flow_terminal_pending()) {
        signing::UserSigningTerminalResult terminal = {};
        expect(signing::user_signing_flow_consume_terminal_result(&terminal),
               "test cleanup consumes terminal flow");
    }
    signing::user_signing_flow_clear();
    signing::user_signing_flow_set_session_validator(validate_flow_session, nullptr);
    signing::session_clear();
    signing::pin_attempt_clear();
    g_now = 1;
    g_history_write_calls = 0;
    g_history_write_result = true;
    g_history_write_clears_flow = false;
    g_worker_cancel_attempt_count = 0;
    g_worker_job_cancellable = false;
    snprintf(g_account_address, sizeof(g_account_address), "%s",
             "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

bool begin_valid_flow_with_deadline(const char* request_id, TickType_t deadline)
{
    const std::vector<uint8_t>& payload = valid_payload();
    if (signing::session_replace(random_bytes, nullptr) !=
        signing::SessionStartResult::ok) {
        return false;
    }
    return signing::user_signing_flow_begin(0,
               make_valid_input(
                   request_id,
                   signing::session_id(),
                   "devnet",
                   payload.data(),
                   payload.size(),
                   deadline)) ==
           signing::UserSigningFlowBeginResult::ok;
}

bool begin_valid_flow(const char* request_id)
{
    return begin_valid_flow_with_deadline(request_id, 300);
}

bool begin_valid_flow_in_current_session(const char* request_id, const char* network)
{
    const std::vector<uint8_t>& payload = valid_payload();
    if (!signing::session_active()) {
        return false;
    }
    return signing::user_signing_flow_begin(0,
               make_valid_input(
                   request_id,
                   signing::session_id(),
                   network,
                   payload.data(),
                   payload.size())) ==
           signing::UserSigningFlowBeginResult::ok;
}

}  // namespace

extern "C" TickType_t xTaskGetTickCount(void)
{
    return g_now;
}

namespace signing {

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

SuiActiveIdentity resolve_active_sui_identity()
{
    SuiActiveIdentity identity = {};
    identity.kind = SuiActiveIdentityKind::native;
    identity.error = SuiActiveIdentityError::none;
    snprintf(identity.address, sizeof(identity.address), "%s", g_account_address);
    return identity;
}

bool local_auth_worker_submit_authenticate(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id)
{
    (void)owner;
    static uint32_t next_job_id = 1;
    if (job_id == nullptr || !keystore_pin_valid(
            pin, kLocalAuthMinDigits, kLocalAuthMaxDigits)) {
        return false;
    }
    *job_id = next_job_id++;
    g_last_worker_job_id = *job_id;
    g_worker_job_cancellable = true;
    return true;
}

bool local_auth_worker_submit_unlock(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id)
{
    return local_auth_worker_submit_authenticate(owner, pin, job_id);
}

bool local_auth_worker_submit_rewrap(
    LocalAuthWorkerOwner owner,
    const char* current_pin,
    const char* new_pin,
    uint32_t* job_id)
{
    return keystore_pin_valid(
               new_pin, kLocalAuthMinDigits, kLocalAuthMaxDigits) &&
           local_auth_worker_submit_authenticate(owner, current_pin, job_id);
}

bool local_auth_worker_cancel_authentication(uint32_t job_id)
{
    ++g_worker_cancel_attempt_count;
    if (!g_worker_job_cancellable || job_id != g_last_worker_job_id) {
        return false;
    }
    g_worker_job_cancellable = false;
    return true;
}

bool read_human_approval_input_mode(HumanApprovalInputMode*)
{
    return false;
}

bool human_approval_requires_pin()
{
    return true;
}

bool store_human_approval_input_mode(HumanApprovalInputMode)
{
    return false;
}

bool wipe_human_approval_input_mode()
{
    return true;
}

}  // namespace signing

int main()
{
    using Confirm = signing::UserSigningConfirmationResult;
    using FlowStage = signing::UserSigningStage;
    using PinPurpose = signing::LocalPinAuthPurpose;
    using PinStage = signing::LocalPinAuthStage;

    {
        reset_all();
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 200)) ==
                   Confirm::inactive,
               "cannot start signing PIN without active request");
        expect(!signing::user_signing_confirmation_pin_active(),
               "inactive begin does not start signing PIN");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_pin_busy"), "begin before local PIN conflict");
        expect(signing::local_pin_auth_begin_connect(99, pin_window(99, 200)),
               "unrelated local PIN flow begins before conflict test");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 200)) ==
                   Confirm::local_pin_busy,
               "active unrelated local PIN blocks signing PIN");
        expect(signing::user_signing_flow_snapshot().stage == FlowStage::reviewing,
               "local PIN conflict leaves request in reviewing");
    }

    {
        reset_all();
        expect(begin_valid_flow_with_deadline("req_pin_busy_paused", 120),
               "begin before paused local PIN conflict");
        expect(signing::user_signing_flow_pause_review_deadline(90) ==
                   signing::UserSigningTransitionResult::ok,
               "review scroll pauses request deadline before local PIN conflict");
        expect(signing::local_pin_auth_begin_connect(99, pin_window(99, 200)),
               "unrelated local PIN flow begins before paused conflict test");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(
                   100,
                   pin_window(100, 200)) == Confirm::local_pin_busy,
               "active unrelated local PIN blocks paused signing PIN without preparing handoff");
        signing::UserSigningFlowSnapshot paused_busy_flow =
            signing::user_signing_flow_snapshot();
        signing::UserSigningReviewTimerState paused_busy_timer =
            signing::user_signing_flow_review_timer_state(100);
        expect(paused_busy_flow.stage == FlowStage::reviewing &&
                   paused_busy_flow.request_window.started_at == 0 &&
                   paused_busy_flow.request_window.deadline == 0 &&
                   paused_busy_timer.paused &&
                   paused_busy_timer.display_tick == 90,
               "local PIN conflict leaves paused review deadline untouched");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_pin_ok"), "begin before signing PIN");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 200)) ==
                   Confirm::ok,
               "review acceptance starts request-bound signing PIN");
        signing::LocalPinAuthSnapshot pin = signing::local_pin_auth_snapshot(100);
        expect(pin.flow_active && pin.purpose == PinPurpose::user_signing &&
                   pin.stage == PinStage::pin_entry,
               "signing PIN state is request-bound");
        expect(signing::user_signing_flow_snapshot().stage == FlowStage::pin_entry,
               "request flow moved to pin_entry");

        enter_pin("123456");
        g_now = 101;
        expect(signing::local_pin_auth_submit(101, 0, pin_window(101, 200), 150) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "signing PIN submit starts verification");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(101) ==
                   Confirm::ok,
               "signing PIN submit pauses only PIN input deadline");
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 120, 0, true, nullptr, nullptr) ==
                   Confirm::invalid_argument,
               "missing history writer fails closed");
        expect(g_history_write_calls == 0,
               "missing history writer does not call history writer");
        expect(!signing::user_signing_confirmation_pin_active(),
               "missing history writer clears signing PIN");
        expect(signing::user_signing_flow_snapshot().terminal_result ==
                   signing::UserSigningTerminalResult::canceled,
               "missing history writer terminalizes request");

        reset_all();
        expect(begin_valid_flow("req_material_lost"),
               "begin before signing material loss");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(
                   99, pin_window(99, 200)) == Confirm::ok,
               "review acceptance starts PIN before signing material loss");
        enter_pin("123456");
        g_now = 101;
        expect(signing::local_pin_auth_submit(101, 0, pin_window(101, 200), 150) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "material-loss test starts PIN verification");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(101) ==
                   Confirm::ok,
               "material-loss test records PIN verification start");
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true),
                   120,
                   0,
                   false,
                   write_confirmation_history,
                   nullptr) == Confirm::auth_unavailable,
               "material loss after PIN result fails closed");
        expect(g_history_write_calls == 0,
               "material loss after PIN result does not write confirmation history");
        expect(!signing::user_signing_confirmation_pin_active(),
               "material loss after PIN result clears local PIN state");
        expect(signing::user_signing_flow_terminal_pending(),
               "material loss after PIN result terminalizes the signing request");

        reset_all();
        expect(begin_valid_flow("req_pin_ok_2"), "begin before signing PIN retry");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 200)) ==
                   Confirm::ok,
               "review acceptance starts request-bound signing PIN retry");
        enter_pin("123456");
        g_now = 101;
        expect(signing::local_pin_auth_submit(101, 0, pin_window(101, 200), 150) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "signing PIN retry submit starts verification");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(101) ==
                   Confirm::ok,
               "signing PIN retry submit pauses only PIN input deadline");
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 120, 0, true, write_confirmation_history, nullptr) ==
                   Confirm::ok,
               "verified PIN completion writes history and enters critical section");
        expect(g_history_write_calls == 1, "history writer called once");
        expect(!signing::user_signing_confirmation_pin_active(),
               "verified PIN terminal handling clears local PIN flow");
        expect(signing::user_signing_flow_in_signing_critical_section(),
               "request flow entered signing critical section");

        reset_all();
        expect(begin_valid_flow("req_pin_late_verify"), "begin before late PIN verify");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 120)) ==
                   Confirm::ok,
               "review acceptance starts short signing PIN window");
        enter_pin("123456");
        g_now = 119;
        expect(signing::local_pin_auth_submit(119, 0, pin_window(119, 120), 125) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "PIN submit starts verification before input window closes");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(119) ==
                   Confirm::ok,
               "PIN verification start pauses only signing PIN input deadline");
        expect(signing::user_signing_flow_snapshot().pin_input_window.deadline == 0 &&
                   signing::user_signing_flow_snapshot().pin_input_window.started_at == 0 &&
                   signing::user_signing_flow_snapshot().request_window.deadline == 300,
               "only signing PIN input deadline is paused during verification");
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 170, 0, true, write_confirmation_history, nullptr) ==
                   Confirm::ok,
               "verified PIN after input deadline still enters critical section");
        expect(signing::user_signing_flow_in_signing_critical_section(),
               "late verified PIN is not converted to timeout");

        reset_all();
        expect(begin_valid_flow("req_pin_worker_late"),
               "begin before late worker terminal result");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(
                   99, pin_window(99, 160)) == Confirm::ok,
               "review acceptance starts PIN before late worker terminal result");
        enter_pin("123456");
        g_now = 100;
        expect(signing::local_pin_auth_submit(100, 0, pin_window(100, 160), 105) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "late worker terminal test starts PIN verification");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(100) ==
                   Confirm::ok,
               "late worker terminal test records PIN verification start");
        const uint32_t cancel_attempts_before_result =
            g_worker_cancel_attempt_count;
        signing::LocalAuthWorkerResult late_worker_result =
            make_verify_result(true);
        g_now = 106;
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   late_worker_result,
                   106,
                   0,
                   true,
                   write_confirmation_history,
                   nullptr) == Confirm::auth_unavailable,
               "late worker terminal result fails closed");
        expect(g_worker_cancel_attempt_count == cancel_attempts_before_result,
               "late signing terminal result cleanup does not cancel an ended worker job");
        expect(!signing::user_signing_confirmation_pin_active(),
               "late worker terminal result clears signing PIN state");
        expect(signing::user_signing_flow_terminal_pending(),
               "late worker terminal result terminalizes the signing request");

        reset_all();
        expect(begin_valid_flow_with_deadline("req_pin_from_paused_review", 100),
               "begin before signing PIN from paused review");
        expect(signing::user_signing_flow_pause_review_deadline(90) ==
                   signing::UserSigningTransitionResult::ok,
               "review scroll pauses request deadline before signing PIN");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(
                   150,
                   pin_window(150, 220)) == Confirm::ok,
               "paused review Sign starts PIN with state-owned cap");
        signing::LocalPinAuthSnapshot paused_pin =
            signing::local_pin_auth_snapshot(150);
        signing::UserSigningFlowSnapshot paused_flow =
            signing::user_signing_flow_snapshot();
        expect(paused_pin.flow_active &&
                   paused_pin.input_window.started_at == 150 &&
                   paused_pin.input_window.deadline == 160,
               "local signing PIN uses resumed review deadline cap");
        expect(paused_flow.stage == FlowStage::pin_entry &&
                   paused_flow.request_window.started_at == 60 &&
                   paused_flow.request_window.deadline == 160 &&
                   paused_flow.pin_input_window.started_at == paused_pin.input_window.started_at &&
                   paused_flow.pin_input_window.deadline == paused_pin.input_window.deadline,
               "flow and local PIN share one capped signing PIN deadline");

        reset_all();
        expect(begin_valid_flow_with_deadline("req_pin_after_abandoned_scroll", 100),
               "begin before signing PIN after abandoned scroll");
        expect(signing::user_signing_flow_pause_review_deadline(90) ==
                   signing::UserSigningTransitionResult::ok,
               "review scroll pauses request deadline before late signing PIN");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(
                   205,
                   pin_window(205, 260)) == Confirm::deadline_expired,
               "late paused review Sign applies abandoned fallback before PIN auth");
        expect(!signing::user_signing_confirmation_pin_active(),
               "late paused review Sign does not start local PIN auth");
        signing::UserSigningFlowSnapshot late_paused_flow =
            signing::user_signing_flow_snapshot();
        expect(late_paused_flow.stage == FlowStage::terminal &&
                   late_paused_flow.terminal_result ==
                       signing::UserSigningTerminalResult::timed_out,
               "late paused review Sign observes fallback-produced timeout");
    }

    {
        reset_all();
        expect(begin_valid_flow_with_deadline("req_pin_after_original_window", 130),
               "begin before late verified PIN");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 120)) ==
                   Confirm::ok,
               "review acceptance starts short signing PIN window");
        enter_pin("123456");
        g_now = 119;
        expect(signing::local_pin_auth_submit(119, 0, pin_window(119, 120), 125) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "PIN submit starts verification before input window closes");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(119) ==
                   Confirm::ok,
               "PIN verification start pauses the signing input deadline");
        expect(signing::user_signing_flow_snapshot().pin_input_window.deadline == 0 &&
                   signing::user_signing_flow_snapshot().pin_input_window.started_at == 0 &&
                   signing::user_signing_flow_snapshot().request_window.deadline == 130,
               "only signing PIN input deadline is paused while verification runs");
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 170, 0, true, write_confirmation_history, nullptr) ==
                   Confirm::ok,
               "verified PIN after request admission window still enters critical section");
        expect(!signing::user_signing_confirmation_pin_active(),
               "verified PIN after request admission window clears signing PIN");
        expect(signing::user_signing_flow_in_signing_critical_section(),
               "verified PIN after request admission window reaches critical section");
        expect(g_history_write_calls == 1,
               "verified PIN after request admission window writes confirmation history");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_wrong_pin"), "begin before wrong PIN");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 120)) ==
                   Confirm::ok,
               "review acceptance before wrong PIN");
        enter_pin("000000");
        g_now = 119;
        expect(signing::local_pin_auth_submit(119, 0, pin_window(119, 120), 125) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "wrong signing PIN starts verification");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(119) ==
                   Confirm::ok,
               "wrong PIN verification start pauses only signing PIN input deadline");
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(false), 170, 300, true, write_confirmation_history, nullptr) ==
                   Confirm::wrong_pin,
               "wrong signing PIN after input deadline resumes remaining input window");
        expect(signing::user_signing_confirmation_pin_active(),
               "wrong signing PIN keeps local PIN active");
        expect(signing::user_signing_flow_snapshot().stage == FlowStage::pin_entry,
               "wrong signing PIN does not write history");
        expect(signing::user_signing_flow_snapshot().request_window.deadline == 300 &&
                   signing::user_signing_flow_snapshot().pin_input_window.started_at == 150 &&
                   signing::user_signing_flow_snapshot().pin_input_window.deadline == 171,
               "wrong signing PIN resumes remaining time without resetting timer fill");
        expect(g_history_write_calls == 0, "wrong signing PIN does not call history writer");
    }

    {
        reset_all();
        expect(begin_valid_flow_with_deadline("req_wrong_pin_after_original_window", 130),
               "begin before wrong PIN after original input window");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 120)) ==
                   Confirm::ok,
               "review acceptance before wrong PIN");
        enter_pin("000000");
        g_now = 119;
        expect(signing::local_pin_auth_submit(119, 0, pin_window(119, 120), 125) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "wrong PIN starts verification before input window closes");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(119) ==
                   Confirm::ok,
               "wrong PIN verification start pauses the input deadline");
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(false), 170, 300, true, write_confirmation_history, nullptr) ==
                   Confirm::wrong_pin,
               "wrong PIN after request admission window resumes remaining input window");
        expect(signing::user_signing_confirmation_pin_active(),
               "wrong PIN after request admission window keeps local PIN active");
        expect(signing::user_signing_flow_snapshot().stage == FlowStage::pin_entry &&
                   signing::user_signing_flow_snapshot().pin_input_window.started_at == 150 &&
                   signing::user_signing_flow_snapshot().pin_input_window.deadline == 171,
               "wrong PIN after request admission window resumes remaining time without resetting timer fill");
        expect(g_history_write_calls == 0,
               "wrong PIN does not write history");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_lockout"), "begin before signing PIN lockout");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 260)) ==
                   Confirm::ok,
               "review acceptance before signing PIN lockout");

        for (uint8_t attempt = 0; attempt < signing::kMaxWrongPinAttempts; ++attempt) {
            const TickType_t submit_at = static_cast<TickType_t>(101 + attempt * 3);
            const TickType_t verify_at = static_cast<TickType_t>(submit_at + 1);
            g_now = submit_at;
            enter_pin("000000");
            expect(signing::local_pin_auth_submit(submit_at, 0, pin_window(submit_at, 260), 200) ==
                       signing::LocalPinAuthSubmitResult::started_verification,
                   "wrong signing PIN attempt starts verification before lockout");
            expect(signing::user_signing_confirmation_mark_pin_verification_started(submit_at) ==
                       Confirm::ok,
                   "wrong signing PIN attempt pauses signing input before lockout");
            g_now = verify_at;
            const Confirm result =
                signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                    make_verify_result(false), verify_at, 240, true, write_confirmation_history, nullptr);
            expect(result ==
                       (attempt + 1 == signing::kMaxWrongPinAttempts
                            ? Confirm::locked
                            : Confirm::wrong_pin),
                   "signing PIN lockout is distinct from wrong-PIN retry");
        }

        const signing::LocalPinAuthSnapshot locked_pin =
            signing::local_pin_auth_snapshot(120);
        const signing::UserSigningFlowSnapshot locked_flow =
            signing::user_signing_flow_snapshot();
        expect(signing::user_signing_confirmation_pin_active(),
               "signing PIN lockout keeps bound PIN flow active");
        expect(locked_pin.lockout_active,
               "signing PIN lockout is visible to local PIN owner");
        expect(locked_pin.input_window.deadline == 0 &&
                   locked_pin.input_window.started_at == 0,
               "signing PIN lockout keeps local input window paused");
        expect(locked_flow.stage == FlowStage::pin_entry &&
                   locked_flow.pin_input_window.deadline == 0 &&
                   locked_flow.pin_input_window.started_at == 0,
               "signing PIN lockout keeps signing input window paused");
        expect(g_history_write_calls == 0,
               "signing PIN lockout does not write confirmation history");

        expect(signing::local_pin_auth_release_lockout_if_elapsed(240) ==
                   signing::LocalPinAuthLockoutReleaseResult::released,
               "signing PIN lockout release resumes local PIN owner");
        expect(signing::user_signing_flow_refresh_pin_deadline(240) ==
                   signing::UserSigningTransitionResult::ok,
               "signing PIN lockout release resumes signing owner");
        const signing::LocalPinAuthSnapshot resumed_pin =
            signing::local_pin_auth_snapshot(240);
        const signing::UserSigningFlowSnapshot resumed_flow =
            signing::user_signing_flow_snapshot();
        expect(signing::timeout_window_active(resumed_pin.input_window) &&
                   signing::timeout_window_active(resumed_flow.pin_input_window),
               "signing PIN lockout release restores active input windows");
        expect(resumed_pin.input_window.started_at == resumed_flow.pin_input_window.started_at &&
                   resumed_pin.input_window.deadline == resumed_flow.pin_input_window.deadline,
               "signing PIN lockout release keeps local and signing windows synchronized");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_auth_fail"), "begin before auth unavailable");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 200)) ==
                   Confirm::ok,
               "review acceptance before auth unavailable");
        enter_pin("123456");
        g_now = 101;
        expect(signing::local_pin_auth_submit(101, 0, pin_window(101, 200), 150) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "PIN submit before auth unavailable");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(101) ==
                   Confirm::ok,
               "auth unavailable submit pauses only PIN input deadline");
        signing::LocalAuthWorkerResult worker_result = make_verify_result(true);
        worker_result.status = signing::LocalAuthWorkerStatus::worker_unavailable;
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   worker_result, 120, 0, true, write_confirmation_history, nullptr) ==
                   Confirm::auth_unavailable,
               "auth unavailable fails closed");
        expect(!signing::user_signing_confirmation_pin_active(),
               "auth unavailable clears signing PIN");
        expect(signing::user_signing_flow_snapshot().terminal_result ==
                   signing::UserSigningTerminalResult::canceled,
               "auth unavailable terminalizes request");
        expect(g_history_write_calls == 0, "auth unavailable does not call history writer");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_same_identity"), "begin before same-id stale PIN");
        const char same_session[signing::kSessionIdSize] = {};
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 200)) ==
                   Confirm::ok,
               "review acceptance before same-id stale PIN");
        char session_copy[signing::kSessionIdSize] = {};
        snprintf(session_copy, sizeof(session_copy), "%s", signing::session_id());
        enter_pin("123456");
        g_now = 101;
        expect(signing::local_pin_auth_submit(101, 0, pin_window(101, 200), 150) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "PIN submit before same-id stale PIN");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(101) ==
                   Confirm::ok,
               "same-id stale PIN submit pauses only PIN input deadline");
        expect(signing::user_signing_flow_clear() ==
                   signing::UserSigningTransitionResult::ok,
               "misuse clears same-id request while PIN worker is pending");
        (void)same_session;
        expect(strcmp(signing::session_id(), session_copy) == 0,
               "replacement keeps same session");
        expect(begin_valid_flow_in_current_session("req_same_identity", "testnet"),
               "begin replacement with same request and session but different network");
        expect(signing::user_signing_flow_accept_review(99, pin_window(99, 220)) ==
                   signing::UserSigningTransitionResult::ok,
               "misuse moves same-id replacement flow to pin_entry without coordinator");
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 120, 0, true, write_confirmation_history, nullptr) ==
                   Confirm::wrong_stage,
               "old PIN cannot verify same-id replacement request");
        expect(g_history_write_calls == 0, "same-id stale PIN does not write history");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_history_fail"), "begin before history failure");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 200)) ==
                   Confirm::ok,
               "review acceptance before history failure");
        enter_pin("123456");
        g_now = 101;
        expect(signing::local_pin_auth_submit(101, 0, pin_window(101, 200), 150) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "PIN submit before history failure");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(101) ==
                   Confirm::ok,
               "history failure submit pauses only PIN input deadline");
        g_history_write_result = false;
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 120, 0, true, write_confirmation_history, nullptr) ==
                   Confirm::history_error,
               "history failure terminalizes request");
        expect(!signing::user_signing_confirmation_pin_active(),
               "history failure clears local PIN");
        expect(signing::user_signing_flow_snapshot().terminal_result ==
                   signing::UserSigningTerminalResult::history_error,
               "history failure terminal result recorded");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_session_loss"), "begin before session loss");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 200)) ==
                   Confirm::ok,
               "review acceptance before session loss");
        enter_pin("123456");
        g_now = 101;
        expect(signing::local_pin_auth_submit(101, 0, pin_window(101, 200), 150) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "PIN submit before session loss");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(101) ==
                   Confirm::ok,
               "session-loss submit pauses only PIN input deadline");
        signing::session_clear();
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 120, 0, true, write_confirmation_history, nullptr) ==
                   Confirm::invalid_session,
               "session loss before history write cancels the active confirmation");
        expect(!signing::user_signing_confirmation_pin_active(),
               "session loss clears local PIN");
        expect(g_history_write_calls == 0, "session loss happens before history writer");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_stale_pin"), "begin before stale PIN misuse");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 200)) ==
                   Confirm::ok,
               "review acceptance before stale PIN misuse");
        enter_pin("123456");
        g_now = 101;
        expect(signing::local_pin_auth_submit(101, 0, pin_window(101, 200), 150) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "PIN submit before stale PIN misuse");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(101) ==
                   Confirm::ok,
               "stale PIN submit pauses only PIN input deadline");
        expect(signing::user_signing_flow_clear() ==
                   signing::UserSigningTransitionResult::ok,
               "misuse clears request flow while PIN worker is pending");
        expect(begin_valid_flow("req_stale_new"), "begin replacement flow");
        expect(signing::user_signing_flow_accept_review(99, pin_window(99, 220)) ==
                   signing::UserSigningTransitionResult::ok,
               "misuse moves replacement flow to pin_entry without coordinator");
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 120, 0, true, write_confirmation_history, nullptr) ==
                   Confirm::wrong_stage,
               "old PIN cannot verify replacement request");
        expect(g_history_write_calls == 0, "stale PIN does not write history");
        expect(signing::user_signing_flow_snapshot().request_id[0] != '\0',
               "replacement flow was not cleared by stale PIN");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_pin_back"), "begin before PIN Back");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 200)) ==
                   Confirm::ok,
               "review acceptance before PIN Back");
        expect(signing::user_signing_confirmation_record_device_rejected() ==
                   Confirm::wrong_stage,
               "PIN entry cannot be recorded as device rejection");
        expect(signing::user_signing_confirmation_return_to_review_from_pin(110, pin_window(110, 170)) ==
                   Confirm::ok,
               "PIN Back returns to review");
        expect(!signing::user_signing_confirmation_pin_active(),
               "PIN Back clears signing PIN scratch");
        expect(signing::user_signing_flow_snapshot().stage ==
                   signing::UserSigningStage::reviewing,
               "PIN Back restores signing review");
        expect(signing::user_signing_flow_snapshot().signable_payload_available,
               "PIN Back preserves signable payload");
        expect(signing::user_signing_confirmation_record_device_rejected() ==
                   Confirm::ok,
               "review rejection after PIN Back clears request");
        expect(signing::user_signing_flow_snapshot().terminal_result ==
                   signing::UserSigningTerminalResult::rejected,
               "review rejection terminal result recorded");
    }

    {
        reset_all();
        expect(begin_valid_flow("req_callback_clear"), "begin before callback clear");
        expect(signing::user_signing_confirmation_accept_review_and_begin_pin(99, pin_window(99, 200)) ==
                   Confirm::ok,
               "review acceptance before callback clear");
        enter_pin("123456");
        g_now = 101;
        expect(signing::local_pin_auth_submit(101, 0, pin_window(101, 200), 150) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "PIN submit before callback clear");
        expect(signing::user_signing_confirmation_mark_pin_verification_started(101) ==
                   Confirm::ok,
               "callback clear submit pauses only PIN input deadline");
        g_history_write_clears_flow = true;
        expect(signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                   make_verify_result(true), 120, 0, true, write_confirmation_history, nullptr) ==
                   Confirm::stale_state,
               "callback clear cannot enter critical section");
        expect(!signing::user_signing_confirmation_pin_active(),
               "callback clear clears signing PIN");
    }

    if (failures != 0) {
        fprintf(stderr, "%d user_signing confirmation test(s) failed\n", failures);
        return 1;
    }
    printf("user_signing confirmation tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -DSUI_TEST_VALID_TRANSFER_TX_HEX=\"${COMMON_ROOT}/sui/testdata/sui_transaction_facts/valid_sui_transfer_tx.bcs.hex\" \
  -I"${TMP_DIR}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_ROOT}/sui" \
  -I"${ARDUINOJSON_ROOT}" \
  "${TMP_DIR}/user_signing_confirmation_test.cpp" \
  "${RUNTIME_DIR}/user_signing_confirmation.cpp" \
  "${COMMON_ROOT}/signing/user_signing_flow.cpp" \
  "${RUNTIME_DIR}/sui_signing_authority.cpp" \
  "${RUNTIME_DIR}/local_pin_auth.cpp" \
  "${RUNTIME_DIR}/pin_attempt.cpp" \
  "${COMMON_ROOT}/protocol/session_state.cpp" \
  "${COMMON_ROOT}/sui/account_binding.cpp" \
  "${COMMON_ROOT}/sui/sign_transaction_adapter.cpp" \
  "${COMMON_ROOT}/sui/transaction_facts.cpp" \
  "${COMMON_ROOT}/sui/bcs_reader.cpp" \
  -o "${TMP_DIR}/user_signing_confirmation_test"

"${TMP_DIR}/user_signing_confirmation_test"
