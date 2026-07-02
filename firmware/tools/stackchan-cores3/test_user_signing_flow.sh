#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_user_signing_flow.sh

Compiles the StackChan CoreS3 device-confirmed user_signing flow owner
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
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-user-signing-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/firmware_common" "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/firmware_common/sui"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/user_signing_flow_test.cpp" <<'CPP'
#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "user_signing_flow_test.h"
#include "sui_account_store.h"
#include "sui_zklogin_proof_store.h"

namespace {

int failures = 0;
bool g_digest_result = true;
int g_digest_calls = 0;
signing::SuiAccountDerivationResult g_account_result =
    signing::SuiAccountDerivationResult::ok;
char g_account_address[signing::kSuiAddressBufferSize] =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
bool g_history_write_result = true;
bool g_history_write_clears_session = false;
bool g_history_write_clears_flow = false;
bool g_history_write_restarts_flow = false;
bool g_history_write_rejects_flow = false;
int g_history_write_calls = 0;
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

constexpr const char* kDefaultStoredSigner =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

signing::TimeoutWindow request_window(TickType_t deadline)
{
    return signing::timeout_window_from_deadline(kDefaultRequestWindowStart, deadline);
}

signing::TimeoutWindow timeout_window(TickType_t started_at, TickType_t deadline)
{
    return signing::timeout_window_from_deadline(started_at, deadline);
}

const uint8_t kRequestIdentity[signing::kSignRequestIdentitySize] = {};

void fill_prepared_sui_facts(
    const uint8_t* payload,
    size_t payload_size,
    signing::SuiPreparedSignTransaction* prepared)
{
    signing::SuiParsedTransactionFacts parsed = {};
    if (signing::parse_sui_parsed_transaction_facts(payload, payload_size, &parsed) ==
        signing::SuiTransactionFactsResult::ok) {
        assert(signing::build_sui_policy_subject_facts(parsed, &prepared->sui_policy_subject));
        assert(signing::build_sui_review_summary(parsed, &prepared->sui_review));
        // Most user-flow tests exercise the clear-review path. Dedicated cases
        // below cover the blind-signing confirmation path for insufficient review
        // coverage.
        prepared->sui_review.status = signing::SuiReviewSummaryStatus::ok;
        prepared->user_mode_authorization_covered = true;
        prepared->user_authorization_outcome =
            signing::SuiUserAuthorizationOutcome::offline_facts_review;
    }
}

signing::UserSigningTransactionBeginInput make_valid_input(
    const char* request_id,
    const char* session_id,
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
    snprintf(prepared.network, sizeof(prepared.network), "%s", "devnet");
    if (payload != nullptr && payload_size > 0) {
        prepared.tx_bytes = static_cast<uint8_t*>(malloc(payload_size));
        assert(prepared.tx_bytes != nullptr);
        memcpy(prepared.tx_bytes, payload, payload_size);
        prepared.tx_bytes_size = payload_size;
        snprintf(prepared.payload_digest, sizeof(prepared.payload_digest),
                 "%s", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        fill_prepared_sui_facts(payload, payload_size, &prepared);
    }
    return signing::UserSigningTransactionBeginInput{
        request_id,
        kRequestIdentity,
        session_id,
        signing::SupportedSignRoute::sui_sign_transaction,
        &prepared,
        request_window(deadline),
    };
}

signing::UserSigningPersonalMessageBeginInput make_valid_message_input(
    const char* request_id,
    const char* session_id,
    const uint8_t* message,
    size_t message_size,
    TickType_t deadline = 300)
{
    static signing::SuiPreparedPersonalMessage prepared = {};
    prepared = {};
    prepared.route = signing::SupportedSignRoute::sui_sign_personal_message;
    snprintf(prepared.network, sizeof(prepared.network), "%s", "devnet");
    if (message != nullptr && message_size <= sizeof(prepared.message)) {
        memcpy(prepared.message, message, message_size);
        prepared.message_size = message_size;
        snprintf(prepared.payload_digest, sizeof(prepared.payload_digest),
                 "%s", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        snprintf(prepared.account_address, sizeof(prepared.account_address), "%s", kDefaultStoredSigner);
    }
    return signing::UserSigningPersonalMessageBeginInput{
        request_id,
        kRequestIdentity,
        session_id,
        signing::SupportedSignRoute::sui_sign_personal_message,
        &prepared,
        request_window(deadline),
    };
}

void reset_history_writer_stub()
{
    g_history_write_result = true;
    g_history_write_clears_session = false;
    g_history_write_clears_flow = false;
    g_history_write_restarts_flow = false;
    g_history_write_rejects_flow = false;
    g_history_write_calls = 0;
}

bool write_confirmation_history(
    const signing::UserSigningFlowCoreSnapshot& snapshot,
    void*)
{
    ++g_history_write_calls;
    expect(snapshot.stage == signing::UserSigningStage::history_write,
           "history writer receives history_write snapshot");
    expect(snapshot.signable_payload_available,
           "history writer runs before payload handoff");
    if (g_history_write_clears_session) {
        signing::session_clear();
    }
    if (g_history_write_clears_flow) {
        expect(signing::user_signing_flow_clear() ==
                   signing::UserSigningTransitionResult::ok,
               "history writer can clear pre-critical flow in misuse test");
    }
    if (g_history_write_restarts_flow) {
        expect(signing::user_signing_flow_clear() ==
                   signing::UserSigningTransitionResult::ok,
               "history writer can clear before reentrant begin in misuse test");
        const std::vector<uint8_t>& payload = valid_payload();
        expect(signing::user_signing_flow_begin(0,
                   make_valid_input(
                       "req_reentrant_writer",
                       signing::session_id(),
                       payload.data(),
                       payload.size())) ==
                   signing::UserSigningFlowBeginResult::ok,
               "history writer can start a different request in misuse test");
    }
    if (g_history_write_rejects_flow) {
        expect(signing::user_signing_flow_record_device_rejected() ==
                   signing::UserSigningTransitionResult::wrong_stage,
               "history writer cannot reclassify confirmed request as rejected");
    }
    return g_history_write_result;
}

signing::UserSigningTransitionResult record_verified_pin_and_write_confirmation_history(
    signing::UserSigningHistoryWriteFn write_fn,
    void* context,
    TickType_t now = 100,
    TickType_t pause_at = 100)
{
    const signing::UserSigningFlowSnapshot snapshot =
        signing::user_signing_flow_snapshot();
    if (signing::timeout_window_active(snapshot.pin_input_window)) {
        const signing::UserSigningTransitionResult pause =
            signing::user_signing_flow_pause_pin_deadline(pause_at);
        if (pause != signing::UserSigningTransitionResult::ok) {
            return pause;
        }
    }
    return signing::user_signing_flow_record_pin_verified_and_write_confirmation_history(
        now,
        write_fn,
        context);
}

bool begin_valid_flow(const char* request_id = "req_signature_1")
{
    const std::vector<uint8_t>& payload = valid_payload();
    return signing::user_signing_flow_begin(0,
               make_valid_input(request_id, signing::session_id(), payload.data(), payload.size())) ==
           signing::UserSigningFlowBeginResult::ok;
}

void expect_terminal_review_metadata_wiped(
    const signing::UserSigningFlowSnapshot& snapshot,
    const char* label)
{
    expect(snapshot.signable_payload_size == 0 && !snapshot.signable_payload_available,
           label);
    expect(snapshot.session_id[0] == '\0', "terminal cleanup wipes session id");
    expect(snapshot.network[0] == '\0', "terminal cleanup wipes network");
    expect(snapshot.request_window.started_at == 0 && snapshot.request_window.deadline == 0,
           "terminal cleanup clears review window");
    expect(snapshot.pin_input_window.started_at == 0 && snapshot.pin_input_window.deadline == 0,
           "terminal cleanup clears PIN window");
    expect(snapshot.sui_policy_subject.sender[0] == '\0' &&
               snapshot.sui_policy_subject.gas_owner[0] == '\0' &&
               snapshot.sui_policy_subject.gas_budget[0] == '\0' &&
               snapshot.sui_policy_subject.gas_price[0] == '\0' &&
               snapshot.sui_policy_subject.command_count == 0 &&
               snapshot.sui_review.row_count == 0,
           "terminal cleanup wipes Sui review metadata");
    expect(snapshot.account_address[0] == '\0',
           "terminal cleanup wipes personal-message account address");
    expect(snapshot.message_preview[0] == '\0',
           "terminal cleanup wipes personal-message preview");
}

}  // namespace

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
    ++g_digest_calls;
    if (!g_digest_result ||
        payload == nullptr ||
        payload_size == 0 ||
        output == nullptr ||
        output_size != kApprovalHistoryDigestSize) {
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

SuiActiveIdentity resolve_active_sui_identity()
{
    SuiActiveIdentity identity = {};
    if (g_account_result != SuiAccountDerivationResult::ok) {
        identity.kind = SuiActiveIdentityKind::error;
        identity.error = SuiActiveIdentityError::native_account_unavailable;
        return identity;
    }
    identity.kind = SuiActiveIdentityKind::native;
    identity.error = SuiActiveIdentityError::none;
    snprintf(identity.address, sizeof(identity.address), "%s", g_account_address);
    return identity;
}

}  // namespace signing

int main()
{
    using Begin = signing::UserSigningFlowBeginResult;
    using Stage = signing::UserSigningStage;
    using Transition = signing::UserSigningTransitionResult;
    using Terminal = signing::UserSigningTerminalResult;
    using SessionValidation = signing::SessionValidationResult;

    Terminal terminal = Terminal::none;

    signing::session_init();
    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "test session starts");

    expect(signing::user_signing_flow_clear() == Transition::inactive,
           "clear on inactive flow reports inactive");
    expect(!signing::user_signing_flow_active(), "clear leaves flow inactive");
    expect(signing::user_signing_flow_validate_session() == SessionValidation::missing,
           "inactive flow has no session");

    static const uint8_t message[] = "Agent-Q personal message";
    expect(signing::user_signing_flow_begin_personal_message(0,
               make_valid_message_input(
                   "req_personal_message",
                   signing::session_id(),
                   message,
                   sizeof(message) - 1)) ==
               Begin::ok,
           "valid personal-message request begins in reviewing stage");
    signing::UserSigningFlowSnapshot personal_snapshot =
        signing::user_signing_flow_snapshot();
    expect(personal_snapshot.active, "personal-message snapshot is active");
    expect(personal_snapshot.stage == Stage::reviewing, "personal-message begin starts at reviewing");
    expect(personal_snapshot.signing_route == signing::Route::sui_sign_personal_message,
           "personal-message snapshot carries verified route enum");
    expect(strcmp(personal_snapshot.request_id, "req_personal_message") == 0,
           "personal-message request id stored");
    expect(strcmp(personal_snapshot.method, "sign_personal_message") == 0,
           "personal-message method stored");
    expect(personal_snapshot.request_window.started_at == kDefaultRequestWindowStart,
           "personal-message request start stored");
    expect(strcmp(personal_snapshot.account_address, kDefaultStoredSigner) == 0,
           "personal-message account address stored");
    expect(strcmp(personal_snapshot.message_preview, "Agent-Q personal message") == 0,
           "personal-message preview stored");
    expect(personal_snapshot.signable_payload_available,
           "personal-message signable payload initially available");
    expect(personal_snapshot.signable_payload_size == sizeof(message) - 1,
           "personal-message payload size stored");
    expect(strcmp(personal_snapshot.payload_digest, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0,
           "personal-message payload digest stored");
    expect(signing::user_signing_flow_clear() == Transition::ok,
           "personal-message flow clears before critical section");

    expect(signing::user_signing_flow_begin_personal_message(0,
               make_valid_message_input(
                   "req_personal_message_reject",
                   signing::session_id(),
                   message,
                   sizeof(message) - 1)) ==
               Begin::ok,
           "personal-message request begins before rejection cleanup test");
    expect(signing::user_signing_flow_record_device_rejected() == Transition::ok,
           "personal-message rejection terminalizes");
    personal_snapshot = signing::user_signing_flow_snapshot();
    expect(personal_snapshot.stage == Stage::terminal &&
               personal_snapshot.terminal_result == Terminal::rejected,
           "personal-message rejection reaches terminal stage");
    expect(strcmp(personal_snapshot.request_id, "req_personal_message_reject") == 0 &&
               strcmp(personal_snapshot.chain, "sui") == 0 &&
               strcmp(personal_snapshot.method, "sign_personal_message") == 0 &&
               strcmp(personal_snapshot.payload_digest, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0,
           "personal-message terminal keeps response/history metadata");
    expect_terminal_review_metadata_wiped(
        personal_snapshot,
        "personal-message terminal wipes signable payload");
    expect(signing::user_signing_flow_consume_terminal_result(&terminal) &&
               terminal == Terminal::rejected,
           "personal-message rejected terminal consumed");

    std::vector<uint8_t> max_transaction_payload(
        signing::kSuiSignTransactionTxBytesMaxBytes,
        0x5A);
    signing::UserSigningTransactionBeginInput max_payload_begin =
        make_valid_input(
            "req_max_transaction_payload",
            signing::session_id(),
            max_transaction_payload.data(),
            max_transaction_payload.size());
    max_payload_begin.prepared->user_mode_authorization_covered = true;
    max_payload_begin.prepared->user_authorization_outcome =
        signing::SuiUserAuthorizationOutcome::offline_facts_review;
    max_payload_begin.prepared->sui_review.status = signing::SuiReviewSummaryStatus::ok;
    expect(signing::user_signing_flow_begin(0, max_payload_begin) == Begin::ok,
           "max transaction payload begins without a smaller user-flow cap");
    signing::UserSigningFlowSnapshot max_payload_snapshot =
        signing::user_signing_flow_snapshot();
    expect(max_payload_snapshot.signable_payload_available,
           "max transaction payload is available to user-flow owner");
    expect(max_payload_snapshot.signable_payload_size == max_transaction_payload.size(),
           "max transaction payload size is stored without truncation");
    expect(signing::user_signing_flow_clear() == Transition::ok,
           "max transaction payload flow clears");

    const std::vector<uint8_t>& payload = valid_payload();
    signing::UserSigningTransactionBeginInput parser_only_begin =
        make_valid_input("req_parser_only", signing::session_id(), payload.data(), payload.size());
    parser_only_begin.prepared->user_mode_authorization_covered = false;
    expect(signing::user_signing_flow_begin(0, parser_only_begin) == Begin::unsupported_transaction,
           "parser-only transaction coverage cannot enter user signing flow");
    expect(parser_only_begin.prepared->tx_bytes != nullptr &&
               parser_only_begin.prepared->tx_bytes_size == payload.size(),
           "rejected parser-only transaction leaves prepared payload with caller");
    expect(!signing::user_signing_flow_active(),
           "parser-only transaction rejection leaves flow inactive");

    signing::UserSigningTransactionBeginInput missing_outcome_begin =
        make_valid_input(
            "req_missing_outcome",
            signing::session_id(),
            payload.data(),
            payload.size());
    missing_outcome_begin.prepared->user_mode_authorization_covered = true;
    missing_outcome_begin.prepared->user_authorization_outcome =
        signing::SuiUserAuthorizationOutcome::unavailable;
    expect(signing::user_signing_flow_begin(0, missing_outcome_begin) ==
               Begin::unsupported_transaction,
           "covered bool without user authorization outcome cannot enter user signing flow");
    expect(!signing::user_signing_flow_active(),
           "missing outcome rejection leaves flow inactive");

    signing::UserSigningTransactionBeginInput incomplete_review_begin =
        make_valid_input(
            "req_incomplete_review",
            signing::session_id(),
            payload.data(),
            payload.size());
    incomplete_review_begin.prepared->user_mode_authorization_covered = true;
    incomplete_review_begin.prepared->user_authorization_outcome =
        signing::SuiUserAuthorizationOutcome::blind_signing;
    incomplete_review_begin.prepared->sui_review.status =
        signing::SuiReviewSummaryStatus::insufficient_review;
    expect(signing::user_signing_flow_begin(0, incomplete_review_begin) == Begin::ok,
           "incomplete review enters blind-signing confirmation");
    signing::UserSigningFlowSnapshot incomplete_review_snapshot =
        signing::user_signing_flow_snapshot();
    expect(incomplete_review_snapshot.blind_signing_confirmation,
           "incomplete review snapshot marks blind-signing confirmation");
    expect(signing::user_signing_flow_clear() == Transition::ok,
           "incomplete review blind-signing flow clears");

    signing::UserSigningTransactionBeginInput mismatched_outcome_begin =
        make_valid_input(
            "req_mismatched_outcome",
            signing::session_id(),
            payload.data(),
            payload.size());
    mismatched_outcome_begin.prepared->user_authorization_outcome =
        signing::SuiUserAuthorizationOutcome::blind_signing;
    mismatched_outcome_begin.prepared->sui_review.status =
        signing::SuiReviewSummaryStatus::ok;
    expect(signing::user_signing_flow_begin(0, mismatched_outcome_begin) ==
               Begin::unsupported_transaction,
           "user authorization outcome must match the review payload");
    expect(!signing::user_signing_flow_active(),
           "mismatched outcome rejection leaves flow inactive");

    signing::UserSigningTransactionBeginInput first_begin =
        make_valid_input("req_signature_1", signing::session_id(), payload.data(), payload.size());
    expect(signing::user_signing_flow_begin(0, first_begin) == Begin::ok,
           "valid request begins in reviewing stage");
    expect(first_begin.prepared->tx_bytes == nullptr &&
               first_begin.prepared->tx_bytes_size == 0,
           "transaction begin transfers prepared payload ownership to user flow");
    signing::UserSigningFlowSnapshot snapshot =
        signing::user_signing_flow_snapshot();
    expect(snapshot.active, "snapshot is active");
    expect(snapshot.stage == Stage::reviewing, "begin starts at reviewing");
    expect(snapshot.signing_route == signing::Route::sui_sign_transaction,
           "transaction snapshot carries verified route enum");
    expect(strcmp(snapshot.request_id, "req_signature_1") == 0, "request id stored");
    expect(strcmp(snapshot.session_id, signing::session_id()) == 0, "session id stored");
    expect(strcmp(snapshot.chain, "sui") == 0, "chain stored");
    expect(strcmp(snapshot.method, "sign_transaction") == 0, "method stored");
    expect(strcmp(snapshot.network, "devnet") == 0, "network stored");
    expect(strcmp(snapshot.payload_digest, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0,
           "payload digest stored");
    expect(snapshot.request_window.deadline == 300,
           "request stores immutable confirmation deadline");
    expect(snapshot.request_window.started_at == kDefaultRequestWindowStart,
           "request stores immutable confirmation start");
    expect(snapshot.pin_input_window.deadline == 0,
           "request starts without a PIN input deadline");
    expect(snapshot.signable_payload_available, "payload initially available to owner");
    expect(snapshot.signable_payload_size == payload.size(), "payload size stored");
    expect(strcmp(snapshot.sui_policy_subject.sender, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0,
           "summary sender is parsed from payload");
    expect(strcmp(snapshot.sui_policy_subject.gas_owner, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0,
           "summary gas owner is parsed from payload");
    expect(snapshot.sui_policy_subject.command_count == 2,
           "summary command count is parsed from payload");
    expect(snapshot.sui_policy_subject.commands[0].kind == signing::SuiCommandFactKind::split_coins,
           "summary first command is parsed from payload");
    expect(snapshot.sui_policy_subject.commands[1].kind == signing::SuiCommandFactKind::transfer_objects,
           "summary second command is parsed from payload");
    expect(strcmp(snapshot.sui_policy_subject.gas_budget, "50000000") == 0, "summary gas budget is parsed from payload");
    expect(strcmp(snapshot.sui_policy_subject.gas_price, "1000") == 0, "summary gas price is parsed from payload");
    expect(snapshot.sui_review.status == signing::SuiReviewSummaryStatus::ok &&
               snapshot.sui_review.row_count > 0,
           "review summary is derived from payload");
    expect(signing::user_signing_flow_validate_session() == SessionValidation::ok,
           "matching active session validates");
    expect(signing::user_signing_flow_session_matches(signing::session_id()),
           "session match helper recognizes owner session");
    signing::UserSigningFlowSnapshot retained_snapshot = snapshot;
    expect(signing::user_signing_flow_clear() == Transition::ok,
           "clear before critical section succeeds");
    expect(strcmp(retained_snapshot.request_id, "req_signature_1") == 0 &&
               strcmp(retained_snapshot.session_id, snapshot.session_id) == 0 &&
               strcmp(retained_snapshot.payload_digest, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0,
           "snapshot owns copied request metadata after flow clear");
    expect(!signing::user_signing_flow_active(), "pre-critical clear leaves flow inactive");
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_signature_1", signing::session_id(), payload.data(), payload.size())) ==
               Begin::ok,
           "valid request restarts after snapshot value test");

    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_signature_2", signing::session_id(), payload.data(), payload.size())) ==
               Begin::active,
           "duplicate begin is rejected");
    snapshot = signing::user_signing_flow_snapshot();
    expect(strcmp(snapshot.request_id, "req_signature_1") == 0,
           "duplicate begin does not overwrite state");

    std::vector<uint8_t> copied(payload.size());
    size_t copied_size = 0;
    expect(signing::user_signing_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::wrong_stage,
           "payload cannot be consumed before history is durable");
    expect(copied_size == 0, "failed consume reports zero size");

    expect(signing::user_signing_flow_record_timeout(99) == Transition::deadline_not_reached,
           "timeout before deadline is rejected");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 0)) == Transition::invalid_deadline,
           "zero PIN deadline is rejected");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::reviewing, "invalid PIN deadline leaves review active");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok,
           "review acceptance moves to PIN entry");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::pin_entry &&
               snapshot.request_window.deadline == 300 &&
               snapshot.pin_input_window.started_at == 99 &&
               snapshot.pin_input_window.deadline == 200,
           "PIN entry stage stores local input deadline");
    expect(record_verified_pin_and_write_confirmation_history(nullptr,
               nullptr) == Transition::invalid_argument,
           "PIN verification requires a history writer callback");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::pin_entry,
           "missing history writer leaves PIN entry active");
    expect(signing::user_signing_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::wrong_stage,
           "payload cannot be consumed before history durable transition");
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr) == Transition::ok,
           "PIN verification writes durable history and enters critical section");
    expect(signing::user_signing_flow_in_signing_critical_section(),
           "critical section helper is true");
    expect(signing::user_signing_flow_clear() == Transition::busy,
           "public clear cannot wipe signing critical section");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section &&
               snapshot.signable_payload_available,
           "critical section remains active after public clear");
    expect(signing::user_signing_flow_complete_signed() == Transition::payload_not_consumed,
           "signed terminal requires one-shot payload handoff first");
    expect(signing::user_signing_flow_consume_signable_payload(copied.data(), copied.size() - 1, &copied_size) ==
               Transition::output_too_small,
           "small output buffer is rejected");
    expect(signing::user_signing_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::ok,
           "payload is consumable after history durability");
    expect(copied_size == payload.size() && memcmp(copied.data(), payload.data(), payload.size()) == 0,
           "payload copy matches source");
    snapshot = signing::user_signing_flow_snapshot();
    expect(!snapshot.signable_payload_available && snapshot.signable_payload_size == 0,
           "payload scratch is wiped after one-shot consume");
    expect(signing::user_signing_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::payload_unavailable,
           "payload cannot be consumed twice");
    expect(signing::user_signing_flow_complete_signed() == Transition::ok,
           "signed terminal is recorded");
    expect(signing::user_signing_flow_terminal_pending(), "signed terminal is pending");
    expect(signing::user_signing_flow_consume_terminal_result(&terminal) &&
               terminal == Terminal::signed_success,
           "signed terminal is one-shot consumable");
    expect(!signing::user_signing_flow_active(), "terminal consume clears state");
    expect(!signing::user_signing_flow_consume_terminal_result(&terminal),
           "terminal result cannot be consumed twice");
    expect(strcmp(signing::user_signing_flow_terminal_status(Terminal::signed_success), "signed") == 0 &&
               strcmp(signing::user_signing_flow_terminal_reason(Terminal::signed_success), "device_confirmed") == 0,
           "signed terminal mapping");

    signing::user_signing_flow_clear();
    reset_history_writer_stub();
    expect(begin_valid_flow("req_physical_confirm"), "begin before physical confirm");
    expect(signing::user_signing_flow_record_physical_confirmed_and_write_confirmation_history(
               99,
               write_confirmation_history,
               nullptr) == Transition::ok,
           "physical confirm writes durable history and enters critical section");
    expect(g_history_write_calls == 1, "physical confirm history writer called once");
    expect(signing::user_signing_flow_in_signing_critical_section(),
           "physical confirm enters signing critical section");
    expect(signing::user_signing_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::ok,
           "payload is consumable after physical confirmation history durability");
    expect(signing::user_signing_flow_complete_signed() == Transition::ok,
           "physical confirm signed terminal is recorded");
    expect(signing::user_signing_flow_consume_terminal_result(&terminal) &&
               terminal == Terminal::signed_success,
           "physical confirm signed terminal consumed");

    signing::user_signing_flow_clear();
    reset_history_writer_stub();
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_physical_scroll", signing::session_id(), payload.data(), payload.size(), 100)) ==
               Begin::ok,
           "begin before physical confirm from paused scroll");
    expect(signing::user_signing_flow_pause_review_deadline(90) == Transition::ok,
           "scroll start pauses review deadline before physical confirm");
    expect(signing::user_signing_flow_record_physical_confirmed_and_write_confirmation_history(
               150,
               write_confirmation_history,
               nullptr) == Transition::ok,
           "physical confirm while scroll-paused resumes review deadline before history");
    expect(g_history_write_calls == 1, "paused physical confirm history writer called once");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section &&
               snapshot.request_window.started_at == 60 &&
               snapshot.request_window.deadline == 160,
           "paused physical confirm preserves remaining review time for the critical snapshot");
    expect(signing::user_signing_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::ok,
           "payload is consumable after paused physical confirmation history durability");
    expect(signing::user_signing_flow_complete_signed() == Transition::ok,
           "paused physical confirm signed terminal is recorded");
    expect(signing::user_signing_flow_consume_terminal_result(&terminal) &&
               terminal == Terminal::signed_success,
           "paused physical confirm signed terminal consumed");

    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_reject"), "begin before reject");
    expect(signing::user_signing_flow_record_device_rejected() == Transition::ok,
           "device rejection terminalizes from review");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::rejected &&
               !snapshot.signable_payload_available,
           "reject terminal wipes payload");
    expect_terminal_review_metadata_wiped(snapshot, "reject terminal clears review metadata");
    expect(signing::user_signing_flow_consume_terminal_result(&terminal) &&
               terminal == Terminal::rejected,
           "rejected terminal consumed");
    expect(strcmp(signing::user_signing_flow_terminal_status(Terminal::rejected), "user_rejected") == 0 &&
               strcmp(signing::user_signing_flow_terminal_reason(Terminal::rejected), "user_rejected") == 0,
           "rejected terminal mapping");

    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_pin_back"), "begin before PIN Back");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok,
           "review acceptance before PIN Back");
    expect(signing::user_signing_flow_record_device_rejected() == Transition::wrong_stage,
           "PIN entry cannot be recorded as device rejection");
    expect(signing::user_signing_flow_return_to_review(110, pin_window(110, 160)) == Transition::ok,
           "PIN Back returns to review");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::reviewing &&
               snapshot.signable_payload_available &&
               strcmp(snapshot.request_id, "req_pin_back") == 0,
           "PIN Back preserves the signable request in review");
    expect(signing::user_signing_flow_record_device_rejected() == Transition::ok,
           "review Reject after PIN Back terminalizes request");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::rejected,
           "review Reject after PIN Back records user_rejected terminal");
    expect_terminal_review_metadata_wiped(snapshot, "PIN Back rejection clears review metadata");

    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_timeout"), "begin before timeout");
    expect(signing::user_signing_flow_record_timeout(300) == Transition::ok,
           "deadline timeout terminalizes");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::timed_out &&
               !snapshot.signable_payload_available,
           "timeout terminal wipes payload");
    expect_terminal_review_metadata_wiped(snapshot, "timeout terminal clears review metadata");
    expect(strcmp(signing::user_signing_flow_terminal_status(Terminal::timed_out), "user_timed_out") == 0 &&
               strcmp(signing::user_signing_flow_terminal_reason(Terminal::timed_out), "user_timed_out") == 0,
           "timeout terminal mapping");

    signing::user_signing_flow_clear();
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_scroll_paused", signing::session_id(), payload.data(), payload.size(), 100)) ==
               Begin::ok,
           "begin before scroll pause");
    expect(signing::user_signing_flow_pause_review_deadline(90) == Transition::ok,
           "scroll start pauses review deadline");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::reviewing &&
               snapshot.request_window.started_at == 0 &&
               snapshot.request_window.deadline == 0 &&
               snapshot.signable_payload_available,
           "paused scroll keeps review active without an active request deadline");
    expect(signing::user_signing_flow_record_timeout(100) == Transition::deadline_not_reached,
           "scroll pause prevents timeout at original deadline");
    signing::UserSigningReviewTimerState timer =
        signing::user_signing_flow_review_timer_state(150);
    expect(timer.available &&
               timer.paused &&
               timer.display_window.started_at == 0 &&
               timer.display_window.deadline == 100 &&
               timer.display_tick == 90,
           "paused review timer state exposes display window and paused display tick");
    expect(!signing::user_signing_flow_apply_deadline_transition(150),
           "deadline transition stays open while scrolling");
    expect(signing::user_signing_flow_resume_review_deadline(150) == Transition::ok,
           "scroll end resumes review deadline");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::reviewing &&
               snapshot.request_window.started_at == 60 &&
               snapshot.request_window.deadline == 160,
           "scroll end resumes with the remaining review time");
    expect(signing::user_signing_flow_record_timeout(159) == Transition::deadline_not_reached,
           "resumed review remains open before shifted deadline");
    expect(signing::user_signing_flow_record_timeout(160) == Transition::ok,
           "resumed review times out after remaining time");

    signing::user_signing_flow_clear();
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_scroll_abandoned", signing::session_id(), payload.data(), payload.size(), 100)) ==
               Begin::ok,
           "begin before abandoned scroll pause");
    expect(signing::user_signing_flow_pause_review_deadline(90) == Transition::ok,
           "abandoned scroll start pauses review deadline");
    expect(signing::user_signing_flow_record_timeout(189) == Transition::deadline_not_reached,
           "abandoned scroll fallback waits for bounded pause duration");
    timer = signing::user_signing_flow_review_timer_state(190);
    expect(timer.available &&
               timer.paused &&
               timer.display_tick == 90,
           "review timer projection does not apply abandoned scroll fallback");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::reviewing &&
               snapshot.request_window.started_at == 0 &&
               snapshot.request_window.deadline == 0,
           "review timer projection leaves paused review state unchanged");
    expect(signing::user_signing_flow_record_timeout(190) == Transition::deadline_not_reached,
           "abandoned scroll fallback resumes review without immediate timeout");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::reviewing &&
               snapshot.request_window.started_at == 100 &&
               snapshot.request_window.deadline == 200,
           "abandoned scroll fallback resumes at fallback deadline");
    expect(signing::user_signing_flow_record_timeout(200) == Transition::ok,
           "abandoned scroll times out after fallback-resumed remaining time");

    signing::user_signing_flow_clear();
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_scroll_late_check", signing::session_id(), payload.data(), payload.size(), 100)) ==
               Begin::ok,
           "begin before late paused deadline check");
    expect(signing::user_signing_flow_pause_review_deadline(90) == Transition::ok,
           "late paused deadline check starts from paused review");
    expect(signing::user_signing_flow_apply_deadline_transition(205),
           "late paused deadline transition applies abandoned fallback");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::timed_out,
           "late paused deadline transition terminalizes timed-out review");

    signing::user_signing_flow_clear();
    reset_history_writer_stub();
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_late_physical_scroll", signing::session_id(), payload.data(), payload.size(), 100)) ==
               Begin::ok,
           "begin before physical confirm after abandoned scroll");
    expect(signing::user_signing_flow_pause_review_deadline(90) == Transition::ok,
           "abandoned scroll starts before late physical confirm");
    expect(signing::user_signing_flow_record_physical_confirmed_and_write_confirmation_history(
               205,
               write_confirmation_history,
               nullptr) == Transition::deadline_expired,
           "late physical confirm applies abandoned fallback before history");
    expect(g_history_write_calls == 0,
           "late physical confirm does not write history after timeout");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::timed_out,
           "late physical confirm observes fallback-produced timeout");

    signing::user_signing_flow_clear();
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_late_scroll_end", signing::session_id(), payload.data(), payload.size(), 100)) ==
               Begin::ok,
           "begin before scroll end after abandoned scroll");
    expect(signing::user_signing_flow_pause_review_deadline(90) == Transition::ok,
           "abandoned scroll starts before late scroll end");
    expect(signing::user_signing_flow_resume_review_deadline(205) ==
               Transition::deadline_expired,
           "late scroll end applies abandoned fallback before resume");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::timed_out,
           "late scroll end observes fallback-produced timeout");

    signing::user_signing_flow_clear();
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_scroll_sign", signing::session_id(), payload.data(), payload.size(), 100)) ==
               Begin::ok,
           "begin before signing from paused scroll");
    expect(signing::user_signing_flow_pause_review_deadline(90) == Transition::ok,
           "scroll start before signing pauses review deadline");
    expect(signing::user_signing_flow_accept_review(150, pin_window(150, 220)) == Transition::ok,
           "Sign while scroll-paused resumes review deadline before PIN handoff");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::pin_entry &&
               snapshot.request_window.started_at == 60 &&
               snapshot.request_window.deadline == 160 &&
               snapshot.pin_input_window.started_at == 150 &&
               snapshot.pin_input_window.deadline == 160,
           "paused-scroll Sign caps PIN entry to remaining review time");
    signing::TimeoutWindow next_pin_window = {};
    expect(signing::user_signing_flow_cap_request_backed_pin_input_window(
               151,
               pin_window(151, 220),
               &next_pin_window) == Transition::ok,
           "request-backed user-signing PIN cap remains available in pin_entry");
    expect(next_pin_window.started_at == 151 && next_pin_window.deadline == 160,
           "request-backed user-signing PIN cap uses flow-owned request deadline in pin_entry");

    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_history_error"), "begin before history error");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok,
           "review before history error");
    g_history_write_result = false;
    g_history_write_rejects_flow = true;
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr) == Transition::history_error,
           "history error terminalizes before signing");
    g_history_write_result = true;
    g_history_write_rejects_flow = false;
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::history_error &&
               !snapshot.signable_payload_available,
           "history error terminal wipes payload");
    expect_terminal_review_metadata_wiped(snapshot, "history error terminal clears review metadata");
    expect(strcmp(signing::user_signing_flow_terminal_status(Terminal::history_error), "") == 0 &&
               strcmp(signing::user_signing_flow_terminal_reason(Terminal::history_error), "") == 0,
           "history error is cleanup-only, not a signing response status");

    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_disconnect"), "begin before disconnect");
    expect(signing::user_signing_flow_cancel_for_session_loss() == Transition::session_still_active,
           "session-loss cancellation cannot be caller-commanded while session is active");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::reviewing && snapshot.signable_payload_available,
           "active session-loss cancellation attempt leaves request active");
    expect(signing::user_signing_flow_cancel_for_disconnect("session_aaaaaaaaaaaaaaaa") ==
               Transition::invalid_session,
           "mismatched disconnect does not cancel");
    expect(signing::user_signing_flow_cancel_for_disconnect(signing::session_id()) ==
               Transition::ok,
           "matching disconnect cancels before critical section");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::canceled &&
               !snapshot.signable_payload_available,
           "disconnect cancel terminal wipes payload");
    expect_terminal_review_metadata_wiped(snapshot, "disconnect terminal clears review metadata");
    expect(strcmp(signing::user_signing_flow_terminal_status(Terminal::canceled), "") == 0 &&
               strcmp(signing::user_signing_flow_terminal_reason(Terminal::canceled), "") == 0,
           "canceled is cleanup-only, not a signing response status");

    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_review_ui_loss"), "begin before review UI loss");
    expect(signing::user_signing_flow_cancel_for_ui_loss() == Transition::ok,
           "review UI loss cancels before PIN exists");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::canceled &&
               !snapshot.signable_payload_available,
           "review UI loss terminalizes canceled and wipes payload");
    expect_terminal_review_metadata_wiped(snapshot, "UI loss terminal clears review metadata");

    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_signing_failed"), "begin before signing failure");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok, "review before signing failure");
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr) == Transition::ok,
           "pin verification writes history before signing failure");
    expect(signing::user_signing_flow_record_signing_failed() == Transition::ok,
           "signing failure terminalizes critical section");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::signing_failed &&
               !snapshot.signable_payload_available,
           "signing failure wipes payload");
    expect_terminal_review_metadata_wiped(snapshot, "signing failure terminal clears review metadata");
    expect(strcmp(signing::user_signing_flow_terminal_status(Terminal::signing_failed), "signing_failed") == 0 &&
               strcmp(signing::user_signing_flow_terminal_reason(Terminal::signing_failed), "signing_failed") == 0,
           "signing failure terminal mapping");

    signing::user_signing_flow_clear();
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_expired_review", signing::session_id(), payload.data(), payload.size(), 100)) ==
               Begin::ok,
           "begin before expired review");
    expect(signing::user_signing_flow_accept_review(100, pin_window(100, 200)) == Transition::deadline_expired,
           "accept review after review deadline terminalizes as timeout");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::timed_out &&
               !snapshot.signable_payload_available,
           "expired review wipes payload");
    expect_terminal_review_metadata_wiped(snapshot, "expired review terminal clears review metadata");

    signing::user_signing_flow_clear();
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_expired_pin", signing::session_id(), payload.data(), payload.size(), 220)) ==
               Begin::ok,
           "begin before expired PIN");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok,
           "review accepted before PIN expiry test");
    expect(signing::user_signing_flow_pause_pin_deadline(100) == Transition::ok,
           "PIN verification pauses only local input deadline");
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr,
               210) == Transition::ok,
           "PIN verification result after input deadline enters critical section");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section &&
               snapshot.signable_payload_available,
           "PIN verification result after input deadline does not timeout");
    expect(signing::user_signing_flow_record_signing_failed() == Transition::ok,
           "late PIN verification test cleanup closes critical section");

    signing::user_signing_flow_clear();
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_late_verified_pin", signing::session_id(), payload.data(), payload.size(), 130)) ==
               Begin::ok,
           "begin before late verified PIN");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 120)) == Transition::ok,
           "review accepted before late verified PIN");
    expect(signing::user_signing_flow_pause_pin_deadline(119) == Transition::ok,
           "PIN submit pauses the local input deadline");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.request_window.deadline == 130 &&
               snapshot.pin_input_window.started_at == 0 &&
               snapshot.pin_input_window.deadline == 0,
           "PIN verification pauses only local input deadline");
    expect(!signing::user_signing_flow_apply_deadline_transition(130),
           "request admission window does not reject while PIN verification runs");
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr,
               130,
               119) == Transition::ok,
           "direct flow helper accepts verified PIN after request admission window while worker is valid");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section &&
               snapshot.signable_payload_available,
           "late verified PIN after request deadline enters critical section");
    expect(signing::user_signing_flow_record_signing_failed() == Transition::ok,
           "late verified PIN request cleanup closes critical section");

    signing::user_signing_flow_clear();
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_late_pin_refresh", signing::session_id(), payload.data(), payload.size(), 130)) ==
               Begin::ok,
           "begin before late PIN refresh");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 140)) == Transition::ok,
           "review accepted before late PIN refresh");
    expect(signing::user_signing_flow_pause_pin_deadline(120) == Transition::ok,
           "PIN retry refresh test pauses input before request admission window closes");
    expect(!signing::user_signing_flow_apply_deadline_transition(130),
           "paused PIN retry does not timeout at request admission window");
    expect(signing::user_signing_flow_refresh_pin_deadline(150) ==
               Transition::ok,
           "PIN retry refresh after request deadline resumes remaining input time");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::pin_entry &&
               snapshot.pin_input_window.started_at == 129 &&
               snapshot.pin_input_window.deadline == 160,
           "late PIN refresh after request deadline resumes remaining time without resetting timer fill");

    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_expired_pin_deadline"), "begin before expired PIN deadline handoff");
    expect(signing::user_signing_flow_accept_review(99, pin_window(98, 99)) ==
               Transition::invalid_deadline,
           "expired PIN deadline handoff is rejected as an invalid candidate");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::reviewing &&
               snapshot.terminal_result == Terminal::none &&
               snapshot.signable_payload_available,
           "expired PIN handoff preserves the active review");

    signing::user_signing_flow_clear();
    char saved_session_id[signing::kSessionIdSize] = {};
    strlcpy(saved_session_id, signing::session_id(), sizeof(saved_session_id));
    signing::session_clear();
    expect(signing::user_signing_flow_begin(0,
               make_valid_input("req_missing_session", saved_session_id, payload.data(), payload.size())) ==
               Begin::invalid_session,
           "begin rejects stale session id");
    expect(!signing::user_signing_flow_active(), "stale session leaves flow inactive");

    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "test session restarts for mid-flow session loss");
    expect(begin_valid_flow("req_session_loss_review"), "begin before review session loss");
    signing::session_clear();
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::invalid_session,
           "review acceptance revalidates session");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::canceled &&
               !snapshot.signable_payload_available,
           "review session loss cancels and wipes payload");
    expect_terminal_review_metadata_wiped(snapshot, "review session loss clears review metadata");

    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "test session restarts for PIN session loss");
    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_session_loss_pin"), "begin before PIN session loss");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok,
           "review accepted before PIN session loss");
    signing::session_clear();
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr) == Transition::invalid_session,
           "PIN verification revalidates session");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::canceled &&
               !snapshot.signable_payload_available,
           "PIN session loss cancels and wipes payload");
    expect_terminal_review_metadata_wiped(snapshot, "PIN session loss clears review metadata");

    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "test session restarts for history session loss");
    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_session_loss_history"), "begin before history session loss");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok,
           "review accepted before history session loss");
    signing::session_clear();
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr) == Transition::invalid_session,
           "combined PIN/history transition revalidates session before history write");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::canceled &&
               !snapshot.signable_payload_available,
           "history session loss cancels and wipes payload");
    expect_terminal_review_metadata_wiped(snapshot, "history session loss clears review metadata");

    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "test session restarts for history writer interleave");
    signing::user_signing_flow_clear();
    reset_history_writer_stub();
    expect(begin_valid_flow("req_history_writer_clears_session"), "begin before writer clears session");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok,
           "review accepted before writer clears session");
    g_history_write_clears_session = true;
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr) ==
               Transition::ok,
           "successful history write cannot be downgraded by post-write session loss");
    g_history_write_clears_session = false;
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section &&
               snapshot.signable_payload_available,
           "writer success enters critical section even if session disappears after write");
    expect(signing::user_signing_flow_record_signing_failed() == Transition::ok,
           "writer interleave flow still ends with signing terminal");

    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "test session restarts for history writer clear reentry");
    signing::user_signing_flow_clear();
    reset_history_writer_stub();
    expect(begin_valid_flow("req_history_writer_clears_flow"), "begin before writer clears flow");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok,
           "review accepted before writer clears flow");
    g_history_write_clears_flow = true;
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr) ==
               Transition::stale_state,
           "writer clear reentry cannot enter critical section");
    g_history_write_clears_flow = false;
    snapshot = signing::user_signing_flow_snapshot();
    expect(!snapshot.active,
           "writer clear reentry leaves no active critical request");

    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "test session restarts for history writer restart reentry");
    signing::user_signing_flow_clear();
    reset_history_writer_stub();
    expect(begin_valid_flow("req_history_writer_restarts_flow"), "begin before writer restarts flow");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok,
           "review accepted before writer restarts flow");
    g_history_write_restarts_flow = true;
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr) ==
               Transition::stale_state,
           "writer restart reentry cannot move a different request to critical");
    g_history_write_restarts_flow = false;
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.active &&
               snapshot.stage == Stage::reviewing &&
               strcmp(snapshot.request_id, "req_reentrant_writer") == 0,
           "writer restart reentry leaves the new request outside critical section");
    expect(signing::user_signing_flow_clear() == Transition::ok,
           "cleanup reentrant writer test request");

    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "test session restarts for critical cancel");
    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_critical_cancel"), "begin before critical cancel");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok,
           "review accepted before critical cancel");
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr) == Transition::ok,
           "PIN verification writes durable history before critical cancel");
    char critical_session_id[signing::kSessionIdSize] = {};
    strlcpy(critical_session_id, signing::session_id(), sizeof(critical_session_id));
    expect(signing::user_signing_flow_cancel_for_disconnect(critical_session_id) == Transition::busy,
           "matching disconnect cannot cancel signing critical section");
    expect(signing::user_signing_flow_cancel_for_session_loss() == Transition::busy,
           "session loss cannot cancel signing critical section");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section &&
               snapshot.signable_payload_available,
           "critical section remains active after disconnect/session loss");
    expect(signing::user_signing_flow_record_signing_failed() == Transition::ok,
           "critical section still requires signed or signing-failed terminal");

    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "test session restarts for critical consume session loss");
    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_session_loss_consume"), "begin before consume session loss");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok,
           "review accepted before consume session loss");
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr) == Transition::ok,
           "PIN verification writes durable history before consume session loss");
    signing::session_clear();
    expect(signing::user_signing_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::ok,
           "payload consume continues after durable history even if session is gone");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::signing_critical_section &&
               !snapshot.signable_payload_available,
           "consume after session loss keeps critical section and wipes payload scratch");
    expect(signing::user_signing_flow_record_signing_failed() == Transition::ok,
           "consume session loss must still end as signing failed or signed");

    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "test session restarts for signed-complete session loss");
    signing::user_signing_flow_clear();
    expect(begin_valid_flow("req_session_loss_complete"), "begin before complete session loss");
    expect(signing::user_signing_flow_accept_review(99, pin_window(99, 200)) == Transition::ok,
           "review accepted before complete session loss");
    expect(record_verified_pin_and_write_confirmation_history(write_confirmation_history,
               nullptr) == Transition::ok,
           "PIN verification writes durable history before complete session loss");
    expect(signing::user_signing_flow_consume_signable_payload(copied.data(), copied.size(), &copied_size) ==
               Transition::ok,
           "payload consumed before complete session loss");
    signing::session_clear();
    expect(signing::user_signing_flow_complete_signed() == Transition::ok,
           "signed completion reports generated signature after session loss");
    snapshot = signing::user_signing_flow_snapshot();
    expect(snapshot.stage == Stage::terminal &&
               snapshot.terminal_result == Terminal::signed_success,
           "complete session loss cannot downgrade generated signature");
    expect_terminal_review_metadata_wiped(snapshot, "signed terminal clears review metadata");

    signing::user_signing_flow_clear();
    expect(signing::session_replace(random_bytes, nullptr) ==
               signing::SessionStartResult::ok,
           "test session restarts for invalid begin cases");

    signing::UserSigningTransactionBeginInput invalid_deadline =
        make_valid_input("req_bad_deadline", signing::session_id(), payload.data(), payload.size());
    invalid_deadline.request_window.deadline = 0;
    expect(signing::user_signing_flow_begin(0, invalid_deadline) == Begin::invalid_deadline,
           "zero review deadline rejected");
    expect(!signing::user_signing_flow_active(), "invalid deadline leaves flow inactive");
    signing::UserSigningTransactionBeginInput expired_deadline =
        make_valid_input("req_expired_deadline", signing::session_id(), payload.data(), payload.size());
    expired_deadline.request_window = timeout_window(300, 300);
    expect(signing::user_signing_flow_begin(300, expired_deadline) == Begin::invalid_deadline,
           "already expired transaction review window rejected");
    expect(!signing::user_signing_flow_active(), "expired transaction deadline leaves flow inactive");
    signing::UserSigningTransactionBeginInput stale_deadline =
        make_valid_input("req_stale_deadline", signing::session_id(), payload.data(), payload.size());
    stale_deadline.request_window = timeout_window(100, 200);
    expect(signing::user_signing_flow_begin(300, stale_deadline) == Begin::invalid_deadline,
           "stale transaction review window rejected at state owner boundary");
    expect(!signing::user_signing_flow_active(), "stale transaction deadline leaves flow inactive");
    signing::UserSigningTransactionBeginInput future_deadline =
        make_valid_input("req_future_deadline", signing::session_id(), payload.data(), payload.size());
    future_deadline.request_window = timeout_window(300, 400);
    expect(signing::user_signing_flow_begin(100, future_deadline) == Begin::invalid_deadline,
           "future transaction review window rejected at state owner boundary");
    expect(!signing::user_signing_flow_active(), "future transaction deadline leaves flow inactive");
    signing::UserSigningPersonalMessageBeginInput expired_message_deadline =
        make_valid_message_input(
            "req_expired_message_deadline",
            signing::session_id(),
            message,
            sizeof(message) - 1);
    expired_message_deadline.request_window = timeout_window(300, 300);
    expect(signing::user_signing_flow_begin_personal_message(300, expired_message_deadline) ==
               Begin::invalid_deadline,
           "already expired personal-message review window rejected");
    expect(!signing::user_signing_flow_active(), "expired personal-message deadline leaves flow inactive");

    signing::UserSigningTransactionBeginInput invalid_network =
        make_valid_input("req_bad_network", signing::session_id(), payload.data(), payload.size());
    snprintf(
        const_cast<signing::SuiPreparedSignTransaction*>(
            invalid_network.prepared)->network,
        signing::kUserSigningNetworkSize,
        "%s",
        "staging");
    expect(signing::user_signing_flow_begin(0, invalid_network) == Begin::invalid_network,
           "invalid prepared network rejected");

    signing::UserSigningTransactionBeginInput unterminated_network_input =
        make_valid_input("req_unterminated_network", signing::session_id(), payload.data(), payload.size());
    unterminated_network_input.prepared = nullptr;
    expect(signing::user_signing_flow_begin(0, unterminated_network_input) == Begin::invalid_argument,
           "missing prepared transaction is rejected");
    expect(!signing::user_signing_flow_active(), "missing prepared transaction leaves flow inactive");

    signing::UserSigningTransactionBeginInput unsupported_method =
        make_valid_input("req_bad_method", signing::session_id(), payload.data(), payload.size());
    unsupported_method.route = signing::SupportedSignRoute::sui_sign_personal_message;
    expect(signing::user_signing_flow_begin(0, unsupported_method) == Begin::invalid_argument,
           "wrong selected route rejected");

    signing::UserSigningTransactionBeginInput empty_payload =
        make_valid_input("req_empty_payload", signing::session_id(), payload.data(), 0);
    expect(signing::user_signing_flow_begin(0, empty_payload) == Begin::invalid_payload,
           "empty payload rejected");

    char overlong_request_id[signing::kUserSigningIdSize + 4] = {};
    memset(overlong_request_id, 'a', sizeof(overlong_request_id) - 1);
    expect(signing::user_signing_flow_begin(0,
               make_valid_input(overlong_request_id, signing::session_id(), payload.data(), payload.size())) ==
               Begin::invalid_argument,
           "overlong request id rejected");
    expect(!signing::user_signing_flow_active(), "overlong request id leaves flow inactive");

    if (failures != 0) {
        fprintf(stderr, "%d user_signing flow test(s) failed\n", failures);
        return 1;
    }
    printf("user_signing flow tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -DSUI_TEST_VALID_TRANSFER_TX_HEX=\"${COMMON_ROOT}/sui/testdata/sui_transaction_facts/valid_sui_transfer_tx.bcs.hex\" \
  -DSUI_TEST_MALFORMED_TX_HEX=\"${COMMON_ROOT}/sui/testdata/sui_transaction_facts/malformed_short_tx.bcs.hex\" \
  -DSUI_TEST_SPONSORED_GAS_OWNER_TX_HEX=\"${COMMON_ROOT}/sui/testdata/sui_transaction_facts/sponsored_gas_owner_tx.bcs.hex\" \
  -I"${TMP_DIR}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_ROOT}/sui" \
  "${TMP_DIR}/user_signing_flow_test.cpp" \
  "${RUNTIME_DIR}/user_signing_flow.cpp" \
  "${RUNTIME_DIR}/sui_signing_authority.cpp" \
  "${RUNTIME_DIR}/session.cpp" \
  "${COMMON_ROOT}/sui/sign_transaction_adapter.cpp" \
  "${COMMON_ROOT}/sui/transaction_facts.cpp" \
  "${COMMON_ROOT}/sui/bcs_reader.cpp" \
  -o "${TMP_DIR}/user_signing_flow_test"

"${TMP_DIR}/user_signing_flow_test"
