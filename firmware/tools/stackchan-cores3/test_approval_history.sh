#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_approval_history.sh

ESP-IDF must already be active in the shell so IDF_PATH points to the ESP-IDF
checkout. The test compiles the StackChan CoreS3 persistent approval-history
store with NVS stubs and ESP-IDF mbedTLS SHA-256, then checks append, bounded
pagination, wipe, invalid-store fail-closed behavior, and payload digest
formatting. This test uses only a host C++ compiler and does NOT require
hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET_ROOT="${REPO_ROOT}/firmware/src/stackchan-cores3"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"

if [[ -z "${IDF_PATH:-}" ]]; then
  echo "IDF_PATH is not set. Source ESP-IDF v5.5.4 export.sh before running this test." >&2
  exit 1
fi

MBEDTLS_ROOT="${IDF_PATH}/components/mbedtls/mbedtls"
MBEDTLS_INCLUDE_DIR="${MBEDTLS_ROOT}/include"
MBEDTLS_LIBRARY_DIR="${MBEDTLS_ROOT}/library"
if [[ ! -f "${MBEDTLS_INCLUDE_DIR}/mbedtls/sha256.h" || ! -f "${MBEDTLS_LIBRARY_DIR}/sha256.c" || ! -f "${MBEDTLS_LIBRARY_DIR}/platform_util.c" ]]; then
  echo "IDF_PATH does not expose the expected ESP-IDF mbedTLS sources: ${IDF_PATH}" >&2
  exit 1
fi

for required in \
  "${TARGET_ROOT}/runtime/approval_history.cpp" \
  "${TARGET_ROOT}/runtime/approval_history.h" \
  "${COMMON_ROOT}/policy/document.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-approval-history.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/firmware_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"

mkdir -p "${TMP_DIR}/stubs"

cat >"${TMP_DIR}/stubs/esp_err.h" <<'H'
#pragma once

typedef int esp_err_t;

#define ESP_OK 0
#define ESP_ERR_NVS_NOT_FOUND 4354

static inline const char* esp_err_to_name(esp_err_t error)
{
    return error == ESP_OK ? "ESP_OK" :
           error == ESP_ERR_NVS_NOT_FOUND ? "ESP_ERR_NVS_NOT_FOUND" :
           "ESP_ERR_TEST";
}
H

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once

#define ESP_LOGI(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGE(tag, format, ...) do { (void)(tag); } while (0)
H

cat >"${TMP_DIR}/stubs/nvs.h" <<'H'
#pragma once

#include <stddef.h>
#include "esp_err.h"

#define NVS_READONLY 1
#define NVS_READWRITE 2

typedef int nvs_handle_t;

extern "C" {
esp_err_t nvs_open(const char* name, int open_mode, nvs_handle_t* out_handle);
void nvs_close(nvs_handle_t handle);
esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* out_value, size_t* length);
esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length);
esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key);
esp_err_t nvs_commit(nvs_handle_t handle);
}
H

cat >"${TMP_DIR}/approval_history_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <vector>

#include "approval_history.h"
#include "esp_err.h"
#include "nvs.h"

namespace {

std::vector<uint8_t> g_blob;
bool g_open_fails = false;
bool g_commit_fails = false;
int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

signing::HistoryAppendInput policy_signing_rejected_input(const char* reason = "policy_rejected")
{
    return signing::HistoryAppendInput{
        signing::HistoryRecordKind::terminal,
        signing::ApprovalHistoryConfirmationKind::policy,
        signing::HistoryTerminalResult::policy_rejected,
        "sui",
        "sign_transaction",
        reason,
        "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
        "default",
    };
}

signing::PolicyUpdateHistoryAppendInput policy_update_input(
    const char* result = "applied",
    const char* reason = "device_confirmed",
    const char* highest_action = "reject")
{
    return signing::PolicyUpdateHistoryAppendInput{
        result,
        reason,
        "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
        1,
        highest_action,
    };
}

signing::HistoryAppendInput user_signing_confirmation_input(
    const char* reason = "device_confirmed",
    signing::ApprovalHistoryConfirmationKind confirmation_kind =
        signing::ApprovalHistoryConfirmationKind::local_pin)
{
    return signing::HistoryAppendInput{
        signing::HistoryRecordKind::confirmation,
        confirmation_kind,
        signing::HistoryTerminalResult::none,
        "sui",
        "sign_transaction",
        reason,
        "sha256:0000000000000000000000000000000000000000000000000000000000000002",
        nullptr,
        nullptr,
    };
}

signing::HistoryAppendInput user_signing_terminal_input(
    signing::HistoryTerminalResult result =
        signing::HistoryTerminalResult::signed_success,
    const char* reason = "device_confirmed")
{
    return signing::HistoryAppendInput{
        signing::HistoryRecordKind::terminal,
        signing::ApprovalHistoryConfirmationKind::none,
        result,
        "sui",
        "sign_transaction",
        reason,
        "sha256:0000000000000000000000000000000000000000000000000000000000000002",
        nullptr,
        nullptr,
    };
}

bool replace_blob_token(const char* from, const char* to)
{
    const size_t from_size = strlen(from);
    const size_t to_size = strlen(to);
    if (from_size != to_size || from_size == 0) {
        return false;
    }
    for (size_t index = 0; index + from_size <= g_blob.size(); ++index) {
        if (memcmp(g_blob.data() + index, from, from_size) == 0) {
            memcpy(g_blob.data() + index, to, to_size);
            return true;
        }
    }
    return false;
}

bool mutate_first_method_record_byte(size_t field_offset, uint8_t value)
{
    constexpr size_t kStoredChainOffset = 24;
    const uint8_t marker[] = {'s', 'u', 'i', '\0'};
    if (field_offset >= kStoredChainOffset) {
        return false;
    }
    for (size_t index = 0; index + sizeof(marker) <= g_blob.size(); ++index) {
        if (memcmp(g_blob.data() + index, marker, sizeof(marker)) == 0 &&
            index >= kStoredChainOffset) {
            g_blob[index - kStoredChainOffset + field_offset] = value;
            return true;
        }
    }
    return false;
}

}  // namespace

extern "C" {

esp_err_t nvs_open(const char*, int, nvs_handle_t* out_handle)
{
    if (g_open_fails) {
        return 1;
    }
    *out_handle = 1;
    return ESP_OK;
}

void nvs_close(nvs_handle_t) {}

esp_err_t nvs_get_blob(nvs_handle_t, const char*, void* out_value, size_t* length)
{
    if (g_blob.empty()) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (length == nullptr) {
        return 1;
    }
    if (out_value == nullptr) {
        *length = g_blob.size();
        return ESP_OK;
    }
    const size_t requested = *length;
    *length = g_blob.size();
    if (requested < g_blob.size()) {
        return 1;
    }
    memcpy(out_value, g_blob.data(), g_blob.size());
    return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t, const char*, const void* value, size_t length)
{
    const uint8_t* bytes = static_cast<const uint8_t*>(value);
    g_blob.assign(bytes, bytes + length);
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t, const char*)
{
    if (g_blob.empty()) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    g_blob.clear();
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t)
{
    return g_commit_fails ? 1 : ESP_OK;
}

}  // extern "C"

int main()
{
    signing::ApprovalHistoryPage page = {};
    expect(signing::approval_history_status() == signing::ApprovalHistoryStorageStatus::missing,
           "missing approval history status is missing");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::ok,
           "missing approval history reads as empty");
    expect(page.count == 0 && !page.has_more, "missing approval history page is empty");

    const uint8_t abc[] = {'a', 'b', 'c'};
    char digest[signing::kApprovalHistoryDigestSize] = {};
    expect(signing::approval_history_digest_payload(abc, sizeof(abc), digest, sizeof(digest)),
           "payload digest helper succeeds");
    expect(strcmp(digest, "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
           "payload digest helper formats canonical sha256");

    uint64_t sequence_value = 0;
    expect(signing::approval_history_parse_sequence("0", &sequence_value) && sequence_value == 0,
           "sequence parser accepts canonical zero");
    expect(signing::approval_history_parse_sequence("18446744073709551615", &sequence_value) &&
               sequence_value == UINT64_MAX,
           "sequence parser accepts uint64 max");
    expect(!signing::approval_history_parse_sequence("01", &sequence_value),
           "sequence parser rejects leading zero");
    expect(!signing::approval_history_parse_sequence("00000000000000000001", &sequence_value),
           "sequence parser rejects long zero-padded values");
    expect(!signing::approval_history_parse_sequence("18446744073709551616", &sequence_value),
           "sequence parser rejects overflow");

    expect(signing::approval_history_append_required_signing(policy_signing_rejected_input(), 100),
           "append first policy signing rejection");
    expect(signing::approval_history_status() == signing::ApprovalHistoryStorageStatus::active,
           "stored approval history status is active");
    expect(g_blob.size() > 4 && g_blob[4] == 1,
           "approval history current format marker is one");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::ok,
           "read first page");
    expect(page.count == 1 && !page.has_more, "one record page shape");
    expect(page.records[0].sequence == 1, "first record sequence");
    expect(page.records[0].uptime_ms == 100, "first record uptime");
    expect(page.records[0].event_kind == signing::ApprovalHistoryEventKind::signing,
           "first record event kind");
    expect(page.records[0].signing_record_kind == signing::HistoryRecordKind::terminal,
           "first record signing terminal kind");
    expect(page.records[0].signing_terminal_result == signing::HistoryTerminalResult::policy_rejected,
           "first record signing terminal result");
    expect(page.records[0].confirmation_kind == signing::ApprovalHistoryConfirmationKind::policy,
           "first record confirmation kind");
    expect(strcmp(page.records[0].chain, "sui") == 0, "first record chain");

    const std::vector<uint8_t> valid_enum_blob = g_blob;
    g_blob[4] = 0;
    expect(signing::approval_history_status() == signing::ApprovalHistoryStorageStatus::invalid,
           "stored unsupported approval history format marker status is invalid");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "stored unsupported approval history format marker fails closed");
    g_blob = valid_enum_blob;
    g_open_fails = true;
    expect(signing::approval_history_status() == signing::ApprovalHistoryStorageStatus::storage_error,
           "approval history status reports storage error on NVS open failure");
    g_open_fails = false;
    expect(mutate_first_method_record_byte(16, 0xFF), "mutate stored confirmation enum");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "stored unsupported confirmation enum fails closed");
    g_blob = valid_enum_blob;

    signing::HistoryAppendInput max_rule_ref = policy_signing_rejected_input();
    max_rule_ref.rule_ref = "abcdefghijklmnopqrstuvwxyzabcdef";
    expect(signing::approval_history_append_required_signing(max_rule_ref, 103),
           "max-length ruleRef matching policy rule id is accepted");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::ok,
           "read max ruleRef page");
    expect(strcmp(page.records[0].rule_ref, "abcdefghijklmnopqrstuvwxyzabcdef") == 0,
           "max-length ruleRef is preserved");
    expect(strcmp(page.records[0].method, "sign_transaction") == 0, "first record method");
    expect(strcmp(page.records[0].payload_digest,
                  "sha256:0000000000000000000000000000000000000000000000000000000000000001") == 0,
           "first record payload digest");
    expect(strcmp(page.records[0].policy_hash,
                  "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3") == 0,
           "first record policy hash");

    const std::vector<uint8_t> valid_blob = g_blob;
    for (size_t index = 0; index + 3 < g_blob.size(); ++index) {
        if (g_blob[index] == 's' && g_blob[index + 1] == 'u' && g_blob[index + 2] == 'i' &&
            g_blob[index + 3] == '\0') {
            g_blob[index] = 'S';
            break;
        }
    }
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "corrupt stored token fails closed instead of being sanitized");
    g_blob = valid_blob;

    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::ok,
           "read newest page before wrap");
    const uint64_t sequence_before_wrap = page.count > 0 ? page.records[0].sequence : 0;
    for (uint32_t index = 0; index < signing::kApprovalHistoryCapacity + 3; ++index) {
        char reason[signing::kApprovalHistoryReasonCodeSize] = {};
        snprintf(reason, sizeof(reason), "reason_%u", static_cast<unsigned>(index));
        expect(signing::approval_history_append_required_signing(
                   policy_signing_rejected_input(reason),
                   200 + (static_cast<uint64_t>(index + 1) *
                          60000ULL)),
               "append ring record");
    }

    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::ok,
           "read newest page");
    expect(page.count == 4 && page.has_more, "newest page is bounded with hasMore");
    expect(page.records[0].sequence == sequence_before_wrap + signing::kApprovalHistoryCapacity + 3,
           "newest record sequence after wrap");
    const uint64_t before = page.records[3].sequence;
    expect(signing::approval_history_read_page(before, 4, &page) == signing::ApprovalHistoryReadResult::ok,
           "read paged page");
    expect(page.count == 4 && page.records[0].sequence == before - 1,
           "beforeSeq reads older records");

    signing::HistoryAppendInput overlong_method = policy_signing_rejected_input();
    overlong_method.method = "this_method_name_is_longer_than_the_current_store_allows";
    expect(!signing::approval_history_append_required_signing(overlong_method, 400),
           "overlong method token is rejected instead of truncated");

    signing::HistoryAppendInput invalid_chain = policy_signing_rejected_input();
    invalid_chain.chain = "Sui";
    expect(!signing::approval_history_append_required_signing(invalid_chain, 401),
           "invalid chain token is rejected instead of sanitized");

    expect(signing::approval_history_wipe(), "wipe approval history");
    expect(g_blob.empty(), "wipe removes approval history blob");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::ok,
           "wiped approval history reads as empty");
    expect(page.count == 0, "wiped page is empty");

    g_blob.assign(31, 0xA5);
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "unsupported approval history blob is rejected");
    expect(!signing::approval_history_append_required_signing(policy_signing_rejected_input(), 900),
           "append refuses unsupported approval history blob");
    expect(signing::approval_history_wipe(), "wipe unsupported approval history blob");
    expect(signing::approval_history_append_required_policy_update(
               policy_update_input(),
               1013),
           "required policy-update history appends");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::ok,
           "read policy-update record after budget exhaustion");
    expect(page.count == 1 &&
               page.records[0].event_kind == signing::ApprovalHistoryEventKind::policy_update,
           "policy-update record is newest approval-history event");
    expect(strcmp(page.records[0].policy_result, "applied") == 0 &&
               strcmp(page.records[0].reason_code, "device_confirmed") == 0 &&
               strcmp(page.records[0].highest_action, "reject") == 0 &&
               page.records[0].policy_count == 1,
           "policy-update record metadata is preserved");
    expect(signing::approval_history_append_required_signing(
               user_signing_confirmation_input(),
               1100),
           "required user_signing confirmation history appends");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::ok,
           "read user_signing confirmation record");
    expect(page.records[0].event_kind == signing::ApprovalHistoryEventKind::signing &&
               page.records[0].signing_record_kind ==
                   signing::HistoryRecordKind::confirmation &&
               page.records[0].confirmation_kind == signing::ApprovalHistoryConfirmationKind::local_pin &&
               page.records[0].signing_terminal_result ==
                   signing::HistoryTerminalResult::none,
           "user_signing confirmation metadata is preserved");
    expect(strcmp(page.records[0].chain, "sui") == 0 &&
               strcmp(page.records[0].method, "sign_transaction") == 0 &&
               strcmp(page.records[0].reason_code, "device_confirmed") == 0 &&
               strcmp(page.records[0].payload_digest,
                      "sha256:0000000000000000000000000000000000000000000000000000000000000002") == 0,
           "user_signing confirmation bounded fields are preserved");
    expect(signing::approval_history_append_required_signing(
               user_signing_confirmation_input("blind_signing_confirmed"),
               1100),
           "required user_signing blind-signing confirmation history appends");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::ok,
           "read user_signing blind-signing confirmation record");
    expect(page.records[0].event_kind == signing::ApprovalHistoryEventKind::signing &&
               page.records[0].signing_record_kind ==
                   signing::HistoryRecordKind::confirmation &&
               page.records[0].confirmation_kind == signing::ApprovalHistoryConfirmationKind::local_pin &&
               strcmp(page.records[0].reason_code, "blind_signing_confirmed") == 0,
           "user_signing blind-signing confirmation metadata is preserved");
    expect(signing::approval_history_append_required_signing(
               user_signing_confirmation_input(
                   "device_confirmed",
                   signing::ApprovalHistoryConfirmationKind::physical_confirm),
               1100),
           "required user_signing physical confirmation history appends");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::ok,
           "read user_signing physical confirmation record");
    expect(page.records[0].event_kind == signing::ApprovalHistoryEventKind::signing &&
               page.records[0].signing_record_kind ==
                   signing::HistoryRecordKind::confirmation &&
               page.records[0].confirmation_kind ==
                   signing::ApprovalHistoryConfirmationKind::physical_confirm,
           "user_signing physical confirmation metadata is preserved");
    expect(signing::approval_history_append_required_signing(
               user_signing_terminal_input(),
               1101),
           "required signing terminal history appends");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::ok,
           "read signing terminal record");
    expect(page.records[0].event_kind == signing::ApprovalHistoryEventKind::signing &&
               page.records[0].signing_record_kind ==
                   signing::HistoryRecordKind::terminal &&
               page.records[0].confirmation_kind == signing::ApprovalHistoryConfirmationKind::none &&
               page.records[0].signing_terminal_result ==
                   signing::HistoryTerminalResult::signed_success,
           "signing terminal metadata is preserved");
	    const char* allowed_results[] = {
	        "applied",
	        "rejected",
	        "timed_out",
	        "storage_error",
	    };
    for (const char* result : allowed_results) {
        expect(signing::approval_history_wipe(), "wipe before allowed policy-update result test");
        expect(signing::approval_history_append_required_policy_update(
                   policy_update_input(result),
                   1500),
               "allowed policy-update result is storable");
    }
    expect(signing::approval_history_wipe(), "wipe before stored response corruption test");
    expect(signing::approval_history_append_required_policy_update(policy_update_input(), 1501),
           "append policy-update result before corruption");
    expect(replace_blob_token("applied", "approve"), "mutate stored policy-update result token");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "stored unsupported policy-update result fails closed");
    expect(signing::approval_history_wipe(), "wipe before stored highest-action corruption test");
    expect(signing::approval_history_append_required_policy_update(policy_update_input(), 1502),
           "append policy-update highest action before corruption");
    expect(replace_blob_token("reject", "accept"), "mutate stored highest-action token");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "stored unsupported highest action fails closed");
    expect(signing::approval_history_wipe(), "wipe after policy-update corruption tests");
    expect(signing::approval_history_wipe(), "wipe approval history after policy-update corruption tests");

	    expect(!signing::approval_history_append_required_policy_update(
	               policy_update_input("Applied"),
	               1200),
	           "policy-update history rejects invalid result token");
	    expect(!signing::approval_history_append_required_policy_update(
	               policy_update_input("history_error"),
	               1201),
	           "policy-update history rejects top-level history error as stored response");
	    expect(!signing::approval_history_append_required_policy_update(
	               policy_update_input("consistency_error"),
	               1202),
	           "policy-update history rejects consistency state as stored response");
	    expect(!signing::approval_history_append_required_policy_update(
	               policy_update_input("applied", "device_confirmed", "approve"),
	               1203),
	           "policy-update history rejects unsupported highest action");
	    signing::PolicyUpdateHistoryAppendInput invalid_policy_hash = policy_update_input();
	    invalid_policy_hash.policy_hash = "not-a-digest";
	    expect(!signing::approval_history_append_required_policy_update(invalid_policy_hash, 1204),
	           "policy-update history rejects invalid policy hash");
	    signing::PolicyUpdateHistoryAppendInput overlarge_policy_count = policy_update_input();
	    overlarge_policy_count.policy_count = signing::kCurrentPolicyMaxTotalPolicies + 1;
	    expect(!signing::approval_history_append_required_policy_update(overlarge_policy_count, 1205),
	           "policy-update history rejects overlarge policy count");
    expect(signing::approval_history_wipe(), "wipe before user_signing invalid input tests");
    signing::HistoryAppendInput invalid_signature = user_signing_confirmation_input();
    invalid_signature.confirmation_kind = signing::ApprovalHistoryConfirmationKind::policy;
    expect(!signing::approval_history_append_required_signing(invalid_signature, 1300),
           "user_signing confirmation rejects policy confirmation kind");
    invalid_signature = user_signing_terminal_input();
    invalid_signature.terminal_result = signing::HistoryTerminalResult::none;
    expect(!signing::approval_history_append_required_signing(invalid_signature, 1301),
           "signing terminal rejects empty terminal result");
    invalid_signature = user_signing_terminal_input(
        signing::HistoryTerminalResult::policy_rejected,
        "policy_rejected");
    expect(!signing::approval_history_append_required_signing(invalid_signature, 1301),
           "user signing terminal rejects policy_rejected");
    invalid_signature = policy_signing_rejected_input();
    invalid_signature.terminal_result = signing::HistoryTerminalResult::user_rejected;
    invalid_signature.reason_code = "user_rejected";
    expect(!signing::approval_history_append_required_signing(invalid_signature, 1301),
           "policy signing terminal rejects user_rejected");
    invalid_signature = user_signing_terminal_input();
    invalid_signature.policy_hash = "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3";
    invalid_signature.rule_ref = "default";
    expect(!signing::approval_history_append_required_signing(invalid_signature, 1301),
           "user signing terminal rejects policy metadata");
    invalid_signature = policy_signing_rejected_input();
    invalid_signature.policy_hash = nullptr;
    expect(!signing::approval_history_append_required_signing(invalid_signature, 1301),
           "policy signing terminal requires policy metadata");
    invalid_signature = user_signing_terminal_input();
    invalid_signature.payload_digest = "not-a-digest";
    expect(!signing::approval_history_append_required_signing(invalid_signature, 1302),
           "signing history rejects invalid payload digest");
    expect(signing::approval_history_append_required_signing(
               user_signing_confirmation_input(),
               1303),
           "append user_signing before enum corruption");
    const std::vector<uint8_t> valid_signature_blob = g_blob;
    expect(mutate_first_method_record_byte(18, 0xFF), "mutate stored event enum");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "stored unsupported event enum fails closed");
    g_blob = valid_signature_blob;
    expect(mutate_first_method_record_byte(22, 0xFF), "mutate signature record kind enum");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "stored unsupported signature record kind fails closed");
    expect(signing::approval_history_wipe(), "wipe after user_signing enum corruption");

    expect(signing::approval_history_append_required_signing(
               user_signing_terminal_input(
                   signing::HistoryTerminalResult::user_rejected,
                   "user_rejected"),
               1400),
           "append user terminal before stored matrix corruption");
    const std::vector<uint8_t> valid_user_terminal_blob = g_blob;
    expect(mutate_first_method_record_byte(16, 1), "mutate user terminal to policy authorization");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "stored user terminal with policy authorization fails closed");
    g_blob = valid_user_terminal_blob;
    expect(mutate_first_method_record_byte(23, 5), "mutate user terminal to policy_rejected result");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "stored user terminal with policy result fails closed");
    expect(signing::approval_history_wipe(), "wipe after stored user terminal corruption");

    expect(signing::approval_history_append_required_signing(policy_signing_rejected_input(), 1410),
           "append policy terminal before stored policy metadata corruption");
    const std::vector<uint8_t> valid_policy_terminal_blob = g_blob;
    expect(mutate_first_method_record_byte(17, 1), "drop stored policy digest flag");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "stored policy terminal without policy metadata fails closed");
    g_blob = valid_policy_terminal_blob;
    expect(mutate_first_method_record_byte(23, 2), "mutate policy terminal to user_rejected result");
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "stored policy terminal with user result fails closed");
    expect(signing::approval_history_wipe(), "wipe after stored policy terminal corruption");

    for (size_t index = 0; index < signing::kApprovalHistoryWriteBudgetMax; ++index) {
        expect(signing::approval_history_append_budgeted_signing(
                   policy_signing_rejected_input(),
                   2000),
               "budgeted policy rejection append within window");
    }
    expect(!signing::approval_history_append_budgeted_signing(
               policy_signing_rejected_input(),
               2000),
           "budgeted policy rejection append fails when write budget is exhausted");
    expect(signing::approval_history_append_budgeted_signing(
               policy_signing_rejected_input(),
               2000 + signing::kApprovalHistoryWriteBudgetWindowMs),
           "budgeted policy rejection append resumes after window");
    expect(signing::approval_history_wipe(), "wipe after budgeted policy rejection tests");

    expect(signing::approval_history_append_required_signing(policy_signing_rejected_input(), 500),
           "append after wipe reinitializes");
    g_blob.push_back(0);
    expect(signing::approval_history_read_page(0, 4, &page) == signing::ApprovalHistoryReadResult::invalid,
           "corrupt history read fails closed");
    expect(!signing::approval_history_append_required_signing(policy_signing_rejected_input(), 501),
           "corrupt history append fails closed");

    if (failures != 0) {
        fprintf(stderr, "%d approval history test(s) failed\n", failures);
        return 1;
    }
    printf("Approval history tests passed\n");
    return 0;
}
CPP

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${TARGET_ROOT}/runtime" \
  -I"${TMP_DIR}/firmware_common" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/approval_history_test.cpp" \
  "${TARGET_ROOT}/runtime/approval_history.cpp" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/approval_history_test"

"${TMP_DIR}/approval_history_test"
