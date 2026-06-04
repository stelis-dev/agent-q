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
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"

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
  "${TARGET_ROOT}/agent_q/agent_q_approval_history.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_approval_history.h" \
  "${COMMON_ROOT}/policy/agent_q_policy_schema.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-approval-history.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"

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

#include "agent_q_approval_history.h"
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

agent_q::AgentQSigningHistoryAppendInput policy_signing_rejected_input(const char* reason = "policy_rejected")
{
    return agent_q::AgentQSigningHistoryAppendInput{
        agent_q::AgentQSigningHistoryRecordKind::terminal,
        agent_q::AgentQApprovalHistoryConfirmationKind::policy,
        agent_q::AgentQSigningHistoryTerminalResult::policy_rejected,
        "sui",
        "sign_transaction",
        reason,
        "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
        "default",
    };
}

agent_q::AgentQPolicyUpdateHistoryAppendInput policy_update_input(
    const char* result = "applied",
    const char* reason = "device_confirmed",
    const char* highest_action = "reject")
{
    return agent_q::AgentQPolicyUpdateHistoryAppendInput{
        result,
        reason,
        "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
        1,
        highest_action,
    };
}

agent_q::AgentQSigningHistoryAppendInput sign_by_user_confirmation_input(
    const char* reason = "device_confirmed")
{
    return agent_q::AgentQSigningHistoryAppendInput{
        agent_q::AgentQSigningHistoryRecordKind::confirmation,
        agent_q::AgentQApprovalHistoryConfirmationKind::local_pin,
        agent_q::AgentQSigningHistoryTerminalResult::none,
        "sui",
        "sign_transaction",
        reason,
        "sha256:0000000000000000000000000000000000000000000000000000000000000002",
        nullptr,
        nullptr,
    };
}

agent_q::AgentQSigningHistoryAppendInput sign_by_user_terminal_input(
    agent_q::AgentQSigningHistoryTerminalResult result =
        agent_q::AgentQSigningHistoryTerminalResult::signed_success,
    const char* reason = "device_confirmed")
{
    return agent_q::AgentQSigningHistoryAppendInput{
        agent_q::AgentQSigningHistoryRecordKind::terminal,
        agent_q::AgentQApprovalHistoryConfirmationKind::none,
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
    agent_q::AgentQApprovalHistoryPage page = {};
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "missing approval history reads as empty");
    expect(page.count == 0 && !page.has_more, "missing approval history page is empty");

    const uint8_t abc[] = {'a', 'b', 'c'};
    char digest[agent_q::kAgentQApprovalHistoryDigestSize] = {};
    expect(agent_q::approval_history_digest_payload(abc, sizeof(abc), digest, sizeof(digest)),
           "payload digest helper succeeds");
    expect(strcmp(digest, "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
           "payload digest helper formats canonical sha256");

    uint64_t sequence_value = 0;
    expect(agent_q::approval_history_parse_sequence("0", &sequence_value) && sequence_value == 0,
           "sequence parser accepts canonical zero");
    expect(agent_q::approval_history_parse_sequence("18446744073709551615", &sequence_value) &&
               sequence_value == UINT64_MAX,
           "sequence parser accepts uint64 max");
    expect(!agent_q::approval_history_parse_sequence("01", &sequence_value),
           "sequence parser rejects leading zero");
    expect(!agent_q::approval_history_parse_sequence("00000000000000000001", &sequence_value),
           "sequence parser rejects long zero-padded values");
    expect(!agent_q::approval_history_parse_sequence("18446744073709551616", &sequence_value),
           "sequence parser rejects overflow");

    expect(agent_q::approval_history_append_required_signing(policy_signing_rejected_input(), 100),
           "append first policy signing rejection");
    expect(g_blob.size() > 4 && g_blob[4] == 0,
           "approval history current format marker is zero");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "read first page");
    expect(page.count == 1 && !page.has_more, "one record page shape");
    expect(page.records[0].sequence == 1, "first record sequence");
    expect(page.records[0].uptime_ms == 100, "first record uptime");
    expect(page.records[0].event_kind == agent_q::AgentQApprovalHistoryEventKind::signing,
           "first record event kind");
    expect(page.records[0].signing_record_kind == agent_q::AgentQSigningHistoryRecordKind::terminal,
           "first record signing terminal kind");
    expect(page.records[0].signing_terminal_result == agent_q::AgentQSigningHistoryTerminalResult::policy_rejected,
           "first record signing terminal result");
    expect(page.records[0].confirmation_kind == agent_q::AgentQApprovalHistoryConfirmationKind::policy,
           "first record confirmation kind");
    expect(strcmp(page.records[0].chain, "sui") == 0, "first record chain");

    const std::vector<uint8_t> valid_enum_blob = g_blob;
    g_blob[4] = 1;
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "stored nonzero approval history format marker fails closed");
    g_blob = valid_enum_blob;
    expect(mutate_first_method_record_byte(17, 0xFF), "mutate stored confirmation enum");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "stored unsupported confirmation enum fails closed");
    g_blob = valid_enum_blob;

    agent_q::AgentQSigningHistoryAppendInput max_rule_ref = policy_signing_rejected_input();
    max_rule_ref.rule_ref = "abcdefghijklmnopqrstuvwxyzabcdef";
    expect(agent_q::approval_history_append_required_signing(max_rule_ref, 103),
           "max-length ruleRef matching policy rule id is accepted");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
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
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "corrupt stored token fails closed instead of being sanitized");
    g_blob = valid_blob;

    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "read newest page before wrap");
    const uint64_t sequence_before_wrap = page.count > 0 ? page.records[0].sequence : 0;
    for (uint32_t index = 0; index < agent_q::kAgentQApprovalHistoryCapacity + 3; ++index) {
        char reason[agent_q::kAgentQApprovalHistoryReasonCodeSize] = {};
        snprintf(reason, sizeof(reason), "reason_%u", static_cast<unsigned>(index));
        expect(agent_q::approval_history_append_required_signing(
                   policy_signing_rejected_input(reason),
                   200 + (static_cast<uint64_t>(index + 1) *
                          60000ULL)),
               "append ring record");
    }

    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "read newest page");
    expect(page.count == 4 && page.has_more, "newest page is bounded with hasMore");
    expect(page.records[0].sequence == sequence_before_wrap + agent_q::kAgentQApprovalHistoryCapacity + 3,
           "newest record sequence after wrap");
    const uint64_t before = page.records[3].sequence;
    expect(agent_q::approval_history_read_page(before, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "read paged page");
    expect(page.count == 4 && page.records[0].sequence == before - 1,
           "beforeSeq reads older records");

    agent_q::AgentQSigningHistoryAppendInput overlong_method = policy_signing_rejected_input();
    overlong_method.method = "this_method_name_is_longer_than_the_current_store_allows";
    expect(!agent_q::approval_history_append_required_signing(overlong_method, 400),
           "overlong method token is rejected instead of truncated");

    agent_q::AgentQSigningHistoryAppendInput invalid_chain = policy_signing_rejected_input();
    invalid_chain.chain = "Sui";
    expect(!agent_q::approval_history_append_required_signing(invalid_chain, 401),
           "invalid chain token is rejected instead of sanitized");

    expect(agent_q::approval_history_wipe(), "wipe approval history");
    expect(g_blob.empty(), "wipe removes approval history blob");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "wiped approval history reads as empty");
    expect(page.count == 0, "wiped page is empty");

    g_blob.assign(31, 0xA5);
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "unsupported approval history blob is rejected");
    expect(!agent_q::approval_history_append_required_signing(policy_signing_rejected_input(), 900),
           "append refuses unsupported approval history blob");
    expect(agent_q::approval_history_wipe(), "wipe unsupported approval history blob");
    expect(agent_q::approval_history_append_required_policy_update(
               policy_update_input(),
               1013),
           "required policy-update history appends");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "read policy-update record after budget exhaustion");
    expect(page.count == 1 &&
               page.records[0].event_kind == agent_q::AgentQApprovalHistoryEventKind::policy_update,
           "policy-update record is newest approval-history event");
    expect(strcmp(page.records[0].policy_result, "applied") == 0 &&
               strcmp(page.records[0].reason_code, "device_confirmed") == 0 &&
               strcmp(page.records[0].highest_action, "reject") == 0 &&
               page.records[0].rule_count == 1,
           "policy-update record metadata is preserved");
    expect(agent_q::approval_history_append_required_signing(
               sign_by_user_confirmation_input(),
               1100),
           "required sign_by_user confirmation history appends");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "read sign_by_user confirmation record");
    expect(page.records[0].event_kind == agent_q::AgentQApprovalHistoryEventKind::signing &&
               page.records[0].signing_record_kind ==
                   agent_q::AgentQSigningHistoryRecordKind::confirmation &&
               page.records[0].confirmation_kind == agent_q::AgentQApprovalHistoryConfirmationKind::local_pin &&
               page.records[0].signing_terminal_result ==
                   agent_q::AgentQSigningHistoryTerminalResult::none,
           "sign_by_user confirmation metadata is preserved");
    expect(strcmp(page.records[0].chain, "sui") == 0 &&
               strcmp(page.records[0].method, "sign_transaction") == 0 &&
               strcmp(page.records[0].payload_digest,
                      "sha256:0000000000000000000000000000000000000000000000000000000000000002") == 0,
           "sign_by_user confirmation bounded fields are preserved");
    expect(agent_q::approval_history_append_required_signing(
               sign_by_user_terminal_input(),
               1101),
           "required signing terminal history appends");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "read signing terminal record");
    expect(page.records[0].event_kind == agent_q::AgentQApprovalHistoryEventKind::signing &&
               page.records[0].signing_record_kind ==
                   agent_q::AgentQSigningHistoryRecordKind::terminal &&
               page.records[0].confirmation_kind == agent_q::AgentQApprovalHistoryConfirmationKind::none &&
               page.records[0].signing_terminal_result ==
                   agent_q::AgentQSigningHistoryTerminalResult::signed_success,
           "signing terminal metadata is preserved");
	    const char* allowed_results[] = {
	        "applied",
	        "rejected",
	        "timed_out",
	        "storage_error",
	    };
    for (const char* result : allowed_results) {
        expect(agent_q::approval_history_wipe(), "wipe before allowed policy-update result test");
        expect(agent_q::approval_history_append_required_policy_update(
                   policy_update_input(result),
                   1500),
               "allowed policy-update result is storable");
    }
    expect(agent_q::approval_history_wipe(), "wipe before stored result corruption test");
    expect(agent_q::approval_history_append_required_policy_update(policy_update_input(), 1501),
           "append policy-update result before corruption");
    expect(replace_blob_token("applied", "approve"), "mutate stored policy-update result token");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "stored unsupported policy-update result fails closed");
    expect(agent_q::approval_history_wipe(), "wipe before stored highest-action corruption test");
    expect(agent_q::approval_history_append_required_policy_update(policy_update_input(), 1502),
           "append policy-update highest action before corruption");
    expect(replace_blob_token("reject", "accept"), "mutate stored highest-action token");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "stored unsupported highest action fails closed");
    expect(agent_q::approval_history_wipe(), "wipe after policy-update corruption tests");
    expect(agent_q::approval_history_wipe(), "wipe approval history after policy-update corruption tests");

	    expect(!agent_q::approval_history_append_required_policy_update(
	               policy_update_input("Applied"),
	               1200),
	           "policy-update history rejects invalid result token");
	    expect(!agent_q::approval_history_append_required_policy_update(
	               policy_update_input("history_error"),
	               1201),
	           "policy-update history rejects top-level history error as stored result");
	    expect(!agent_q::approval_history_append_required_policy_update(
	               policy_update_input("consistency_error"),
	               1202),
	           "policy-update history rejects consistency state as stored result");
	    expect(!agent_q::approval_history_append_required_policy_update(
	               policy_update_input("applied", "device_confirmed", "approve"),
	               1203),
	           "policy-update history rejects unsupported highest action");
	    agent_q::AgentQPolicyUpdateHistoryAppendInput invalid_policy_hash = policy_update_input();
	    invalid_policy_hash.policy_hash = "not-a-digest";
	    expect(!agent_q::approval_history_append_required_policy_update(invalid_policy_hash, 1204),
	           "policy-update history rejects invalid policy hash");
	    agent_q::AgentQPolicyUpdateHistoryAppendInput overlarge_rule_count = policy_update_input();
	    overlarge_rule_count.rule_count = agent_q::kAgentQPolicyMaxRules + 1;
	    expect(!agent_q::approval_history_append_required_policy_update(overlarge_rule_count, 1205),
	           "policy-update history rejects overlarge rule count");
    expect(agent_q::approval_history_wipe(), "wipe before sign_by_user invalid input tests");
    agent_q::AgentQSigningHistoryAppendInput invalid_signature = sign_by_user_confirmation_input();
    invalid_signature.confirmation_kind = agent_q::AgentQApprovalHistoryConfirmationKind::policy;
    expect(!agent_q::approval_history_append_required_signing(invalid_signature, 1300),
           "sign_by_user confirmation rejects policy confirmation kind");
    invalid_signature = sign_by_user_terminal_input();
    invalid_signature.terminal_result = agent_q::AgentQSigningHistoryTerminalResult::none;
    expect(!agent_q::approval_history_append_required_signing(invalid_signature, 1301),
           "signing terminal rejects empty terminal result");
    invalid_signature = sign_by_user_terminal_input(
        agent_q::AgentQSigningHistoryTerminalResult::policy_rejected,
        "policy_rejected");
    expect(!agent_q::approval_history_append_required_signing(invalid_signature, 1301),
           "user signing terminal rejects policy_rejected");
    invalid_signature = policy_signing_rejected_input();
    invalid_signature.terminal_result = agent_q::AgentQSigningHistoryTerminalResult::user_rejected;
    invalid_signature.reason_code = "user_rejected";
    expect(!agent_q::approval_history_append_required_signing(invalid_signature, 1301),
           "policy signing terminal rejects user_rejected");
    invalid_signature = sign_by_user_terminal_input();
    invalid_signature.policy_hash = "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3";
    invalid_signature.rule_ref = "default";
    expect(!agent_q::approval_history_append_required_signing(invalid_signature, 1301),
           "user signing terminal rejects policy metadata");
    invalid_signature = policy_signing_rejected_input();
    invalid_signature.policy_hash = nullptr;
    expect(!agent_q::approval_history_append_required_signing(invalid_signature, 1301),
           "policy signing terminal requires policy metadata");
    invalid_signature = sign_by_user_terminal_input();
    invalid_signature.payload_digest = "not-a-digest";
    expect(!agent_q::approval_history_append_required_signing(invalid_signature, 1302),
           "signing history rejects invalid payload digest");
    expect(agent_q::approval_history_append_required_signing(
               sign_by_user_confirmation_input(),
               1303),
           "append sign_by_user before enum corruption");
    const std::vector<uint8_t> valid_signature_blob = g_blob;
    expect(mutate_first_method_record_byte(19, 0xFF), "mutate stored event enum");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "stored unsupported event enum fails closed");
    g_blob = valid_signature_blob;
    expect(mutate_first_method_record_byte(22, 0xFF), "mutate signature record kind enum");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "stored unsupported signature record kind fails closed");
    expect(agent_q::approval_history_wipe(), "wipe after sign_by_user enum corruption");

    expect(agent_q::approval_history_append_required_signing(
               sign_by_user_terminal_input(
                   agent_q::AgentQSigningHistoryTerminalResult::user_rejected,
                   "user_rejected"),
               1400),
           "append user terminal before stored matrix corruption");
    const std::vector<uint8_t> valid_user_terminal_blob = g_blob;
    expect(mutate_first_method_record_byte(17, 1), "mutate user terminal to policy authorization");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "stored user terminal with policy authorization fails closed");
    g_blob = valid_user_terminal_blob;
    expect(mutate_first_method_record_byte(23, 5), "mutate user terminal to policy_rejected result");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "stored user terminal with policy result fails closed");
    expect(agent_q::approval_history_wipe(), "wipe after stored user terminal corruption");

    expect(agent_q::approval_history_append_required_signing(policy_signing_rejected_input(), 1410),
           "append policy terminal before stored policy metadata corruption");
    const std::vector<uint8_t> valid_policy_terminal_blob = g_blob;
    expect(mutate_first_method_record_byte(18, 1), "drop stored policy digest flag");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "stored policy terminal without policy metadata fails closed");
    g_blob = valid_policy_terminal_blob;
    expect(mutate_first_method_record_byte(23, 2), "mutate policy terminal to user_rejected result");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "stored policy terminal with user result fails closed");
    expect(agent_q::approval_history_wipe(), "wipe after stored policy terminal corruption");

    for (size_t index = 0; index < agent_q::kAgentQApprovalHistoryWriteBudgetMax; ++index) {
        expect(agent_q::approval_history_append_budgeted_signing(
                   policy_signing_rejected_input(),
                   2000),
               "budgeted policy rejection append within window");
    }
    expect(!agent_q::approval_history_append_budgeted_signing(
               policy_signing_rejected_input(),
               2000),
           "budgeted policy rejection append fails when write budget is exhausted");
    expect(agent_q::approval_history_append_budgeted_signing(
               policy_signing_rejected_input(),
               2000 + agent_q::kAgentQApprovalHistoryWriteBudgetWindowMs),
           "budgeted policy rejection append resumes after window");
    expect(agent_q::approval_history_wipe(), "wipe after budgeted policy rejection tests");

    expect(agent_q::approval_history_append_required_signing(policy_signing_rejected_input(), 500),
           "append after wipe reinitializes");
    g_blob.push_back(0);
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "corrupt history read fails closed");
    expect(!agent_q::approval_history_append_required_signing(policy_signing_rejected_input(), 501),
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
  -I"${TARGET_ROOT}/agent_q" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/approval_history_test.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_approval_history.cpp" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/approval_history_test"

"${TMP_DIR}/approval_history_test"
