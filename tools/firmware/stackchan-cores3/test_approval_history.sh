#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_approval_history.sh

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
TARGET_ROOT="${REPO_ROOT}/products/firmware/src/stackchan-cores3"
COMMON_ROOT="${REPO_ROOT}/products/firmware/src/common/agent_q"

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

agent_q::AgentQApprovalHistoryAppendInput policy_rejected_input(const char* reason = "policy_rejected")
{
    return agent_q::AgentQApprovalHistoryAppendInput{
        agent_q::AgentQApprovalHistoryDecision::policy_rejected,
        agent_q::AgentQApprovalHistoryConfirmationKind::policy,
        "sui",
        "sign_transaction",
        reason,
        "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        "sha256:4d180eb74c192a7952def9d3932128bd91dac4ebbe9fe96e21eeb32671f441ab",
        "default",
    };
}

struct LegacyApprovalHistoryRecordV1 {
    uint64_t sequence;
    uint64_t uptime_ms;
    uint8_t decision;
    uint8_t confirmation_kind;
    uint8_t flags;
    uint8_t reserved[5];
    char chain[agent_q::kAgentQApprovalHistoryChainSize];
    char method[agent_q::kAgentQApprovalHistoryMethodSize];
    char reason_code[agent_q::kAgentQApprovalHistoryReasonCodeSize];
    char rule_ref[16];
    uint8_t payload_digest[32];
    uint8_t policy_hash[32];
};

struct LegacyApprovalHistoryV1 {
    uint8_t magic[4];
    uint8_t format_version;
    uint8_t reserved0;
    uint16_t start;
    uint16_t count;
    uint16_t reserved1;
    uint64_t next_sequence;
    LegacyApprovalHistoryRecordV1 records[agent_q::kAgentQApprovalHistoryCapacity];
};

void write_legacy_history_blob()
{
    LegacyApprovalHistoryV1 legacy = {};
    legacy.magic[0] = 'A';
    legacy.magic[1] = 'Q';
    legacy.magic[2] = 'A';
    legacy.magic[3] = 'H';
    legacy.format_version = 1;
    legacy.count = 1;
    legacy.next_sequence = 2;
    legacy.records[0].sequence = 1;
    legacy.records[0].uptime_ms = 77;
    legacy.records[0].decision = 1;
    legacy.records[0].confirmation_kind = 1;
    strcpy(legacy.records[0].chain, "sui");
    strcpy(legacy.records[0].method, "sign_transaction");
    strcpy(legacy.records[0].reason_code, "policy_rejected");
    strcpy(legacy.records[0].rule_ref, "legacy_rule");
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&legacy);
    g_blob.assign(bytes, bytes + sizeof(legacy));
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

    expect(agent_q::approval_history_append(policy_rejected_input(), 100),
           "append first policy rejection");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "read first page");
    expect(page.count == 1 && !page.has_more, "one record page shape");
    expect(page.records[0].sequence == 1, "first record sequence");
    expect(page.records[0].uptime_ms == 100, "first record uptime");
    expect(page.records[0].decision == agent_q::AgentQApprovalHistoryDecision::policy_rejected,
           "first record decision");
    expect(page.records[0].confirmation_kind == agent_q::AgentQApprovalHistoryConfirmationKind::policy,
           "first record confirmation kind");
    expect(strcmp(page.records[0].chain, "sui") == 0, "first record chain");

    agent_q::AgentQApprovalHistoryAppendInput max_rule_ref = policy_rejected_input();
    max_rule_ref.rule_ref = "abcdefghijklmnopqrstuvwxyzabcdef";
    expect(agent_q::approval_history_append(max_rule_ref, 101),
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
                  "sha256:4d180eb74c192a7952def9d3932128bd91dac4ebbe9fe96e21eeb32671f441ab") == 0,
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

    for (uint32_t index = 0; index < agent_q::kAgentQApprovalHistoryCapacity + 3; ++index) {
        char reason[agent_q::kAgentQApprovalHistoryReasonCodeSize] = {};
        snprintf(reason, sizeof(reason), "reason_%u", static_cast<unsigned>(index));
        expect(agent_q::approval_history_append(
                   policy_rejected_input(reason),
                   200 + (static_cast<uint64_t>(index + 1) *
                          agent_q::kAgentQApprovalHistoryWriteBudgetWindowMs)),
               "append ring record");
    }

    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "read newest page");
    expect(page.count == 4 && page.has_more, "newest page is bounded with hasMore");
    expect(page.records[0].sequence == agent_q::kAgentQApprovalHistoryCapacity + 5,
           "newest record sequence after wrap");
    const uint64_t before = page.records[3].sequence;
    expect(agent_q::approval_history_read_page(before, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "read paged page");
    expect(page.count == 4 && page.records[0].sequence == before - 1,
           "beforeSeq reads older records");

    agent_q::AgentQApprovalHistoryAppendInput overlong_method = policy_rejected_input();
    overlong_method.method = "this_method_name_is_longer_than_the_current_store_allows";
    expect(!agent_q::approval_history_append(overlong_method, 400),
           "overlong method token is rejected instead of truncated");

    agent_q::AgentQApprovalHistoryAppendInput invalid_chain = policy_rejected_input();
    invalid_chain.chain = "Sui";
    expect(!agent_q::approval_history_append(invalid_chain, 401),
           "invalid chain token is rejected instead of sanitized");

    expect(agent_q::approval_history_wipe(), "wipe approval history");
    expect(g_blob.empty(), "wipe removes approval history blob");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "wiped approval history reads as empty");
    expect(page.count == 0, "wiped page is empty");

    write_legacy_history_blob();
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "legacy approval history layout migrates for read");
    expect(page.count == 1 && page.records[0].sequence == 1,
           "legacy approval history record is readable");
    expect(strcmp(page.records[0].rule_ref, "legacy_rule") == 0,
           "legacy approval history ruleRef is preserved");
    expect(agent_q::approval_history_append(policy_rejected_input(), 900),
           "append migrates legacy approval history layout");
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::ok,
           "read migrated approval history after append");
    expect(page.count == 2 && page.records[0].sequence == 2,
           "migrated approval history appends after legacy sequence");
    expect(agent_q::approval_history_wipe(), "wipe approval history after legacy migration test");

    for (size_t index = 0; index < agent_q::kAgentQApprovalHistoryWriteBudgetMax; ++index) {
        expect(agent_q::approval_history_append(policy_rejected_input(), 1000 + index),
               "append within write budget");
    }
    expect(!agent_q::approval_history_append(
               policy_rejected_input(),
               1000 + agent_q::kAgentQApprovalHistoryWriteBudgetMax),
           "approval history write budget rejects excessive writes in one window");
    expect(agent_q::approval_history_append(
               policy_rejected_input(),
               1000 + agent_q::kAgentQApprovalHistoryWriteBudgetWindowMs),
           "approval history write budget resets after window elapses");
    expect(agent_q::approval_history_wipe(), "wipe approval history after budget test");

    expect(agent_q::approval_history_append(policy_rejected_input(), 500),
           "append after wipe reinitializes");
    g_blob.push_back(0);
    expect(agent_q::approval_history_read_page(0, 4, &page) == agent_q::AgentQApprovalHistoryReadResult::invalid,
           "corrupt history read fails closed");
    expect(!agent_q::approval_history_append(policy_rejected_input(), 501),
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
