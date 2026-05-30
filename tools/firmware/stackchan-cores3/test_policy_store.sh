#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_policy_store.sh

ESP-IDF must already be active in the shell so IDF_PATH points to the ESP-IDF
checkout. The test compiles the StackChan CoreS3 active policy store with NVS
stubs and ESP-IDF mbedTLS SHA-256, then checks stored default-policy metadata and
provider fail-closed behavior.
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
  echo "IDF_PATH does not expose the expected ESP-IDF mbedtls sources: ${IDF_PATH}" >&2
  exit 1
fi

for required in \
  "${TARGET_ROOT}/agent_q/agent_q_policy_store.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_store.h" \
  "${COMMON_ROOT}/policy/agent_q_policy_v0.cpp" \
  "${COMMON_ROOT}/policy/agent_q_policy_runtime.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-policy-store.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/stubs"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"

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

cat >"${TMP_DIR}/policy_store_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <vector>

#include "esp_err.h"
#include "nvs.h"
#include "agent_q_policy_store.h"

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

agent_q::AgentQTransactionFacts valid_facts()
{
    return agent_q::AgentQTransactionFacts{
        "sui",
        "sign_transaction",
        "devnet",
        "transfer",
        "0x1111111111111111111111111111111111111111111111111111111111111111",
        "1",
        "1000",
    };
}

agent_q::AgentQPolicyDecision evaluate_active_policy()
{
    return agent_q::evaluate_agent_q_policy_runtime(agent_q::active_policy_provider(), valid_facts());
}

}  // namespace

extern "C" {

esp_err_t nvs_open(const char* name, int open_mode, nvs_handle_t* out_handle)
{
    (void)name;
    (void)open_mode;
    if (g_open_fails) {
        return 1;
    }
    *out_handle = 1;
    return ESP_OK;
}

void nvs_close(nvs_handle_t handle)
{
    (void)handle;
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* out_value, size_t* length)
{
    (void)handle;
    (void)key;
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

esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length)
{
    (void)handle;
    (void)key;
    const uint8_t* bytes = static_cast<const uint8_t*>(value);
    g_blob.assign(bytes, bytes + length);
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key)
{
    (void)handle;
    (void)key;
    if (g_blob.empty()) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    g_blob.clear();
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t handle)
{
    (void)handle;
    return g_commit_fails ? 1 : ESP_OK;
}

}  // extern "C"

int main()
{
    agent_q::AgentQStoredPolicySummary summary = {};

    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::missing, "missing policy status");
    expect(!agent_q::read_active_policy_summary(&summary), "missing policy summary fails closed");
    agent_q::AgentQPolicyDecision decision = evaluate_active_policy();
    expect(decision.action == agent_q::AgentQPolicyAction::reject, "missing policy rejects");
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::invalid_policy, "missing policy reason is invalid_policy");

    expect(agent_q::store_default_policy(), "store default policy");
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "stored policy status");
    expect(agent_q::read_active_policy_summary(&summary), "read default policy summary");
    expect(strcmp(summary.schema, "agentq.policy.v0") == 0, "policy schema");
    expect(strcmp(summary.default_action, "reject") == 0, "policy default action");
    expect(summary.rule_count == 0, "policy rule count");
    expect(strcmp(summary.policy_id, "sha256:4d180eb74c192a7952def9d3932128bd91dac4ebbe9fe96e21eeb32671f441ab") == 0, "policy id");

    decision = evaluate_active_policy();
    expect(decision.action == agent_q::AgentQPolicyAction::reject, "default policy rejects");
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::default_reject, "default policy reason");

    g_blob[0] = 0;
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::invalid, "corrupt policy status");
    expect(!agent_q::read_active_policy_summary(&summary), "corrupt policy summary fails closed");
    decision = evaluate_active_policy();
    expect(decision.action == agent_q::AgentQPolicyAction::reject, "corrupt policy rejects");
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::invalid_policy, "corrupt policy reason is invalid_policy");

    expect(agent_q::store_default_policy(), "restore default policy");
    g_blob.push_back(0);
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::invalid, "oversized policy status");

    expect(agent_q::store_default_policy(), "restore default policy again");
    expect(agent_q::wipe_policy(), "wipe policy");
    expect(g_blob.empty(), "policy blob wiped");
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::missing, "wiped policy status");
    expect(!agent_q::read_active_policy_summary(&summary), "wiped policy summary fails closed");

    g_commit_fails = true;
    expect(!agent_q::store_default_policy(), "commit failure fails closed");
    expect(g_blob.empty(), "commit failure wipes partial policy");
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::missing, "commit failure policy status");
    g_commit_fails = false;

    g_open_fails = true;
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::storage_error, "storage error policy status");
    g_open_fails = false;

    if (failures != 0) {
        fprintf(stderr, "Policy store tests failed: %d\n", failures);
        return 1;
    }
    printf("Policy store tests passed\n");
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
  "${TMP_DIR}/policy_store_test.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_store.cpp" \
  "${COMMON_ROOT}/policy/agent_q_policy_v0.cpp" \
  "${COMMON_ROOT}/policy/agent_q_policy_runtime.cpp" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/policy_store_test"

"${TMP_DIR}/policy_store_test"
