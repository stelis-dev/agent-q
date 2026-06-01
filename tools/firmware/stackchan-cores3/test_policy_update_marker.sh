#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_policy_update_marker.sh

Compiles the StackChan CoreS3 policy-update terminal marker with host NVS stubs
and verifies pending/clear, invalid stored marker, storage-error, and input
validation behavior. This test uses only a host C++ compiler and does NOT
require ESP-IDF or hardware.
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
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-policy-update-marker.XXXXXX")"
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

cat >"${TMP_DIR}/policy_update_marker_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <vector>

#include "agent_q_policy_update_marker.h"
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

void reset_storage()
{
    g_blob.clear();
    g_open_fails = false;
    g_commit_fails = false;
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
    using Status = agent_q::AgentQPolicyUpdateMarkerStatus;
    using BeginResult = agent_q::AgentQPolicyUpdateMarkerBeginResult;
    uint8_t digest[agent_q::kAgentQPolicyUpdateDigestBytes] = {};
    digest[0] = 0x42;

    reset_storage();
    expect(agent_q::policy_update_marker_status() == Status::clear,
           "missing marker is clear");

    expect(agent_q::policy_update_marker_begin(
               digest,
               sizeof(digest),
               1,
               agent_q::AgentQPolicyUpdateHighestAction::reject) == BeginResult::written,
           "valid marker begin succeeds");
    expect(agent_q::policy_update_marker_status() == Status::pending,
           "valid marker reads as pending");
    expect(agent_q::policy_update_marker_clear(), "marker clear succeeds");
    expect(agent_q::policy_update_marker_status() == Status::clear,
           "cleared marker reads as clear");

    expect(agent_q::policy_update_marker_begin(
               nullptr,
               sizeof(digest),
               1,
               agent_q::AgentQPolicyUpdateHighestAction::reject) == BeginResult::invalid_input,
           "null policy digest is rejected");
    expect(agent_q::policy_update_marker_begin(
               digest,
               sizeof(digest) - 1,
               1,
               agent_q::AgentQPolicyUpdateHighestAction::reject) == BeginResult::invalid_input,
           "wrong digest size is rejected");
    expect(agent_q::policy_update_marker_begin(
               digest,
               sizeof(digest),
               agent_q::kAgentQPolicyMaxRules + 1,
               agent_q::AgentQPolicyUpdateHighestAction::reject) == BeginResult::invalid_input,
           "overlarge rule count is rejected");
    expect(agent_q::policy_update_marker_begin(
               digest,
               sizeof(digest),
               1,
               static_cast<agent_q::AgentQPolicyUpdateHighestAction>(99)) == BeginResult::invalid_input,
           "unknown highest action is rejected");

    expect(agent_q::policy_update_marker_begin(
               digest,
               sizeof(digest),
               agent_q::kAgentQPolicyMaxRules,
               agent_q::AgentQPolicyUpdateHighestAction::sign) == BeginResult::written,
           "max rule count marker succeeds");
    g_blob[0] = 'X';
    expect(agent_q::policy_update_marker_status() == Status::invalid,
           "corrupt marker magic fails closed");

    reset_storage();
    g_blob.assign(3, 0xAA);
    expect(agent_q::policy_update_marker_status() == Status::invalid,
           "wrong marker size fails closed");

    reset_storage();
    g_open_fails = true;
    expect(agent_q::policy_update_marker_status() == Status::storage_error,
           "NVS open failure reports storage error");
    expect(!agent_q::policy_update_marker_clear(),
           "marker clear reports NVS open failure");

    reset_storage();
    g_commit_fails = true;
    expect(agent_q::policy_update_marker_begin(
               digest,
               sizeof(digest),
               1,
               agent_q::AgentQPolicyUpdateHighestAction::ask) == BeginResult::pending_after_error,
           "marker begin reports durable pending marker after commit failure");
    expect(agent_q::policy_update_marker_status() == Status::pending,
           "durable marker remains pending after commit failure");

    if (failures != 0) {
        fprintf(stderr, "%d policy update marker test(s) failed\n", failures);
        return 1;
    }
    printf("Policy update marker tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${TARGET_ROOT}/agent_q" \
  "${TMP_DIR}/policy_update_marker_test.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_update_marker.cpp" \
  -o "${TMP_DIR}/policy_update_marker_test"

"${TMP_DIR}/policy_update_marker_test"
