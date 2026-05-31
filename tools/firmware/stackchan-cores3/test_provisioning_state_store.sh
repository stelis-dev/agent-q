#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_provisioning_state_store.sh

Compiles the StackChan CoreS3 provisioning-state NVS store against host stubs
and verifies missing/present/unreadable storage classification plus state writes.
This test uses only a host C++ compiler and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/products/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/products/firmware/src/common/agent_q"
CXX_BIN="${CXX:-c++}"

for required in \
  "${AGENT_Q_DIR}/agent_q_provisioning_state_store.cpp" \
  "${AGENT_Q_DIR}/agent_q_provisioning_state_store.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-provisioning-state-store.XXXXXX")"
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
esp_err_t nvs_get_str(nvs_handle_t handle, const char* key, char* out_value, size_t* length);
esp_err_t nvs_set_str(nvs_handle_t handle, const char* key, const char* value);
esp_err_t nvs_commit(nvs_handle_t handle);
}
H

cat >"${TMP_DIR}/provisioning_state_store_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_provisioning_state_store.h"
#include "esp_err.h"
#include "nvs.h"

namespace {

bool g_has_value = false;
bool g_open_fails = false;
bool g_read_fails = false;
bool g_set_fails = false;
bool g_commit_fails = false;
char g_value[agent_q::kAgentQProvisioningStateStoreValueSize] = {};
int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void reset_stubs()
{
    g_has_value = false;
    g_open_fails = false;
    g_read_fails = false;
    g_set_fails = false;
    g_commit_fails = false;
    memset(g_value, 0, sizeof(g_value));
}

}  // namespace

namespace agent_q {

const char* provisioning_runtime_state_to_string(AgentQProvisioningRuntimeState state)
{
    switch (state) {
        case AgentQProvisioningRuntimeState::provisioned:
            return "provisioned";
        case AgentQProvisioningRuntimeState::provisioning:
            return "provisioning";
        case AgentQProvisioningRuntimeState::unprovisioned:
        default:
            return "unprovisioned";
    }
}

}  // namespace agent_q

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

esp_err_t nvs_get_str(nvs_handle_t handle, const char* key, char* out_value, size_t* length)
{
    (void)handle;
    (void)key;
    if (g_read_fails) {
        return 2;
    }
    if (!g_has_value) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    const size_t required = strlen(g_value) + 1;
    if (out_value == nullptr || length == nullptr || *length < required) {
        return 3;
    }
    memcpy(out_value, g_value, required);
    *length = required;
    return ESP_OK;
}

esp_err_t nvs_set_str(nvs_handle_t handle, const char* key, const char* value)
{
    (void)handle;
    (void)key;
    if (g_set_fails) {
        return 4;
    }
    strlcpy(g_value, value, sizeof(g_value));
    g_has_value = true;
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t handle)
{
    (void)handle;
    return g_commit_fails ? 5 : ESP_OK;
}

}  // extern "C"

int main()
{
    using Status = agent_q::AgentQProvisioningStateStorageStatus;

    agent_q::AgentQProvisioningStateStoreRecord record = {};

    reset_stubs();
    expect(agent_q::provisioning_state_store_load(&record), "missing state load returns transport success");
    expect(record.status == Status::missing, "missing state is classified");
    expect(record.value[0] == '\0', "missing state has empty value");

    reset_stubs();
    g_has_value = true;
    strlcpy(g_value, "provisioned", sizeof(g_value));
    expect(agent_q::provisioning_state_store_load(&record), "present state load succeeds");
    expect(record.status == Status::present, "present state is classified");
    expect(strcmp(record.value, "provisioned") == 0, "present state value is copied");

    reset_stubs();
    g_open_fails = true;
    expect(agent_q::provisioning_state_store_load(&record), "open failure load is represented as a record");
    expect(record.status == Status::unreadable, "open failure is unreadable");
    expect(record.value[0] == '\0', "open failure has empty value");

    reset_stubs();
    g_read_fails = true;
    expect(agent_q::provisioning_state_store_load(&record), "read failure load is represented as a record");
    expect(record.status == Status::unreadable, "read failure is unreadable");

    reset_stubs();
    expect(agent_q::provisioning_state_store_save(agent_q::AgentQProvisioningRuntimeState::provisioned),
           "save provisioned succeeds");
    expect(g_has_value && strcmp(g_value, "provisioned") == 0,
           "save writes provisioning state string");

    reset_stubs();
    g_set_fails = true;
    expect(!agent_q::provisioning_state_store_save(agent_q::AgentQProvisioningRuntimeState::unprovisioned),
           "set failure returns false");

    reset_stubs();
    g_commit_fails = true;
    expect(!agent_q::provisioning_state_store_save(agent_q::AgentQProvisioningRuntimeState::unprovisioned),
           "commit failure returns false");

    if (failures != 0) {
        fprintf(stderr, "%d provisioning state store test(s) failed\n", failures);
        return 1;
    }
    printf("Provisioning state store tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/provisioning_state_store_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_provisioning_state_store.cpp" \
  -o "${TMP_DIR}/provisioning_state_store_test"

"${TMP_DIR}/provisioning_state_store_test"
