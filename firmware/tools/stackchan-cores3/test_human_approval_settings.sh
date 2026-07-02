#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_human_approval_settings.sh

Compiles the StackChan CoreS3 human approval input mode store against host NVS
stubs and verifies the missing-key PIN default, stored Confirm override, invalid
value fail-closed behavior, and reset wipe back to the missing-key default.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"

for required in \
  "${RUNTIME_DIR}/human_approval_settings.cpp" \
  "${RUNTIME_DIR}/human_approval_settings.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-human-approval-settings.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

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
H

cat >"${TMP_DIR}/stubs/nvs.h" <<'H'
#pragma once

#include <stdint.h>
#include "esp_err.h"

#define NVS_READONLY 1
#define NVS_READWRITE 2

typedef int nvs_handle_t;

extern "C" {
esp_err_t nvs_open(const char* name, int open_mode, nvs_handle_t* out_handle);
void nvs_close(nvs_handle_t handle);
esp_err_t nvs_get_u8(nvs_handle_t handle, const char* key, uint8_t* out_value);
esp_err_t nvs_set_u8(nvs_handle_t handle, const char* key, uint8_t value);
esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key);
esp_err_t nvs_commit(nvs_handle_t handle);
}
H

cat >"${TMP_DIR}/human_approval_settings_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>

#include "human_approval_settings.h"
#include "esp_err.h"
#include "nvs.h"

namespace {

bool g_has_value = false;
uint8_t g_value = 1;
bool g_namespace_missing = false;
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

}  // namespace

extern "C" {

esp_err_t nvs_open(const char* name, int open_mode, nvs_handle_t* out_handle)
{
    (void)name;
    (void)open_mode;
    if (g_namespace_missing) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
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

esp_err_t nvs_get_u8(nvs_handle_t handle, const char* key, uint8_t* out_value)
{
    (void)handle;
    (void)key;
    if (!g_has_value) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    *out_value = g_value;
    return ESP_OK;
}

esp_err_t nvs_set_u8(nvs_handle_t handle, const char* key, uint8_t value)
{
    (void)handle;
    (void)key;
    g_has_value = true;
    g_value = value;
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key)
{
    (void)handle;
    (void)key;
    if (!g_has_value) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    g_has_value = false;
    g_value = 1;
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
    signing::HumanApprovalInputMode mode =
        signing::HumanApprovalInputMode::confirm;

    expect(signing::read_human_approval_input_mode(&mode), "missing setting read succeeds");
    expect(mode == signing::HumanApprovalInputMode::pin,
           "missing setting defaults to PIN input");
    expect(signing::human_approval_requires_pin(), "missing setting requires PIN");

    expect(signing::store_human_approval_input_mode(signing::HumanApprovalInputMode::confirm),
           "store Confirm input mode");
    expect(signing::read_human_approval_input_mode(&mode), "stored setting read succeeds");
    expect(mode == signing::HumanApprovalInputMode::confirm,
           "stored Confirm input mode is observed");
    expect(!signing::human_approval_requires_pin(), "stored Confirm mode does not require PIN");

    expect(signing::wipe_human_approval_input_mode(), "wipe human approval input mode");
    expect(signing::read_human_approval_input_mode(&mode), "wiped setting read succeeds");
    expect(mode == signing::HumanApprovalInputMode::pin,
           "wiped setting returns to PIN default");

    g_namespace_missing = true;
    expect(signing::wipe_human_approval_input_mode(), "missing namespace wipe succeeds");
    g_namespace_missing = false;

    g_has_value = true;
    g_value = 2;
    mode = signing::HumanApprovalInputMode::confirm;
    expect(!signing::read_human_approval_input_mode(&mode), "invalid setting reports read failure");
    expect(mode == signing::HumanApprovalInputMode::pin,
           "invalid setting fails closed to PIN mode");
    expect(signing::human_approval_requires_pin(), "invalid setting requires PIN");

    g_open_fails = true;
    mode = signing::HumanApprovalInputMode::confirm;
    expect(!signing::read_human_approval_input_mode(&mode), "storage error reports read failure");
    expect(mode == signing::HumanApprovalInputMode::pin,
           "storage error fails closed to PIN mode");
    expect(signing::human_approval_requires_pin(), "storage error requires PIN");
    g_open_fails = false;

    if (failures != 0) {
        fprintf(stderr, "Human approval settings tests failed: %d\n", failures);
        return 1;
    }
    printf("Human approval settings tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/human_approval_settings_test.cpp" \
  "${RUNTIME_DIR}/human_approval_settings.cpp" \
  -o "${TMP_DIR}/human_approval_settings_test"

"${TMP_DIR}/human_approval_settings_test"
