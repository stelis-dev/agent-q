#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sui_account_settings.sh

Compiles the StackChan CoreS3 Sui account settings store against host NVS stubs
and verifies missing, stored reject, stored accept, invalid, unreadable, and
wipe behavior. This test uses only a host C++ compiler and does NOT require
ESP-IDF.
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
  "${RUNTIME_DIR}/sui_account_settings.cpp" \
  "${RUNTIME_DIR}/sui_account_settings.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-sui-account-settings.XXXXXX")"
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

cat >"${TMP_DIR}/sui_account_settings_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sui_account_settings.h"
#include "esp_err.h"
#include "nvs.h"

namespace {

constexpr const char* kExpectedNamespace = "signing";
constexpr const char* kExpectedKey = "sui_acct_set";

bool g_has_value = false;
uint8_t g_value = 0;
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

void reset_stubs()
{
    g_has_value = false;
    g_value = 0;
    g_namespace_missing = false;
    g_open_fails = false;
    g_commit_fails = false;
}

}  // namespace

extern "C" {

esp_err_t nvs_open(const char* name, int open_mode, nvs_handle_t* out_handle)
{
    (void)open_mode;
    if (strcmp(name, kExpectedNamespace) != 0) {
        return 1;
    }
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
    if (strcmp(key, kExpectedKey) != 0) {
        return 1;
    }
    if (!g_has_value) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    *out_value = g_value;
    return ESP_OK;
}

esp_err_t nvs_set_u8(nvs_handle_t handle, const char* key, uint8_t value)
{
    (void)handle;
    if (strcmp(key, kExpectedKey) != 0) {
        return 1;
    }
    g_has_value = true;
    g_value = value;
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key)
{
    (void)handle;
    if (strcmp(key, kExpectedKey) != 0) {
        return 1;
    }
    if (!g_has_value) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    g_has_value = false;
    g_value = 0;
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
    using Status = signing::SuiAccountSettingsStatus;

    signing::SuiAccountSettings settings = {true};

    reset_stubs();
    expect(signing::sui_account_settings_status() == Status::missing,
           "missing Sui account settings report missing status");
    expect(!signing::read_sui_account_settings(&settings),
           "missing Sui account settings read fails");
    expect(!settings.accept_gas_sponsor,
           "missing Sui account settings fail closed to rejecting gas sponsors");

    expect(signing::store_sui_account_settings(signing::kDefaultSuiAccountSettings),
           "store default Sui account settings");
    expect(signing::sui_account_settings_status() == Status::active,
           "stored default Sui account settings report active status");
    settings = {true};
    expect(signing::read_sui_account_settings(&settings),
           "stored default Sui account settings read succeeds");
    expect(!settings.accept_gas_sponsor,
           "stored default rejects gas sponsors");

    settings = {true};
    expect(signing::store_sui_account_settings(settings),
           "store Sui account settings that accept gas sponsors");
    settings = {false};
    expect(signing::read_sui_account_settings(&settings),
           "stored accepting Sui account settings read succeeds");
    expect(settings.accept_gas_sponsor,
           "stored accepting Sui account settings are observed");

    expect(signing::wipe_sui_account_settings(), "wipe Sui account settings");
    expect(signing::sui_account_settings_status() == Status::missing,
           "wiped Sui account settings report missing status");

    g_namespace_missing = true;
    expect(signing::wipe_sui_account_settings(), "missing namespace wipe succeeds");
    expect(signing::sui_account_settings_status() == Status::missing,
           "missing namespace reports missing status");
    g_namespace_missing = false;

    g_has_value = true;
    g_value = 2;
    settings = {true};
    expect(signing::sui_account_settings_status() == Status::invalid,
           "invalid Sui account settings report invalid status");
    expect(!signing::read_sui_account_settings(&settings),
           "invalid Sui account settings read fails");
    expect(!settings.accept_gas_sponsor,
           "invalid Sui account settings fail closed to rejecting gas sponsors");

    g_open_fails = true;
    settings = {true};
    expect(signing::sui_account_settings_status() == Status::unreadable,
           "unreadable Sui account settings report unreadable status");
    expect(!signing::read_sui_account_settings(&settings),
           "unreadable Sui account settings read fails");
    expect(!settings.accept_gas_sponsor,
           "unreadable Sui account settings fail closed to rejecting gas sponsors");
    g_open_fails = false;

    g_commit_fails = true;
    expect(!signing::store_sui_account_settings(signing::kDefaultSuiAccountSettings),
           "commit failure reports Sui account settings store failure");

    if (failures != 0) {
        fprintf(stderr, "Sui account settings tests failed: %d\n", failures);
        return 1;
    }
    printf("Sui account settings tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/sui_account_settings_test.cpp" \
  "${RUNTIME_DIR}/sui_account_settings.cpp" \
  -o "${TMP_DIR}/sui_account_settings_test"

"${TMP_DIR}/sui_account_settings_test"
