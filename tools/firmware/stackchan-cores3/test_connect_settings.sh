#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_connect_settings.sh

Compiles the StackChan CoreS3 connect approval setting store against host NVS
stubs and verifies the missing-key secure default, stored OFF override, invalid
value fail-closed behavior, and reset wipe back to the missing-key default.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/products/firmware/src/stackchan-cores3/agent_q"

for required in \
  "${AGENT_Q_DIR}/agent_q_connect_settings.cpp" \
  "${AGENT_Q_DIR}/agent_q_connect_settings.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-connect-settings.XXXXXX")"
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

cat >"${TMP_DIR}/connect_settings_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>

#include "agent_q_connect_settings.h"
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
    bool required = false;

    expect(agent_q::read_require_pin_on_connect(&required), "missing setting read succeeds");
    expect(required, "missing setting defaults to PIN required");
    expect(agent_q::connect_requires_pin(), "missing setting requires PIN");

    expect(agent_q::store_require_pin_on_connect(false), "store PIN-off setting");
    expect(agent_q::read_require_pin_on_connect(&required), "stored setting read succeeds");
    expect(!required, "stored OFF disables connect PIN");
    expect(!agent_q::connect_requires_pin(), "stored OFF is observed");

    expect(agent_q::wipe_require_pin_on_connect(), "wipe connect PIN setting");
    expect(agent_q::read_require_pin_on_connect(&required), "wiped setting read succeeds");
    expect(required, "wiped setting returns to secure missing-key default");

    g_namespace_missing = true;
    expect(agent_q::wipe_require_pin_on_connect(), "missing namespace wipe succeeds");
    g_namespace_missing = false;

    g_has_value = true;
    g_value = 2;
    required = false;
    expect(!agent_q::read_require_pin_on_connect(&required), "invalid setting reports read failure");
    expect(required, "invalid setting fails closed to PIN required");
    expect(agent_q::connect_requires_pin(), "invalid setting requires PIN");

    g_open_fails = true;
    required = false;
    expect(!agent_q::read_require_pin_on_connect(&required), "storage error reports read failure");
    expect(required, "storage error fails closed to PIN required");
    expect(agent_q::connect_requires_pin(), "storage error requires PIN");
    g_open_fails = false;

    if (failures != 0) {
        fprintf(stderr, "Connect settings tests failed: %d\n", failures);
        return 1;
    }
    printf("Connect settings tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/connect_settings_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_connect_settings.cpp" \
  -o "${TMP_DIR}/connect_settings_test"

"${TMP_DIR}/connect_settings_test"
