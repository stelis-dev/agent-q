#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_local_auth.sh

Compiles the StackChan CoreS3 local PIN verifier store against host NVS/RNG
stubs and the pinned MicroSui Monocypher source. This test uses only a host
C/C++ compiler and does NOT require ESP-IDF. Set AGENT_Q_SIGNING_CRYPTO_ROOT to
override the signing source location; otherwise the pinned .firmware-cache
checkout from build.sh is used.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DEFAULT_SIGNING_DIR="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib"
SIGNING_ROOT="${AGENT_Q_SIGNING_CRYPTO_ROOT:-${DEFAULT_SIGNING_DIR}}"
SIGNING_CORE="${SIGNING_ROOT}/src/microsui_core"
AGENT_Q_DIR="${REPO_ROOT}/products/firmware/src/stackchan-cores3/agent_q"

for required in \
  "${SIGNING_CORE}/lib/monocypher/monocypher.c" \
  "${AGENT_Q_DIR}/agent_q_local_auth.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_auth.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run tools/firmware/stackchan-cores3/build.sh first, or set AGENT_Q_SIGNING_CRYPTO_ROOT." >&2
    exit 1
  fi
done

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-local-auth.XXXXXX")"
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

cat >"${TMP_DIR}/stubs/agent_q_bip39.cpp" <<'CPP'
#include <stddef.h>
#include <stdint.h>

namespace agent_q {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

}  // namespace agent_q
CPP

cat >"${TMP_DIR}/stubs/agent_q_entropy.cpp" <<'CPP'
#include <stddef.h>
#include <stdint.h>

namespace {

bool g_rng_fails = false;
uint8_t g_rng_counter = 1;

}  // namespace

namespace agent_q {

bool init_secure_random_from_early_boot_entropy()
{
    return true;
}

bool secure_random_ready()
{
    return !g_rng_fails;
}

bool fill_secure_random(void* output, size_t size)
{
    if (g_rng_fails || output == nullptr) {
        return false;
    }
    uint8_t* bytes = static_cast<uint8_t*>(output);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = static_cast<uint8_t>(g_rng_counter + index);
    }
    g_rng_counter = static_cast<uint8_t>(g_rng_counter + 17);
    return true;
}

void test_set_rng_fails(bool value)
{
    g_rng_fails = value;
}

}  // namespace agent_q
CPP

cat >"${TMP_DIR}/local_auth_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <vector>

#include "agent_q_local_auth.h"
#include "esp_err.h"
#include "nvs.h"

namespace agent_q {
void test_set_rng_fails(bool value);
}

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
    bool verified = true;

    expect(agent_q::kLocalPinDigits == 6, "PIN is exactly six digits");
    expect(agent_q::is_valid_local_pin("000000"), "valid all-zero PIN shape");
    expect(agent_q::is_valid_local_pin("123456"), "valid numeric PIN shape");
    expect(!agent_q::is_valid_local_pin("12345"), "short PIN rejected");
    expect(!agent_q::is_valid_local_pin("1234567"), "long PIN rejected");
    expect(!agent_q::is_valid_local_pin("12345a"), "non-digit PIN rejected");
    expect(!agent_q::is_valid_local_pin(nullptr), "null PIN rejected");

    expect(agent_q::local_auth_status() == agent_q::AgentQLocalAuthStatus::missing, "missing local auth status");
    expect(!agent_q::verify_local_pin("123456", &verified), "missing local auth verify fails");
    expect(!verified, "missing local auth leaves verified false");

    expect(agent_q::store_local_pin_verifier("123456"), "store local PIN verifier");
    expect(agent_q::local_auth_status() == agent_q::AgentQLocalAuthStatus::active, "stored local auth active");
    verified = false;
    expect(agent_q::verify_local_pin("123456", &verified), "verify correct PIN call succeeds");
    expect(verified, "correct PIN verifies");
    verified = true;
    expect(agent_q::verify_local_pin("654321", &verified), "verify wrong PIN call succeeds");
    expect(!verified, "wrong PIN does not verify");

    std::vector<uint8_t> original_blob = g_blob;
    expect(agent_q::store_local_pin_verifier("123456"), "store same PIN with fresh salt");
    expect(g_blob != original_blob, "fresh salt changes stored verifier record");
    verified = false;
    expect(agent_q::verify_local_pin("123456", &verified) && verified, "fresh-salt record verifies");

    expect(agent_q::wipe_local_auth(), "wipe local auth");
    expect(g_blob.empty(), "local auth blob wiped");
    expect(agent_q::local_auth_status() == agent_q::AgentQLocalAuthStatus::missing, "wiped local auth missing");

    expect(agent_q::store_local_pin_verifier("222222"), "restore local auth");
    g_blob[0] = 0;
    expect(agent_q::local_auth_status() == agent_q::AgentQLocalAuthStatus::invalid, "corrupt local auth invalid");
    verified = true;
    expect(!agent_q::verify_local_pin("222222", &verified), "corrupt local auth verify fails closed");
    expect(!verified, "corrupt local auth leaves verified false");

    expect(agent_q::store_local_pin_verifier("333333"), "restore local auth again");
    g_blob.push_back(0);
    expect(agent_q::local_auth_status() == agent_q::AgentQLocalAuthStatus::invalid, "oversized local auth invalid");

    g_blob.clear();
    g_commit_fails = true;
    expect(!agent_q::store_local_pin_verifier("444444"), "commit failure fails closed");
    expect(g_blob.empty(), "commit failure wipes partial local auth");
    expect(agent_q::local_auth_status() == agent_q::AgentQLocalAuthStatus::missing, "commit failure status missing");
    g_commit_fails = false;

    agent_q::test_set_rng_fails(true);
    expect(!agent_q::store_local_pin_verifier("555555"), "RNG failure refuses storage");
    expect(g_blob.empty(), "RNG failure leaves no local auth");
    agent_q::test_set_rng_fails(false);

    g_open_fails = true;
    expect(agent_q::local_auth_status() == agent_q::AgentQLocalAuthStatus::storage_error, "storage error status");
    g_open_fails = false;

    if (failures != 0) {
        fprintf(stderr, "Local auth tests failed: %d\n", failures);
        return 1;
    }
    printf("Local auth tests passed\n");
    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${SIGNING_CORE}" \
  -c "${SIGNING_CORE}/lib/monocypher/monocypher.c" -o "${TMP_DIR}/monocypher.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${SIGNING_CORE}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/local_auth_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_auth.cpp" \
  "${TMP_DIR}/stubs/agent_q_bip39.cpp" \
  "${TMP_DIR}/stubs/agent_q_entropy.cpp" \
  "${TMP_DIR}/monocypher.o" \
  -o "${TMP_DIR}/local_auth_test"

"${TMP_DIR}/local_auth_test"
