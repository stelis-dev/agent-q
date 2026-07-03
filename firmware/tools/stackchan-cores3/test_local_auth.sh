#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_local_auth.sh

Compiles the StackChan CoreS3 local PIN verifier store against host NVS/RNG
stubs and the pinned MicroSui Monocypher source. This test uses only a host
C/C++ compiler and does NOT require ESP-IDF. Set SIGNING_CRYPTO_ROOT to
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
DEFAULT_RUNTIME_DIR="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib"
CRYPTO_ROOT="${SIGNING_CRYPTO_ROOT:-${DEFAULT_RUNTIME_DIR}}"
MICROSUI_CORE="${CRYPTO_ROOT}/src/microsui_core"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"

for required in \
  "${MICROSUI_CORE}/lib/monocypher/monocypher.c" \
  "${RUNTIME_DIR}/local_auth.cpp" \
  "${RUNTIME_DIR}/local_auth.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first, or set SIGNING_CRYPTO_ROOT." >&2
    exit 1
  fi
done

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-local-auth.XXXXXX")"
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

cat >"${TMP_DIR}/stubs/bip39.cpp" <<'CPP'
#include <stddef.h>
#include <stdint.h>

namespace signing {

size_t g_test_wipe_calls = 0;
size_t g_test_last_wipe_size = 0;

void wipe_sensitive_buffer(void* data, size_t size)
{
    ++g_test_wipe_calls;
    g_test_last_wipe_size = size;
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

}  // namespace signing
CPP

cat >"${TMP_DIR}/stubs/entropy.cpp" <<'CPP'
#include <stddef.h>
#include <stdint.h>

namespace {

bool g_rng_fails = false;
uint8_t g_rng_counter = 1;

}  // namespace

namespace signing {

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

}  // namespace signing
CPP

cat >"${TMP_DIR}/local_auth_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <vector>

#include "local_auth_test.h"
#include "esp_err.h"
#include "nvs.h"

namespace signing {
void test_set_rng_fails(bool value);
extern size_t g_test_wipe_calls;
extern size_t g_test_last_wipe_size;
}

namespace {

std::vector<uint8_t> g_blob;
std::vector<uint8_t> g_pending_blob;
bool g_pending_set = false;
bool g_pending_erase = false;
bool g_open_fails = false;
bool g_commit_fails = false;
bool g_set_fails_after_write = false;
bool g_set_fails_with_corrupt_write = false;
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
    g_pending_blob.clear();
    g_pending_set = false;
    g_pending_erase = false;
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
    if (g_set_fails_with_corrupt_write) {
        g_blob.assign(length, 0);
        return 1;
    }
    if (g_set_fails_after_write) {
        g_blob.assign(bytes, bytes + length);
        return 1;
    }
    g_pending_blob.assign(bytes, bytes + length);
    g_pending_set = true;
    g_pending_erase = false;
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key)
{
    (void)handle;
    (void)key;
    if (g_blob.empty()) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    g_pending_blob.clear();
    g_pending_set = false;
    g_pending_erase = true;
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t handle)
{
    (void)handle;
    if (g_commit_fails) {
        return 1;
    }
    if (g_pending_erase) {
        g_blob.clear();
    } else if (g_pending_set) {
        g_blob = g_pending_blob;
    }
    g_pending_blob.clear();
    g_pending_set = false;
    g_pending_erase = false;
    return ESP_OK;
}

}  // extern "C"

int main()
{
    bool verified = true;

    expect(signing::kLocalPinDigits == 6, "PIN is exactly six digits");
    expect(signing::is_valid_local_pin("000000"), "valid all-zero PIN shape");
    expect(signing::is_valid_local_pin("123456"), "valid numeric PIN shape");
    expect(!signing::is_valid_local_pin("12345"), "short PIN rejected");
    expect(!signing::is_valid_local_pin("1234567"), "long PIN rejected");
    expect(!signing::is_valid_local_pin("12345a"), "non-digit PIN rejected");
    expect(!signing::is_valid_local_pin(nullptr), "null PIN rejected");

    expect(signing::local_auth_status() == signing::LocalAuthStatus::missing, "missing local auth status");
    expect(!signing::verify_local_pin("123456", &verified), "missing local auth verify fails");
    expect(!verified, "missing local auth leaves verified false");

    expect(signing::store_local_pin_verifier("123456"), "store local PIN verifier");
    signing::g_test_wipe_calls = 0;
    signing::g_test_last_wipe_size = 0;
    expect(signing::local_auth_status() == signing::LocalAuthStatus::active, "stored local auth active");
    expect(signing::g_test_wipe_calls > 0, "status check wipes local auth record copy");
    expect(signing::g_test_last_wipe_size == signing::kLocalAuthPreparedRecordBytes,
           "status check wipes full local auth record copy");
    expect(g_blob.size() > 4 && g_blob[4] == 0, "local auth current format marker is zero");
    {
        const std::vector<uint8_t> current_auth_blob = g_blob;
        g_blob[4] = 1;
        expect(signing::local_auth_status() == signing::LocalAuthStatus::invalid,
               "nonzero local auth format marker fails closed");
        g_blob = current_auth_blob;
        expect(signing::local_auth_status() == signing::LocalAuthStatus::active,
               "restored current local auth format marker is active");
    }
    verified = false;
    expect(signing::verify_local_pin("123456", &verified), "verify correct PIN call succeeds");
    expect(verified, "correct PIN verifies");
    verified = true;
    expect(signing::verify_local_pin("654321", &verified), "verify wrong PIN call succeeds");
    expect(!verified, "wrong PIN does not verify");

    std::vector<uint8_t> original_blob = g_blob;
    expect(signing::store_local_pin_verifier("123456"), "store same PIN with fresh salt");
    expect(g_blob != original_blob, "fresh salt changes stored verifier record");
    verified = false;
    expect(signing::verify_local_pin("123456", &verified) && verified, "fresh-salt record verifies");

    expect(signing::clear_local_auth(), "wipe local auth");
    expect(g_blob.empty(), "local auth blob wiped");
    expect(signing::local_auth_status() == signing::LocalAuthStatus::missing, "wiped local auth missing");

    expect(signing::store_local_pin_verifier("222222"), "restore local auth");
    g_blob[0] = 0;
    expect(signing::local_auth_status() == signing::LocalAuthStatus::invalid, "corrupt local auth invalid");
    verified = true;
    expect(!signing::verify_local_pin("222222", &verified), "corrupt local auth verify fails closed");
    expect(!verified, "corrupt local auth leaves verified false");

    expect(signing::store_local_pin_verifier("333333"), "restore local auth again");
    g_blob.push_back(0);
    expect(signing::local_auth_status() == signing::LocalAuthStatus::invalid, "oversized local auth invalid");

    g_blob.clear();
    g_commit_fails = true;
    expect(!signing::store_local_pin_verifier("444444"), "commit failure fails closed");
    expect(g_blob.empty(), "commit failure leaves no local auth when none existed");
    expect(signing::local_auth_status() == signing::LocalAuthStatus::missing, "commit failure status missing");
    g_commit_fails = false;

    expect(signing::store_local_pin_verifier("666666"), "restore local auth before failed replacement");
    const std::vector<uint8_t> previous_blob = g_blob;
    g_commit_fails = true;
    expect(!signing::store_local_pin_verifier("777777"), "failed replacement refuses storage");
    expect(g_blob == previous_blob, "failed replacement preserves previous verifier record");
    verified = false;
    expect(signing::verify_local_pin("666666", &verified) && verified, "old PIN still verifies after failed replacement");
    verified = true;
    expect(signing::verify_local_pin("777777", &verified), "new PIN verify call succeeds after failed replacement");
    expect(!verified, "new PIN does not verify after failed replacement");
    g_commit_fails = false;

    expect(signing::store_local_pin_verifier("101010"), "restore local auth before set failure with replacement");
    g_set_fails_after_write = true;
    expect(signing::store_local_pin_verifier("202020"), "set failure with active replacement is treated as success");
    verified = false;
    expect(signing::verify_local_pin("202020", &verified) && verified, "replacement PIN verifies after set failure");
    verified = true;
    expect(signing::verify_local_pin("101010", &verified), "old PIN verify call succeeds after set failure replacement");
    expect(!verified, "old PIN no longer verifies after set failure replacement");
    g_set_fails_after_write = false;

    expect(signing::store_local_pin_verifier("303030"), "restore local auth before corrupt set failure");
    g_set_fails_with_corrupt_write = true;
    expect(!signing::store_local_pin_verifier("404040"), "corrupt set failure refuses storage");
    expect(signing::local_auth_status() == signing::LocalAuthStatus::missing,
           "corrupt set failure wipes ambiguous verifier state");
    g_set_fails_with_corrupt_write = false;

    expect(signing::clear_local_auth(), "wipe local auth before empty RNG failure");
    signing::test_set_rng_fails(true);
    expect(!signing::store_local_pin_verifier("555555"), "RNG failure refuses empty storage");
    expect(g_blob.empty(), "RNG failure leaves no local auth when none existed");
    signing::test_set_rng_fails(false);

    expect(signing::store_local_pin_verifier("888888"), "restore local auth before RNG replacement failure");
    const std::vector<uint8_t> rng_previous_blob = g_blob;
    signing::test_set_rng_fails(true);
    expect(!signing::store_local_pin_verifier("999999"), "RNG replacement failure refuses storage");
    expect(g_blob == rng_previous_blob, "RNG replacement failure preserves previous verifier record");
    signing::test_set_rng_fails(false);

    g_open_fails = true;
    expect(signing::local_auth_status() == signing::LocalAuthStatus::storage_error, "storage error status");
    g_open_fails = false;

    if (failures != 0) {
        fprintf(stderr, "Local auth tests failed: %d\n", failures);
        return 1;
    }
    printf("Local auth tests passed\n");
    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${MICROSUI_CORE}" \
  -c "${MICROSUI_CORE}/lib/monocypher/monocypher.c" -o "${TMP_DIR}/monocypher.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${MICROSUI_CORE}" \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/local_auth_test.cpp" \
  "${RUNTIME_DIR}/local_auth.cpp" \
  "${TMP_DIR}/stubs/bip39.cpp" \
  "${TMP_DIR}/stubs/entropy.cpp" \
  "${TMP_DIR}/monocypher.o" \
  -o "${TMP_DIR}/local_auth_test"

"${TMP_DIR}/local_auth_test"
