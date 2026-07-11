#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
MONOCYPHER_ROOT="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib/src/microsui_core"
CXX_BIN="${CXX:-c++}"
CC_BIN="${CC:-cc}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/encrypted-keystore-nvs.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/esp_err.h" <<'H'
#pragma once
using esp_err_t = int;
constexpr esp_err_t ESP_OK = 0;
constexpr esp_err_t ESP_FAIL = 1;
constexpr esp_err_t ESP_ERR_NVS_NOT_FOUND = 2;
constexpr esp_err_t ESP_ERR_NVS_INVALID_LENGTH = 3;
const char* esp_err_to_name(esp_err_t error);
H

cat >"${TMP_DIR}/esp_log.h" <<'H'
#pragma once
#define ESP_LOGW(tag, format, ...) ((void)(tag))
H

cat >"${TMP_DIR}/nvs.h" <<'H'
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
using nvs_handle_t = uint32_t;
enum nvs_open_mode_t { NVS_READONLY, NVS_READWRITE };
esp_err_t nvs_open(const char* name, nvs_open_mode_t mode, nvs_handle_t* handle);
void nvs_close(nvs_handle_t handle);
esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* output, size_t* length);
esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length);
esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key);
esp_err_t nvs_commit(nvs_handle_t handle);
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <assert.h>
#include <string.h>

#include <map>
#include <string>
#include <vector>

#include "keystore/encrypted_keystore_nvs.h"
#include "nvs.h"

namespace {

std::map<std::string, std::vector<uint8_t>> g_committed;
std::map<std::string, std::vector<uint8_t>> g_pending;
bool g_namespace_exists = false;
bool g_write_open = false;
bool g_fail_set = false;
bool g_fail_commit = false;
bool g_fail_erase = false;
int g_close_count = 0;

void reset()
{
    g_committed.clear();
    g_pending.clear();
    g_namespace_exists = false;
    g_write_open = false;
    g_fail_set = false;
    g_fail_commit = false;
    g_fail_erase = false;
    g_close_count = 0;
}

}  // namespace

const char* esp_err_to_name(esp_err_t)
{
    return "test error";
}

esp_err_t nvs_open(const char* name, nvs_open_mode_t mode, nvs_handle_t* handle)
{
    if (name == nullptr || handle == nullptr || strcmp(name, "keystore") != 0) {
        return ESP_FAIL;
    }
    if (!g_namespace_exists && mode == NVS_READONLY) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (mode == NVS_READWRITE) {
        g_namespace_exists = true;
        g_pending = g_committed;
        g_write_open = true;
    }
    *handle = 0;
    return ESP_OK;
}

void nvs_close(nvs_handle_t)
{
    ++g_close_count;
    g_write_open = false;
    g_pending.clear();
}

esp_err_t nvs_get_blob(nvs_handle_t, const char* key, void* output, size_t* length)
{
    if (key == nullptr || length == nullptr) {
        return ESP_FAIL;
    }
    const auto found = g_committed.find(key);
    if (found == g_committed.end()) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (output == nullptr) {
        *length = found->second.size();
        return ESP_OK;
    }
    if (*length < found->second.size()) {
        *length = found->second.size();
        return ESP_ERR_NVS_INVALID_LENGTH;
    }
    memcpy(output, found->second.data(), found->second.size());
    *length = found->second.size();
    return ESP_OK;
}

esp_err_t nvs_set_blob(
    nvs_handle_t,
    const char* key,
    const void* value,
    size_t length)
{
    if (!g_write_open || g_fail_set || key == nullptr || value == nullptr ||
        length == 0) {
        return ESP_FAIL;
    }
    const auto* bytes = static_cast<const uint8_t*>(value);
    g_pending[key] = std::vector<uint8_t>(bytes, bytes + length);
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t, const char* key)
{
    if (!g_write_open || g_fail_erase || key == nullptr) {
        return ESP_FAIL;
    }
    const auto found = g_pending.find(key);
    if (found == g_pending.end()) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    g_pending.erase(found);
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t)
{
    if (!g_write_open || g_fail_commit) {
        return ESP_FAIL;
    }
    g_committed = g_pending;
    return ESP_OK;
}

int main()
{
    reset();
    const signing::EncryptedKeystoreNvsConfig config{"keystore", "test"};
    const signing::KeystoreStorageOps storage =
        signing::encrypted_keystore_nvs_storage_ops(&config);

    uint8_t output[8] = {};
    size_t output_size = 99;
    assert(storage.read_blob(
               "keyslot", output, sizeof(output), &output_size, storage.context) ==
           signing::KeystoreBlobReadStatus::missing);
    assert(output_size == 0);

    const uint8_t value[] = {1, 2, 3, 4};
    assert(storage.write_blob(
        "keyslot", value, sizeof(value), storage.context));
    assert(g_close_count == 1);  // Handle value zero is still a valid opened handle.
    assert(storage.read_blob(
               "keyslot", output, sizeof(output), &output_size, storage.context) ==
           signing::KeystoreBlobReadStatus::found);
    assert(output_size == sizeof(value));
    assert(memcmp(output, value, sizeof(value)) == 0);
    assert(g_close_count == 2);

    uint8_t short_output[2] = {};
    assert(storage.read_blob(
               "keyslot", short_output, sizeof(short_output), &output_size,
               storage.context) == signing::KeystoreBlobReadStatus::error);
    assert(g_close_count == 3);

    g_fail_commit = true;
    const uint8_t replacement[] = {5, 6, 7, 8};
    assert(!storage.write_blob(
        "keyslot", replacement, sizeof(replacement), storage.context));
    g_fail_commit = false;
    assert(g_committed.at("keyslot") ==
           std::vector<uint8_t>(value, value + sizeof(value)));

    g_fail_set = true;
    assert(!storage.write_blob(
        "keyslot", replacement, sizeof(replacement), storage.context));
    g_fail_set = false;

    assert(storage.erase_blob("keyslot", storage.context));
    assert(g_committed.empty());
    assert(storage.erase_blob("keyslot", storage.context));

    g_committed["keyslot"] = std::vector<uint8_t>(value, value + sizeof(value));
    g_fail_erase = true;
    assert(!storage.erase_blob("keyslot", storage.context));

    const signing::EncryptedKeystoreNvsConfig long_namespace{
        "namespace_is_too_long", "test"};
    const auto invalid_storage =
        signing::encrypted_keystore_nvs_storage_ops(&long_namespace);
    assert(!invalid_storage.write_blob(
        "keyslot", value, sizeof(value), invalid_storage.context));
    assert(!storage.write_blob(
        "storage_key_is_too_long", value, sizeof(value), storage.context));
    return 0;
}
CPP

"${CC_BIN}" -std=c11 -Wall -Wextra -Werror \
  -I"${MONOCYPHER_ROOT}" \
  -c "${MONOCYPHER_ROOT}/lib/monocypher/monocypher.c" \
  -o "${TMP_DIR}/monocypher.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${MONOCYPHER_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_ROOT}/keystore/encrypted_keystore.cpp" \
  "${COMMON_ROOT}/keystore/encrypted_keystore_nvs.cpp" \
  "${TMP_DIR}/monocypher.o" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
