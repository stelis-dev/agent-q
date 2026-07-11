#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/local-transport-nvs-identity.XXXXXX")"
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

#include "nvs.h"
#include "transport/local_transport_nvs_identity_storage.h"

namespace {

constexpr const char* kNamespace = "pairing_id";
constexpr const char* kPrivateKey = "static_priv";
constexpr const char* kPublicKey = "static_pub";

struct Blob {
    bool exists = false;
    uint8_t bytes[signing::kLocalTransportStaticKeyBytes] = {};
};

bool g_namespace_exists = false;
bool g_pending_active = false;
Blob g_committed_private;
Blob g_committed_public;
Blob g_pending_private;
Blob g_pending_public;
bool g_fail_public_write = false;
bool g_fail_private_erase = false;
bool g_fail_public_erase = false;
int g_fail_commit_count = 0;
int g_private_size_queries = 0;
int g_private_value_reads = 0;

bool all_zero(const uint8_t* bytes, size_t size)
{
    for (size_t index = 0; index < size; ++index) {
        if (bytes[index] != 0) {
            return false;
        }
    }
    return true;
}

void reset_store()
{
    g_namespace_exists = false;
    g_pending_active = false;
    g_committed_private = {};
    g_committed_public = {};
    g_pending_private = {};
    g_pending_public = {};
    g_fail_public_write = false;
    g_fail_private_erase = false;
    g_fail_public_erase = false;
    g_fail_commit_count = 0;
    g_private_size_queries = 0;
    g_private_value_reads = 0;
}

void install_pair(uint8_t secret_byte, uint8_t public_byte)
{
    g_namespace_exists = true;
    g_committed_private.exists = true;
    g_committed_public.exists = true;
    memset(g_committed_private.bytes, secret_byte, sizeof(g_committed_private.bytes));
    memset(g_committed_public.bytes, public_byte, sizeof(g_committed_public.bytes));
}

const Blob* committed_blob(const char* key)
{
    if (strcmp(key, kPrivateKey) == 0) {
        return &g_committed_private;
    }
    if (strcmp(key, kPublicKey) == 0) {
        return &g_committed_public;
    }
    return nullptr;
}

Blob* pending_blob(const char* key)
{
    if (strcmp(key, kPrivateKey) == 0) {
        return &g_pending_private;
    }
    if (strcmp(key, kPublicKey) == 0) {
        return &g_pending_public;
    }
    return nullptr;
}

}  // namespace

const char* esp_err_to_name(esp_err_t)
{
    return "test error";
}

esp_err_t nvs_open(const char* name, nvs_open_mode_t mode, nvs_handle_t* handle)
{
    if (name == nullptr || handle == nullptr || strcmp(name, kNamespace) != 0) {
        return ESP_FAIL;
    }
    if (!g_namespace_exists && mode == NVS_READONLY) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (mode == NVS_READWRITE) {
        g_namespace_exists = true;
        g_pending_private = g_committed_private;
        g_pending_public = g_committed_public;
        g_pending_active = true;
    }
    *handle = 1;
    return ESP_OK;
}

void nvs_close(nvs_handle_t)
{
    g_pending_active = false;
    g_pending_private = {};
    g_pending_public = {};
}

esp_err_t nvs_get_blob(nvs_handle_t, const char* key, void* output, size_t* length)
{
    if (key == nullptr || length == nullptr) {
        return ESP_FAIL;
    }
    const Blob* blob = committed_blob(key);
    if (blob == nullptr || !blob->exists) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (strcmp(key, kPrivateKey) == 0) {
        if (output == nullptr) {
            ++g_private_size_queries;
        } else {
            ++g_private_value_reads;
        }
    }
    if (output == nullptr) {
        *length = signing::kLocalTransportStaticKeyBytes;
        return ESP_OK;
    }
    if (*length < signing::kLocalTransportStaticKeyBytes) {
        *length = signing::kLocalTransportStaticKeyBytes;
        return ESP_ERR_NVS_INVALID_LENGTH;
    }
    memcpy(output, blob->bytes, sizeof(blob->bytes));
    *length = sizeof(blob->bytes);
    return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t, const char* key, const void* value, size_t length)
{
    if (!g_pending_active || key == nullptr || value == nullptr ||
        length != signing::kLocalTransportStaticKeyBytes) {
        return ESP_FAIL;
    }
    if (strcmp(key, kPublicKey) == 0 && g_fail_public_write) {
        return ESP_FAIL;
    }
    Blob* blob = pending_blob(key);
    if (blob == nullptr) {
        return ESP_FAIL;
    }
    blob->exists = true;
    memcpy(blob->bytes, value, sizeof(blob->bytes));
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t, const char* key)
{
    if (!g_pending_active || key == nullptr) {
        return ESP_FAIL;
    }
    if ((strcmp(key, kPrivateKey) == 0 && g_fail_private_erase) ||
        (strcmp(key, kPublicKey) == 0 && g_fail_public_erase)) {
        return ESP_FAIL;
    }
    Blob* blob = pending_blob(key);
    if (blob == nullptr) {
        return ESP_FAIL;
    }
    if (!blob->exists) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    *blob = {};
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t)
{
    if (!g_pending_active) {
        return ESP_FAIL;
    }
    if (g_fail_commit_count > 0) {
        --g_fail_commit_count;
        return ESP_FAIL;
    }
    g_committed_private = g_pending_private;
    g_committed_public = g_pending_public;
    return ESP_OK;
}

int main()
{
    static const signing::LocalTransportNvsIdentityStorageConfig config{
        kNamespace,
        kPrivateKey,
        kPublicKey,
        "NvsIdentityTest",
    };
    const signing::LocalTransportIdentityStorageOps ops =
        signing::local_transport_nvs_identity_storage_ops(&config);

    uint8_t secret[signing::kLocalTransportStaticKeyBytes];
    uint8_t public_key[signing::kLocalTransportStaticKeyBytes];
    uint8_t expected_secret[signing::kLocalTransportStaticKeyBytes];
    uint8_t expected_public[signing::kLocalTransportStaticKeyBytes];
    memset(expected_secret, 0x11, sizeof(expected_secret));
    memset(expected_public, 0x22, sizeof(expected_public));

    reset_store();
    memset(public_key, 0xa5, sizeof(public_key));
    assert(ops.read_public_key(public_key, ops.context) ==
           signing::LocalTransportIdentityRecordReadStatus::missing);
    assert(all_zero(public_key, sizeof(public_key)));
    assert(g_private_value_reads == 0);
    memset(secret, 0xa5, sizeof(secret));
    memset(public_key, 0xa5, sizeof(public_key));
    assert(ops.read_key_pair(secret, public_key, ops.context) ==
           signing::LocalTransportIdentityRecordReadStatus::missing);
    assert(all_zero(secret, sizeof(secret)) && all_zero(public_key, sizeof(public_key)));

    assert(ops.write_key_pair(expected_secret, expected_public, ops.context));
    memset(public_key, 0xa5, sizeof(public_key));
    assert(ops.read_public_key(public_key, ops.context) ==
           signing::LocalTransportIdentityRecordReadStatus::found);
    assert(memcmp(public_key, expected_public, sizeof(public_key)) == 0);
    assert(g_private_size_queries == 1 && g_private_value_reads == 0);
    assert(ops.read_key_pair(secret, public_key, ops.context) ==
           signing::LocalTransportIdentityRecordReadStatus::found);
    assert(memcmp(secret, expected_secret, sizeof(secret)) == 0);
    assert(memcmp(public_key, expected_public, sizeof(public_key)) == 0);
    assert(g_private_value_reads == 1);

    g_committed_public = {};
    memset(public_key, 0xa5, sizeof(public_key));
    assert(ops.read_public_key(public_key, ops.context) ==
           signing::LocalTransportIdentityRecordReadStatus::error);
    assert(all_zero(public_key, sizeof(public_key)));
    memset(secret, 0xa5, sizeof(secret));
    memset(public_key, 0xa5, sizeof(public_key));
    assert(ops.read_key_pair(secret, public_key, ops.context) ==
           signing::LocalTransportIdentityRecordReadStatus::error);
    assert(all_zero(secret, sizeof(secret)) && all_zero(public_key, sizeof(public_key)));

    reset_store();
    g_namespace_exists = true;
    g_committed_public.exists = true;
    memset(g_committed_public.bytes, 0x22, sizeof(g_committed_public.bytes));
    memset(public_key, 0xa5, sizeof(public_key));
    assert(ops.read_public_key(public_key, ops.context) ==
           signing::LocalTransportIdentityRecordReadStatus::error);
    assert(all_zero(public_key, sizeof(public_key)));

    reset_store();
    g_fail_public_write = true;
    assert(!ops.write_key_pair(expected_secret, expected_public, ops.context));
    assert(!g_committed_private.exists && !g_committed_public.exists);

    reset_store();
    install_pair(0x31, 0x32);
    g_fail_commit_count = 1;
    assert(!ops.write_key_pair(expected_secret, expected_public, ops.context));
    assert(!g_committed_private.exists && !g_committed_public.exists);

    reset_store();
    install_pair(0x41, 0x42);
    assert(ops.erase_key_pair(ops.context));
    assert(!g_committed_private.exists && !g_committed_public.exists);
    assert(ops.erase_key_pair(ops.context));

    reset_store();
    install_pair(0x51, 0x52);
    g_fail_private_erase = true;
    assert(!ops.erase_key_pair(ops.context));
    assert(g_committed_private.exists && !g_committed_public.exists);

    reset_store();
    install_pair(0x61, 0x62);
    g_fail_public_erase = true;
    assert(!ops.erase_key_pair(ops.context));
    assert(!g_committed_private.exists && g_committed_public.exists);

    reset_store();
    install_pair(0x71, 0x72);
    g_fail_commit_count = 1;
    assert(!ops.erase_key_pair(ops.context));
    assert(g_committed_private.exists && !g_committed_public.exists);

    signing::LocalTransportNvsIdentityStorageConfig invalid = config;
    invalid.namespace_name = "namespace_too_long";
    const signing::LocalTransportIdentityStorageOps invalid_ops =
        signing::local_transport_nvs_identity_storage_ops(&invalid);
    memset(public_key, 0xa5, sizeof(public_key));
    assert(invalid_ops.read_public_key(public_key, invalid_ops.context) ==
           signing::LocalTransportIdentityRecordReadStatus::error);
    assert(all_zero(public_key, sizeof(public_key)));
    assert(!invalid_ops.write_key_pair(expected_secret, expected_public, invalid_ops.context));
    assert(!invalid_ops.erase_key_pair(invalid_ops.context));

    signing::LocalTransportNvsIdentityStorageConfig aliased = config;
    aliased.public_key_name = kPrivateKey;
    const signing::LocalTransportIdentityStorageOps aliased_ops =
        signing::local_transport_nvs_identity_storage_ops(&aliased);
    memset(secret, 0xa5, sizeof(secret));
    memset(public_key, 0xa5, sizeof(public_key));
    assert(aliased_ops.read_key_pair(secret, public_key, aliased_ops.context) ==
           signing::LocalTransportIdentityRecordReadStatus::error);
    assert(all_zero(secret, sizeof(secret)) && all_zero(public_key, sizeof(public_key)));
    assert(!aliased_ops.write_key_pair(expected_secret, expected_public, aliased_ops.context));
    assert(!aliased_ops.erase_key_pair(aliased_ops.context));
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${COMMON_ROOT}" \
  "${COMMON_ROOT}/transport/local_transport_crypto.cpp" \
  "${COMMON_ROOT}/transport/local_transport_nvs_identity_storage.cpp" \
  "${TMP_DIR}/test.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
echo "Local transport NVS identity storage tests passed"
