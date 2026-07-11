#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_stackchan_keystore.sh

Compiles the StackChan encrypted-keystore adapter against host NVS and RNG
stubs plus the pinned Monocypher source. It verifies the target KDF profile,
mandatory-record unlock gate, callback-scoped secret access, PIN rewrap,
record authentication, fail-closed relock, and complete erase. This test uses
only a host compiler and does not require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
MONOCYPHER_ROOT="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib/src/microsui_core"
CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

for required in \
  "${COMMON_ROOT}/keystore/encrypted_keystore.cpp" \
  "${COMMON_ROOT}/keystore/encrypted_keystore_nvs.cpp" \
  "${RUNTIME_DIR}/stackchan_keystore.cpp" \
  "${MONOCYPHER_ROOT}/lib/monocypher/monocypher.c"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stackchan-keystore.XXXXXX")"
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

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <map>
#include <string>
#include <vector>

#include "stackchan_keystore.h"
#include "esp_err.h"
#include "nvs.h"

namespace {

std::map<std::string, std::vector<uint8_t>> g_blobs;
std::map<std::string, std::vector<uint8_t>> g_pending_writes;
std::vector<std::string> g_pending_erases;
std::string g_last_namespace;
uint8_t g_random_counter = 1;
bool g_fail_next_commit_before_apply = false;
int failures = 0;

struct Capture {
    std::vector<uint8_t> bytes;
    int calls = 0;
};

struct KeyPairCapture {
    uint8_t secret[signing::kLocalTransportStaticKeyBytes] = {};
    uint8_t public_key[signing::kLocalTransportStaticKeyBytes] = {};
    int calls = 0;
};

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

bool contains_sequence(
    const std::vector<uint8_t>& bytes,
    const uint8_t* needle,
    size_t needle_size)
{
    if (needle == nullptr || needle_size == 0 || needle_size > bytes.size()) {
        return false;
    }
    for (size_t offset = 0; offset + needle_size <= bytes.size(); ++offset) {
        if (memcmp(bytes.data() + offset, needle, needle_size) == 0) {
            return true;
        }
    }
    return false;
}

bool capture_record(const uint8_t* plaintext, size_t plaintext_size, void* context)
{
    auto* capture = static_cast<Capture*>(context);
    if (capture == nullptr || plaintext == nullptr) {
        return false;
    }
    capture->bytes.assign(plaintext, plaintext + plaintext_size);
    ++capture->calls;
    return true;
}

bool capture_key_pair(
    const uint8_t* secret_key,
    const uint8_t* public_key,
    void* context)
{
    auto* capture = static_cast<KeyPairCapture*>(context);
    if (capture == nullptr || secret_key == nullptr || public_key == nullptr) {
        return false;
    }
    memcpy(capture->secret, secret_key, sizeof(capture->secret));
    memcpy(capture->public_key, public_key, sizeof(capture->public_key));
    ++capture->calls;
    return true;
}

void set_pin(char output[signing::kKeystorePinBufferBytes], const char* pin)
{
    memset(output, 0, signing::kKeystorePinBufferBytes);
    memcpy(output, pin, strlen(pin));
}

}  // namespace

namespace signing {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool fill_secure_random(void* output, size_t size)
{
    if (output == nullptr) {
        return false;
    }
    auto* bytes = static_cast<uint8_t*>(output);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = static_cast<uint8_t>(
            g_random_counter ^ static_cast<uint8_t>(index * 0x9du));
    }
    g_random_counter = static_cast<uint8_t>(g_random_counter + 37);
    return true;
}

}  // namespace signing

extern "C" {

esp_err_t nvs_open(const char* name, int open_mode, nvs_handle_t* out_handle)
{
    if (name == nullptr || out_handle == nullptr) {
        return 1;
    }
    g_last_namespace = name;
    if (open_mode == NVS_READONLY && g_blobs.empty()) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    *out_handle = 1;
    return ESP_OK;
}

void nvs_close(nvs_handle_t)
{
    g_pending_writes.clear();
    g_pending_erases.clear();
}

esp_err_t nvs_get_blob(nvs_handle_t, const char* key, void* output, size_t* size)
{
    if (key == nullptr || size == nullptr) {
        return 1;
    }
    const auto found = g_blobs.find(key);
    if (found == g_blobs.end()) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (output == nullptr) {
        *size = found->second.size();
        return ESP_OK;
    }
    if (*size < found->second.size()) {
        return 1;
    }
    memcpy(output, found->second.data(), found->second.size());
    *size = found->second.size();
    return ESP_OK;
}

esp_err_t nvs_set_blob(
    nvs_handle_t,
    const char* key,
    const void* value,
    size_t size)
{
    if (key == nullptr || value == nullptr || size == 0) {
        return 1;
    }
    const auto* bytes = static_cast<const uint8_t*>(value);
    g_pending_writes[key] = std::vector<uint8_t>(bytes, bytes + size);
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t, const char* key)
{
    if (key == nullptr || g_blobs.find(key) == g_blobs.end()) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    g_pending_erases.emplace_back(key);
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t)
{
    if (g_fail_next_commit_before_apply) {
        g_fail_next_commit_before_apply = false;
        return 1;
    }
    for (const std::string& key : g_pending_erases) {
        g_blobs.erase(key);
    }
    for (const auto& entry : g_pending_writes) {
        g_blobs[entry.first] = entry.second;
    }
    g_pending_erases.clear();
    g_pending_writes.clear();
    return ESP_OK;
}

}  // extern "C"

int main()
{
    using signing::KeystoreOperationStatus;
    using signing::KeystoreState;
    using signing::LocalTransportIdentityRecordReadStatus;
    using signing::StackChanKeystoreMaterialStatus;

    std::vector<uint8_t> work_area(signing::kStackChanKeystoreKdfWorkAreaBytes);
    char pin[signing::kKeystorePinBufferBytes] = {};

    expect(signing::kStackChanKeystoreKdfProfile.memory_kib == 512 &&
               signing::kStackChanKeystoreKdfProfile.passes == 6 &&
               signing::kStackChanKeystoreKdfProfile.lanes == 1,
           "StackChan uses its measured fixed KDF optimization profile");
    expect(signing::kLocalAuthMinDigits == 6 &&
               signing::kLocalAuthMaxDigits == 6,
           "StackChan fixes the target PIN policy to exactly six digits");
    expect(signing::stackchan_keystore_initialize() == KeystoreState::absent,
           "empty NVS initializes an absent keystore");

    set_pin(pin, "1234");
    expect(signing::stackchan_keystore_create(
               pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::invalid_input,
           "setup rejects a shorter PIN");
    memset(pin, '1', sizeof(pin));
    expect(signing::stackchan_keystore_create(
               pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::invalid_input,
           "setup rejects a PIN without a terminator inside the bounded buffer");
    expect(g_blobs.count("keyslot") == 0,
           "rejected PINs write no keyslot");

    set_pin(pin, "123456");
    expect(signing::stackchan_keystore_create(
               pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::success,
           "setup creates and opens the encrypted keyslot");
    expect(g_last_namespace == "signing", "target adapter uses the signing namespace");
    expect(g_blobs.count("keyslot") == 1, "keyslot is persisted");
    expect(!contains_sequence(
               g_blobs.at("keyslot"),
               reinterpret_cast<const uint8_t*>("123456"),
               signing::kLocalAuthMaxDigits),
           "persisted keyslot does not contain the PIN");
    expect(signing::stackchan_keystore_initialize() == KeystoreState::locked,
           "reboot locks an incomplete setup keyslot");
    set_pin(pin, "123456");
    expect(signing::stackchan_keystore_unlock(
               pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::missing,
           "unlock rejects a keyslot without the mandatory root record");
    expect(signing::stackchan_keystore_state() == KeystoreState::locked,
           "mandatory-record failure relocks and wipes the master key");
    expect(signing::stackchan_keystore_erase() == KeystoreOperationStatus::success,
           "incomplete setup can be erased");

    set_pin(pin, "123456");
    expect(signing::stackchan_keystore_create(
               pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::success,
           "setup recreates the encrypted keyslot");
    uint8_t root[signing::kStackChanRootMaterialBytes] = {};
    for (size_t index = 0; index < sizeof(root); ++index) {
        root[index] = static_cast<uint8_t>(0xa0 + index);
    }
    expect(signing::stackchan_keystore_replace_root(root) ==
               KeystoreOperationStatus::success,
           "setup stores the encrypted root record");
    expect(signing::stackchan_keystore_root_status() ==
               StackChanKeystoreMaterialStatus::active,
           "encrypted root is structurally active");
    expect(!contains_sequence(g_blobs.at("root"), root, sizeof(root)),
           "persisted root record contains no root plaintext");

    uint8_t identity_secret[signing::kLocalTransportStaticKeyBytes] = {};
    uint8_t identity_public[signing::kLocalTransportStaticKeyBytes] = {};
    uint8_t identity_plaintext[2 * signing::kLocalTransportStaticKeyBytes] = {};
    for (size_t index = 0; index < sizeof(identity_secret); ++index) {
        identity_secret[index] = static_cast<uint8_t>(0x30 + index);
        identity_public[index] = static_cast<uint8_t>(0x70 + index);
    }
    memcpy(identity_plaintext, identity_secret, sizeof(identity_secret));
    memcpy(
        identity_plaintext + sizeof(identity_secret),
        identity_public,
        sizeof(identity_public));
    const signing::LocalTransportIdentityStorageOps& identity_storage =
        signing::stackchan_transport_identity_storage_ops();
    expect(identity_storage.write_key_pair(
               identity_secret, identity_public, identity_storage.context),
           "first local-transport use stores an encrypted identity record");
    expect(!contains_sequence(
               g_blobs.at("transport_id"),
               identity_plaintext,
               sizeof(identity_plaintext)),
           "persisted transport identity contains no private-key plaintext");

    KeyPairCapture identity_capture;
    expect(identity_storage.with_key_pair(
               capture_key_pair,
               &identity_capture,
               identity_storage.context) ==
               LocalTransportIdentityRecordReadStatus::found &&
               identity_capture.calls == 1 &&
               memcmp(identity_capture.secret,
                      identity_secret,
                      sizeof(identity_secret)) == 0 &&
               memcmp(identity_capture.public_key,
                      identity_public,
                      sizeof(identity_public)) == 0,
           "transport identity is available only through the storage consumer");

    uint8_t replacement_secret[signing::kLocalTransportStaticKeyBytes] = {};
    uint8_t replacement_public[signing::kLocalTransportStaticKeyBytes] = {};
    memset(replacement_secret, 0x91, sizeof(replacement_secret));
    memset(replacement_public, 0xa2, sizeof(replacement_public));
    const std::vector<uint8_t> original_identity_ciphertext =
        g_blobs.at("transport_id");
    g_fail_next_commit_before_apply = true;
    expect(!identity_storage.write_key_pair(
               replacement_secret,
               replacement_public,
               identity_storage.context),
           "unchanged identity write is not reported as committed");
    expect(g_blobs.at("transport_id") == original_identity_ciphertext,
           "failed identity replacement preserves the prior encrypted record");

    Capture capture;
    expect(signing::stackchan_keystore_with_root(capture_record, &capture) ==
               KeystoreOperationStatus::success &&
               capture.calls == 1 && capture.bytes.size() == sizeof(root) &&
               memcmp(capture.bytes.data(), root, sizeof(root)) == 0,
           "unlocked root is exposed only through the scoped consumer");
    expect(signing::stackchan_keystore_initialize() == KeystoreState::locked,
           "reboot locks before access denial test");
    capture = {};
    expect(signing::stackchan_keystore_with_root(capture_record, &capture) ==
               KeystoreOperationStatus::locked && capture.calls == 0,
           "locked keystore never invokes a root consumer");

    set_pin(pin, "000000");
    expect(signing::stackchan_keystore_unlock(
               pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::wrong_pin,
           "wrong PIN cannot open the keyslot");
    set_pin(pin, "123456");
    expect(signing::stackchan_keystore_unlock(
               pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::success,
           "correct PIN opens and authenticates all current records");

    const std::vector<uint8_t> root_ciphertext = g_blobs.at("root");
    const std::vector<uint8_t> identity_ciphertext = g_blobs.at("transport_id");
    char new_pin[signing::kKeystorePinBufferBytes] = {};
    set_pin(pin, "123456");
    set_pin(new_pin, "654321");
    expect(signing::stackchan_keystore_rewrap(
               pin, new_pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::success,
           "PIN change atomically rewraps the unchanged master key");
    expect(g_blobs.at("root") == root_ciphertext &&
               g_blobs.at("transport_id") == identity_ciphertext,
           "PIN change does not rewrite protected records");
    expect(signing::stackchan_keystore_initialize() == KeystoreState::locked,
           "reboot locks the rewrapped keystore");
    set_pin(pin, "123456");
    expect(signing::stackchan_keystore_unlock(
               pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::wrong_pin,
           "old PIN is rejected after rewrap");
    set_pin(pin, "654321");
    expect(signing::stackchan_keystore_unlock(
               pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::success,
           "new PIN opens existing protected records");

    expect(signing::stackchan_keystore_initialize() == KeystoreState::locked,
           "reboot locks before corruption test");
    g_blobs["root"].back() ^= 0x80;
    set_pin(pin, "654321");
    expect(signing::stackchan_keystore_unlock(
               pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::invalid_record,
           "authenticated unlock rejects a corrupted root record");
    expect(signing::stackchan_keystore_state() == KeystoreState::invalid,
           "record-authentication failure enters invalid state and wipes the master key");
    expect(signing::stackchan_keystore_with_root(capture_record, &capture) ==
               KeystoreOperationStatus::locked,
           "record-authentication failure keeps secret access closed");

    expect(signing::stackchan_keystore_erase() == KeystoreOperationStatus::success,
           "Device reset erases the full encrypted keystore");
    expect(g_blobs.count("keyslot") == 0 && g_blobs.count("root") == 0 &&
               g_blobs.count("transport_id") == 0,
           "Device reset removes keyslot, root, and transport identity records");
    expect(signing::stackchan_keystore_state() == KeystoreState::absent,
           "Device reset returns the keystore to absent");

    if (failures != 0) {
        fprintf(stderr, "%d StackChan keystore test(s) failed\n", failures);
        return 1;
    }
    puts("StackChan keystore tests passed");
    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${MONOCYPHER_ROOT}" \
  -c "${MONOCYPHER_ROOT}/lib/monocypher/monocypher.c" \
  -o "${TMP_DIR}/monocypher.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${MONOCYPHER_ROOT}" \
  -I"${COMMON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_ROOT}/keystore/encrypted_keystore.cpp" \
  "${COMMON_ROOT}/keystore/encrypted_keystore_nvs.cpp" \
  "${RUNTIME_DIR}/stackchan_keystore.cpp" \
  "${TMP_DIR}/monocypher.o" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
