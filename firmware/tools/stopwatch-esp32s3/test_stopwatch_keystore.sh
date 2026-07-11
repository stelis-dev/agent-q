#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stopwatch-esp32s3/test_stopwatch_keystore.sh

Compiles the StopWatch encrypted-keystore adapter against host NVS, heap, and
RNG stubs plus the pinned Monocypher source. It verifies target configuration,
callback-scoped credential and transport-key access, locked denial, incomplete
storage rejection, ciphertext-at-rest, and complete erase. This test does not
require ESP-IDF or hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime"
MONOCYPHER_ROOT="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib/src/microsui_core"
CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

for required in \
  "${COMMON_ROOT}/keystore/encrypted_keystore.cpp" \
  "${COMMON_ROOT}/keystore/encrypted_keystore_nvs.cpp" \
  "${RUNTIME_DIR}/stopwatch_keystore.cpp" \
  "${MONOCYPHER_ROOT}/lib/monocypher/monocypher.c"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-keystore.XXXXXX")"
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

cat >"${TMP_DIR}/stubs/esp_heap_caps.h" <<'H'
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#define MALLOC_CAP_SPIRAM 0x01u
#define MALLOC_CAP_8BIT 0x02u
static inline void* heap_caps_calloc(size_t count, size_t size, uint32_t)
{
    return calloc(count, size);
}
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

#include "esp_err.h"
#include "nvs.h"
#include "stopwatch_keystore.h"

namespace {

std::map<std::string, std::vector<uint8_t>> g_blobs;
std::map<std::string, std::vector<uint8_t>> g_pending_writes;
std::vector<std::string> g_pending_erases;
std::string g_last_namespace;
uint8_t g_random_counter = 1;
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

namespace stopwatch_target {

bool secure_random_fill(void* output, size_t size)
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

}  // namespace stopwatch_target

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
    using namespace signing;
    using namespace stopwatch_target;

    std::vector<uint8_t> work_area(kStopWatchKeystoreKdfWorkAreaBytes);
    char pin[kKeystorePinBufferBytes] = {};

    expect(kStopWatchKeystoreKdfProfile.memory_kib == 512 &&
               kStopWatchKeystoreKdfProfile.passes == 5 &&
               kStopWatchKeystoreKdfProfile.lanes == 1,
           "StopWatch uses its measured fixed KDF optimization profile");
    expect(kLocalAuthMinDigits == 1 && kLocalAuthMaxDigits == 4,
           "StopWatch fixes the target PIN policy to one through four digits");
    expect(stopwatch_keystore_initialize() == KeystoreState::absent,
           "empty NVS initializes an absent keystore");
    expect(stopwatch_keystore_storage_consistent(),
           "empty target storage is a consistent setup state");

    set_pin(pin, "12345");
    expect(stopwatch_keystore_create(pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::invalid_input,
           "setup rejects a five-digit PIN before writing a keyslot");
    expect(g_blobs.count("keyslot") == 0,
           "rejected PIN writes no keyslot");

    set_pin(pin, "1234");
    expect(stopwatch_keystore_create(pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::success,
           "setup creates and opens the encrypted keyslot");
    expect(g_last_namespace == "sw_keystore", "target adapter owns its NVS namespace");
    expect(g_blobs.count("keyslot") == 1, "keyslot is persisted");
    expect(!contains_sequence(
               g_blobs.at("keyslot"),
               reinterpret_cast<const uint8_t*>("1234"),
               kLocalAuthMaxDigits),
           "persisted keyslot does not contain the PIN");

    uint8_t credential[160] = {};
    for (size_t index = 0; index < sizeof(credential); ++index) {
        credential[index] = static_cast<uint8_t>(0x40u + index);
    }
    expect(stopwatch_keystore_replace_credential(
               credential,
               sizeof(credential)) == KeystoreOperationStatus::success,
           "credential adapter stores a protected record");
    expect(!contains_sequence(g_blobs.at("credential"), credential, sizeof(credential)),
           "persisted credential contains no prepared-seed plaintext");

    Capture credential_capture;
    expect(stopwatch_keystore_with_credential(
               capture_record,
               &credential_capture) == KeystoreOperationStatus::success &&
               credential_capture.calls == 1 &&
               credential_capture.bytes.size() == sizeof(credential) &&
               memcmp(credential_capture.bytes.data(), credential, sizeof(credential)) == 0,
           "credential plaintext is available only inside its consumer");

    uint8_t identity_secret[kLocalTransportStaticKeyBytes] = {};
    uint8_t identity_public[kLocalTransportStaticKeyBytes] = {};
    uint8_t identity_plaintext[2 * kLocalTransportStaticKeyBytes] = {};
    for (size_t index = 0; index < sizeof(identity_secret); ++index) {
        identity_secret[index] = static_cast<uint8_t>(0x20 + index);
        identity_public[index] = static_cast<uint8_t>(0x80 + index);
    }
    memcpy(identity_plaintext, identity_secret, sizeof(identity_secret));
    memcpy(
        identity_plaintext + sizeof(identity_secret),
        identity_public,
        sizeof(identity_public));
    const LocalTransportIdentityStorageOps& identity_storage =
        stopwatch_transport_identity_storage_ops();
    expect(identity_storage.write_key_pair(
               identity_secret,
               identity_public,
               identity_storage.context),
           "first local-transport use stores an encrypted identity record");
    expect(!contains_sequence(
               g_blobs.at("transport_id"),
               identity_plaintext,
               sizeof(identity_plaintext)),
           "persisted transport identity contains no private-key plaintext");
    expect(stopwatch_keystore_transport_identity_valid_or_missing(),
           "unlocked transport identity record has the exact target shape");

    KeyPairCapture identity_capture;
    expect(identity_storage.with_key_pair(
               capture_key_pair,
               &identity_capture,
               identity_storage.context) ==
               LocalTransportIdentityRecordReadStatus::found &&
               identity_capture.calls == 1 &&
               memcmp(identity_capture.secret, identity_secret, sizeof(identity_secret)) == 0 &&
               memcmp(identity_capture.public_key, identity_public, sizeof(identity_public)) == 0,
           "transport private key is available only inside its consumer");
    expect(stopwatch_keystore_storage_consistent(),
           "keyslot and optional protected records are structurally consistent");

    expect(stopwatch_keystore_initialize() == KeystoreState::locked,
           "reboot locks the StopWatch keystore");
    credential_capture = {};
    expect(stopwatch_keystore_with_credential(
               capture_record,
               &credential_capture) == KeystoreOperationStatus::locked &&
               credential_capture.calls == 0,
           "locked keystore never invokes the credential consumer");
    identity_capture = {};
    expect(identity_storage.with_key_pair(
               capture_key_pair,
               &identity_capture,
               identity_storage.context) == LocalTransportIdentityRecordReadStatus::error &&
               identity_capture.calls == 0,
           "locked keystore never invokes the transport-key consumer");

    set_pin(pin, "0");
    expect(stopwatch_keystore_unlock(pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::wrong_pin,
           "wrong PIN cannot open the keyslot");
    set_pin(pin, "1234");
    expect(stopwatch_keystore_unlock(pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::success,
           "correct PIN opens the keyslot");

    expect(stopwatch_keystore_initialize() == KeystoreState::locked,
           "reboot locks before record-authentication failure test");
    g_blobs["credential"].back() ^= 0x80;
    set_pin(pin, "1234");
    expect(stopwatch_keystore_unlock(pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::success,
           "keyslot unlock is separate from optional record validation");
    expect(stopwatch_keystore_with_credential(capture_record, &credential_capture) ==
               KeystoreOperationStatus::invalid_record,
           "authenticated credential corruption fails closed");
    expect(stopwatch_keystore_state() == KeystoreState::invalid,
           "credential authentication failure invalidates the keystore");

    expect(stopwatch_keystore_erase() == KeystoreOperationStatus::success,
           "Device reset erases the full encrypted keystore");
    expect(g_blobs.empty(), "Device reset removes keyslot and protected records");
    expect(stopwatch_keystore_state() == KeystoreState::absent,
           "Device reset returns the keystore to absent");

    set_pin(pin, "1");
    expect(stopwatch_keystore_create(pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::success,
           "setup can restart with a one-digit PIN after complete erase");
    expect(stopwatch_keystore_replace_credential(credential, sizeof(credential)) ==
               KeystoreOperationStatus::success,
           "setup stores a new encrypted credential");
    g_blobs.erase("keyslot");
    expect(stopwatch_keystore_initialize() == KeystoreState::absent,
           "missing keyslot is observed after interrupted erase");
    expect(!stopwatch_keystore_storage_consistent(),
           "protected ciphertext without a keyslot is inconsistent");
    set_pin(pin, "4321");
    expect(stopwatch_keystore_create(pin, work_area.data(), work_area.size()) ==
               KeystoreOperationStatus::invalid_record,
           "setup cannot bind a new master key to stale ciphertext");
    expect(stopwatch_keystore_erase() == KeystoreOperationStatus::success,
           "inconsistent storage remains recoverable through Device reset");

    if (failures != 0) {
        fprintf(stderr, "%d StopWatch keystore test(s) failed\n", failures);
        return 1;
    }
    puts("StopWatch keystore tests passed");
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
  "${RUNTIME_DIR}/stopwatch_keystore.cpp" \
  "${TMP_DIR}/monocypher.o" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
