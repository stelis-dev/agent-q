#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sui_zklogin_proof_store.sh

Compiles the Agent-Q Sui zkLogin proof record store and active-identity
resolver against host stubs for ESP-IDF NVS. This test uses the pinned
MicroSui signing source for blake2b and byte encoding helpers; it does NOT
require ESP-IDF. Set AGENT_Q_SIGNING_CRYPTO_ROOT to override the signing source
location, otherwise the pinned .firmware-cache checkout from build.sh is used.
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
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_AGENT_Q_DIR="${REPO_ROOT}/firmware/src/common/agent_q"

for required in \
  "${SIGNING_CORE}/lib/monocypher/monocypher.c" \
  "${SIGNING_CORE}/byte_conversions.c" \
  "${AGENT_Q_DIR}/agent_q_sui_zklogin_proof_store.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_zklogin_proof_store.h" \
  "${COMMON_AGENT_Q_DIR}/agent_q_u64_decimal.h" \
  "${COMMON_AGENT_Q_DIR}/sui/agent_q_sui_network.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first, or set AGENT_Q_SIGNING_CRYPTO_ROOT." >&2
    exit 1
  fi
done

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sui-zklogin-proof.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/esp_err.h" <<'H'
#pragma once

typedef int esp_err_t;

#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NVS_NOT_FOUND 4354

static inline const char* esp_err_to_name(esp_err_t err)
{
    switch (err) {
        case ESP_OK:
            return "ESP_OK";
        case ESP_FAIL:
            return "ESP_FAIL";
        case ESP_ERR_NVS_NOT_FOUND:
            return "ESP_ERR_NVS_NOT_FOUND";
        default:
            return "ESP_ERR_UNKNOWN";
    }
}
H

cat >"${TMP_DIR}/esp_log.h" <<'H'
#pragma once

#define ESP_LOGW(tag, fmt, ...) \
    do {                        \
        (void)(tag);            \
    } while (0)
H

cat >"${TMP_DIR}/nvs.h" <<'H'
#pragma once

#include <stddef.h>

#include "esp_err.h"

typedef int nvs_handle_t;

typedef enum {
    NVS_READONLY = 1,
    NVS_READWRITE = 2,
} nvs_open_mode_t;

esp_err_t nvs_open(const char* name, nvs_open_mode_t open_mode, nvs_handle_t* out_handle);
void nvs_close(nvs_handle_t handle);
esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* out_value, size_t* length);
esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length);
esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key);
esp_err_t nvs_commit(nvs_handle_t handle);
H

cat >"${TMP_DIR}/sui_zklogin_proof_store_test.cpp" <<'CPP'
#include <cstdio>
#include <cstring>
#include <vector>

#include "agent_q_sui_account_store.h"
#include "agent_q_sui_zklogin_proof_store.h"
#include "nvs.h"

namespace {

constexpr const char* kExpectedNamespace = "agent_q";
constexpr const char* kExpectedProofKey = "sui_zkl_proof";
constexpr const char* kNativeAddress =
    "0x1111111111111111111111111111111111111111111111111111111111111111";

std::vector<unsigned char> g_blob;
std::vector<unsigned char> g_pending_blob;
bool g_has_blob = false;
bool g_pending_set = false;
bool g_pending_erase = false;
bool g_commit_corrupts_write = false;
bool g_native_derivation_fails = false;
esp_err_t g_open_result = ESP_OK;
esp_err_t g_get_result = ESP_OK;
esp_err_t g_set_result = ESP_OK;
esp_err_t g_erase_result = ESP_OK;
esp_err_t g_commit_result = ESP_OK;
int g_failures = 0;

void expect(bool condition, const char* message)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        ++g_failures;
    }
}

void reset_stubs()
{
    g_blob.clear();
    g_pending_blob.clear();
    g_has_blob = false;
    g_pending_set = false;
    g_pending_erase = false;
    g_commit_corrupts_write = false;
    g_native_derivation_fails = false;
    g_open_result = ESP_OK;
    g_get_result = ESP_OK;
    g_set_result = ESP_OK;
    g_erase_result = ESP_OK;
    g_commit_result = ESP_OK;
}

bool set_field(char* out, size_t out_size, const char* value)
{
    const size_t length = std::strlen(value);
    if (length + 1 > out_size) {
        return false;
    }
    std::memset(out, 0, out_size);
    std::memcpy(out, value, length + 1);
    return true;
}

void set_proof_hash(char out[agent_q::kAgentQSuiZkLoginProofHashBufferSize])
{
    constexpr const char* kPrefix = "sha256:";
    std::memset(out, 0, agent_q::kAgentQSuiZkLoginProofHashBufferSize);
    std::memcpy(out, kPrefix, std::strlen(kPrefix));
    for (size_t index = 0; index < 64; ++index) {
        out[std::strlen(kPrefix) + index] = 'a';
    }
}

agent_q::AgentQSuiZkLoginProofRecord make_valid_record()
{
    agent_q::AgentQSuiZkLoginProofRecord record = {};
    const char* issuer = "https://accounts.google.com";
    const size_t issuer_len = std::strlen(issuer);

    expect(set_field(record.network, sizeof(record.network), "testnet"), "test record network fits");
    expect(set_field(record.issuer, sizeof(record.issuer), issuer), "test record issuer fits");
    expect(set_field(record.address_seed, sizeof(record.address_seed), "1"), "test record address seed fits");
    expect(set_field(record.max_epoch, sizeof(record.max_epoch), "123"), "test record max epoch fits");

    record.public_key[0] = agent_q::kAgentQSuiSignatureSchemeFlagZkLogin;
    record.public_key[1] = static_cast<unsigned char>(issuer_len);
    std::memcpy(record.public_key + 2, issuer, issuer_len);
    std::memset(record.public_key + 2 + issuer_len, 0, 32);
    record.public_key[2 + issuer_len + 31] = 1;
    record.public_key_size = 2 + issuer_len + 32;
    expect(
        agent_q::derive_sui_address_from_scheme_prefixed_public_key(
            record.public_key,
            record.public_key_size,
            record.address,
            sizeof(record.address)),
        "valid test record address derives");

    const char* a_values[] = {"1", "2", "1"};
    const char* b_values[][agent_q::kAgentQSuiZkLoginProofPointBInnerCount] = {
        {"3", "4"},
        {"5", "6"},
        {"1", "0"},
    };
    const char* c_values[] = {"7", "8", "1"};
    for (size_t index = 0; index < agent_q::kAgentQSuiZkLoginProofPointACount; ++index) {
        expect(
            set_field(
                record.inputs.proof_points.a[index],
                sizeof(record.inputs.proof_points.a[index]),
                a_values[index]),
            "test record proof point a fits");
    }
    for (size_t row = 0; row < agent_q::kAgentQSuiZkLoginProofPointBOuterCount; ++row) {
        for (size_t column = 0; column < agent_q::kAgentQSuiZkLoginProofPointBInnerCount; ++column) {
            expect(
                set_field(
                    record.inputs.proof_points.b[row][column],
                    sizeof(record.inputs.proof_points.b[row][column]),
                    b_values[row][column]),
                "test record proof point b fits");
        }
    }
    for (size_t index = 0; index < agent_q::kAgentQSuiZkLoginProofPointCCount; ++index) {
        expect(
            set_field(
                record.inputs.proof_points.c[index],
                sizeof(record.inputs.proof_points.c[index]),
                c_values[index]),
            "test record proof point c fits");
    }

    record.inputs.iss_base64_details.index_mod4 = 1;
    expect(
        set_field(
            record.inputs.iss_base64_details.value,
            sizeof(record.inputs.iss_base64_details.value),
            "yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC"),
        "test record issBase64Details fits");
    expect(
        set_field(
            record.inputs.header_base64,
            sizeof(record.inputs.header_base64),
            "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ"),
        "test record headerBase64 fits");
    expect(
        set_field(
            record.inputs.address_seed,
            sizeof(record.inputs.address_seed),
            record.address_seed),
        "test record input addressSeed fits");
    set_proof_hash(record.proof_hash);
    return record;
}

void expect_native_identity(const char* label)
{
    const agent_q::AgentQSuiActiveIdentity identity = agent_q::resolve_active_sui_identity();
    expect(identity.kind == agent_q::AgentQSuiActiveIdentityKind::native, label);
    expect(identity.error == agent_q::AgentQSuiActiveIdentityError::none, "native identity has no error");
    expect(std::strcmp(identity.address, kNativeAddress) == 0, "native identity returns stored account address");
    expect(
        identity.public_key_size == agent_q::kAgentQSuiSchemePrefixedEd25519PublicKeyBytes,
        "native identity returns scheme-prefixed public key length");
    expect(
        identity.public_key[0] == agent_q::kAgentQSuiSignatureSchemeFlagEd25519,
        "native identity public key has Ed25519 scheme flag");
}

void expect_proof_storage_error(const char* label)
{
    const agent_q::AgentQSuiActiveIdentity identity = agent_q::resolve_active_sui_identity();
    expect(identity.kind == agent_q::AgentQSuiActiveIdentityKind::error, label);
    expect(
        identity.error == agent_q::AgentQSuiActiveIdentityError::proof_storage_error,
        "proof storage errors do not fall back to native identity");
}

void store_valid_record(agent_q::AgentQSuiZkLoginProofRecord* out)
{
    const agent_q::AgentQSuiZkLoginProofRecord record = make_valid_record();
    expect(
        agent_q::store_sui_zklogin_proof_record(&record) ==
            agent_q::AgentQSuiZkLoginProofRecordWriteResult::stored,
        "valid proof record stores");
    if (out != nullptr) {
        *out = record;
    }
}

}  // namespace

esp_err_t nvs_open(const char* name, nvs_open_mode_t, nvs_handle_t* out_handle)
{
    if (g_open_result != ESP_OK) {
        return g_open_result;
    }
    if (name == nullptr || std::strcmp(name, kExpectedNamespace) != 0 || out_handle == nullptr) {
        return ESP_FAIL;
    }
    *out_handle = 1;
    return ESP_OK;
}

void nvs_close(nvs_handle_t)
{
}

esp_err_t nvs_get_blob(nvs_handle_t, const char* key, void* out_value, size_t* length)
{
    if (g_get_result != ESP_OK) {
        return g_get_result;
    }
    if (key == nullptr || std::strcmp(key, kExpectedProofKey) != 0 || length == nullptr) {
        return ESP_FAIL;
    }
    if (!g_has_blob) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (out_value == nullptr) {
        *length = g_blob.size();
        return ESP_OK;
    }
    if (*length < g_blob.size()) {
        *length = g_blob.size();
        return ESP_FAIL;
    }
    std::memcpy(out_value, g_blob.data(), g_blob.size());
    *length = g_blob.size();
    return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t, const char* key, const void* value, size_t length)
{
    if (g_set_result != ESP_OK) {
        return g_set_result;
    }
    if (key == nullptr || std::strcmp(key, kExpectedProofKey) != 0 || value == nullptr) {
        return ESP_FAIL;
    }
    const unsigned char* begin = static_cast<const unsigned char*>(value);
    g_pending_blob.assign(begin, begin + length);
    g_pending_set = true;
    g_pending_erase = false;
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t, const char* key)
{
    if (g_erase_result != ESP_OK) {
        return g_erase_result;
    }
    if (key == nullptr || std::strcmp(key, kExpectedProofKey) != 0) {
        return ESP_FAIL;
    }
    if (!g_has_blob) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    g_pending_erase = true;
    g_pending_set = false;
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t)
{
    if (g_commit_result != ESP_OK) {
        g_pending_set = false;
        g_pending_erase = false;
        return g_commit_result;
    }
    if (g_pending_erase) {
        g_blob.clear();
        g_has_blob = false;
    } else if (g_pending_set) {
        g_blob = g_pending_blob;
        if (g_commit_corrupts_write && !g_blob.empty()) {
            g_blob[0] ^= 0x7F;
        }
        g_has_blob = true;
    }
    g_pending_set = false;
    g_pending_erase = false;
    return ESP_OK;
}

namespace agent_q {

void wipe_sensitive_buffer(void* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (size > 0) {
        *cursor++ = 0;
        --size;
    }
}

SuiAccountDerivationResult derive_sui_ed25519_account_from_stored_root(
    uint8_t public_key_out[kSuiEd25519PublicKeyBytes],
    char* address_out,
    size_t address_out_size)
{
    if (public_key_out != nullptr) {
        std::memset(public_key_out, 0, kSuiEd25519PublicKeyBytes);
    }
    if (address_out != nullptr && address_out_size > 0) {
        std::memset(address_out, 0, address_out_size);
    }
    if (g_native_derivation_fails) {
        return SuiAccountDerivationResult::root_material_unavailable;
    }
    if (public_key_out == nullptr || address_out == nullptr || address_out_size < kSuiAddressBufferSize) {
        return SuiAccountDerivationResult::derivation_error;
    }
    for (size_t index = 0; index < kSuiEd25519PublicKeyBytes; ++index) {
        public_key_out[index] = static_cast<uint8_t>(0xA0 + index);
    }
    std::memcpy(address_out, kNativeAddress, std::strlen(kNativeAddress) + 1);
    return SuiAccountDerivationResult::ok;
}

}  // namespace agent_q

int main()
{
    using Status = agent_q::AgentQSuiZkLoginProofRecordStatus;
    using Write = agent_q::AgentQSuiZkLoginProofRecordWriteResult;

    reset_stubs();
    expect(agent_q::sui_zklogin_proof_record_status() == Status::missing, "empty store reports missing proof");
    expect_native_identity("missing proof resolves native identity");

    reset_stubs();
    agent_q::AgentQSuiZkLoginProofRecord original = {};
    store_valid_record(&original);
    expect(agent_q::sui_zklogin_proof_record_status() == Status::active, "stored proof reports active");
    agent_q::AgentQSuiZkLoginProofRecord readback = {};
    expect(
        agent_q::read_sui_zklogin_proof_record(&readback) == Status::active,
        "stored proof can be read");
    expect(std::strcmp(readback.address, original.address) == 0, "read proof preserves address");
    expect(std::strcmp(readback.max_epoch, original.max_epoch) == 0, "read proof preserves maxEpoch");
    const agent_q::AgentQSuiActiveIdentity zklogin_identity = agent_q::resolve_active_sui_identity();
    expect(
        zklogin_identity.kind == agent_q::AgentQSuiActiveIdentityKind::zklogin,
        "active proof resolves zkLogin identity");
    expect(
        zklogin_identity.public_key_size == original.public_key_size &&
            zklogin_identity.public_key[0] == agent_q::kAgentQSuiSignatureSchemeFlagZkLogin,
        "zkLogin identity returns scheme-prefixed public key");

    reset_stubs();
    store_valid_record(nullptr);
    g_blob[0] ^= 0x7F;
    expect(agent_q::sui_zklogin_proof_record_status() == Status::invalid, "corrupt stored proof reports invalid");
    expect_proof_storage_error("corrupt proof makes active identity fail closed");

    reset_stubs();
    store_valid_record(nullptr);
    g_get_result = ESP_FAIL;
    expect(
        agent_q::sui_zklogin_proof_record_status() == Status::storage_error,
        "unreadable proof reports storage error");
    expect_proof_storage_error("unreadable proof makes active identity fail closed");

    reset_stubs();
    agent_q::AgentQSuiZkLoginProofRecord invalid = make_valid_record();
    expect(set_field(invalid.network, sizeof(invalid.network), "bogus"), "invalid network mutation fits");
    expect(
        agent_q::store_sui_zklogin_proof_record(&invalid) == Write::invalid_record,
        "invalid proof record is rejected");
    expect(agent_q::sui_zklogin_proof_record_status() == Status::missing, "invalid write does not create proof");

    reset_stubs();
    store_valid_record(&original);
    agent_q::AgentQSuiZkLoginProofRecord updated = original;
    expect(set_field(updated.max_epoch, sizeof(updated.max_epoch), "124"), "updated maxEpoch fits");
    g_set_result = ESP_FAIL;
    expect(
        agent_q::store_sui_zklogin_proof_record(&updated) == Write::storage_error,
        "NVS set failure reports storage error");
    g_set_result = ESP_OK;
    readback = {};
    expect(agent_q::read_sui_zklogin_proof_record(&readback) == Status::active, "previous proof remains readable");
    expect(std::strcmp(readback.max_epoch, "123") == 0, "NVS set failure preserves previous proof");

    reset_stubs();
    store_valid_record(&original);
    updated = original;
    expect(set_field(updated.max_epoch, sizeof(updated.max_epoch), "125"), "corrupt write maxEpoch fits");
    g_commit_corrupts_write = true;
    expect(
        agent_q::store_sui_zklogin_proof_record(&updated) == Write::consistency_error,
        "corrupt committed write reports consistency error");
    g_commit_corrupts_write = false;
    expect(agent_q::sui_zklogin_proof_record_status() == Status::invalid, "corrupt committed write fails closed");
    expect_proof_storage_error("corrupt committed write does not fall back to native identity");

    reset_stubs();
    store_valid_record(nullptr);
    expect(agent_q::wipe_sui_zklogin_proof_record(), "proof wipe succeeds");
    expect(agent_q::sui_zklogin_proof_record_status() == Status::missing, "proof wipe clears record");
    expect_native_identity("cleared proof resolves native identity again");

    reset_stubs();
    g_native_derivation_fails = true;
    const agent_q::AgentQSuiActiveIdentity missing_native = agent_q::resolve_active_sui_identity();
    expect(
        missing_native.kind == agent_q::AgentQSuiActiveIdentityKind::error,
        "missing proof with unavailable native account reports error identity");
    expect(
        missing_native.error == agent_q::AgentQSuiActiveIdentityError::native_account_unavailable,
        "missing proof preserves native account unavailable error");

    if (g_failures != 0) {
        std::fprintf(stderr, "Sui zkLogin proof store tests FAILED: %d\n", g_failures);
        return 1;
    }
    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${SIGNING_CORE}" \
  -c "${SIGNING_CORE}/lib/monocypher/monocypher.c" -o "${TMP_DIR}/monocypher.o"
"${CC_BIN}" -std=c99 -I"${SIGNING_CORE}" \
  -c "${SIGNING_CORE}/byte_conversions.c" -o "${TMP_DIR}/byte_conversions.o"

"${CXX_BIN}" -std=c++17 -I"${TMP_DIR}" -I"${SIGNING_CORE}" -I"${AGENT_Q_DIR}" -I"${COMMON_AGENT_Q_DIR}" \
  -c "${AGENT_Q_DIR}/agent_q_sui_zklogin_proof_store.cpp" -o "${TMP_DIR}/agent_q_sui_zklogin_proof_store.o"
"${CXX_BIN}" -std=c++17 -I"${TMP_DIR}" -I"${SIGNING_CORE}" -I"${AGENT_Q_DIR}" -I"${COMMON_AGENT_Q_DIR}" \
  -c "${TMP_DIR}/sui_zklogin_proof_store_test.cpp" -o "${TMP_DIR}/sui_zklogin_proof_store_test.o"

"${CXX_BIN}" \
  "${TMP_DIR}/monocypher.o" \
  "${TMP_DIR}/byte_conversions.o" \
  "${TMP_DIR}/agent_q_sui_zklogin_proof_store.o" \
  "${TMP_DIR}/sui_zklogin_proof_store_test.o" \
  -o "${TMP_DIR}/sui_zklogin_proof_store_test"

"${TMP_DIR}/sui_zklogin_proof_store_test"
echo "Sui zkLogin proof store tests passed"
