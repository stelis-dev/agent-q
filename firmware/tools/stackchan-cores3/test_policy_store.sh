#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_policy_store.sh

ESP-IDF must already be active in the shell so IDF_PATH points to the ESP-IDF
checkout. This test compiles the StackChan CoreS3 active policy store with NVS
stubs and ESP-IDF mbedTLS SHA-256, then checks current-schema default policy,
scoped default-reject policy commit/readback, invalid material rejection, and
fail-closed storage consistency behavior. This test uses only a host C++
compiler and does NOT require hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET_ROOT="${REPO_ROOT}/firmware/src/stackchan-cores3"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CXX_BIN="${CXX:-c++}"
CC_BIN="${CC:-cc}"

if [[ -z "${IDF_PATH:-}" ]]; then
  echo "IDF_PATH is not set. Source ESP-IDF v5.5.4 export.sh before running this test." >&2
  exit 1
fi

MBEDTLS_ROOT="${IDF_PATH}/components/mbedtls/mbedtls"
MBEDTLS_INCLUDE_DIR="${MBEDTLS_ROOT}/include"
MBEDTLS_LIBRARY_DIR="${MBEDTLS_ROOT}/library"
if [[ ! -f "${MBEDTLS_INCLUDE_DIR}/mbedtls/sha256.h" || ! -f "${MBEDTLS_LIBRARY_DIR}/sha256.c" || ! -f "${MBEDTLS_LIBRARY_DIR}/platform_util.c" ]]; then
  echo "IDF_PATH does not expose the expected ESP-IDF mbedTLS sources: ${IDF_PATH}" >&2
  exit 1
fi

for required in \
  "${TARGET_ROOT}/runtime/policy_store.cpp" \
  "${TARGET_ROOT}/runtime/policy_store.h" \
  "${COMMON_ROOT}/policy/document.cpp" \
  "${COMMON_ROOT}/policy/document.h" \
  "${COMMON_ROOT}/policy/u64.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-policy-store.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/firmware_common" "${TMP_DIR}/stubs"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"

cat >"${TMP_DIR}/stubs/esp_err.h" <<'H'
#pragma once

typedef int esp_err_t;

#define ESP_OK 0
#define ESP_ERR_NVS_NOT_FOUND 4354
#define ESP_ERR_TEST_FAIL 9999

static inline const char* esp_err_to_name(esp_err_t error)
{
    return error == ESP_OK ? "ESP_OK" :
           error == ESP_ERR_NVS_NOT_FOUND ? "ESP_ERR_NVS_NOT_FOUND" :
           "ESP_ERR_TEST_FAIL";
}
H

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once

#define ESP_LOGI(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, format, ...) do { (void)(tag); } while (0)
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

cat >"${TMP_DIR}/policy_store_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <map>
#include <string>
#include <vector>

#include "esp_err.h"
#include "nvs.h"
#include "firmware_common/policy/document.h"
#include "policy_store.h"

namespace {

std::map<std::string, std::vector<uint8_t>> g_blobs;
bool g_open_fails = false;
bool g_commit_fails = false;
std::string g_set_fails_for_key;
std::string g_erase_fails_for_key;
bool g_commit_metadata_write_fails = false;
int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void reset_store_stubs()
{
    g_blobs.clear();
    g_open_fails = false;
    g_commit_fails = false;
    g_set_fails_for_key.clear();
    g_erase_fails_for_key.clear();
    g_commit_metadata_write_fails = false;
}

bool make_scoped_empty_policy_record(std::vector<uint8_t>* output)
{
    if (output == nullptr) {
        return false;
    }

    const signing::CurrentPolicyNetworkScope networks[] = {
        {
            "testnet",
            nullptr,
            0,
        },
    };
    const signing::CurrentPolicyBlockchainScope blockchains[] = {
        {
            "sui",
            networks,
            sizeof(networks) / sizeof(networks[0]),
        },
    };
    const signing::CurrentPolicyDocument policy = {
        signing::kCurrentPolicySchema,
        signing::CurrentPolicyAction::reject,
        blockchains,
        sizeof(blockchains) / sizeof(blockchains[0]),
    };

    auto* canonical = new signing::CurrentPolicyCanonicalDocument();
    uint8_t bytes[signing::kCurrentPolicyMaxCanonicalRecordBytes] = {};
    size_t size = 0;
    const bool ok =
        signing::canonicalize_current_policy_document(policy, canonical) ==
            signing::CurrentPolicyDocumentStatus::ok &&
        signing::encode_current_policy_canonical_record(
            *canonical,
            bytes,
            sizeof(bytes),
            &size) == signing::CurrentPolicyDocumentStatus::ok &&
        size > signing::kCurrentPolicyDefaultCanonicalRecordBytes;
    if (ok) {
        output->assign(bytes, bytes + size);
    }
    delete canonical;
    return ok;
}

bool make_non_empty_policy_record(std::vector<uint8_t>* output)
{
    if (output == nullptr) {
        return false;
    }

    constexpr const char* kSuiTypeTag =
        "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";
    const char* amount_values[] = {"1000000000"};
    const signing::CurrentPolicyCondition conditions[] = {
        {
            "sui.token_totals_by_type.amount_raw",
            signing::CurrentPolicyOperator::lte,
            amount_values,
            sizeof(amount_values) / sizeof(amount_values[0]),
            kSuiTypeTag,
        },
    };
    const signing::CurrentPolicy policies[] = {
        {
            "sui-testnet-max-one-sui",
            signing::CurrentPolicyAction::sign,
            conditions,
            sizeof(conditions) / sizeof(conditions[0]),
        },
    };
    const signing::CurrentPolicyNetworkScope networks[] = {
        {
            "testnet",
            policies,
            sizeof(policies) / sizeof(policies[0]),
        },
    };
    const signing::CurrentPolicyBlockchainScope blockchains[] = {
        {
            "sui",
            networks,
            sizeof(networks) / sizeof(networks[0]),
        },
    };
    const signing::CurrentPolicyDocument policy = {
        signing::kCurrentPolicySchema,
        signing::CurrentPolicyAction::reject,
        blockchains,
        sizeof(blockchains) / sizeof(blockchains[0]),
    };

    auto* canonical = new signing::CurrentPolicyCanonicalDocument();
    uint8_t bytes[signing::kCurrentPolicyMaxCanonicalRecordBytes] = {};
    size_t size = 0;
    const bool ok =
        signing::canonicalize_current_policy_document(policy, canonical) ==
            signing::CurrentPolicyDocumentStatus::ok &&
        signing::encode_current_policy_canonical_record(
            *canonical,
            bytes,
            sizeof(bytes),
            &size) == signing::CurrentPolicyDocumentStatus::ok &&
        size > signing::kCurrentPolicyDefaultCanonicalRecordBytes;
    if (ok) {
        output->assign(bytes, bytes + size);
    }
    delete canonical;
    return ok;
}

bool make_default_record(std::vector<uint8_t>* output)
{
    if (output == nullptr) {
        return false;
    }
    uint8_t bytes[signing::kCurrentPolicyDefaultCanonicalRecordBytes] = {};
    size_t size = 0;
    if (signing::encode_current_policy_default_record(bytes, sizeof(bytes), &size) !=
            signing::CurrentPolicyDocumentStatus::ok ||
        size != sizeof(bytes)) {
        return false;
    }
    output->assign(bytes, bytes + size);
    return true;
}

}  // namespace

extern "C" {

esp_err_t nvs_open(const char*, int, nvs_handle_t* out_handle)
{
    if (g_open_fails || out_handle == nullptr) {
        return ESP_ERR_TEST_FAIL;
    }
    *out_handle = 1;
    return ESP_OK;
}

void nvs_close(nvs_handle_t) {}

esp_err_t nvs_get_blob(nvs_handle_t, const char* key, void* out_value, size_t* length)
{
    if (key == nullptr || length == nullptr) {
        return ESP_ERR_TEST_FAIL;
    }
    const auto found = g_blobs.find(key);
    if (found == g_blobs.end()) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (out_value == nullptr) {
        *length = found->second.size();
        return ESP_OK;
    }
    if (*length < found->second.size()) {
        return ESP_ERR_TEST_FAIL;
    }
    memcpy(out_value, found->second.data(), found->second.size());
    *length = found->second.size();
    return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t, const char* key, const void* value, size_t length)
{
    if (key == nullptr || value == nullptr ||
        key == g_set_fails_for_key ||
        (g_commit_metadata_write_fails &&
         (strcmp(key, "pol_c0") == 0 || strcmp(key, "pol_c1") == 0))) {
        return ESP_ERR_TEST_FAIL;
    }
    const uint8_t* bytes = static_cast<const uint8_t*>(value);
    g_blobs[key] = std::vector<uint8_t>(bytes, bytes + length);
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t, const char* key)
{
    if (key == nullptr || key == g_erase_fails_for_key) {
        return ESP_ERR_TEST_FAIL;
    }
    const auto erased = g_blobs.erase(key);
    return erased == 0 ? ESP_ERR_NVS_NOT_FOUND : ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t)
{
    return g_commit_fails ? ESP_ERR_TEST_FAIL : ESP_OK;
}

}  // extern "C"

int main()
{
    reset_store_stubs();
    expect(signing::active_policy_status() == signing::PolicyStoreStatus::missing,
           "empty NVS reports missing policy");

    expect(signing::store_default_policy(), "store default current policy");
    expect(signing::active_policy_status() == signing::PolicyStoreStatus::active,
           "default current policy is active");
    signing::StoredPolicySummary summary = {};
    expect(signing::read_active_policy_summary(&summary), "read default policy summary");
    expect(strcmp(summary.schema, signing::kCurrentPolicySchema) == 0,
           "default policy schema");
    expect(strcmp(summary.default_action, "reject") == 0, "default action is reject");
    expect(summary.blockchain_count == 0, "default blockchain count");
    expect(summary.network_count == 0, "default network count");
    expect(summary.policy_count == 0, "default policy count");
    expect(summary.condition_count == 0, "default condition count");

    signing::StoredPolicyDocument document = {};
    expect(signing::read_active_policy_document(&document), "read default policy document");
    expect(document.document != nullptr, "default policy runtime document exists");
    expect(document.document->blockchain_count == 0, "default runtime document has no scopes");

    std::vector<uint8_t> scoped_record;
    expect(make_scoped_empty_policy_record(&scoped_record), "build scoped empty current policy record");
    expect(signing::store_active_policy_record(scoped_record.data(), scoped_record.size()) ==
               signing::PolicyStoreWriteResult::applied,
           "store scoped empty current policy record");
    expect(signing::read_active_policy_summary(&summary), "read scoped empty policy summary");
    expect(summary.blockchain_count == 1, "scoped empty blockchain count");
    expect(summary.network_count == 1, "scoped empty network count");
    expect(summary.policy_count == 0, "scoped empty policy count");
    expect(summary.condition_count == 0, "scoped empty condition count");
    expect(signing::read_active_policy_document(&document), "read scoped empty policy document");
    expect(document.document != nullptr, "scoped empty policy runtime document exists");
    expect(document.document->blockchain_count == 1, "scoped empty runtime blockchain count");
    expect(strcmp(document.document->blockchains[0].blockchain, "sui") == 0,
           "scoped empty runtime blockchain name");
    expect(document.document->blockchains[0].network_count == 1, "scoped empty runtime network count");
    expect(strcmp(document.document->blockchains[0].networks[0].network, "testnet") == 0,
           "scoped empty runtime network name");
    expect(document.document->blockchains[0].networks[0].policy_count == 0,
           "scoped empty runtime policy count");

    std::vector<uint8_t> non_empty_record;
    expect(make_non_empty_policy_record(&non_empty_record), "build non-empty current policy record");
    expect(signing::store_active_policy_record(non_empty_record.data(), non_empty_record.size()) ==
               signing::PolicyStoreWriteResult::applied,
           "store non-empty current policy record");
    expect(signing::read_active_policy_summary(&summary), "read non-empty policy summary");
    expect(summary.blockchain_count == 1, "non-empty blockchain count");
    expect(summary.network_count == 1, "non-empty network count");
    expect(summary.policy_count == 1, "non-empty policy count");
    expect(summary.condition_count == 1, "non-empty condition count");
    expect(signing::read_active_policy_document(&document), "read non-empty policy document");
    expect(document.document != nullptr, "non-empty policy runtime document exists");
    expect(document.document->blockchains[0].networks[0].policy_count == 1,
           "non-empty runtime policy count");
    expect(strcmp(document.document->blockchains[0].networks[0].policies[0].id,
                  "sui-testnet-max-one-sui") == 0,
           "non-empty runtime policy id");
    expect(document.document->blockchains[0].networks[0].policies[0].action ==
               signing::CurrentPolicyAction::sign,
           "non-empty runtime policy action");
    expect(document.document->blockchains[0].networks[0].policies[0].condition_count == 1,
           "non-empty runtime condition count");

    const uint8_t previous_shape_record[] = {'A', 'Q', 'P', '0', 0, 0, 0, 0};
    expect(signing::store_active_policy_record(previous_shape_record, sizeof(previous_shape_record)) ==
               signing::PolicyStoreWriteResult::invalid_record,
           "previous policy material is not active current policy");
    expect(signing::read_active_policy_summary(&summary), "previous invalid write preserves active policy");
    expect(summary.policy_count == 1, "active policy unchanged after invalid record");

    std::vector<uint8_t> default_record;
    expect(make_default_record(&default_record), "build default current record");
    g_commit_metadata_write_fails = true;
    expect(signing::store_active_policy_record(default_record.data(), default_record.size()) !=
               signing::PolicyStoreWriteResult::applied,
           "commit metadata write failure does not report applied");
    g_commit_metadata_write_fails = false;
    expect(signing::read_active_policy_summary(&summary), "policy remains readable after failed commit");
    expect(summary.policy_count == 1, "failed commit preserves previous active policy");

    expect(signing::wipe_policy(), "wipe policy material");
    expect(signing::active_policy_status() == signing::PolicyStoreStatus::missing,
           "wipe removes policy material");

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("policy store tests passed\n");
    return 0;
}
CPP

"${CC_BIN}" -std=c11 -Wall -Wextra -Werror \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"
"${CC_BIN}" -std=c11 -Wall -Wextra -Werror \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${TARGET_ROOT}/runtime" \
  -I"${COMMON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/policy_store_test.cpp" \
  "${TARGET_ROOT}/runtime/policy_store.cpp" \
  "${COMMON_ROOT}/policy/document.cpp" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/policy_store_test"

"${TMP_DIR}/policy_store_test"
