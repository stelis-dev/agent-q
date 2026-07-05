#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime"
COMMON_DIR="${REPO_ROOT}/firmware/src/common"
CRYPTO_ROOT="${SIGNING_CRYPTO_ROOT:-${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib}"
MICROSUI_CORE="${CRYPTO_ROOT}/src/microsui_core"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-zklogin-store.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

for required in \
  "${MICROSUI_CORE}/byte_conversions.c" \
  "${MICROSUI_CORE}/key_management.c" \
  "${MICROSUI_CORE}/lib/monocypher/monocypher.c" \
  "${RUNTIME_DIR}/sui_zklogin_credential_store.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_credential_store.h" \
  "${RUNTIME_DIR}/sui_public_material.cpp" \
  "${COMMON_DIR}/sui/zklogin_proof_record.cpp" \
  "${COMMON_DIR}/sui/network.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stopwatch-esp32s3/build.sh first, or set SIGNING_CRYPTO_ROOT." >&2
    exit 1
  fi
done

cat >"${TMP_DIR}/sui_zklogin_credential_store_test.cpp" <<'CPP'
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sui_zklogin_credential_store.h"

using namespace stopwatch_target;

namespace {

void copy_text(char* output, size_t output_size, const char* text)
{
    assert(output != nullptr);
    assert(text != nullptr);
    assert(strlen(text) < output_size);
    strcpy(output, text);
}

void fill_points(SuiZkLoginProofPoints* points)
{
    assert(points != nullptr);
    for (size_t index = 0; index < kSuiZkLoginProofPointACount; ++index) {
        snprintf(points->a[index], sizeof(points->a[index]), "%u", static_cast<unsigned>(index + 1));
    }
    for (size_t row = 0; row < kSuiZkLoginProofPointBOuterCount; ++row) {
        for (size_t column = 0; column < kSuiZkLoginProofPointBInnerCount; ++column) {
            snprintf(points->b[row][column], sizeof(points->b[row][column]), "%u",
                     static_cast<unsigned>(10 + row * 2 + column));
        }
    }
    for (size_t index = 0; index < kSuiZkLoginProofPointCCount; ++index) {
        snprintf(points->c[index], sizeof(points->c[index]), "%u", static_cast<unsigned>(20 + index));
    }
}

SuiZkLoginCredentialRecord valid_record()
{
    SuiZkLoginCredentialRecord record = {};
    copy_text(record.proof.network, sizeof(record.proof.network), "testnet");
    copy_text(record.proof.issuer, sizeof(record.proof.issuer), "https://accounts.google.com");
    copy_text(record.proof.address_seed, sizeof(record.proof.address_seed), "1");
    copy_text(record.proof.max_epoch, sizeof(record.proof.max_epoch), "123");
    copy_text(record.proof.inputs.iss_base64_details.value,
              sizeof(record.proof.inputs.iss_base64_details.value),
              "ZXhhbXBsZQ");
    record.proof.inputs.iss_base64_details.index_mod4 = 0;
    copy_text(record.proof.inputs.header_base64,
              sizeof(record.proof.inputs.header_base64),
              "eyJhbGciOiJSUzI1NiJ9");
    copy_text(record.proof.inputs.address_seed,
              sizeof(record.proof.inputs.address_seed),
              record.proof.address_seed);
    fill_points(&record.proof.inputs.proof_points);
    copy_text(record.proof.proof_hash,
              sizeof(record.proof.proof_hash),
              "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

    const size_t issuer_len = strlen(record.proof.issuer);
    record.proof.public_key[0] = kSuiSignatureSchemeFlagZkLogin;
    record.proof.public_key[1] = static_cast<uint8_t>(issuer_len);
    memcpy(record.proof.public_key + 2, record.proof.issuer, issuer_len);
    record.proof.public_key[2 + issuer_len + 31] = 1;
    record.proof.public_key_size = 2 + issuer_len + 32;
    assert(derive_sui_address_from_scheme_prefixed_public_key(
        record.proof.public_key,
        record.proof.public_key_size,
        record.proof.address,
        sizeof(record.proof.address)));

    for (size_t index = 0; index < sizeof(record.prepared_seed); ++index) {
        record.prepared_seed[index] = static_cast<uint8_t>(index + 1);
    }
    return record;
}

}  // namespace

int main()
{
    sui_zklogin_credential_test_reset_store();
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::missing);
    SuiZkLoginAccountProjection projection = sui_zklogin_account_projection();
    assert(!projection.active);
    assert(projection.status == SuiZkLoginCredentialStatus::missing);

    SuiZkLoginCredentialRecord record = valid_record();
    assert(validate_sui_zklogin_proof_record(&record.proof));
    assert(validate_sui_zklogin_credential_record(&record));
    assert(store_sui_zklogin_credential(&record) == SuiZkLoginCredentialWriteResult::stored);
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::active);

    SuiZkLoginCredentialRecord readback = {};
    assert(read_sui_zklogin_credential(&readback) == SuiZkLoginCredentialStatus::active);
    assert(strcmp(readback.proof.address, record.proof.address) == 0);
    assert(readback.proof.public_key_size == record.proof.public_key_size);
    assert(memcmp(readback.proof.public_key, record.proof.public_key, record.proof.public_key_size) == 0);
    assert(memcmp(readback.prepared_seed, record.prepared_seed, sizeof(record.prepared_seed)) == 0);

    projection = sui_zklogin_account_projection();
    assert(projection.active);
    assert(projection.status == SuiZkLoginCredentialStatus::active);
    assert(strcmp(projection.address, record.proof.address) == 0);
    assert(projection.public_key_size == record.proof.public_key_size);
    assert(memcmp(projection.public_key, record.proof.public_key, record.proof.public_key_size) == 0);

    SuiZkLoginCredentialRecord invalid = record;
    invalid.proof.public_key[0] = kSuiSignatureSchemeFlagEd25519;
    assert(!validate_sui_zklogin_credential_record(&invalid));
    assert(store_sui_zklogin_credential(&invalid) == SuiZkLoginCredentialWriteResult::invalid_record);
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::active);

    SuiZkLoginCredentialRecord updated = valid_record();
    copy_text(updated.proof.max_epoch, sizeof(updated.proof.max_epoch), "456");
    sui_zklogin_credential_test_set_write_failure(true);
    assert(store_sui_zklogin_credential(&updated) == SuiZkLoginCredentialWriteResult::storage_error);
    sui_zklogin_credential_test_set_write_failure(false);
    assert(read_sui_zklogin_credential(&readback) == SuiZkLoginCredentialStatus::active);
    assert(strcmp(readback.proof.max_epoch, "123") == 0);

    sui_zklogin_credential_test_corrupt_store();
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::invalid);
    projection = sui_zklogin_account_projection();
    assert(!projection.active);
    assert(projection.status == SuiZkLoginCredentialStatus::invalid);

    sui_zklogin_credential_test_reset_store();
    assert(store_sui_zklogin_credential(&record) == SuiZkLoginCredentialWriteResult::stored);
    sui_zklogin_credential_test_set_read_failure(true);
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::storage_error);
    projection = sui_zklogin_account_projection();
    assert(!projection.active);
    assert(projection.status == SuiZkLoginCredentialStatus::storage_error);
    sui_zklogin_credential_test_set_read_failure(false);

    assert(wipe_sui_zklogin_credential());
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::missing);

    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${MICROSUI_CORE}" \
  -c "${MICROSUI_CORE}/byte_conversions.c" \
  -o "${TMP_DIR}/byte_conversions.o"
"${CC_BIN}" -std=c99 -I"${MICROSUI_CORE}" \
  -c "${MICROSUI_CORE}/key_management.c" \
  -o "${TMP_DIR}/key_management.o"
"${CC_BIN}" -std=c99 -I"${MICROSUI_CORE}" \
  -c "${MICROSUI_CORE}/lib/monocypher/monocypher.c" \
  -o "${TMP_DIR}/monocypher.o"

"${CXX_BIN}" -std=c++17 \
  -DSTOPWATCH_ZKLOGIN_CREDENTIAL_STORE_HOST_TEST \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_DIR}" \
  -I"${MICROSUI_CORE}" \
  "${TMP_DIR}/sui_zklogin_credential_store_test.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_credential_store.cpp" \
  "${RUNTIME_DIR}/sui_public_material.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${COMMON_DIR}/sui/zklogin_proof_record.cpp" \
  "${TMP_DIR}/byte_conversions.o" \
  "${TMP_DIR}/key_management.o" \
  "${TMP_DIR}/monocypher.o" \
  -o "${TMP_DIR}/sui_zklogin_credential_store_test"

"${TMP_DIR}/sui_zklogin_credential_store_test"
echo "StopWatch Sui zkLogin credential store tests passed"
