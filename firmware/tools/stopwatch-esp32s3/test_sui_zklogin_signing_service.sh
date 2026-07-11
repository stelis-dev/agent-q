#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime"
COMMON_DIR="${REPO_ROOT}/firmware/src/common"
CRYPTO_ROOT="${SIGNING_CRYPTO_ROOT:-${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib}"
MICROSUI_CORE="${CRYPTO_ROOT}/src/microsui_core"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-zklogin-signing.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

for required in \
  "${MICROSUI_CORE}/byte_conversions.c" \
  "${MICROSUI_CORE}/key_management.c" \
  "${MICROSUI_CORE}/sign.c" \
  "${MICROSUI_CORE}/lib/monocypher/monocypher.c" \
  "${RUNTIME_DIR}/sui_zklogin_credential_store.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_signing_service.cpp" \
  "${RUNTIME_DIR}/sui_public_material.cpp" \
  "${COMMON_DIR}/sui/personal_message_intent.cpp" \
  "${COMMON_DIR}/sui/zklogin_proof_record.cpp" \
  "${COMMON_DIR}/sui/zklogin_signature.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stopwatch-esp32s3/build.sh first, or set SIGNING_CRYPTO_ROOT." >&2
    exit 1
  fi
done

cat >"${TMP_DIR}/sui_zklogin_signing_service_test.cpp" <<'CPP'
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <vector>

#include "stopwatch_keystore.h"
#include "sui_zklogin_credential_store.h"
#include "sui_zklogin_signing_service.h"

using namespace signing;
using namespace stopwatch_target;

namespace stopwatch_target {

std::vector<uint8_t> g_test_credential_blob;
KeystoreState g_test_keystore_state = KeystoreState::unlocked;

KeystoreState stopwatch_keystore_state()
{
    return g_test_keystore_state;
}

KeystoreOperationStatus stopwatch_keystore_credential_status()
{
    return g_test_credential_blob.empty()
        ? KeystoreOperationStatus::missing
        : KeystoreOperationStatus::success;
}

KeystoreOperationStatus stopwatch_keystore_with_credential(
    KeystoreRecordConsumer consumer,
    void* consumer_context)
{
    if (g_test_keystore_state != KeystoreState::unlocked) {
        return KeystoreOperationStatus::locked;
    }
    if (g_test_credential_blob.empty()) {
        return KeystoreOperationStatus::missing;
    }
    if (consumer == nullptr) {
        return KeystoreOperationStatus::invalid_input;
    }
    return consumer(
               g_test_credential_blob.data(),
               g_test_credential_blob.size(),
               consumer_context)
        ? KeystoreOperationStatus::success
        : KeystoreOperationStatus::consumer_failed;
}

KeystoreOperationStatus stopwatch_keystore_replace_credential(
    const uint8_t* plaintext,
    size_t plaintext_size)
{
    if (g_test_keystore_state != KeystoreState::unlocked) {
        return KeystoreOperationStatus::locked;
    }
    if (plaintext == nullptr || plaintext_size == 0) {
        return KeystoreOperationStatus::invalid_input;
    }
    g_test_credential_blob.assign(plaintext, plaintext + plaintext_size);
    return KeystoreOperationStatus::success;
}

}  // namespace stopwatch_target

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
    record.proof.public_key[0] = signing::kSuiSignatureSchemeFlagZkLogin;
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

void fill(uint8_t* output, size_t size, uint8_t value)
{
    assert(output != nullptr);
    memset(output, value, size);
}

}  // namespace

int main()
{
    g_test_credential_blob.clear();
    g_test_keystore_state = KeystoreState::unlocked;

    uint8_t signature[signing::kSuiSignatureEnvelopeMaxBytes] = {};
    size_t signature_size = 999;
    const uint8_t message[] = {'h', 'e', 'l', 'l', 'o'};
    assert(sign_sui_zklogin_personal_message(
               message,
               sizeof(message),
               signature,
               &signature_size) == SuiZkLoginSigningResult::account_unavailable);
    assert(signature_size == 0);

    SuiZkLoginCredentialRecord record = valid_record();
    assert(store_sui_zklogin_credential(&record) == SuiZkLoginCredentialWriteResult::stored);

    fill(signature, sizeof(signature), 0xff);
    signature_size = 0;
    assert(sign_sui_zklogin_personal_message(
               message,
               sizeof(message),
               signature,
               &signature_size) == SuiZkLoginSigningResult::ok);
    assert(signature_size > signing::kSuiEd25519SignatureBytes);
    assert(signature[0] == signing::kSuiSignatureSchemeFlagZkLogin);

    const uint8_t tx_bytes[] = {
        0x00, 0x01, 0x02, 0x03, 0x04,
    };
    fill(signature, sizeof(signature), 0xff);
    signature_size = 0;
    assert(sign_sui_zklogin_transaction(
               tx_bytes,
               sizeof(tx_bytes),
               signature,
               &signature_size) == SuiZkLoginSigningResult::ok);
    assert(signature_size > signing::kSuiEd25519SignatureBytes);
    assert(signature[0] == signing::kSuiSignatureSchemeFlagZkLogin);

    g_test_keystore_state = KeystoreState::locked;
    fill(signature, sizeof(signature), 0xff);
    signature_size = 123;
    assert(sign_sui_zklogin_transaction(
               tx_bytes,
               sizeof(tx_bytes),
               signature,
               &signature_size) == SuiZkLoginSigningResult::account_unavailable);
    assert(signature_size == 0);
    for (size_t index = 0; index < sizeof(signature); ++index) {
        assert(signature[index] == 0);
    }
    g_test_keystore_state = KeystoreState::unlocked;

    uint8_t digest[signing::kSuiPersonalMessageIntentDigestBytes] = {};
    assert(signing::build_sui_personal_message_intent_digest(message, sizeof(message), digest));
    uint8_t zero_digest[signing::kSuiPersonalMessageIntentDigestBytes] = {};
    assert(memcmp(digest, zero_digest, sizeof(digest)) != 0);

    fill(signature, sizeof(signature), 0xff);
    signature_size = 123;
    assert(sign_sui_zklogin_personal_message(
               nullptr,
               0,
               signature,
               &signature_size) == SuiZkLoginSigningResult::invalid_input);
    assert(signature_size == 0);
    for (size_t index = 0; index < sizeof(signature); ++index) {
        assert(signature[index] == 0);
    }

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
  -c "${MICROSUI_CORE}/sign.c" \
  -o "${TMP_DIR}/sign.o"
"${CC_BIN}" -std=c99 -I"${MICROSUI_CORE}" \
  -c "${MICROSUI_CORE}/lib/monocypher/monocypher.c" \
  -o "${TMP_DIR}/monocypher.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_DIR}" \
  -I"${MICROSUI_CORE}" \
  "${TMP_DIR}/sui_zklogin_signing_service_test.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_signing_service.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_credential_store.cpp" \
  "${RUNTIME_DIR}/sui_public_material.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${COMMON_DIR}/sui/personal_message_intent.cpp" \
  "${COMMON_DIR}/sui/zklogin_proof_record.cpp" \
  "${COMMON_DIR}/sui/zklogin_signature.cpp" \
  "${TMP_DIR}/byte_conversions.o" \
  "${TMP_DIR}/key_management.o" \
  "${TMP_DIR}/sign.o" \
  "${TMP_DIR}/monocypher.o" \
  -o "${TMP_DIR}/sui_zklogin_signing_service_test"

"${TMP_DIR}/sui_zklogin_signing_service_test"
echo "StopWatch Sui zkLogin signing service tests passed"
