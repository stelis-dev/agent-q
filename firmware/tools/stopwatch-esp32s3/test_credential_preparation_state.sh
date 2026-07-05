#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CRYPTO_ROOT="${SIGNING_CRYPTO_ROOT:-${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib}"
MICROSUI_CORE="${CRYPTO_ROOT}/src/microsui_core"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-credential-prep.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

for required in \
  "${MICROSUI_CORE}/byte_conversions.c" \
  "${MICROSUI_CORE}/key_management.c" \
  "${MICROSUI_CORE}/lib/monocypher/monocypher.c" \
  "${RUNTIME_DIR}/credential_preparation_state.cpp" \
  "${RUNTIME_DIR}/sui_public_material.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stopwatch-esp32s3/build.sh first, or set SIGNING_CRYPTO_ROOT." >&2
    exit 1
  fi
done

cat >"${TMP_DIR}/credential_preparation_state_test.cpp" <<'CPP'
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "credential_preparation_state.h"

using namespace stopwatch_target;

namespace {

bool fill_sequence(void* output, size_t size, void* context)
{
    uint8_t* cursor = static_cast<uint8_t*>(output);
    uint8_t* value = static_cast<uint8_t*>(context);
    if (cursor == nullptr || value == nullptr) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        cursor[index] = static_cast<uint8_t>((*value)++);
    }
    return true;
}

bool fail_random(void*, size_t, void*)
{
    return false;
}

}  // namespace

int main()
{
    credential_preparation_state_init();
    CredentialPreparationSnapshot empty = credential_preparation_snapshot();
    assert(!empty.active);
    assert(strcmp(empty.session_id, "") == 0);

    uint8_t counter = 0;
    assert(credential_preparation_begin("bad", fill_sequence, &counter) ==
           CredentialPreparationBeginResult::invalid_session);
    assert(!credential_preparation_snapshot().active);

    assert(credential_preparation_begin("session_0011223344556677", fail_random, nullptr) ==
           CredentialPreparationBeginResult::rng_error);
    assert(!credential_preparation_snapshot().active);

    assert(credential_preparation_begin("session_0011223344556677", fill_sequence, &counter) ==
           CredentialPreparationBeginResult::ok);
    CredentialPreparationSnapshot first = credential_preparation_snapshot();
    assert(first.active);
    assert(strcmp(first.session_id, "session_0011223344556677") == 0);
    assert(sui_address_format_valid(first.address));
    assert(strlen(first.public_key_base64) == 44);
    char first_public_key_base64[kSuiSchemePrefixedEd25519PublicKeyBase64Size] = {};
    strcpy(first_public_key_base64, first.public_key_base64);

    uint8_t seed[kSuiEd25519SeedBytes] = {};
    assert(!credential_preparation_copy_seed_for_session("session_8899aabbccddeeff", seed));
    assert(credential_preparation_copy_seed_for_session("session_0011223344556677", seed));
    for (size_t index = 0; index < sizeof(seed); ++index) {
        assert(seed[index] == index);
    }

    assert(credential_preparation_begin("session_8899aabbccddeeff", fill_sequence, &counter) ==
           CredentialPreparationBeginResult::ok);
    CredentialPreparationSnapshot second = credential_preparation_snapshot();
    assert(second.active);
    assert(strcmp(second.session_id, "session_8899aabbccddeeff") == 0);
    assert(strcmp(second.public_key_base64, first_public_key_base64) != 0);
    assert(!credential_preparation_copy_seed_for_session("session_0011223344556677", seed));

    assert(credential_preparation_begin("session_8899aabbccddeeff", fail_random, nullptr) ==
           CredentialPreparationBeginResult::rng_error);
    assert(!credential_preparation_snapshot().active);
    memset(seed, 0xA5, sizeof(seed));
    assert(!credential_preparation_copy_seed_for_session("session_8899aabbccddeeff", seed));
    for (size_t index = 0; index < sizeof(seed); ++index) {
        assert(seed[index] == 0);
    }

    credential_preparation_state_clear();
    assert(!credential_preparation_snapshot().active);

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
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${MICROSUI_CORE}" \
  "${TMP_DIR}/credential_preparation_state_test.cpp" \
  "${RUNTIME_DIR}/credential_preparation_state.cpp" \
  "${RUNTIME_DIR}/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/sui_public_material.cpp" \
  "${TMP_DIR}/byte_conversions.o" \
  "${TMP_DIR}/key_management.o" \
  "${TMP_DIR}/monocypher.o" \
  -o "${TMP_DIR}/credential_preparation_state_test"

"${TMP_DIR}/credential_preparation_state_test"
echo "StopWatch credential preparation state tests passed"
