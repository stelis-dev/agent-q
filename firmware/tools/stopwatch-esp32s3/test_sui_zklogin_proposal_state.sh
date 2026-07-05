#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime"
COMMON_DIR="${REPO_ROOT}/firmware/src/common"
CRYPTO_ROOT="${SIGNING_CRYPTO_ROOT:-${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib}"
MICROSUI_CORE="${CRYPTO_ROOT}/src/microsui_core"
IDF_PATH="${FIRMWARE_IDF_PATH:-${REPO_ROOT}/.WORK/toolchains/esp-idf-v5.5.4}"
MBEDTLS_ROOT="${IDF_PATH}/components/mbedtls/mbedtls"
MBEDTLS_INCLUDE_DIR="${MBEDTLS_ROOT}/include"
MBEDTLS_LIBRARY_DIR="${MBEDTLS_ROOT}/library"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stopwatch-esp32s3/M5StopWatch-UserDemo/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-zklogin-proposal-state.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${MICROSUI_CORE}/byte_conversions.c" \
  "${MICROSUI_CORE}/key_management.c" \
  "${MICROSUI_CORE}/lib/monocypher/monocypher.c" \
  "${MBEDTLS_INCLUDE_DIR}/mbedtls/sha256.h" \
  "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  "${COMMON_DIR}/protocol/base64.cpp" \
  "${COMMON_DIR}/protocol/request_id.cpp" \
  "${COMMON_DIR}/sui/zklogin_credential_outcome.cpp" \
  "${COMMON_DIR}/sui/zklogin_proof_record.cpp" \
  "${RUNTIME_DIR}/protocol_input_encoding.cpp" \
  "${RUNTIME_DIR}/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/sui_public_material.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_credential_store.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_proposal_state.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stopwatch-esp32s3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

cat >"${TMP_DIR}/sui_zklogin_proposal_state_test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sensitive_memory.h"
#include "sui_zklogin_proposal_state.h"

extern "C" {
#include "byte_conversions.h"
}

using namespace stopwatch_target;

namespace {

constexpr const char* kIssuer = "https://accounts.google.com";
constexpr const char* kIssuerBase64Details = "ImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSJ9";

void fill_seed(uint8_t seed[kSuiEd25519SeedBytes])
{
    for (size_t index = 0; index < kSuiEd25519SeedBytes; ++index) {
        seed[index] = static_cast<uint8_t>(index + 1);
    }
}

void add_proof_point_vector(JsonArray array, size_t count, unsigned start)
{
    for (size_t index = 0; index < count; ++index) {
        char value[8] = {};
        snprintf(value, sizeof(value), "%u", start + static_cast<unsigned>(index));
        array.add(value);
    }
}

void add_valid_inputs(JsonObject inputs)
{
    JsonObject proof_points = inputs["proofPoints"].to<JsonObject>();
    add_proof_point_vector(proof_points["a"].to<JsonArray>(), kSuiZkLoginProofPointACount, 1);
    JsonArray b = proof_points["b"].to<JsonArray>();
    for (size_t row = 0; row < kSuiZkLoginProofPointBOuterCount; ++row) {
        add_proof_point_vector(
            b.add<JsonArray>(),
            kSuiZkLoginProofPointBInnerCount,
            10 + static_cast<unsigned>(row * kSuiZkLoginProofPointBInnerCount));
    }
    add_proof_point_vector(proof_points["c"].to<JsonArray>(), kSuiZkLoginProofPointCCount, 20);

    JsonObject details = inputs["issBase64Details"].to<JsonObject>();
    details["value"] = kIssuerBase64Details;
    details["indexMod4"] = 0;
    inputs["headerBase64"] = "eyJhbGciOiJSUzI1NiJ9";
    inputs["addressSeed"] = "1";
}

void build_valid_payload(JsonDocument& doc)
{
    doc.clear();
    JsonObject payload = doc.to<JsonObject>();
    payload["chain"] = "sui";
    payload["credential"] = "zklogin";
    payload["network"] = "testnet";
    payload["maxEpoch"] = "123";

    uint8_t public_key[kSuiZkLoginPublicKeyMaxBytes] = {};
    const size_t issuer_len = strlen(kIssuer);
    public_key[0] = kSuiSignatureSchemeFlagZkLogin;
    public_key[1] = static_cast<uint8_t>(issuer_len);
    memcpy(public_key + 2, kIssuer, issuer_len);
    public_key[2 + issuer_len + 31] = 1;
    const size_t public_key_size = 2 + issuer_len + 32;

    char address[kSuiAddressBufferSize] = {};
    assert(derive_sui_address_from_scheme_prefixed_public_key(
        public_key,
        public_key_size,
        address,
        sizeof(address)));
    payload["address"] = address;

    char public_key_base64[((kSuiZkLoginPublicKeyMaxBytes + 2) / 3) * 4 + 1] = {};
    assert(bytes_to_base64(
               public_key,
               public_key_size,
               public_key_base64,
               sizeof(public_key_base64)) == 0);
    payload["publicKey"] = public_key_base64;

    add_valid_inputs(payload["inputs"].to<JsonObject>());
}

void expect_terminal_strings()
{
    assert(strcmp(sui_zklogin_proposal_terminal_status(
                      SuiZkLoginProposalTerminalResult::activated),
                  "activated") == 0);
    assert(strcmp(sui_zklogin_proposal_terminal_status(
                      SuiZkLoginProposalTerminalResult::invalid_proof),
                  "invalid_proof") == 0);
    assert(strcmp(sui_zklogin_proposal_terminal_reason(
                      SuiZkLoginProposalTerminalResult::activated),
                  "device_confirmed") == 0);
    assert(strcmp(sui_zklogin_proposal_terminal_reason(
                      SuiZkLoginProposalTerminalResult::invalid_proof),
                  "invalid_proof") == 0);
    assert(sui_zklogin_proposal_terminal_ends_session(
        SuiZkLoginProposalTerminalResult::activated));
    assert(sui_zklogin_proposal_terminal_ends_session(
        SuiZkLoginProposalTerminalResult::consistency_error));
    assert(!sui_zklogin_proposal_terminal_ends_session(
        SuiZkLoginProposalTerminalResult::invalid_proof));
    assert(!sui_zklogin_proposal_terminal_ends_session(
        SuiZkLoginProposalTerminalResult::storage_error));
}

signing::TimeoutWindow proposal_window(uint32_t now_ms)
{
    return signing::timeout_window_from_deadline(
        now_ms,
        now_ms + kSuiZkLoginProposalWindowMs);
}

void begin_valid(JsonDocument& payload, const uint8_t seed[kSuiEd25519SeedBytes])
{
    assert(sui_zklogin_proposal_state_begin(
               payload.as<JsonVariantConst>(),
               "req_valid",
               "session_aaaaaaaaaaaaaaaa",
               100,
               proposal_window(100),
               seed) == SuiZkLoginProposalBeginResult::ok);
    SuiZkLoginProposalSnapshot snapshot = sui_zklogin_proposal_state_snapshot();
    assert(snapshot.active);
    assert(snapshot.stage == SuiZkLoginProposalStage::reviewing);
    assert(strcmp(snapshot.request_id, "req_valid") == 0);
    assert(strcmp(snapshot.session_id, "session_aaaaaaaaaaaaaaaa") == 0);
    assert(snapshot.request_window.started_at == 100);
    assert(snapshot.request_window.deadline == 100 + kSuiZkLoginProposalWindowMs);
    assert(strcmp(snapshot.network, "testnet") == 0);
    assert(strcmp(snapshot.issuer, kIssuer) == 0);
    assert(strcmp(snapshot.max_epoch, "123") == 0);
    assert(strncmp(snapshot.proof_hash, "sha256:", 7) == 0);
    assert(strlen(snapshot.proof_hash) == kSuiZkLoginProofHashBufferSize - 1);
}

void valid_commit_flow()
{
    sui_zklogin_credential_test_reset_store();
    sui_zklogin_proposal_state_clear();
    JsonDocument payload;
    build_valid_payload(payload);
    uint8_t seed[kSuiEd25519SeedBytes] = {};
    fill_seed(seed);

    begin_valid(payload, seed);
    assert(sui_zklogin_proposal_continue_to_auth(101) ==
           SuiZkLoginProposalTransitionResult::ok);
    assert(sui_zklogin_proposal_mark_auth_verifying() ==
           SuiZkLoginProposalTransitionResult::ok);
    assert(sui_zklogin_proposal_commit() ==
           SuiZkLoginProposalTerminalResult::activated);

    SuiZkLoginCredentialRecord stored = {};
    assert(read_sui_zklogin_credential(&stored) == SuiZkLoginCredentialStatus::active);
    assert(memcmp(stored.prepared_seed, seed, sizeof(stored.prepared_seed)) == 0);
    assert(strcmp(stored.proof.network, "testnet") == 0);
    assert(strcmp(stored.proof.issuer, kIssuer) == 0);
    wipe_sensitive_buffer(&stored, sizeof(stored));
    sui_zklogin_proposal_state_clear();
}

void invalid_payload_cases()
{
    sui_zklogin_credential_test_reset_store();
    uint8_t seed[kSuiEd25519SeedBytes] = {};
    fill_seed(seed);

    {
        JsonDocument payload;
        build_valid_payload(payload);
        payload["extra"] = "not-allowed";
        assert(sui_zklogin_proposal_state_begin(
                   payload.as<JsonVariantConst>(),
                   "req_extra",
                   "session_aaaaaaaaaaaaaaaa",
                   1,
                   proposal_window(1),
                   seed) == SuiZkLoginProposalBeginResult::invalid_proof);
        assert(!sui_zklogin_proposal_state_active());
    }
    {
        JsonDocument payload;
        build_valid_payload(payload);
        payload["network"] = "unsupported";
        assert(sui_zklogin_proposal_state_begin(
                   payload.as<JsonVariantConst>(),
                   "req_network",
                   "session_aaaaaaaaaaaaaaaa",
                   1,
                   proposal_window(1),
                   seed) == SuiZkLoginProposalBeginResult::invalid_proof);
        assert(!sui_zklogin_proposal_state_active());
    }
    {
        JsonDocument payload;
        build_valid_payload(payload);
        payload["address"] = "0x0000000000000000000000000000000000000000000000000000000000000000";
        assert(sui_zklogin_proposal_state_begin(
                   payload.as<JsonVariantConst>(),
                   "req_address",
                   "session_aaaaaaaaaaaaaaaa",
                   1,
                   proposal_window(1),
                   seed) == SuiZkLoginProposalBeginResult::invalid_proof);
        assert(!sui_zklogin_proposal_state_active());
    }
    {
        JsonDocument payload;
        build_valid_payload(payload);
        payload["inputs"]["extra"] = "not-allowed";
        assert(sui_zklogin_proposal_state_begin(
                   payload.as<JsonVariantConst>(),
                   "req_inputs",
                   "session_aaaaaaaaaaaaaaaa",
                   1,
                   proposal_window(1),
                   seed) == SuiZkLoginProposalBeginResult::invalid_proof);
        assert(!sui_zklogin_proposal_state_active());
    }
}

void transition_and_failure_cases()
{
    uint8_t seed[kSuiEd25519SeedBytes] = {};
    fill_seed(seed);
    JsonDocument payload;
    build_valid_payload(payload);

    sui_zklogin_proposal_state_clear();
    assert(sui_zklogin_proposal_commit() ==
           SuiZkLoginProposalTerminalResult::invalid_state);
    assert(sui_zklogin_proposal_state_begin(
               payload.as<JsonVariantConst>(),
               "req_timeout",
               "session_aaaaaaaaaaaaaaaa",
               100,
               proposal_window(100),
               seed) == SuiZkLoginProposalBeginResult::ok);
    assert(sui_zklogin_proposal_continue_to_auth(100 + kSuiZkLoginProposalWindowMs) ==
           SuiZkLoginProposalTransitionResult::timed_out);
    assert(sui_zklogin_proposal_record_timed_out() ==
           SuiZkLoginProposalTerminalResult::timed_out);
    sui_zklogin_proposal_state_clear();

    sui_zklogin_credential_test_reset_store();
    sui_zklogin_credential_test_set_write_failure(true);
    build_valid_payload(payload);
    begin_valid(payload, seed);
    assert(sui_zklogin_proposal_continue_to_auth(101) ==
           SuiZkLoginProposalTransitionResult::ok);
    assert(sui_zklogin_proposal_mark_auth_verifying() ==
           SuiZkLoginProposalTransitionResult::ok);
    assert(sui_zklogin_proposal_commit() ==
           SuiZkLoginProposalTerminalResult::storage_error);
    sui_zklogin_credential_test_set_write_failure(false);
    sui_zklogin_proposal_state_clear();
}

void deadline_wrap_cases()
{
    uint8_t seed[kSuiEd25519SeedBytes] = {};
    fill_seed(seed);
    JsonDocument payload;
    build_valid_payload(payload);

    const uint32_t zero_deadline_start = 0u - kSuiZkLoginProposalWindowMs;
    sui_zklogin_proposal_state_clear();
    assert(sui_zklogin_proposal_state_begin(
               payload.as<JsonVariantConst>(),
               "req_zero_deadline",
               "session_aaaaaaaaaaaaaaaa",
               zero_deadline_start,
               proposal_window(zero_deadline_start),
               seed) == SuiZkLoginProposalBeginResult::invalid_argument);
    assert(!sui_zklogin_proposal_state_active());

    const uint32_t wrapped_deadline_start = zero_deadline_start + 1;
    assert(sui_zklogin_proposal_state_begin(
               payload.as<JsonVariantConst>(),
               "req_wrapped_deadline",
               "session_aaaaaaaaaaaaaaaa",
               wrapped_deadline_start,
               proposal_window(wrapped_deadline_start),
               seed) == SuiZkLoginProposalBeginResult::ok);
    SuiZkLoginProposalSnapshot snapshot = sui_zklogin_proposal_state_snapshot();
    assert(snapshot.active);
    assert(snapshot.request_window.deadline == 1);
    assert(!sui_zklogin_proposal_deadline_reached(0));
    assert(sui_zklogin_proposal_deadline_reached(1));
    assert(sui_zklogin_proposal_continue_to_auth(1) ==
           SuiZkLoginProposalTransitionResult::timed_out);
    sui_zklogin_proposal_state_clear();
}

}  // namespace

int main()
{
    sui_zklogin_credential_test_reset_store();
    sui_zklogin_proposal_state_init();
    expect_terminal_strings();
    valid_commit_flow();
    invalid_payload_cases();
    transition_and_failure_cases();
    deadline_wrap_cases();
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
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -DSTOPWATCH_ZKLOGIN_CREDENTIAL_STORE_HOST_TEST \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_DIR}" \
  -I"${MICROSUI_CORE}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/sui_zklogin_proposal_state_test.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_proposal_state.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_credential_store.cpp" \
  "${RUNTIME_DIR}/protocol_input_encoding.cpp" \
  "${RUNTIME_DIR}/sui_public_material.cpp" \
  "${RUNTIME_DIR}/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${COMMON_DIR}/protocol/base64.cpp" \
  "${COMMON_DIR}/protocol/request_id.cpp" \
  "${COMMON_DIR}/sui/zklogin_credential_outcome.cpp" \
  "${COMMON_DIR}/sui/zklogin_proof_record.cpp" \
  "${TMP_DIR}/byte_conversions.o" \
  "${TMP_DIR}/key_management.o" \
  "${TMP_DIR}/monocypher.o" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/sui_zklogin_proposal_state_test"

"${TMP_DIR}/sui_zklogin_proposal_state_test"
echo "StopWatch Sui zkLogin proposal state tests passed"
