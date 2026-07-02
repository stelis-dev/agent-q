#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_signing_preflight_order.sh

ESP-IDF must already be active in the shell so IDF_PATH points to the ESP-IDF
checkout. This host test composes the production route classifier, signing
ingress, request identity, response store, and Sui preparation helpers to verify
the critical signing preflight order by behavior:

  route -> state/session -> shallow params -> identity/replay -> preparation

It does not require hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"
DEFAULT_RUNTIME_DIR="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib"
CRYPTO_ROOT="${SIGNING_CRYPTO_ROOT:-${DEFAULT_RUNTIME_DIR}}"
MICROSUI_CORE="${CRYPTO_ROOT}/src/microsui_core"

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
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${MICROSUI_CORE}/byte_conversions.c" \
  "${RUNTIME_DIR}/base64.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.h" \
  "${COMMON_ROOT}/protocol/request_id.cpp" \
  "${RUNTIME_DIR}/session.cpp" \
  "${RUNTIME_DIR}/sign_request_identity.cpp" \
  "${RUNTIME_DIR}/payload_delivery_admission.cpp" \
  "${RUNTIME_DIR}/payload_delivery_primitives.cpp" \
  "${RUNTIME_DIR}/payload_delivery_store.cpp" \
  "${RUNTIME_DIR}/usb_signing_outcome_writer.cpp" \
  "${RUNTIME_DIR}/signing_preflight.cpp" \
  "${RUNTIME_DIR}/signing_retry_response.cpp" \
  "${RUNTIME_DIR}/sign_personal_message_user_ingress.cpp" \
  "${RUNTIME_DIR}/sign_personal_message_user_validation.cpp" \
  "${RUNTIME_DIR}/signing_retry_delivery.cpp" \
  "${RUNTIME_DIR}/sign_transaction_user_ingress.cpp" \
  "${RUNTIME_DIR}/sign_transaction_user_validation.cpp" \
  "${RUNTIME_DIR}/signing_response_store.cpp" \
  "${RUNTIME_DIR}/sui_signing_preparation.cpp" \
  "${COMMON_SUI_DIR}/offline_policy_facts.cpp" \
  "${COMMON_SUI_DIR}/sign_transaction_adapter.cpp" \
  "${COMMON_SUI_DIR}/transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/bcs_reader.cpp" \
  "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/synthetic_swap_shape_tx.bcs.hex"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
CC_BIN="${CC:-cc}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-signing-preflight-order.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/firmware_common"
mkdir -p "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/firmware_common/sui"

cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

#include "protocol/sign_route.h"
#include "sign_transaction_user_ingress.h"
#include "signing_preflight.h"
#include "sign_request_identity.h"
#include "signing_retry_response.h"
#include "signing_response_store.h"
#include "protocol/device_contract.h"
#include "protocol/protocol_constants.h"
#include "usb_signing_outcome_writer.h"
#include "sui_account_store.h"
#include "sui_signing_authority.h"
#include "sui_signing_preparation.h"
#include "sui_zklogin_proof_store.h"

extern "C" {
#include "byte_conversions.h"
}

namespace {

int g_failures = 0;
int g_session_calls = 0;
int g_digest_calls = 0;
int g_binding_calls = 0;
signing::SuiActiveIdentityKind g_active_identity_kind =
    signing::SuiActiveIdentityKind::native;
char g_zklogin_network[signing::kSuiNetworkBufferSize] = "devnet";

signing::SessionValidationResult g_session_result =
    signing::SessionValidationResult::ok;
signing::SuiSigningAccountBindingResult g_binding_result =
    signing::SuiSigningAccountBindingResult::ok;
signing::AuthorizationMode g_signing_mode =
    signing::AuthorizationMode::user;
signing::RetryDeliveryStatus g_retry_status =
    signing::RetryDeliveryStatus::not_found;
signing::SuiSigningPreparationResult g_last_preparation_result =
    signing::SuiSigningPreparationResult::ok;
int g_retry_response_write_calls = 0;
std::string g_retry_response_json;

enum class PreflightOutcome {
    ok_prepared,
    route_invalid_params,
    route_unsupported_chain,
    route_unsupported_method,
    ingress_invalid_state,
    ingress_busy,
    ingress_invalid_session,
    ingress_invalid_tx_bytes,
    identity_error,
    replay_match,
    replay_conflict,
    network_mismatch,
    preparation_error,
    preparation_payload_too_large,
    payload_unavailable,
};

int hex_value(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return 10 + value - 'a';
    }
    if (value >= 'A' && value <= 'F') {
        return 10 + value - 'A';
    }
    return -1;
}

std::vector<uint8_t> read_hex(const char* path)
{
    FILE* file = fopen(path, "rb");
    assert(file != nullptr);
    std::string hex;
    int ch = 0;
    while ((ch = fgetc(file)) != EOF) {
        if (!isspace(ch)) {
            hex.push_back(static_cast<char>(ch));
        }
    }
    fclose(file);
    assert((hex.size() % 2) == 0);
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t index = 0; index < bytes.size(); ++index) {
        const int high = hex_value(hex[index * 2]);
        const int low = hex_value(hex[index * 2 + 1]);
        assert(high >= 0 && low >= 0);
        bytes[index] = static_cast<uint8_t>((high << 4) | low);
    }
    return bytes;
}

std::string base64(const std::vector<uint8_t>& bytes)
{
    std::string out(((bytes.size() + 2) / 3) * 4 + 1, '\0');
    assert(bytes_to_base64(bytes.data(), bytes.size(), out.data(), out.size()) == 0);
    out.resize(strlen(out.c_str()));
    return out;
}

JsonDocument parse_json(const std::string& json)
{
    JsonDocument document;
    const DeserializationError error = deserializeJson(document, json.c_str());
    assert(!error);
    assert(!document.overflowed());
    return document;
}

std::string request_json(
    const char* request_id,
    const char* session_id,
    const char* chain,
    const char* method,
    const char* network,
    const char* tx_bytes)
{
    (void)method;
    return std::string("{\"id\":\"") + request_id +
           "\",\"version\":1,\"method\":\"sign_transaction\"," +
           "\"sessionId\":\"" + session_id + "\"," +
           "\"payload\":{\"chain\":\"" + chain + "\",\"network\":\"" + network +
           "\",\"txBytes\":\"" + tx_bytes + "\"}}";
}

signing::SessionValidationResult validate_session(
    const char* session_id,
    void*)
{
    ++g_session_calls;
    if (strcmp(session_id, "session_aaaaaaaaaaaaaaaa") != 0) {
        return signing::SessionValidationResult::mismatch;
    }
    return g_session_result;
}

signing::PayloadDeliveryAdmissionDecision admit_payload_delivery(
    const signing::PayloadDeliveryOperationAdmissionInput& input)
{
    return signing::payload_delivery_admit_operation(input);
}

signing::SignTransactionUserIngressState state(bool material_ready, bool busy)
{
    return signing::SignTransactionUserIngressState{
        0,
        material_ready,
        busy,
        validate_session,
        nullptr,
        admit_payload_delivery,
    };
}

PreflightOutcome preflight_result_outcome(
    signing::PreflightResult result,
    const signing::SignTransactionPreflightOutput& output)
{
    switch (result) {
        case signing::PreflightResult::ok:
            return PreflightOutcome::ok_prepared;
        case signing::PreflightResult::route_invalid_params:
            return PreflightOutcome::route_invalid_params;
        case signing::PreflightResult::route_unsupported_chain:
            return PreflightOutcome::route_unsupported_chain;
        case signing::PreflightResult::route_unsupported_method:
            return PreflightOutcome::route_unsupported_method;
        case signing::PreflightResult::transaction_ingress_error:
            switch (output.ingress_result) {
                case signing::SignTransactionUserIngressResult::invalid_state:
                    return PreflightOutcome::ingress_invalid_state;
                case signing::SignTransactionUserIngressResult::busy:
                    return PreflightOutcome::ingress_busy;
                case signing::SignTransactionUserIngressResult::invalid_session:
                    return PreflightOutcome::ingress_invalid_session;
                case signing::SignTransactionUserIngressResult::invalid_tx_bytes:
                    return PreflightOutcome::ingress_invalid_tx_bytes;
                default:
                    return PreflightOutcome::identity_error;
            }
        case signing::PreflightResult::retry_consumed:
            if (g_retry_status == signing::RetryDeliveryStatus::match) {
                return PreflightOutcome::replay_match;
            }
            if (g_retry_status ==
                signing::RetryDeliveryStatus::request_id_conflict) {
                return PreflightOutcome::replay_conflict;
            }
            return PreflightOutcome::identity_error;
        case signing::PreflightResult::transaction_preparation_error:
            if (output.preparation_result ==
                signing::SuiSigningPreparationResult::invalid_network) {
                return PreflightOutcome::network_mismatch;
            }
            if (output.preparation_result ==
                signing::SuiSigningPreparationResult::payload_too_large) {
                return PreflightOutcome::preparation_payload_too_large;
            }
            if (output.preparation_result ==
                signing::SuiSigningPreparationResult::payload_unavailable) {
                return PreflightOutcome::payload_unavailable;
            }
            return PreflightOutcome::preparation_error;
        default:
            return PreflightOutcome::identity_error;
    }
}

bool read_signing_mode(
    signing::AuthorizationMode* mode,
    void*)
{
    assert(mode != nullptr);
    *mode = g_signing_mode;
    return true;
}

bool capture_retry_response(JsonDocument& response, void*)
{
    ++g_retry_response_write_calls;
    g_retry_response_json.clear();
    serializeJson(response, g_retry_response_json);
    return true;
}

signing::PreflightRetryDisposition respond_to_retry(
    const char* request_id,
    const char* method,
    const signing::RetryDeliveryResult& retry,
    const char* stored_response,
    void*)
{
    g_retry_status = retry.status;
    const signing::RetryResponseResult response_result =
        signing::deliver_signing_retry_response(
            request_id,
            method,
            retry,
            stored_response,
            capture_retry_response,
            nullptr);
    switch (response_result) {
        case signing::RetryResponseResult::not_found:
        case signing::RetryResponseResult::invalid_stored_response:
        case signing::RetryResponseResult::replay_write_failed:
            return signing::PreflightRetryDisposition::continue_preflight;
        case signing::RetryResponseResult::replayed_result:
        case signing::RetryResponseResult::error_response:
        case signing::RetryResponseResult::error_write_failed:
            return signing::PreflightRetryDisposition::consumed;
    }
    return signing::PreflightRetryDisposition::consumed;
}

PreflightOutcome run_transaction_preflight(
    const std::string& json,
    bool material_ready,
    bool busy)
{
    JsonDocument document = parse_json(json);
    signing::SignTransactionPreflightOutput output = {};
    char retry_stored_response[signing::kResponseMaxSize] = {};
    const signing::PreflightResult result =
        signing::evaluate_sign_transaction_preflight(
            document,
            state(material_ready, busy),
            signing::PreflightRuntime{
                0,
                read_signing_mode,
                nullptr,
                respond_to_retry,
                nullptr,
                retry_stored_response,
                sizeof(retry_stored_response),
            },
            &output);
    g_last_preparation_result = output.preparation_result;
    const PreflightOutcome outcome = preflight_result_outcome(result, output);
    signing::clear_prepared_sui_sign_transaction(&output.prepared);
    return outcome;
}

void reset_counters()
{
    g_session_calls = 0;
    g_digest_calls = 0;
    g_binding_calls = 0;
    g_active_identity_kind = signing::SuiActiveIdentityKind::native;
    snprintf(g_zklogin_network, sizeof(g_zklogin_network), "%s", "devnet");
    g_session_result = signing::SessionValidationResult::ok;
    g_binding_result = signing::SuiSigningAccountBindingResult::ok;
    g_signing_mode = signing::AuthorizationMode::user;
    g_retry_status = signing::RetryDeliveryStatus::not_found;
    g_retry_response_write_calls = 0;
    g_retry_response_json.clear();
    signing::signing_response_clear_all();
}

void expect_case(
    const char* label,
    PreflightOutcome actual,
    PreflightOutcome expected,
    int expected_session_calls,
    int expected_digest_calls,
    int expected_binding_calls)
{
    if (actual != expected ||
        g_session_calls != expected_session_calls ||
        g_digest_calls != expected_digest_calls ||
        g_binding_calls != expected_binding_calls) {
        fprintf(stderr,
                "%s: outcome/session/digest/binding = %d/%d/%d/%d, expected %d/%d/%d/%d\n",
                label,
                static_cast<int>(actual),
                g_session_calls,
                g_digest_calls,
                g_binding_calls,
                static_cast<int>(expected),
                expected_session_calls,
                expected_digest_calls,
                expected_binding_calls);
        fprintf(stderr,
                "%s: last preparation result = %d\n",
                label,
                static_cast<int>(g_last_preparation_result));
        ++g_failures;
    }
}

void expect_contains(const char* label, const std::string& value, const char* expected)
{
    if (value.find(expected) == std::string::npos) {
        fprintf(stderr, "%s: expected JSON to contain %s, got %s\n",
                label,
                expected,
                value.c_str());
        ++g_failures;
    }
}

void expect_no_stored_response(const char* label, const char* session_id, const char* request_id)
{
    char stored[signing::kResponseMaxSize] = {};
    size_t stored_len = 0;
    if (signing::signing_response_find(
            session_id,
            request_id,
            stored,
            sizeof(stored),
            &stored_len)) {
        fprintf(stderr, "%s: unexpected stored signing response\n", label);
        ++g_failures;
    }
}

void store_identity_for(
    const std::string& json,
    const char* stored_response)
{
    JsonDocument document = parse_json(json);
    const signing::SignRouteClassification classification =
        signing::classify_sign_route(
            signing::SignOperation::sign_transaction,
            document["payload"]["chain"].as<const char*>(),
            document["method"].as<const char*>());
    assert(classification.result == signing::SignRouteResult::ok);
    signing::SignTransactionUserIngressOutput ingress = {};
    assert(signing::evaluate_sign_transaction_user_ingress(
               document,
               classification.route,
               state(true, false),
               &ingress) == signing::SignTransactionUserIngressResult::ok);
    uint8_t identity[signing::kSignRequestIdentitySize] = {};
    assert(signing::sign_request_identity(
        classification.route,
        ingress.params.network,
        ingress.params.tx_bytes_base64,
        identity,
        sizeof(identity)));
    assert(signing::signing_response_store(
               ingress.session.session_id,
               ingress.envelope.request_id,
               identity,
               sizeof(identity),
               stored_response,
               strlen(stored_response)) == signing::ResponseStoreOutcome::stored);
    g_session_calls = 0;
}

}  // namespace

namespace signing {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool approval_history_digest_payload(
    const uint8_t* payload,
    size_t payload_size,
    char* digest_out,
    size_t digest_out_size)
{
    ++g_digest_calls;
    if (payload == nullptr || payload_size == 0 || digest_out_size < 72) {
        return false;
    }
    snprintf(digest_out, digest_out_size,
             "%s", "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    return true;
}

const char* user_signing_flow_terminal_status(UserSigningTerminalResult)
{
    return "failed";
}

const char* user_signing_flow_terminal_reason(UserSigningTerminalResult)
{
    return "signing_failed";
}

bool usb_response_write_json(JsonDocument& response)
{
    (void)response;
    return true;
}

bool device_response_prepare_success_result(
    JsonDocument& response,
    const char* id,
    const char* method,
    JsonObjectConst result)
{
    if (method == nullptr || method[0] == '\0' || result.isNull()) {
        return false;
    }
    response.clear();
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["success"] = true;
    response["method"] = method;
    response["result"].set(result);
    return true;
}

bool device_response_prepare_method_error(
    JsonDocument& response,
    const char* id,
    const char* method,
    const char* code)
{
    const DeviceErrorRow* error = device_error_row(code);
    if (error == nullptr) {
        error = device_error_row("unknown_error");
    }
    if (error == nullptr) {
        return false;
    }
    response.clear();
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["success"] = false;
    if (method != nullptr && method[0] != '\0') {
        response["method"] = method;
    }
    response["error"]["code"] = error->code;
    response["error"]["message"] = error->message;
    response["error"]["retryable"] = error->retryable;
    return true;
}

bool usb_response_write_method_error(
    const char* id,
    const char* method,
    const char* code)
{
    JsonDocument response;
    if (!device_response_prepare_method_error(response, id, method, code)) {
        return false;
    }
    return usb_response_write_json(response);
}

bool usb_response_write_error(const char* id, const char* code)
{
    (void)id;
    (void)code;
    return true;
}

SuiSigningAccountBindingResult verify_sui_signing_active_account_binding(
    const SuiPolicySubjectFacts&,
    const SuiActiveIdentity&,
    const SuiAccountSettings&)
{
    ++g_binding_calls;
    return g_binding_result;
}

bool read_sui_account_settings(SuiAccountSettings* settings)
{
    if (settings == nullptr) {
        return false;
    }
    settings->accept_gas_sponsor = true;
    return true;
}

SuiSigningActiveIdentityNetworkResult verify_sui_signing_active_identity_network(
    const SuiActiveIdentity& active_identity,
    const char* request_network)
{
    if (active_identity.kind == SuiActiveIdentityKind::error) {
        return active_identity.error == SuiActiveIdentityError::native_account_unavailable
                   ? SuiSigningActiveIdentityNetworkResult::account_unavailable
                   : SuiSigningActiveIdentityNetworkResult::active_identity_unavailable;
    }
    if (active_identity.kind == SuiActiveIdentityKind::zklogin) {
        if (request_network == nullptr || request_network[0] == '\0') {
            return SuiSigningActiveIdentityNetworkResult::network_mismatch;
        }
        return strcmp(active_identity.zklogin.network, request_network) == 0
                   ? SuiSigningActiveIdentityNetworkResult::ok
                   : SuiSigningActiveIdentityNetworkResult::network_mismatch;
    }
    return active_identity.kind == SuiActiveIdentityKind::native
               ? SuiSigningActiveIdentityNetworkResult::ok
               : SuiSigningActiveIdentityNetworkResult::active_identity_unavailable;
}

SuiSigningActiveIdentityNetworkResult verify_sui_signing_active_identity_network(
    const char* request_network)
{
    return verify_sui_signing_active_identity_network(resolve_active_sui_identity(), request_network);
}

SuiAccountDerivationResult derive_sui_ed25519_account_from_stored_root(
    uint8_t* public_key,
    char* address,
    size_t address_size)
{
    memset(public_key, 0xA5, kSuiEd25519PublicKeyBytes);
    snprintf(address, address_size,
             "%s", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    return SuiAccountDerivationResult::ok;
}

SuiActiveIdentity resolve_active_sui_identity()
{
    SuiActiveIdentity identity = {};
    identity.kind = g_active_identity_kind;
    identity.error = SuiActiveIdentityError::none;
    snprintf(identity.address,
             sizeof(identity.address),
             "%s",
             "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    identity.public_key[0] = identity.kind == SuiActiveIdentityKind::zklogin
                                 ? kSuiSignatureSchemeFlagZkLogin
                                 : kSuiSignatureSchemeFlagEd25519;
    memset(identity.public_key + 1, 0xA5, kSuiEd25519PublicKeyBytes);
    identity.public_key_size = identity.kind == SuiActiveIdentityKind::zklogin
                                   ? kSuiZkLoginPublicKeyMinBytes
                                   : kSuiEd25519PublicKeyBytes + 1;
    if (identity.kind == SuiActiveIdentityKind::zklogin) {
        snprintf(identity.zklogin.network, sizeof(identity.zklogin.network), "%s", g_zklogin_network);
    }
    return identity;
}

}  // namespace signing

int main(int argc, char** argv)
{
    assert(argc == 3);
    const std::vector<uint8_t> valid = read_hex(argv[1]);
    const std::vector<uint8_t> large_valid = read_hex(argv[2]);
    const std::string valid_b64 = base64(valid);
    const std::string large_valid_b64 = base64(large_valid);
    const std::string valid_request =
        request_json(
            "req_sign_1",
            "session_aaaaaaaaaaaaaaaa",
            "sui",
            "sign_transaction",
            "devnet",
            valid_b64.c_str());
    reset_counters();
    expect_case(
        "unsupported chain stops before state/session",
        run_transaction_preflight(
            request_json(
                "req_sign_1",
                "session_aaaaaaaaaaaaaaaa",
                "evm",
                "sign_transaction",
                "devnet",
                valid_b64.c_str()),
            false,
            false),
        PreflightOutcome::route_unsupported_chain,
        0,
        0,
        0);

    reset_counters();
    expect_case(
        "wrong state stops before session, params, replay, and preparation",
        run_transaction_preflight(
            request_json(
                "req_sign_1",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                "%%%"),
            false,
            false),
        PreflightOutcome::ingress_invalid_state,
        0,
        0,
        0);

    reset_counters();
    expect_case(
        "invalid base64 runs after session but before replay/preparation",
        run_transaction_preflight(
            request_json(
                "req_sign_1",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                "%%%"),
            true,
            false),
        PreflightOutcome::ingress_invalid_tx_bytes,
        1,
        0,
        0);

    reset_counters();
    store_identity_for(
        valid_request,
        "{\"version\":1,\"success\":true,\"method\":\"sign_transaction\","
        "\"result\":{\"authorization\":\"user\",\"chain\":\"sui\","
        "\"method\":\"sign_transaction\",\"signature\":\"sig\"}}");
    expect_case(
        "matching retry replays before preparation",
        run_transaction_preflight(valid_request, true, false),
        PreflightOutcome::replay_match,
        1,
        0,
        0);
    if (g_retry_response_write_calls != 1) {
        fprintf(stderr, "matching retry: expected one public JSON response, got %d\n",
                g_retry_response_write_calls);
        ++g_failures;
    }
    expect_contains("matching retry response", g_retry_response_json, "\"success\":true");
    expect_contains("matching retry response", g_retry_response_json, "\"method\":\"sign_transaction\"");
    expect_contains("matching retry response", g_retry_response_json, "\"signature\":\"sig\"");

    reset_counters();
    store_identity_for(
        valid_request,
        "{\"version\":1,\"success\":false,\"method\":\"sign_transaction\","
        "\"error\":{\"code\":\"signing_failed\","
        "\"message\":\"The device could not produce a signature.\",\"retryable\":false}}");
    expect_case(
        "matching signing_failed retry replays terminal failure without preparation",
        run_transaction_preflight(valid_request, true, false),
        PreflightOutcome::replay_match,
        1,
        0,
        0);
    if (g_retry_response_write_calls != 1) {
        fprintf(stderr,
                "matching signing_failed retry: expected one public JSON response, got %d\n",
                g_retry_response_write_calls);
        ++g_failures;
    }
    expect_contains(
        "matching signing_failed retry response",
        g_retry_response_json,
        "\"success\":false");
    expect_contains(
        "matching signing_failed retry response",
        g_retry_response_json,
        "\"code\":\"signing_failed\"");

    reset_counters();
    store_identity_for(
        valid_request,
        "{\"version\":1,\"success\":true,\"method\":\"sign_transaction\","
        "\"result\":{\"authorization\":\"user\",\"chain\":\"sui\","
        "\"method\":\"sign_transaction\",\"signature\":\"sig\"}}");
    expect_case(
        "conflicting retry stops before preparation",
        run_transaction_preflight(
            request_json(
                "req_sign_1",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                "AQID"),
            true,
            false),
        PreflightOutcome::replay_conflict,
        1,
        0,
        0);
    if (g_retry_response_write_calls != 1) {
        fprintf(stderr, "conflicting retry: expected one public JSON response, got %d\n",
                g_retry_response_write_calls);
        ++g_failures;
    }
    expect_contains("conflicting retry response", g_retry_response_json, "\"success\":false");
    expect_contains("conflicting retry response", g_retry_response_json, "request_id_conflict");

    reset_counters();
    store_identity_for(
        valid_request,
        "{\"version\":1,\"success\":true,\"method\":\"sign_transaction\","
        "\"result\":{\"authorization\":\"user\",\"chain\":\"sui\","
        "\"method\":\"sign_transaction\",\"signature\":\"sig\"}}");
    expect_case(
        "invalid current request shape cannot replay a stored response",
        run_transaction_preflight(
            request_json(
                "req_sign_1",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                "%%%"),
            true,
            false),
        PreflightOutcome::ingress_invalid_tx_bytes,
        1,
        0,
        0);
    if (g_retry_response_write_calls != 0) {
        fprintf(stderr,
                "invalid current request shape: unexpected retry response count %d\n",
                g_retry_response_write_calls);
        ++g_failures;
    }

    reset_counters();
    g_active_identity_kind = signing::SuiActiveIdentityKind::zklogin;
    snprintf(g_zklogin_network, sizeof(g_zklogin_network), "%s", "testnet");
    expect_case(
        "zkLogin network mismatch stops before transaction preparation",
        run_transaction_preflight(valid_request, true, false),
        PreflightOutcome::network_mismatch,
        1,
        0,
        0);

    reset_counters();
    expect_case(
        "fresh valid request reaches preparation",
        run_transaction_preflight(valid_request, true, false),
        PreflightOutcome::ok_prepared,
        1,
        1,
        1);

    reset_counters();
    expect_case(
        "fresh transaction above removed inline cap reaches preparation",
        run_transaction_preflight(
            request_json(
                "req_above_inline_cap",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                large_valid_b64.c_str()),
            true,
            false),
        PreflightOutcome::ok_prepared,
        1,
        1,
        1);

    reset_counters();
    const std::vector<uint8_t> malformed_tx(
        512,
        0x42);
    const std::string malformed_b64 = base64(malformed_tx);
    expect_case(
        "malformed prepared payload fails without buffering a result",
        run_transaction_preflight(
            request_json(
                "req_sign_malformed",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                malformed_b64.c_str()),
            true,
            false),
        PreflightOutcome::preparation_error,
        1,
        1,
        0);
    expect_no_stored_response(
        "malformed prepared payload",
        "session_aaaaaaaaaaaaaaaa",
        "req_sign_malformed");

    if (g_failures != 0) {
        fprintf(stderr, "signing preflight order tests failed: %d\n", g_failures);
        return 1;
    }
    printf("Signing preflight order tests passed\n");
    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${MICROSUI_CORE}" \
  -c "${MICROSUI_CORE}/byte_conversions.c" \
  -o "${TMP_DIR}/byte_conversions.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${TMP_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_SUI_DIR}" \
  -I"${MICROSUI_CORE}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/base64.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/request_id.cpp" \
  "${RUNTIME_DIR}/session.cpp" \
  "${RUNTIME_DIR}/sign_request_identity.cpp" \
  "${RUNTIME_DIR}/payload_delivery_admission.cpp" \
  "${RUNTIME_DIR}/payload_delivery_primitives.cpp" \
  "${RUNTIME_DIR}/payload_delivery_store.cpp" \
  "${RUNTIME_DIR}/usb_signing_outcome_writer.cpp" \
  "${RUNTIME_DIR}/signing_preflight.cpp" \
  "${RUNTIME_DIR}/signing_retry_response.cpp" \
  "${RUNTIME_DIR}/sign_personal_message_user_ingress.cpp" \
  "${RUNTIME_DIR}/sign_personal_message_user_validation.cpp" \
  "${RUNTIME_DIR}/signing_retry_delivery.cpp" \
  "${RUNTIME_DIR}/sign_transaction_user_ingress.cpp" \
  "${RUNTIME_DIR}/sign_transaction_user_validation.cpp" \
  "${RUNTIME_DIR}/signing_response_store.cpp" \
  "${RUNTIME_DIR}/sui_signing_preparation.cpp" \
  "${COMMON_SUI_DIR}/offline_policy_facts.cpp" \
  "${COMMON_SUI_DIR}/sign_transaction_adapter.cpp" \
  "${COMMON_SUI_DIR}/transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/bcs_reader.cpp" \
  "${TMP_DIR}/byte_conversions.o" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test" \
  "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/synthetic_swap_shape_tx.bcs.hex"
