#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_signing_preflight_order.sh

ESP-IDF must already be active in the shell so IDF_PATH points to the ESP-IDF
checkout. This host test composes the production route classifier, signing
ingress, request identity, result store, and Sui preparation helpers to verify
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
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"
DEFAULT_SIGNING_DIR="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib"
SIGNING_ROOT="${AGENT_Q_SIGNING_CRYPTO_ROOT:-${DEFAULT_SIGNING_DIR}}"
SIGNING_CORE="${SIGNING_ROOT}/src/microsui_core"

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
  "${SIGNING_CORE}/byte_conversions.c" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_request_identity.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_preflight.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_retry_response.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_ingress.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_retry_delivery.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_ingress.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_result_store.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_signing_preparation.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_sign_transaction_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
CC_BIN="${CC:-cc}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-signing-preflight-order.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "agent_q_sign_route.h"
#include "agent_q_sign_transaction_user_ingress.h"
#include "agent_q_signing_preflight.h"
#include "agent_q_sign_request_identity.h"
#include "agent_q_signing_retry_response.h"
#include "agent_q_signing_result_store.h"
#include "agent_q_sui_account_store.h"
#include "agent_q_sui_signing_authority.h"
#include "agent_q_sui_signing_preparation.h"

extern "C" {
#include "byte_conversions.h"
}

namespace {

int g_failures = 0;
int g_session_calls = 0;
int g_digest_calls = 0;
int g_binding_calls = 0;

agent_q::AgentQSessionValidationResult g_session_result =
    agent_q::AgentQSessionValidationResult::ok;
agent_q::AgentQSuiSigningAccountBindingResult g_binding_result =
    agent_q::AgentQSuiSigningAccountBindingResult::ok;
agent_q::AgentQSigningAuthorizationMode g_signing_mode =
    agent_q::AgentQSigningAuthorizationMode::user;
agent_q::AgentQSigningRetryDeliveryStatus g_retry_status =
    agent_q::AgentQSigningRetryDeliveryStatus::not_found;
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
    preparation_error,
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
    return std::string("{\"id\":\"") + request_id +
           "\",\"version\":1,\"type\":\"sign_transaction\"," +
           "\"sessionId\":\"" + session_id + "\"," +
           "\"chain\":\"" + chain + "\"," +
           "\"method\":\"" + method + "\"," +
           "\"params\":{\"network\":\"" + network + "\",\"txBytes\":\"" + tx_bytes + "\"}}";
}

agent_q::AgentQSessionValidationResult validate_session(
    const char* session_id,
    void*)
{
    ++g_session_calls;
    if (strcmp(session_id, "session_aaaaaaaaaaaaaaaa") != 0) {
        return agent_q::AgentQSessionValidationResult::mismatch;
    }
    return g_session_result;
}

agent_q::AgentQSignTransactionUserIngressState state(bool material_ready, bool busy)
{
    return agent_q::AgentQSignTransactionUserIngressState{
        material_ready,
        busy,
        validate_session,
        nullptr,
    };
}

PreflightOutcome preflight_result_outcome(
    agent_q::AgentQSigningPreflightResult result,
    const agent_q::AgentQSignTransactionPreflightOutput& output)
{
    switch (result) {
        case agent_q::AgentQSigningPreflightResult::ok:
            return PreflightOutcome::ok_prepared;
        case agent_q::AgentQSigningPreflightResult::route_invalid_params:
            return PreflightOutcome::route_invalid_params;
        case agent_q::AgentQSigningPreflightResult::route_unsupported_chain:
            return PreflightOutcome::route_unsupported_chain;
        case agent_q::AgentQSigningPreflightResult::route_unsupported_method:
            return PreflightOutcome::route_unsupported_method;
        case agent_q::AgentQSigningPreflightResult::transaction_ingress_error:
            switch (output.ingress_result) {
                case agent_q::AgentQSignTransactionUserIngressResult::invalid_state:
                    return PreflightOutcome::ingress_invalid_state;
                case agent_q::AgentQSignTransactionUserIngressResult::busy:
                    return PreflightOutcome::ingress_busy;
                case agent_q::AgentQSignTransactionUserIngressResult::invalid_session:
                    return PreflightOutcome::ingress_invalid_session;
                case agent_q::AgentQSignTransactionUserIngressResult::invalid_tx_bytes:
                    return PreflightOutcome::ingress_invalid_tx_bytes;
                default:
                    return PreflightOutcome::identity_error;
            }
        case agent_q::AgentQSigningPreflightResult::retry_consumed:
            if (g_retry_status == agent_q::AgentQSigningRetryDeliveryStatus::match) {
                return PreflightOutcome::replay_match;
            }
            if (g_retry_status ==
                agent_q::AgentQSigningRetryDeliveryStatus::request_id_conflict) {
                return PreflightOutcome::replay_conflict;
            }
            return PreflightOutcome::identity_error;
        case agent_q::AgentQSigningPreflightResult::transaction_preparation_error:
            return PreflightOutcome::preparation_error;
        default:
            return PreflightOutcome::identity_error;
    }
}

bool read_signing_mode(
    agent_q::AgentQSigningAuthorizationMode* mode,
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

agent_q::AgentQSigningPreflightRetryDisposition respond_to_retry(
    const char* request_id,
    const agent_q::AgentQSigningRetryDeliveryResult& retry,
    const char* stored_result,
    void*)
{
    g_retry_status = retry.status;
    const agent_q::AgentQSigningRetryResponseResult response_result =
        agent_q::deliver_signing_retry_response(
            request_id,
            retry,
            stored_result,
            capture_retry_response,
            nullptr);
    switch (response_result) {
        case agent_q::AgentQSigningRetryResponseResult::not_found:
        case agent_q::AgentQSigningRetryResponseResult::invalid_stored_result:
        case agent_q::AgentQSigningRetryResponseResult::replay_write_failed:
            return agent_q::AgentQSigningPreflightRetryDisposition::continue_preflight;
        case agent_q::AgentQSigningRetryResponseResult::replayed_result:
        case agent_q::AgentQSigningRetryResponseResult::error_response:
        case agent_q::AgentQSigningRetryResponseResult::error_write_failed:
            return agent_q::AgentQSigningPreflightRetryDisposition::consumed;
    }
    return agent_q::AgentQSigningPreflightRetryDisposition::consumed;
}

PreflightOutcome run_transaction_preflight(
    const std::string& json,
    bool material_ready,
    bool busy)
{
    JsonDocument document = parse_json(json);
    agent_q::AgentQSignTransactionPreflightOutput output = {};
    char retry_stored_result[agent_q::kSigningResultMaxSize] = {};
    const agent_q::AgentQSigningPreflightResult result =
        agent_q::evaluate_sign_transaction_preflight(
            document,
            state(material_ready, busy),
            agent_q::AgentQSigningPreflightRuntime{
                read_signing_mode,
                nullptr,
                respond_to_retry,
                nullptr,
                retry_stored_result,
                sizeof(retry_stored_result),
            },
            &output);
    const PreflightOutcome outcome = preflight_result_outcome(result, output);
    agent_q::clear_prepared_sui_sign_transaction(&output.prepared);
    return outcome;
}

void reset_counters()
{
    g_session_calls = 0;
    g_digest_calls = 0;
    g_binding_calls = 0;
    g_session_result = agent_q::AgentQSessionValidationResult::ok;
    g_binding_result = agent_q::AgentQSuiSigningAccountBindingResult::ok;
    g_signing_mode = agent_q::AgentQSigningAuthorizationMode::user;
    g_retry_status = agent_q::AgentQSigningRetryDeliveryStatus::not_found;
    g_retry_response_write_calls = 0;
    g_retry_response_json.clear();
    agent_q::signing_result_clear_all();
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

void expect_no_stored_result(const char* label, const char* session_id, const char* request_id)
{
    char stored[agent_q::kSigningResultMaxSize] = {};
    size_t stored_len = 0;
    if (agent_q::signing_result_find(
            session_id,
            request_id,
            stored,
            sizeof(stored),
            &stored_len)) {
        fprintf(stderr, "%s: unexpected stored signing result\n", label);
        ++g_failures;
    }
}

void store_identity_for(
    const std::string& json,
    const char* stored_result)
{
    JsonDocument document = parse_json(json);
    const agent_q::AgentQSignRouteClassification classification =
        agent_q::classify_sign_route(
            agent_q::AgentQSignOperation::sign_transaction,
            document["chain"].as<const char*>(),
            document["method"].as<const char*>());
    assert(classification.result == agent_q::AgentQSignRouteResult::ok);
    agent_q::AgentQSignTransactionUserIngressOutput ingress = {};
    assert(agent_q::evaluate_sign_transaction_user_ingress(
               document,
               classification.route,
               state(true, false),
               &ingress) == agent_q::AgentQSignTransactionUserIngressResult::ok);
    uint8_t identity[agent_q::kAgentQSignRequestIdentitySize] = {};
    assert(agent_q::sign_request_identity(
        classification.route,
        ingress.params.network,
        ingress.params.tx_bytes_base64,
        identity,
        sizeof(identity)));
    assert(agent_q::signing_result_store(
               ingress.session.session_id,
               ingress.envelope.request_id,
               identity,
               sizeof(identity),
               stored_result,
               strlen(stored_result)) == agent_q::SigningResultStoreOutcome::stored);
    g_session_calls = 0;
}

}  // namespace

namespace agent_q {

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

AgentQSuiSigningAccountBindingResult verify_sui_signing_stored_account_binding(
    const SuiTransferFacts&)
{
    ++g_binding_calls;
    return g_binding_result;
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

}  // namespace agent_q

int main(int argc, char** argv)
{
    assert(argc == 2);
    const std::vector<uint8_t> valid = read_hex(argv[1]);
    const std::string valid_b64 = base64(valid);
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
    store_identity_for(valid_request, "{\"type\":\"sign_result\",\"status\":\"signed\"}");
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
    expect_contains("matching retry response", g_retry_response_json, "\"type\":\"sign_result\"");
    expect_contains("matching retry response", g_retry_response_json, "\"status\":\"signed\"");

    reset_counters();
    store_identity_for(
        valid_request,
        "{\"type\":\"sign_result\",\"status\":\"signing_failed\","
        "\"error\":{\"code\":\"signing_failed\","
        "\"message\":\"The device could not produce a signature.\"}}");
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
        "\"type\":\"sign_result\"");
    expect_contains(
        "matching signing_failed retry response",
        g_retry_response_json,
        "\"status\":\"signing_failed\"");
    expect_contains(
        "matching signing_failed retry response",
        g_retry_response_json,
        "\"code\":\"signing_failed\"");

    reset_counters();
    store_identity_for(valid_request, "{\"type\":\"sign_result\",\"status\":\"signed\"}");
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
    expect_contains("conflicting retry response", g_retry_response_json, "\"type\":\"error\"");
    expect_contains("conflicting retry response", g_retry_response_json, "request_id_conflict");

    reset_counters();
    store_identity_for(valid_request, "{\"type\":\"sign_result\",\"status\":\"signed\"}");
    expect_case(
        "invalid current request shape cannot replay a stored result",
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
    expect_case(
        "fresh valid request reaches preparation",
        run_transaction_preflight(valid_request, true, false),
        PreflightOutcome::ok_prepared,
        1,
        1,
        1);

    reset_counters();
    const std::vector<uint8_t> oversized_tx(385, 0x42);
    const std::string oversized_b64 = base64(oversized_tx);
    expect_case(
        "oversized prepared payload fails without buffering a result",
        run_transaction_preflight(
            request_json(
                "req_sign_oversized",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                oversized_b64.c_str()),
            true,
            false),
        PreflightOutcome::preparation_error,
        1,
        0,
        0);
    expect_no_stored_result(
        "oversized prepared payload",
        "session_aaaaaaaaaaaaaaaa",
        "req_sign_oversized");

    if (g_failures != 0) {
        fprintf(stderr, "signing preflight order tests failed: %d\n", g_failures);
        return 1;
    }
    printf("Signing preflight order tests passed\n");
    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${SIGNING_CORE}" \
  -c "${SIGNING_CORE}/byte_conversions.c" \
  -o "${TMP_DIR}/byte_conversions.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${TMP_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_SUI_DIR}" \
  -I"${SIGNING_CORE}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_request_identity.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_preflight.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_retry_response.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_ingress.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_retry_delivery.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_ingress.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_result_store.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_signing_preparation.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_sign_transaction_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${TMP_DIR}/byte_conversions.o" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test" "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex"
