#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sign_transaction_user_validation.sh

Compiles the StackChan CoreS3 sign_transaction_user split validation helpers
against ArduinoJson with a host C++ compiler and checks protocol shape
boundaries. This test does not require ESP-IDF, but it uses the pinned
StackChan ArduinoJson component checkout prepared by fetch.sh/build.sh. Set
AGENT_Q_ARDUINOJSON_ROOT to override the ArduinoJson source root.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${AGENT_Q_DIR}/agent_q_base64.h" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_primitives.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_primitives.h" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.h" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.h" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_validation.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first, or set AGENT_Q_ARDUINOJSON_ROOT." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-signature-request-validation.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/agent_q_common"
ln -s "${REPO_ROOT}/firmware/src/common/agent_q/policy" "${TMP_DIR}/agent_q_common/policy"

cat >"${TMP_DIR}/sign_transaction_user_validation_test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include "agent_q_base64.h"
#include "agent_q_payload_delivery_primitives.h"
#include "agent_q_sign_transaction_user_validation.h"

namespace {

int failures = 0;

JsonDocument parse_json(const char* label, const std::string& json)
{
    JsonDocument document;
    const DeserializationError error = deserializeJson(document, json.c_str());
    if (error) {
        fprintf(stderr, "%s: test JSON did not parse: %s\n%s\n", label, error.c_str(), json.c_str());
        exit(1);
    }
    if (document.overflowed()) {
        fprintf(stderr, "%s: test JSON overflowed ArduinoJson document\n", label);
        exit(1);
    }
    return document;
}

std::string valid_request_with_params(const std::string& params)
{
    return "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction\","
           "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
           "\"chain\":\"sui\",\"method\":\"sign_transaction\","
           "\"params\":" + params + "}";
}

std::string request_with_shape(
    const char* chain_fragment,
    const char* method_fragment,
    const std::string& params)
{
    return "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction\","
           "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\"," +
           std::string(chain_fragment == nullptr ? "" : chain_fragment) +
           std::string(method_fragment == nullptr ? "" : method_fragment) +
           "\"params\":" + params + "}";
}

void expect_base64(const char* label, const char* value, size_t max_size, bool expected)
{
    size_t decoded_size = 9999;
    const bool actual = agent_q::validate_canonical_base64_syntax(value, max_size, &decoded_size);
    if (actual != expected) {
        fprintf(stderr, "%s: expected base64 result %s, got %s\n",
                label, expected ? "true" : "false", actual ? "true" : "false");
        ++failures;
    }
    if (!actual && decoded_size != 0) {
        fprintf(stderr, "%s: rejected base64 did not clear decoded size\n", label);
        ++failures;
    }
}

void expect_payload_primitive(const char* label, bool actual, bool expected)
{
    if (actual != expected) {
        fprintf(stderr, "%s: expected %s\n", label, expected ? "valid" : "invalid");
        ++failures;
    }
}

void expect_envelope(
    const char* label,
    const std::string& json,
    agent_q::AgentQSignTransactionUserValidationResult expected,
    const char* expected_request_id = nullptr)
{
    JsonDocument document = parse_json(label, json);
    agent_q::AgentQSignTransactionUserEnvelope output = {};
    memset(&output, 0xA5, sizeof(output));
    const agent_q::AgentQSignTransactionUserValidationResult actual =
        agent_q::validate_sign_transaction_user_envelope(document, &output);
    if (actual != expected) {
        fprintf(stderr, "%s: expected envelope result %d, got %d\n",
                label, static_cast<int>(expected), static_cast<int>(actual));
        ++failures;
    }
    if (actual != agent_q::AgentQSignTransactionUserValidationResult::ok &&
        output.request_id[0] != '\0') {
        fprintf(stderr, "%s: envelope failure did not clear output\n", label);
        ++failures;
    }
    if (actual == agent_q::AgentQSignTransactionUserValidationResult::ok &&
        expected_request_id != nullptr &&
        strcmp(output.request_id, expected_request_id) != 0) {
        fprintf(stderr, "%s: envelope request id did not match\n", label);
        ++failures;
    }
}

void expect_session(
    const char* label,
    const std::string& json,
    agent_q::AgentQSignTransactionUserValidationResult expected,
    const char* expected_session_id = nullptr)
{
    JsonDocument document = parse_json(label, json);
    agent_q::AgentQSignTransactionUserSessionRef output = {};
    memset(&output, 0xA5, sizeof(output));
    const agent_q::AgentQSignTransactionUserValidationResult actual =
        agent_q::validate_sign_transaction_user_session_format(document, &output);
    if (actual != expected) {
        fprintf(stderr, "%s: expected session result %d, got %d\n",
                label, static_cast<int>(expected), static_cast<int>(actual));
        ++failures;
    }
    if (actual != agent_q::AgentQSignTransactionUserValidationResult::ok &&
        output.session_id[0] != '\0') {
        fprintf(stderr, "%s: session failure did not clear output\n", label);
        ++failures;
    }
    if (actual == agent_q::AgentQSignTransactionUserValidationResult::ok &&
        expected_session_id != nullptr &&
        strcmp(output.session_id, expected_session_id) != 0) {
        fprintf(stderr, "%s: session id did not match\n", label);
        ++failures;
    }
}

void expect_params(
    const char* label,
    const std::string& json,
    agent_q::AgentQSignTransactionUserValidationResult expected,
    size_t expected_decoded_size = 0,
    const char* expected_network = nullptr,
    const char* expected_tx_bytes = "AAAA")
{
    JsonDocument document = parse_json(label, json);
    agent_q::AgentQSignTransactionUserParams output = {};
    memset(&output, 0xA5, sizeof(output));
    const agent_q::AgentQSignTransactionUserValidationResult actual =
        agent_q::validate_sign_transaction_user_params(document, agent_q::AgentQSupportedSignRoute::sui_sign_transaction, &output);
    if (actual != expected) {
        fprintf(stderr, "%s: expected params result %d, got %d\n",
                label, static_cast<int>(expected), static_cast<int>(actual));
        ++failures;
        return;
    }
    if (actual != agent_q::AgentQSignTransactionUserValidationResult::ok &&
        (output.network[0] != '\0' ||
         output.tx_bytes_base64 != nullptr ||
         output.tx_bytes_decoded_size != 0)) {
        fprintf(stderr, "%s: params failure did not clear output\n", label);
        ++failures;
    }
    if (actual == agent_q::AgentQSignTransactionUserValidationResult::ok &&
        expected_network == nullptr) {
        fprintf(stderr, "%s: params test did not provide expected output fields\n", label);
        ++failures;
    }
    if (actual == agent_q::AgentQSignTransactionUserValidationResult::ok &&
        expected_network != nullptr &&
        (strcmp(output.network, expected_network) != 0 ||
         strcmp(output.tx_bytes_base64, expected_tx_bytes) != 0 ||
         output.tx_bytes_decoded_size != expected_decoded_size)) {
        fprintf(stderr, "%s: params output fields did not match\n", label);
        ++failures;
    }
}

void expect_staged_params(
    const char* label,
    const std::string& json,
    agent_q::AgentQSignTransactionUserValidationResult expected,
    const char* expected_network = nullptr,
    const char* expected_payload_ref = nullptr,
    size_t expected_payload_size = 0,
    const char* expected_payload_digest = nullptr)
{
    JsonDocument document = parse_json(label, json);
    agent_q::AgentQSignTransactionUserParams output = {};
    memset(&output, 0xA5, sizeof(output));
    const agent_q::AgentQSignTransactionUserValidationResult actual =
        agent_q::validate_sign_transaction_user_params(document, agent_q::AgentQSupportedSignRoute::sui_sign_transaction, &output);
    if (actual != expected) {
        fprintf(stderr, "%s: expected staged params result %d, got %d\n",
                label, static_cast<int>(expected), static_cast<int>(actual));
        ++failures;
        return;
    }
    if (actual != agent_q::AgentQSignTransactionUserValidationResult::ok) {
        return;
    }
    if (expected_network == nullptr ||
        expected_payload_ref == nullptr ||
        expected_payload_digest == nullptr ||
        strcmp(output.network, expected_network) != 0 ||
        strcmp(output.payload_ref, expected_payload_ref) != 0 ||
        strcmp(output.payload_kind, "transaction") != 0 ||
        output.payload_size_bytes != expected_payload_size ||
        strcmp(output.payload_digest, expected_payload_digest) != 0) {
        fprintf(stderr, "%s: staged params output fields did not match\n", label);
        ++failures;
    }
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

}  // namespace agent_q

int main()
{
    using Result = agent_q::AgentQSignTransactionUserValidationResult;

    const std::string malformed_params_request =
        "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":[]}";

    expect_envelope(
        "valid envelope ignores malformed params",
        malformed_params_request,
        Result::ok,
        "req_sign_1");
    expect_session(
        "valid session ignores malformed params",
        malformed_params_request,
        Result::ok,
        "session_aaaaaaaaaaaaaaaa");

    expect_params(
        "valid params",
        valid_request_with_params("{\"network\":\"devnet\",\"txBytes\":\"AAAA\"}"),
        Result::ok,
        3,
        "devnet");
    for (const char* network : {"mainnet", "testnet", "devnet", "localnet"}) {
        const std::string label = std::string("valid network ") + network;
        expect_params(
            label.c_str(),
            valid_request_with_params(std::string("{\"network\":\"") + network + "\",\"txBytes\":\"AAAA\"}"),
            Result::ok,
            3,
            network);
    }
    expect_params(
        "unsupported extra params field",
        valid_request_with_params("{\"network\":\"devnet\",\"txBytes\":\"AAAA\","
                                  "\"extra\":true}"),
        Result::unsupported_field);

    expect_envelope(
        "missing id",
        "{\"version\":1,\"type\":\"sign_transaction\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_request_shape);
    expect_envelope(
        "embedded nul id",
        "{\"id\":\"req_sign_1\\u0000x\",\"version\":1,\"type\":\"sign_transaction\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_request_shape);
    expect_envelope(
        "unsafe id with slash",
        "{\"id\":\"req/signature/1\",\"version\":1,\"type\":\"sign_transaction\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_request_shape);
    expect_envelope(
        "unsafe id with space",
        "{\"id\":\"req signature 1\",\"version\":1,\"type\":\"sign_transaction\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_request_shape);
    expect_envelope(
        "overlong id",
        "{\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"version\":1,\"type\":\"sign_transaction\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_request_shape);
    expect_envelope(
        "unsupported version",
        "{\"id\":\"req_sign_1\",\"version\":2,\"type\":\"sign_transaction\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::unsupported_version);
    expect_envelope(
        "missing type",
        "{\"id\":\"req_sign_1\",\"version\":1,"
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::unsupported_type);
    expect_envelope(
        "wrong type",
        "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction_policy\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::unsupported_type);
    expect_envelope(
        "top level unsupported field",
        "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"extra\":true,\"params\":{"
        "\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::unsupported_field);
    expect_session(
        "missing session",
        "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction\","
        "\"params\":{\"network\":\"devnet\",\"txBytes\":\"AAAA\"}}",
        Result::invalid_session);
    expect_session(
        "bad session prefix",
        "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction\","
        "\"sessionId\":\"not_session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_session);
    expect_session(
        "uppercase session hex",
        "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction\","
        "\"sessionId\":\"session_AAAAAAAAAAAAAAAA\",\"params\":{"
        "\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_session);
    expect_session(
        "embedded nul session",
        "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction\","
        "\"sessionId\":\"session_aaaaaaaa\\u0000x\",\"params\":{"
        "\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_session);
    expect_session(
        "overlong session",
        "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"params\":{\"network\":\"devnet\",\"txBytes\":\"AAAA\"}}",
        Result::invalid_session);
    expect_params(
        "params missing",
        "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\"}",
        Result::invalid_params_shape);
    expect_params(
        "params array",
        valid_request_with_params("[]"),
        Result::invalid_params_shape);
    expect_params(
        "params unsupported field",
        valid_request_with_params("{\"network\":\"devnet\",\"txBytes\":\"AAAA\","
                                  "\"requestAuthority\":\"user_confirmed\"}"),
        Result::unsupported_field);
    expect_params(
        "selected route owns identity when raw chain is absent",
        request_with_shape(
            nullptr,
            "\"method\":\"sign_transaction\",",
            "{\"network\":\"devnet\",\"txBytes\":\"AAAA\"}"),
        Result::ok,
        3,
        "devnet");
    expect_params(
        "selected route owns identity when raw chain differs",
        request_with_shape(
            "\"chain\":\"evm\",",
            "\"method\":\"sign_transaction\",",
            "{\"network\":\"devnet\",\"txBytes\":\"AAAA\"}"),
        Result::ok,
        3,
        "devnet");
    expect_params(
        "selected route owns identity when raw method differs",
        request_with_shape(
            "\"chain\":\"sui\",",
            "\"method\":\"sign_personal_message\",",
            "{\"network\":\"devnet\",\"txBytes\":\"AAAA\"}"),
        Result::ok,
        3,
        "devnet");
    expect_params(
        "network missing",
        valid_request_with_params("{\"txBytes\":\"AAAA\"}"),
        Result::invalid_network);
    expect_params(
        "network unsupported",
        valid_request_with_params("{\"network\":\"staging\",\"txBytes\":\"AAAA\"}"),
        Result::invalid_network);
    expect_params(
        "network embedded nul",
        valid_request_with_params("{\"network\":\"devnet\\u0000x\",\"txBytes\":\"AAAA\"}"),
        Result::invalid_network);
    expect_params(
        "txBytes missing",
        valid_request_with_params("{\"network\":\"devnet\"}"),
        Result::invalid_params_shape);
    expect_params(
        "txBytes invalid base64",
        valid_request_with_params("{\"network\":\"devnet\",\"txBytes\":\"AA!A\"}"),
        Result::invalid_tx_bytes);
    expect_params(
        "txBytes noncanonical padding",
        valid_request_with_params("{\"network\":\"devnet\",\"txBytes\":\"AAB=\"}"),
        Result::invalid_tx_bytes);
    expect_params(
        "txBytes embedded nul",
        valid_request_with_params("{\"network\":\"devnet\",\"txBytes\":\"AAAA\\u0000x\"}"),
        Result::invalid_tx_bytes);
    const std::string above_adapter_capacity(516, 'A');
    expect_params(
        "txBytes above adapter capacity remains valid request format",
        valid_request_with_params(std::string("{\"network\":\"devnet\",\"txBytes\":\"") +
                                  above_adapter_capacity +
                                  "\"}"),
        Result::ok,
        387,
        "devnet",
        above_adapter_capacity.c_str());
    const char* digest =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    expect_staged_params(
        "valid staged params",
        valid_request_with_params(std::string("{\"network\":\"devnet\","
                                  "\"payloadRef\":\"payload_abcdef0123456789\","
                                  "\"payloadKind\":\"transaction\","
                                  "\"sizeBytes\":\"131072\","
                                  "\"payloadDigest\":\"") + digest + "\"}"),
        Result::ok,
        "devnet",
        "payload_abcdef0123456789",
        131072,
        digest);
    expect_staged_params(
        "staged params reject non-canonical size",
        valid_request_with_params(std::string("{\"network\":\"devnet\","
                                  "\"payloadRef\":\"payload_abcdef0123456789\","
                                  "\"payloadKind\":\"transaction\","
                                  "\"sizeBytes\":\"00037\","
                                  "\"payloadDigest\":\"") + digest + "\"}"),
        Result::invalid_payload_descriptor);
    expect_staged_params(
        "staged params reject uint64 overflow size",
        valid_request_with_params(std::string("{\"network\":\"devnet\","
                                  "\"payloadRef\":\"payload_abcdef0123456789\","
                                  "\"payloadKind\":\"transaction\","
                                  "\"sizeBytes\":\"18446744073709551616\","
                                  "\"payloadDigest\":\"") + digest + "\"}"),
        Result::invalid_payload_descriptor);
    expect_staged_params(
        "staged params missing descriptor",
        valid_request_with_params("{\"network\":\"devnet\","
                                  "\"payloadRef\":\"payload_abcdef0123456789\"}"),
        Result::invalid_params_shape);
    expect_staged_params(
        "staged params malformed digest",
        valid_request_with_params("{\"network\":\"devnet\","
                                  "\"payloadRef\":\"payload_abcdef0123456789\","
                                  "\"payloadKind\":\"transaction\","
                                  "\"sizeBytes\":\"131072\","
                                  "\"payloadDigest\":\"sha256:xyz\"}"),
        Result::invalid_payload_descriptor);
    expect_params(
        "inline params reject descriptor echo",
        valid_request_with_params(std::string("{\"network\":\"devnet\","
                                  "\"txBytes\":\"AAAA\","
                                  "\"payloadKind\":\"transaction\","
                                  "\"sizeBytes\":\"3\","
                                  "\"payloadDigest\":\"") + digest + "\"}"),
        Result::invalid_params_shape);
    if (strcmp(agent_q::sign_transaction_user_validation_result_name(Result::ok), "ok") != 0 ||
        strcmp(agent_q::sign_transaction_user_validation_result_name(Result::unsupported_type),
               "unsupported_type") != 0 ||
        strcmp(agent_q::sign_transaction_user_validation_result_name(Result::invalid_tx_bytes),
               "invalid_tx_bytes") != 0 ||
        strcmp(agent_q::sign_transaction_user_validation_result_name(Result::invalid_payload_descriptor),
               "invalid_payload_descriptor") != 0) {
        fprintf(stderr, "result names did not match\n");
        ++failures;
    }

    expect_base64("base64 valid", "AAAA", 512, true);
    char unterminated[4] = {'A', 'A', 'A', 'A'};
    expect_base64("base64 unterminated within max", unterminated, 3, false);

    expect_payload_primitive(
        "upload id valid max suffix",
        agent_q::payload_delivery_upload_id_format_valid(
            "upload_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-ABCDEFG"),
        true);
    expect_payload_primitive(
        "upload id rejects empty suffix",
        agent_q::payload_delivery_upload_id_format_valid("upload_"),
        false);
    expect_payload_primitive(
        "upload id rejects slash",
        agent_q::payload_delivery_upload_id_format_valid("upload_abc/def"),
        false);
    expect_payload_primitive(
        "upload id rejects long suffix",
        agent_q::payload_delivery_upload_id_format_valid(
            "upload_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-ABCDEFGH"),
        false);
    expect_payload_primitive(
        "payload ref valid max suffix",
        agent_q::payload_delivery_payload_ref_format_valid(
            "payload_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-ABCDEFG"),
        true);
    expect_payload_primitive(
        "payload ref rejects empty suffix",
        agent_q::payload_delivery_payload_ref_format_valid("payload_"),
        false);
    expect_payload_primitive(
        "payload ref rejects slash",
        agent_q::payload_delivery_payload_ref_format_valid("payload_abc/def"),
        false);
    expect_payload_primitive(
        "payload digest accepts lowercase sha256",
        agent_q::payload_delivery_payload_digest_format_valid(digest),
        true);
    expect_payload_primitive(
        "payload digest rejects uppercase hex",
        agent_q::payload_delivery_payload_digest_format_valid(
            "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"),
        false);
    expect_payload_primitive(
        "payload digest rejects short value",
        agent_q::payload_delivery_payload_digest_format_valid("sha256:0123"),
        false);

    if (failures != 0) {
        fprintf(stderr, "%d sign_transaction_user validation checks failed\n", failures);
        return 1;
    }
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${REPO_ROOT}/firmware/src/common" \
  -I"${REPO_ROOT}/firmware/src/common/agent_q" \
  "${TMP_DIR}/sign_transaction_user_validation_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_primitives.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_validation.cpp" \
  -o "${TMP_DIR}/sign_transaction_user_validation_test"

"${TMP_DIR}/sign_transaction_user_validation_test"
