#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_signature_request_validation.sh

Compiles the StackChan CoreS3 future request_signature split validation helpers
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
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.h" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.h" \
  "${AGENT_Q_DIR}/agent_q_signature_request_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_signature_request_validation.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first, or set AGENT_Q_ARDUINOJSON_ROOT." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-signature-request-validation.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/signature_request_validation_test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include "agent_q_base64.h"
#include "agent_q_signature_request_validation.h"

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
    return "{\"id\":\"req_signature_1\",\"version\":1,\"type\":\"request_signature\","
           "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":" + params + "}";
}

void expect_base64(const char* label, const char* value, size_t max_size, bool expected)
{
    size_t decoded_size = 9999;
    const bool actual = agent_q::validate_canonical_base64(value, max_size, 384, &decoded_size);
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

void expect_envelope(
    const char* label,
    const std::string& json,
    agent_q::AgentQSignatureRequestValidationResult expected,
    const char* expected_request_id = nullptr)
{
    JsonDocument document = parse_json(label, json);
    agent_q::AgentQSignatureRequestEnvelope output = {};
    memset(&output, 0xA5, sizeof(output));
    const agent_q::AgentQSignatureRequestValidationResult actual =
        agent_q::validate_signature_request_envelope(document, &output);
    if (actual != expected) {
        fprintf(stderr, "%s: expected envelope result %d, got %d\n",
                label, static_cast<int>(expected), static_cast<int>(actual));
        ++failures;
    }
    if (actual != agent_q::AgentQSignatureRequestValidationResult::ok &&
        output.request_id[0] != '\0') {
        fprintf(stderr, "%s: envelope failure did not clear output\n", label);
        ++failures;
    }
    if (actual == agent_q::AgentQSignatureRequestValidationResult::ok &&
        expected_request_id != nullptr &&
        strcmp(output.request_id, expected_request_id) != 0) {
        fprintf(stderr, "%s: envelope request id did not match\n", label);
        ++failures;
    }
}

void expect_session(
    const char* label,
    const std::string& json,
    agent_q::AgentQSignatureRequestValidationResult expected,
    const char* expected_session_id = nullptr)
{
    JsonDocument document = parse_json(label, json);
    agent_q::AgentQSignatureRequestSessionRef output = {};
    memset(&output, 0xA5, sizeof(output));
    const agent_q::AgentQSignatureRequestValidationResult actual =
        agent_q::validate_signature_request_session_format(document, &output);
    if (actual != expected) {
        fprintf(stderr, "%s: expected session result %d, got %d\n",
                label, static_cast<int>(expected), static_cast<int>(actual));
        ++failures;
    }
    if (actual != agent_q::AgentQSignatureRequestValidationResult::ok &&
        output.session_id[0] != '\0') {
        fprintf(stderr, "%s: session failure did not clear output\n", label);
        ++failures;
    }
    if (actual == agent_q::AgentQSignatureRequestValidationResult::ok &&
        expected_session_id != nullptr &&
        strcmp(output.session_id, expected_session_id) != 0) {
        fprintf(stderr, "%s: session id did not match\n", label);
        ++failures;
    }
}

void expect_params(
    const char* label,
    const std::string& json,
    agent_q::AgentQSignatureRequestValidationResult expected,
    uint32_t expected_timeout_ms = 0,
    size_t expected_decoded_size = 0,
    const char* expected_network = nullptr)
{
    JsonDocument document = parse_json(label, json);
    agent_q::AgentQSignatureRequestParams output = {};
    memset(&output, 0xA5, sizeof(output));
    const agent_q::AgentQSignatureRequestValidationResult actual =
        agent_q::validate_signature_request_params(document, &output);
    if (actual != expected) {
        fprintf(stderr, "%s: expected params result %d, got %d\n",
                label, static_cast<int>(expected), static_cast<int>(actual));
        ++failures;
        return;
    }
    if (actual != agent_q::AgentQSignatureRequestValidationResult::ok &&
        (output.chain[0] != '\0' ||
         output.method[0] != '\0' ||
         output.network[0] != '\0' ||
         output.tx_bytes_base64[0] != '\0' ||
         output.tx_bytes_decoded_size != 0 ||
         output.approval_timeout_ms != 0)) {
        fprintf(stderr, "%s: params failure did not clear output\n", label);
        ++failures;
    }
    if (actual == agent_q::AgentQSignatureRequestValidationResult::ok &&
        expected_network == nullptr) {
        fprintf(stderr, "%s: params test did not provide expected output fields\n", label);
        ++failures;
    }
    if (actual == agent_q::AgentQSignatureRequestValidationResult::ok &&
        expected_network != nullptr &&
        (strcmp(output.chain, "sui") != 0 ||
         strcmp(output.method, "sign_transaction") != 0 ||
         strcmp(output.network, expected_network) != 0 ||
         strcmp(output.tx_bytes_base64, "AAAA") != 0 ||
         output.tx_bytes_decoded_size != expected_decoded_size ||
         output.approval_timeout_ms != expected_timeout_ms)) {
        fprintf(stderr, "%s: params output fields did not match\n", label);
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
    using Result = agent_q::AgentQSignatureRequestValidationResult;

    const std::string malformed_params_request =
        "{\"id\":\"req_signature_1\",\"version\":1,\"type\":\"request_signature\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":[]}";

    expect_envelope(
        "valid envelope ignores malformed params",
        malformed_params_request,
        Result::ok,
        "req_signature_1");
    expect_session(
        "valid session ignores malformed params",
        malformed_params_request,
        Result::ok,
        "session_aaaaaaaaaaaaaaaa");

    expect_params(
        "valid default timeout",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\",\"txBytes\":\"AAAA\"}"),
        Result::ok,
        agent_q::kAgentQSignatureRequestApprovalTimeoutDefaultMs,
        3,
        "devnet");
    for (const char* network : {"mainnet", "testnet", "devnet", "localnet"}) {
        const std::string label = std::string("valid network ") + network;
        expect_params(
            label.c_str(),
            valid_request_with_params(std::string("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                                  "\"network\":\"") + network + "\",\"txBytes\":\"AAAA\"}"),
            Result::ok,
            agent_q::kAgentQSignatureRequestApprovalTimeoutDefaultMs,
            3,
            network);
    }
    expect_params(
        "valid max timeout",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\",\"txBytes\":\"AAAA\","
                                  "\"approvalTimeoutMs\":60000}"),
        Result::ok,
        60000,
        3,
        "devnet");

    expect_envelope(
        "missing id",
        "{\"version\":1,\"type\":\"request_signature\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"chain\":\"sui\",\"method\":\"sign_transaction\",\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_request_shape);
    expect_envelope(
        "embedded nul id",
        "{\"id\":\"req_signature_1\\u0000x\",\"version\":1,\"type\":\"request_signature\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"chain\":\"sui\",\"method\":\"sign_transaction\",\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_request_shape);
    expect_envelope(
        "unsafe id with slash",
        "{\"id\":\"req/signature/1\",\"version\":1,\"type\":\"request_signature\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"chain\":\"sui\",\"method\":\"sign_transaction\",\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_request_shape);
    expect_envelope(
        "unsafe id with space",
        "{\"id\":\"req signature 1\",\"version\":1,\"type\":\"request_signature\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"chain\":\"sui\",\"method\":\"sign_transaction\",\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_request_shape);
    expect_envelope(
        "overlong id",
        "{\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"version\":1,\"type\":\"request_signature\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"chain\":\"sui\",\"method\":\"sign_transaction\",\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_request_shape);
    expect_envelope(
        "unsupported version",
        "{\"id\":\"req_signature_1\",\"version\":2,\"type\":\"request_signature\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"chain\":\"sui\",\"method\":\"sign_transaction\",\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::unsupported_version);
    expect_envelope(
        "missing type",
        "{\"id\":\"req_signature_1\",\"version\":1,"
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"chain\":\"sui\",\"method\":\"sign_transaction\",\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::unsupported_type);
    expect_envelope(
        "wrong type",
        "{\"id\":\"req_signature_1\",\"version\":1,\"type\":\"call_method\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"chain\":\"sui\",\"method\":\"sign_transaction\",\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::unsupported_type);
    expect_envelope(
        "top level unsupported field",
        "{\"id\":\"req_signature_1\",\"version\":1,\"type\":\"request_signature\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"extra\":true,\"params\":{"
        "\"chain\":\"sui\",\"method\":\"sign_transaction\",\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::unsupported_field);
    expect_session(
        "missing session",
        "{\"id\":\"req_signature_1\",\"version\":1,\"type\":\"request_signature\","
        "\"params\":{\"chain\":\"sui\",\"method\":\"sign_transaction\","
        "\"network\":\"devnet\",\"txBytes\":\"AAAA\"}}",
        Result::invalid_session);
    expect_session(
        "bad session prefix",
        "{\"id\":\"req_signature_1\",\"version\":1,\"type\":\"request_signature\","
        "\"sessionId\":\"not_session_aaaaaaaaaaaaaaaa\",\"params\":{"
        "\"chain\":\"sui\",\"method\":\"sign_transaction\",\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_session);
    expect_session(
        "uppercase session hex",
        "{\"id\":\"req_signature_1\",\"version\":1,\"type\":\"request_signature\","
        "\"sessionId\":\"session_AAAAAAAAAAAAAAAA\",\"params\":{"
        "\"chain\":\"sui\",\"method\":\"sign_transaction\",\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_session);
    expect_session(
        "embedded nul session",
        "{\"id\":\"req_signature_1\",\"version\":1,\"type\":\"request_signature\","
        "\"sessionId\":\"session_aaaaaaaa\\u0000x\",\"params\":{"
        "\"chain\":\"sui\",\"method\":\"sign_transaction\",\"network\":\"devnet\","
        "\"txBytes\":\"AAAA\"}}",
        Result::invalid_session);
    expect_session(
        "overlong session",
        "{\"id\":\"req_signature_1\",\"version\":1,\"type\":\"request_signature\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"params\":{\"chain\":\"sui\",\"method\":\"sign_transaction\","
        "\"network\":\"devnet\",\"txBytes\":\"AAAA\"}}",
        Result::invalid_session);
    expect_params(
        "params missing",
        "{\"id\":\"req_signature_1\",\"version\":1,\"type\":\"request_signature\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\"}",
        Result::invalid_params_shape);
    expect_params(
        "params array",
        valid_request_with_params("[]"),
        Result::invalid_params_shape);
    expect_params(
        "params unsupported field",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\",\"txBytes\":\"AAAA\","
                                  "\"requestAuthority\":\"user_confirmed\"}"),
        Result::unsupported_field);
    expect_params(
        "missing chain",
        valid_request_with_params("{\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\",\"txBytes\":\"AAAA\"}"),
        Result::unsupported_method);
    expect_params(
        "wrong chain",
        valid_request_with_params("{\"chain\":\"evm\",\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\",\"txBytes\":\"AAAA\"}"),
        Result::unsupported_method);
    expect_params(
        "wrong method",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_personal_message\","
                                  "\"network\":\"devnet\",\"txBytes\":\"AAAA\"}"),
        Result::unsupported_method);
    expect_params(
        "network missing",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"txBytes\":\"AAAA\"}"),
        Result::invalid_network);
    expect_params(
        "network unsupported",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"network\":\"staging\",\"txBytes\":\"AAAA\"}"),
        Result::invalid_network);
    expect_params(
        "network embedded nul",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\\u0000x\",\"txBytes\":\"AAAA\"}"),
        Result::invalid_network);
    expect_params(
        "txBytes missing",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\"}"),
        Result::invalid_tx_bytes);
    expect_params(
        "txBytes invalid base64",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\",\"txBytes\":\"AA!A\"}"),
        Result::invalid_tx_bytes);
    expect_params(
        "txBytes noncanonical padding",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\",\"txBytes\":\"AAB=\"}"),
        Result::invalid_tx_bytes);
    expect_params(
        "txBytes embedded nul",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\",\"txBytes\":\"AAAA\\u0000x\"}"),
        Result::invalid_tx_bytes);
    expect_params(
        "txBytes too large",
        valid_request_with_params(std::string("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                             "\"network\":\"devnet\",\"txBytes\":\"") +
                                  std::string(agent_q::kAgentQSuiSignTransactionTxBytesMaxBase64Size + 4, 'A') +
                                  "\"}"),
        Result::invalid_tx_bytes);
    expect_params(
        "timeout zero",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\",\"txBytes\":\"AAAA\","
                                  "\"approvalTimeoutMs\":0}"),
        Result::invalid_timeout);
    expect_params(
        "timeout too large",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\",\"txBytes\":\"AAAA\","
                                  "\"approvalTimeoutMs\":60001}"),
        Result::invalid_timeout);
    expect_params(
        "timeout string",
        valid_request_with_params("{\"chain\":\"sui\",\"method\":\"sign_transaction\","
                                  "\"network\":\"devnet\",\"txBytes\":\"AAAA\","
                                  "\"approvalTimeoutMs\":\"30000\"}"),
        Result::invalid_timeout);

    if (strcmp(agent_q::signature_request_validation_result_name(Result::ok), "ok") != 0 ||
        strcmp(agent_q::signature_request_validation_result_name(Result::unsupported_type),
               "unsupported_type") != 0 ||
        strcmp(agent_q::signature_request_validation_result_name(Result::invalid_tx_bytes),
               "invalid_tx_bytes") != 0) {
        fprintf(stderr, "result names did not match\n");
        ++failures;
    }

    expect_base64("base64 valid", "AAAA", 512, true);
    char unterminated[4] = {'A', 'A', 'A', 'A'};
    expect_base64("base64 unterminated within max", unterminated, 3, false);

    if (failures != 0) {
        fprintf(stderr, "%d signature request validation checks failed\n", failures);
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
  "${TMP_DIR}/signature_request_validation_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${AGENT_Q_DIR}/agent_q_signature_request_validation.cpp" \
  -o "${TMP_DIR}/signature_request_validation_test"

"${TMP_DIR}/signature_request_validation_test"
