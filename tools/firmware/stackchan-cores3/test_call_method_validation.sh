#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_call_method_validation.sh

Compiles the StackChan CoreS3 Agent-Q call_method validation helper against
ArduinoJson with a host C++ compiler and checks protocol field/type boundaries.
This test does not require ESP-IDF, but it uses the pinned StackChan ArduinoJson
component checkout prepared by fetch.sh/build.sh. Set AGENT_Q_ARDUINOJSON_ROOT
to override the ArduinoJson source root.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/products/firmware/src/stackchan-cores3/agent_q"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${AGENT_Q_DIR}/agent_q_call_method_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_call_method_validation.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run tools/firmware/stackchan-cores3/build.sh first, or set AGENT_Q_ARDUINOJSON_ROOT." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-call-method-validation.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/call_method_validation_test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include "agent_q_call_method_validation.h"

namespace {

int failures = 0;

void fail(const char* label, const char* message)
{
    fprintf(stderr, "%s: %s\n", label, message);
    ++failures;
}

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

void expect_field_result(
    const char* label,
    const std::string& json,
    agent_q::CallMethodFieldValidation expected)
{
    JsonDocument document = parse_json(label, json);
    const agent_q::CallMethodFieldValidation actual =
        agent_q::validate_call_method_request_fields(document);
    if (actual != expected) {
        fprintf(stderr, "%s: expected field result %d, got %d\n",
                label, static_cast<int>(expected), static_cast<int>(actual));
        ++failures;
    }
}

void expect_sui_params(const char* label, const std::string& params_json, bool expected, size_t expected_size)
{
    JsonDocument document = parse_json(label, params_json);
    size_t decoded_size = 9999;
    const bool actual = agent_q::validate_sui_sign_transaction_params(document.as<JsonVariant>(), &decoded_size);
    if (actual != expected) {
        fprintf(stderr, "%s: expected params result %s, got %s\n",
                label, expected ? "true" : "false", actual ? "true" : "false");
        ++failures;
    }
    if (decoded_size != expected_size) {
        fprintf(stderr, "%s: expected decoded size %zu, got %zu\n", label, expected_size, decoded_size);
        ++failures;
    }
}

std::string request_with_params(const std::string& params)
{
    return "{\"chain\":\"sui\",\"method\":\"sign_transaction\",\"params\":" + params + "}";
}

}  // namespace

int main()
{
    using agent_q::CallMethodFieldValidation;

    expect_field_result(
        "valid envelope",
        request_with_params("{\"network\":\"devnet\",\"txBytes\":\"AAAA\"}"),
        CallMethodFieldValidation::valid);

    expect_field_result(
        "chain missing",
        "{\"method\":\"sign_transaction\",\"params\":{}}",
        CallMethodFieldValidation::invalid_method);
    expect_field_result(
        "chain number",
        "{\"chain\":1,\"method\":\"sign_transaction\",\"params\":{}}",
        CallMethodFieldValidation::invalid_method);
    expect_field_result(
        "chain object",
        "{\"chain\":{},\"method\":\"sign_transaction\",\"params\":{}}",
        CallMethodFieldValidation::invalid_method);
    expect_field_result(
        "chain array",
        "{\"chain\":[],\"method\":\"sign_transaction\",\"params\":{}}",
        CallMethodFieldValidation::invalid_method);
    expect_field_result(
        "chain null",
        "{\"chain\":null,\"method\":\"sign_transaction\",\"params\":{}}",
        CallMethodFieldValidation::invalid_method);
    expect_field_result(
        "chain uppercase",
        "{\"chain\":\"Sui\",\"method\":\"sign_transaction\",\"params\":{}}",
        CallMethodFieldValidation::invalid_method);
    expect_field_result(
        "chain too long",
        "{\"chain\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"method\":\"sign_transaction\",\"params\":{}}",
        CallMethodFieldValidation::invalid_method);

    expect_field_result(
        "method missing",
        "{\"chain\":\"sui\",\"params\":{}}",
        CallMethodFieldValidation::invalid_method);
    expect_field_result(
        "method number",
        "{\"chain\":\"sui\",\"method\":1,\"params\":{}}",
        CallMethodFieldValidation::invalid_method);
    expect_field_result(
        "method unsafe char",
        "{\"chain\":\"sui\",\"method\":\"sign/transaction\",\"params\":{}}",
        CallMethodFieldValidation::invalid_method);
    expect_field_result(
        "method too long",
        "{\"chain\":\"sui\",\"method\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"params\":{}}",
        CallMethodFieldValidation::invalid_method);

    expect_field_result(
        "params missing",
        "{\"chain\":\"sui\",\"method\":\"sign_transaction\"}",
        CallMethodFieldValidation::invalid_params_shape);
    expect_field_result(
        "params array",
        "{\"chain\":\"sui\",\"method\":\"sign_transaction\",\"params\":[]}",
        CallMethodFieldValidation::invalid_params_shape);
    expect_field_result(
        "params string",
        "{\"chain\":\"sui\",\"method\":\"sign_transaction\",\"params\":\"not-object\"}",
        CallMethodFieldValidation::invalid_params_shape);

    const std::string oversized_params =
        "{\"chain\":\"sui\",\"method\":\"sign_transaction\",\"params\":{\"network\":\"devnet\",\"txBytes\":\"" +
        std::string(601, 'A') + "\"}}";
    expect_field_result("params too large", oversized_params, CallMethodFieldValidation::invalid_params_size);

    for (const char* network : {"mainnet", "testnet", "devnet", "localnet"}) {
        const std::string label = std::string("valid network ") + network;
        expect_sui_params(
            label.c_str(),
            std::string("{\"network\":\"") + network + "\",\"txBytes\":\"AAAA\"}",
            true,
            3);
    }

    expect_sui_params("params not object", "[]", false, 0);
    expect_sui_params("extra field", "{\"network\":\"devnet\",\"txBytes\":\"AAAA\",\"seed\":\"x\"}", false, 0);
    expect_sui_params("network missing", "{\"txBytes\":\"AAAA\"}", false, 0);
    expect_sui_params("network number", "{\"network\":1,\"txBytes\":\"AAAA\"}", false, 0);
    expect_sui_params("network unsupported", "{\"network\":\"prodnet\",\"txBytes\":\"AAAA\"}", false, 0);
    expect_sui_params("txBytes missing", "{\"network\":\"devnet\"}", false, 0);
    expect_sui_params("txBytes number", "{\"network\":\"devnet\",\"txBytes\":1}", false, 0);
    expect_sui_params("txBytes empty", "{\"network\":\"devnet\",\"txBytes\":\"\"}", false, 0);
    expect_sui_params("txBytes malformed", "{\"network\":\"devnet\",\"txBytes\":\"!!!!\"}", false, 0);
    expect_sui_params("txBytes non-canonical", "{\"network\":\"devnet\",\"txBytes\":\"AAB=\"}", false, 0);

    const std::string too_large_tx =
        "{\"network\":\"devnet\",\"txBytes\":\"" + std::string(516, 'A') + "\"}";
    expect_sui_params("txBytes too large", too_large_tx, false, 0);

    if (failures != 0) {
        fprintf(stderr, "Call method validation tests failed: %d\n", failures);
        return 1;
    }
    printf("Call method validation tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/call_method_validation_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_call_method_validation.cpp" \
  -o "${TMP_DIR}/call_method_validation_test"

"${TMP_DIR}/call_method_validation_test"
