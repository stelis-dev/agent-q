#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_method_runtime.sh

Compiles the StackChan CoreS3 call_method runtime boundary against ArduinoJson,
the common Sui facts parser, the common policy runtime, and pinned MicroSui
base64 helpers. It verifies unsupported methods, invalid Sui params, and the
stored default-reject policy decision for a valid restricted SUI transfer
fixture. This test uses only host compilers and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/products/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/products/firmware/src/common/agent_q"
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"
DEFAULT_SIGNING_DIR="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib"
SIGNING_ROOT="${AGENT_Q_SIGNING_CRYPTO_ROOT:-${DEFAULT_SIGNING_DIR}}"
SIGNING_CORE="${SIGNING_ROOT}/src/microsui_core"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${SIGNING_CORE}/byte_conversions.c" \
  "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex" \
  "${AGENT_Q_DIR}/agent_q_method_runtime.cpp" \
  "${AGENT_Q_DIR}/agent_q_call_method_validation.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_runtime.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_policy_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run tools/firmware/stackchan-cores3/build.sh first, or set AGENT_Q_ARDUINOJSON_ROOT/AGENT_Q_SIGNING_CRYPTO_ROOT." >&2
    exit 1
  fi
done

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-method-runtime.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/stubs"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once

#define ESP_LOGI(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGE(tag, format, ...) do { (void)(tag); } while (0)
H

cat >"${TMP_DIR}/method_runtime_test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <string>
#include <vector>

#include "agent_q_method_runtime.h"
#include "agent_q_policy_store.h"
#include "agent_q_common/policy/agent_q_policy_v0.h"

extern "C" {
#include "byte_conversions.h"
}

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

JsonDocument parse_json(const char* label, const std::string& json)
{
    JsonDocument document;
    const DeserializationError error = deserializeJson(document, json.c_str());
    if (error) {
        fprintf(stderr, "%s: JSON did not parse: %s\n%s\n", label, error.c_str(), json.c_str());
        exit(1);
    }
    return document;
}

uint8_t hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(c - 'A' + 10);
    }
    fprintf(stderr, "Invalid fixture hex char: %c\n", c);
    exit(1);
}

std::vector<uint8_t> read_hex_fixture(const char* path)
{
    std::ifstream input(path);
    if (!input) {
        fprintf(stderr, "Could not open fixture: %s\n", path);
        exit(1);
    }
    std::string hex;
    input >> hex;
    if ((hex.size() % 2) != 0) {
        fprintf(stderr, "Fixture has odd hex length\n");
        exit(1);
    }
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<uint8_t>(
            (hex_value(hex[index * 2]) << 4) | hex_value(hex[index * 2 + 1]));
    }
    return bytes;
}

std::string base64_fixture(const char* path)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(path);
    std::string output(((bytes.size() + 2) / 3) * 4 + 1, '\0');
    if (bytes_to_base64(bytes.data(), bytes.size(), output.data(), output.size()) != 0) {
        fprintf(stderr, "Fixture base64 encoding failed\n");
        exit(1);
    }
    output.resize(strlen(output.c_str()));
    return output;
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

bool load_default_policy(AgentQPolicyDocument* out, void*)
{
    if (out == nullptr) {
        return false;
    }
    *out = AgentQPolicyDocument{
        kAgentQPolicyV0Schema,
        AgentQPolicyAction::reject,
        nullptr,
        0,
    };
    return true;
}

bool store_default_policy()
{
    return false;
}

bool wipe_policy()
{
    return false;
}

AgentQPolicyStoreStatus active_policy_status()
{
    return AgentQPolicyStoreStatus::active;
}

AgentQPolicyProvider active_policy_provider()
{
    return AgentQPolicyProvider{load_default_policy, nullptr};
}

bool read_active_policy_summary(AgentQStoredPolicySummary*)
{
    return false;
}

}  // namespace agent_q

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: method_runtime_test <valid_tx_hex_fixture>\n");
        return 2;
    }

    const std::string valid_tx = base64_fixture(argv[1]);
    JsonDocument valid_params = parse_json(
        "valid params",
        std::string("{\"network\":\"devnet\",\"txBytes\":\"") + valid_tx + "\"}");

    const agent_q::AgentQMethodRuntimeResult policy_result =
        agent_q::evaluate_call_method("sui", "sign_transaction", valid_params.as<JsonVariant>());
    expect(policy_result.status == agent_q::AgentQMethodRuntimeStatus::rejected,
           "valid Sui transfer returns method rejection, not protocol error");
    expect(strcmp(policy_result.code, "policy_rejected") == 0,
           "default policy rejects valid Sui transfer");

    const agent_q::AgentQMethodRuntimeResult unsupported =
        agent_q::evaluate_call_method("sui", "unknown", valid_params.as<JsonVariant>());
    expect(unsupported.status == agent_q::AgentQMethodRuntimeStatus::rejected,
           "unknown method returns method rejection");
    expect(strcmp(unsupported.code, "unsupported_method") == 0,
           "unknown method reports unsupported_method");

    JsonDocument invalid_params = parse_json(
        "invalid params",
        "{\"network\":\"devnet\",\"txBytes\":\"AAAA\",\"seed\":\"x\"}");
    const agent_q::AgentQMethodRuntimeResult invalid =
        agent_q::evaluate_call_method("sui", "sign_transaction", invalid_params.as<JsonVariant>());
    expect(invalid.status == agent_q::AgentQMethodRuntimeStatus::invalid_params,
           "invalid Sui params return protocol invalid_params");
    expect(strcmp(invalid.code, "invalid_params") == 0,
           "invalid Sui params code is invalid_params");

    if (failures != 0) {
        fprintf(stderr, "%d method runtime test(s) failed\n", failures);
        return 1;
    }
    printf("Method runtime tests passed\n");
    return 0;
}
CPP

"${CC_BIN}" -c "${SIGNING_CORE}/byte_conversions.c" -o "${TMP_DIR}/byte_conversions.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${SIGNING_CORE}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_POLICY_DIR}" \
  -I"${COMMON_SUI_DIR}" \
  "${TMP_DIR}/method_runtime_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_method_runtime.cpp" \
  "${AGENT_Q_DIR}/agent_q_call_method_validation.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_runtime.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_policy_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  "${TMP_DIR}/byte_conversions.o" \
  -o "${TMP_DIR}/method_runtime_test"

"${TMP_DIR}/method_runtime_test" "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex"
