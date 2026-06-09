#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sign_personal_message_user_validation.sh

Compiles the StackChan CoreS3 sign_personal_message user-mode validation helper
against host stubs. This verifies bounded envelope/session/params validation and
does NOT require ESP-IDF.
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
CXX_BIN="${CXX:-c++}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${AGENT_Q_DIR}/agent_q_base64.h" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.h" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.h" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_validation.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first, or set AGENT_Q_ARDUINOJSON_ROOT." >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sign-personal-message-validation.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/sign_personal_message_user_validation_test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include "agent_q_sign_personal_message_user_validation.h"

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
    return document;
}

std::string valid_params()
{
    return "{\"network\":\"devnet\",\"message\":\"aGVsbG8=\"}";
}

std::string valid_request_with_params(const std::string& params)
{
    return "{\"id\":\"req_sign_msg_1\",\"version\":1,\"type\":\"sign_personal_message\","
           "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
           "\"chain\":\"sui\",\"method\":\"sign_personal_message\","
           "\"params\":" + params + "}";
}

std::string request_with_type(const char* type)
{
    return "{\"id\":\"req_sign_msg_1\",\"version\":1,\"type\":\"" + std::string(type) + "\","
           "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
           "\"chain\":\"sui\",\"method\":\"sign_personal_message\","
           "\"params\":" + valid_params() + "}";
}

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void expect_envelope(
    const char* label,
    const std::string& json,
    agent_q::AgentQSignPersonalMessageUserValidationResult expected)
{
    JsonDocument document = parse_json(label, json);
    agent_q::AgentQSignPersonalMessageUserEnvelope output = {};
    memset(&output, 0xA5, sizeof(output));
    const agent_q::AgentQSignPersonalMessageUserValidationResult actual =
        agent_q::validate_sign_personal_message_user_envelope(document, &output);
    expect(actual == expected, label);
    if (actual != agent_q::AgentQSignPersonalMessageUserValidationResult::ok) {
        expect(output.request_id[0] == '\0', "envelope failure clears output");
    }
}

void expect_session(
    const char* label,
    const std::string& json,
    agent_q::AgentQSignPersonalMessageUserValidationResult expected)
{
    JsonDocument document = parse_json(label, json);
    agent_q::AgentQSignPersonalMessageUserSessionRef output = {};
    memset(&output, 0xA5, sizeof(output));
    const agent_q::AgentQSignPersonalMessageUserValidationResult actual =
        agent_q::validate_sign_personal_message_user_session_format(document, &output);
    expect(actual == expected, label);
    if (actual != agent_q::AgentQSignPersonalMessageUserValidationResult::ok) {
        expect(output.session_id[0] == '\0', "session failure clears output");
    }
}

void expect_params(
    const char* label,
    const std::string& json,
    agent_q::AgentQSignPersonalMessageUserValidationResult expected,
    size_t expected_decoded_size = 0,
    const char* expected_message = "aGVsbG8=")
{
    JsonDocument document = parse_json(label, json);
    agent_q::AgentQSignPersonalMessageUserParams output = {};
    memset(&output, 0xA5, sizeof(output));
    const agent_q::AgentQSignPersonalMessageUserValidationResult actual =
        agent_q::validate_sign_personal_message_user_params(document, agent_q::AgentQSupportedSignRoute::sui_sign_personal_message, &output);
    expect(actual == expected, label);
    if (actual == agent_q::AgentQSignPersonalMessageUserValidationResult::ok) {
        expect(strcmp(output.network, "devnet") == 0, "params copies network");
        expect(strcmp(output.message_base64, expected_message) == 0, "params references message");
        expect(output.message_decoded_size == expected_decoded_size, "params records decoded size");
    } else {
        expect(output.network[0] == '\0' &&
                   output.message_base64 == nullptr &&
                   output.message_decoded_size == 0,
               "params failure clears output");
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
    using Result = agent_q::AgentQSignPersonalMessageUserValidationResult;

    const std::string valid = valid_request_with_params(valid_params());
    expect_envelope("valid envelope", valid, Result::ok);
    expect_session("valid session", valid, Result::ok);
    expect_params("valid params", valid, Result::ok, 5);

    expect_envelope("wrong type rejected", request_with_type("sign_transaction"), Result::unsupported_type);
    expect_envelope("extra top-level rejected",
                    valid.substr(0, valid.size() - 1) + ",\"authorization\":\"user\"}",
                    Result::unsupported_field);
    expect_session("bad session rejected",
                   "{\"id\":\"req_sign_msg_1\",\"version\":1,\"type\":\"sign_personal_message\","
                   "\"sessionId\":\"bad_session\","
                   "\"chain\":\"sui\",\"method\":\"sign_personal_message\","
                   "\"params\":{\"network\":\"devnet\",\"message\":\"aGVsbG8=\"}}",
                   Result::invalid_session);
    expect_params("selected route owns identity when raw method differs",
                  "{\"id\":\"req_sign_msg_1\",\"version\":1,\"type\":\"sign_personal_message\","
                  "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
                  "\"chain\":\"sui\",\"method\":\"sign_message\","
                  "\"params\":{\"network\":\"devnet\",\"message\":\"aGVsbG8=\"}}",
                  Result::ok,
                  5);
    expect_params("bad network rejected",
                  valid_request_with_params("{\"network\":\"staging\",\"message\":\"aGVsbG8=\"}"),
                  Result::invalid_network);
    expect_params("extra param rejected",
                  valid_request_with_params("{\"network\":\"devnet\",\"message\":\"aGVsbG8=\",\"timeoutMs\":1}"),
                  Result::unsupported_field);
    expect_params("noncanonical message rejected",
                  valid_request_with_params("{\"network\":\"devnet\",\"message\":\"aGVsbG9\"}"),
                  Result::invalid_message);
    const std::string above_adapter_capacity(344, 'A');
    expect_params(
        "message above adapter capacity remains valid request format",
        valid_request_with_params(std::string("{\"network\":\"devnet\",\"message\":\"") +
                                  above_adapter_capacity +
                                  "\"}"),
        Result::ok,
        258,
        above_adapter_capacity.c_str());

    expect(strcmp(agent_q::sign_personal_message_user_validation_result_name(Result::invalid_message),
                  "invalid_message") == 0,
           "result names expose invalid_message");

    if (failures != 0) {
        fprintf(stderr, "%d sign_personal_message validation test(s) failed\n", failures);
        return 1;
    }
    printf("sign_personal_message user validation tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${AGENT_Q_DIR}/../../common/agent_q" \
  "${TMP_DIR}/sign_personal_message_user_validation_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  -o "${TMP_DIR}/sign_personal_message_user_validation_test"

"${TMP_DIR}/sign_personal_message_user_validation_test"
