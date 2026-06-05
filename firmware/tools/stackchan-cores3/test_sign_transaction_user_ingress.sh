#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sign_transaction_user_ingress.sh

Compiles the StackChan CoreS3 sign_transaction_user ingress decision helper
against ArduinoJson with a host C++ compiler and checks that envelope, state,
session, and params gates stay ordered. This test does not require ESP-IDF,
but it uses the pinned StackChan ArduinoJson component checkout prepared by
fetch.sh/build.sh. Set AGENT_Q_ARDUINOJSON_ROOT to override the ArduinoJson
source root.
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
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_ingress.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_ingress.h" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_validation.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first, or set AGENT_Q_ARDUINOJSON_ROOT." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-signature-request-ingress.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/sign_transaction_user_ingress_test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include "agent_q_sign_transaction_user_ingress.h"

namespace {

int failures = 0;

struct SessionCheck {
    const char* expected_session_id;
    agent_q::AgentQSessionValidationResult result;
    int calls;
};

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

std::string valid_params()
{
    return "{\"network\":\"devnet\",\"txBytes\":\"AAAA\"}";
}

std::string request_with_session_and_params(
    const std::string& session_id,
    const std::string& params)
{
    return "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction\","
           "\"sessionId\":\"" + session_id + "\","
           "\"chain\":\"sui\",\"method\":\"sign_transaction\","
           "\"params\":" + params + "}";
}

std::string valid_request()
{
    return request_with_session_and_params("session_aaaaaaaaaaaaaaaa", valid_params());
}

std::string request_with_extra_top_level(
    const std::string& session_id,
    const std::string& params)
{
    return "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction\","
           "\"sessionId\":\"" + session_id + "\","
           "\"chain\":\"sui\",\"method\":\"sign_transaction\","
           "\"params\":" + params + ","
           "\"extra\":true}";
}

agent_q::AgentQSessionValidationResult validate_session(
    const char* session_id,
    void* context)
{
    SessionCheck* check = static_cast<SessionCheck*>(context);
    if (check == nullptr) {
        return agent_q::AgentQSessionValidationResult::missing;
    }
    ++check->calls;
    if (check->expected_session_id != nullptr &&
        strcmp(session_id, check->expected_session_id) != 0) {
        fprintf(stderr, "session callback got unexpected session id: %s\n", session_id);
        ++failures;
        return agent_q::AgentQSessionValidationResult::mismatch;
    }
    return check->result;
}

agent_q::AgentQSignTransactionUserIngressState state(
    bool material_ready,
    bool busy,
    SessionCheck* check)
{
    return agent_q::AgentQSignTransactionUserIngressState{
        material_ready,
        busy,
        validate_session,
        check,
    };
}

void expect_ingress(
    const char* label,
    const std::string& json,
    const agent_q::AgentQSignTransactionUserIngressState& input_state,
    agent_q::AgentQSignTransactionUserIngressResult expected,
    int* expected_session_calls = nullptr,
    bool expect_valid_output = false)
{
    JsonDocument document = parse_json(label, json);
    agent_q::AgentQSignTransactionUserIngressOutput output = {};
    memset(&output, 0xA5, sizeof(output));
    const agent_q::AgentQSignTransactionUserIngressResult actual =
        agent_q::evaluate_sign_transaction_user_ingress(document, input_state, &output);
    if (actual != expected) {
        fprintf(stderr, "%s: expected ingress result %d, got %d\n",
                label, static_cast<int>(expected), static_cast<int>(actual));
        ++failures;
    }
    if (expected_session_calls != nullptr &&
        input_state.session_context != nullptr) {
        const SessionCheck* check = static_cast<const SessionCheck*>(input_state.session_context);
        if (check->calls != *expected_session_calls) {
            fprintf(stderr, "%s: expected session callback calls %d, got %d\n",
                    label, *expected_session_calls, check->calls);
            ++failures;
        }
    }
    if (actual != agent_q::AgentQSignTransactionUserIngressResult::ok &&
        (output.envelope.request_id[0] != '\0' ||
         output.session.session_id[0] != '\0' ||
         output.params.chain[0] != '\0' ||
         output.params.method[0] != '\0' ||
         output.params.network[0] != '\0' ||
         output.params.tx_bytes_base64[0] != '\0' ||
         output.params.tx_bytes_decoded_size != 0)) {
        fprintf(stderr, "%s: ingress failure did not clear output\n", label);
        ++failures;
    }
    if (expect_valid_output &&
        (strcmp(output.envelope.request_id, "req_sign_1") != 0 ||
         strcmp(output.session.session_id, "session_aaaaaaaaaaaaaaaa") != 0 ||
         strcmp(output.params.chain, "sui") != 0 ||
         strcmp(output.params.method, "sign_transaction") != 0 ||
         strcmp(output.params.network, "devnet") != 0 ||
         strcmp(output.params.tx_bytes_base64, "AAAA") != 0 ||
         output.params.tx_bytes_decoded_size != 3)) {
        fprintf(stderr, "%s: valid ingress output did not match expected fields\n", label);
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
    using IngressResult = agent_q::AgentQSignTransactionUserIngressResult;
    using SessionResult = agent_q::AgentQSessionValidationResult;

    {
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
        int calls = 1;
        expect_ingress(
            "valid request",
            valid_request(),
            state(true, false, &check),
            IngressResult::ok,
            &calls,
            true);
    }

    {
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
        int calls = 0;
        expect_ingress(
            "unsupported type before state",
            "{\"id\":\"req_sign_1\",\"version\":1,\"type\":\"sign_transaction_policy\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"params\":[]}",
            state(false, false, &check),
            IngressResult::unsupported_type,
            &calls);
    }

    {
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
        int calls = 0;
        expect_ingress(
            "wrong device state ignores malformed params",
            request_with_session_and_params("session_aaaaaaaaaaaaaaaa", "[]"),
            state(false, false, &check),
            IngressResult::invalid_state,
            &calls);
    }

    {
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
        int calls = 0;
        expect_ingress(
            "wrong device state ignores unsupported top-level fields",
            request_with_extra_top_level("session_aaaaaaaaaaaaaaaa", "[]"),
            state(false, false, &check),
            IngressResult::invalid_state,
            &calls);
    }

    {
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
        int calls = 0;
        expect_ingress(
            "busy state ignores malformed params",
            request_with_session_and_params("session_aaaaaaaaaaaaaaaa", "[]"),
            state(true, true, &check),
            IngressResult::busy,
            &calls);
    }

    {
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
        int calls = 0;
        expect_ingress(
            "busy state ignores unsupported top-level fields",
            request_with_extra_top_level("session_aaaaaaaaaaaaaaaa", "[]"),
            state(true, true, &check),
            IngressResult::busy,
            &calls);
    }

    {
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
        int calls = 0;
        expect_ingress(
            "invalid session format before params",
            request_with_session_and_params("bad_session", "[]"),
            state(true, false, &check),
            IngressResult::invalid_session,
            &calls);
    }

    {
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::mismatch, 0};
        int calls = 1;
        expect_ingress(
            "session mismatch before params",
            request_with_session_and_params("session_aaaaaaaaaaaaaaaa", "[]"),
            state(true, false, &check),
            IngressResult::invalid_session,
            &calls);
    }

    {
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::mismatch, 0};
        int calls = 1;
        expect_ingress(
            "session mismatch before unsupported top-level fields",
            request_with_extra_top_level("session_aaaaaaaaaaaaaaaa", "[]"),
            state(true, false, &check),
            IngressResult::invalid_session,
            &calls);
    }

    {
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
        int calls = 1;
        expect_ingress(
            "unsupported top-level fields after valid session",
            request_with_extra_top_level("session_aaaaaaaaaaaaaaaa", valid_params()),
            state(true, false, &check),
            IngressResult::unsupported_field,
            &calls);
    }

    {
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
        int calls = 1;
        expect_ingress(
            "params malformed after valid session",
            request_with_session_and_params("session_aaaaaaaaaaaaaaaa", "[]"),
            state(true, false, &check),
            IngressResult::invalid_params_shape,
            &calls);
    }

    {
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
        int calls = 1;
        expect_ingress(
            "params invalid network after valid session",
            request_with_session_and_params(
                "session_aaaaaaaaaaaaaaaa",
                "{\"network\":\"bogus\",\"txBytes\":\"AAAA\"}"),
            state(true, false, &check),
            IngressResult::invalid_network,
            &calls);
    }

    {
        JsonDocument document = parse_json("null output", valid_request());
        SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
        const IngressResult result =
            agent_q::evaluate_sign_transaction_user_ingress(document, state(true, false, &check), nullptr);
        if (result != IngressResult::invalid_request_shape || check.calls != 0) {
            fprintf(stderr, "null output should fail before session validation\n");
            ++failures;
        }
    }

    if (strcmp(agent_q::sign_transaction_user_ingress_result_name(IngressResult::busy), "busy") != 0 ||
        strcmp(agent_q::sign_transaction_user_ingress_result_name(IngressResult::invalid_state), "invalid_state") != 0 ||
        strcmp(agent_q::sign_transaction_user_ingress_result_name(IngressResult::invalid_tx_bytes), "invalid_tx_bytes") != 0) {
        fprintf(stderr, "ingress result names mismatch\n");
        ++failures;
    }

    if (failures != 0) {
        fprintf(stderr, "sign_transaction_user ingress tests failed: %d\n", failures);
        return 1;
    }
    return 0;
}
CPP

"${CXX_BIN}" \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/sign_transaction_user_ingress_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_ingress.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_validation.cpp" \
  -o "${TMP_DIR}/sign_transaction_user_ingress_test"

"${TMP_DIR}/sign_transaction_user_ingress_test"
