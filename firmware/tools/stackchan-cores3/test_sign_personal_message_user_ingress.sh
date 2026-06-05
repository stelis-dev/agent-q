#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sign_personal_message_user_ingress.sh

Compiles the StackChan CoreS3 sign_personal_message user-mode ingress helper
against host stubs. It verifies state-first ingress ordering and bounded output
ownership. This test does NOT require ESP-IDF.
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
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_ingress.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_ingress.h" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_validation.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first, or set AGENT_Q_ARDUINOJSON_ROOT." >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sign-personal-message-ingress.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/sign_personal_message_user_ingress_test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include "agent_q_sign_personal_message_user_ingress.h"

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
    return document;
}

std::string valid_params()
{
    return "{\"network\":\"devnet\",\"message\":\"aGVsbG8=\"}";
}

std::string request_with_session_and_params(
    const std::string& session_id,
    const std::string& params)
{
    return "{\"id\":\"req_sign_msg_1\",\"version\":1,\"type\":\"sign_personal_message\","
           "\"sessionId\":\"" + session_id + "\","
           "\"chain\":\"sui\",\"method\":\"sign_personal_message\","
           "\"params\":" + params + "}";
}

std::string valid_request()
{
    return request_with_session_and_params("session_aaaaaaaaaaaaaaaa", valid_params());
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

agent_q::AgentQSignPersonalMessageUserIngressState state(
    bool material_ready,
    bool busy,
    SessionCheck* check)
{
    return agent_q::AgentQSignPersonalMessageUserIngressState{
        material_ready,
        busy,
        validate_session,
        check,
    };
}

void expect_ingress(
    const char* label,
    const std::string& json,
    const agent_q::AgentQSignPersonalMessageUserIngressState& input_state,
    agent_q::AgentQSignPersonalMessageUserIngressResult expected,
    int expected_session_calls,
    bool expect_valid_output = false)
{
    JsonDocument document = parse_json(label, json);
    agent_q::AgentQSignPersonalMessageUserIngressOutput output = {};
    memset(&output, 0xA5, sizeof(output));
    const agent_q::AgentQSignPersonalMessageUserIngressResult actual =
        agent_q::evaluate_sign_personal_message_user_ingress(document, input_state, &output);
    if (actual != expected) {
        fprintf(stderr, "%s: expected ingress result %d, got %d\n",
                label, static_cast<int>(expected), static_cast<int>(actual));
        ++failures;
    }
    if (input_state.session_context != nullptr) {
        const SessionCheck* check = static_cast<const SessionCheck*>(input_state.session_context);
        if (check->calls != expected_session_calls) {
            fprintf(stderr, "%s: expected session callback calls %d, got %d\n",
                    label, expected_session_calls, check->calls);
            ++failures;
        }
    }
    if (actual != agent_q::AgentQSignPersonalMessageUserIngressResult::ok &&
        (output.envelope.request_id[0] != '\0' ||
         output.session.session_id[0] != '\0' ||
         output.params.chain[0] != '\0' ||
         output.params.method[0] != '\0' ||
         output.params.network[0] != '\0' ||
         output.params.message_base64[0] != '\0' ||
         output.params.message_decoded_size != 0)) {
        fprintf(stderr, "%s: ingress failure did not clear output\n", label);
        ++failures;
    }
    if (expect_valid_output &&
        (strcmp(output.envelope.request_id, "req_sign_msg_1") != 0 ||
         strcmp(output.session.session_id, "session_aaaaaaaaaaaaaaaa") != 0 ||
         strcmp(output.params.chain, "sui") != 0 ||
         strcmp(output.params.method, "sign_personal_message") != 0 ||
         strcmp(output.params.network, "devnet") != 0 ||
         strcmp(output.params.message_base64, "aGVsbG8=") != 0 ||
         output.params.message_decoded_size != 5)) {
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
    using IngressResult = agent_q::AgentQSignPersonalMessageUserIngressResult;
    using SessionResult = agent_q::AgentQSessionValidationResult;

    SessionCheck check{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
    expect_ingress("valid ingress", valid_request(), state(true, false, &check),
                   IngressResult::ok, 1, true);

    check = SessionCheck{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
    expect_ingress("bad type stops before state",
                   "{\"id\":\"req_sign_msg_1\",\"version\":1,\"type\":\"sign_transaction\","
                   "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
                   "\"chain\":\"sui\",\"method\":\"sign_personal_message\","
                   "\"params\":{\"network\":\"devnet\",\"message\":\"aGVsbG8=\"}}",
                   state(false, false, &check),
                   IngressResult::unsupported_type,
                   0);

    check = SessionCheck{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
    expect_ingress("missing material stops before session",
                   valid_request(),
                   state(false, false, &check),
                   IngressResult::invalid_state,
                   0);

    check = SessionCheck{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
    expect_ingress("busy stops before session",
                   valid_request(),
                   state(true, true, &check),
                   IngressResult::busy,
                   0);

    check = SessionCheck{"session_aaaaaaaaaaaaaaaa", SessionResult::mismatch, 0};
    expect_ingress("session mismatch rejects before params",
                   valid_request(),
                   state(true, false, &check),
                   IngressResult::invalid_session,
                   1);

    check = SessionCheck{"session_aaaaaaaaaaaaaaaa", SessionResult::ok, 0};
    expect_ingress("invalid message rejected after session",
                   request_with_session_and_params(
                       "session_aaaaaaaaaaaaaaaa",
                       "{\"network\":\"devnet\",\"message\":\"not-base64\"}"),
                   state(true, false, &check),
                   IngressResult::invalid_message,
                   1);

    if (strcmp(agent_q::sign_personal_message_user_ingress_result_name(IngressResult::busy), "busy") != 0 ||
        strcmp(agent_q::sign_personal_message_user_ingress_result_name(IngressResult::invalid_message),
               "invalid_message") != 0) {
        fprintf(stderr, "FAILED: ingress result names are stable\n");
        ++failures;
    }

    if (failures != 0) {
        fprintf(stderr, "%d sign_personal_message ingress test(s) failed\n", failures);
        return 1;
    }
    printf("sign_personal_message user ingress tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/sign_personal_message_user_ingress_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_ingress.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  -o "${TMP_DIR}/sign_personal_message_user_ingress_test"

"${TMP_DIR}/sign_personal_message_user_ingress_test"
