#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_signing_retry_response.sh

Compiles the signing retry public-response mapper and verifies the JSON response
shape for retained-result replay, conflict, lookup error, not-found, malformed
stored result, and writer-failure outcomes. It does not require hardware.
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
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${AGENT_Q_DIR}/agent_q_signing_retry_response.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_retry_response.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-signing-retry-response.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include "agent_q_signing_retry_response.h"

namespace {

struct Capture {
    bool fail = false;
    int calls = 0;
    std::string json;
};

bool capture_response(JsonDocument& response, void* context)
{
    Capture* capture = static_cast<Capture*>(context);
    assert(capture != nullptr);
    capture->calls += 1;
    if (capture->fail) {
        return false;
    }
    capture->json.clear();
    serializeJson(response, capture->json);
    return true;
}

JsonDocument parse_json(const std::string& json)
{
    JsonDocument document;
    assert(!deserializeJson(document, json));
    return document;
}

agent_q::AgentQSigningRetryDeliveryResult retry_result(
    agent_q::AgentQSigningRetryDeliveryStatus status,
    size_t stored_result_len = 0,
    const char* code = nullptr,
    const char* message = nullptr)
{
    return agent_q::AgentQSigningRetryDeliveryResult{
        status,
        stored_result_len,
        code,
        message,
    };
}

}  // namespace

int main()
{
    const char stored[] = "{\"id\":\"req_sign\",\"version\":1,\"type\":\"sign_result\",\"status\":\"signed\"}";

    {
        Capture capture;
        const auto result = agent_q::deliver_signing_retry_response(
            "req_sign",
            retry_result(agent_q::AgentQSigningRetryDeliveryStatus::not_found),
            stored,
            capture_response,
            &capture);
        assert(result == agent_q::AgentQSigningRetryResponseResult::not_found);
        assert(capture.calls == 0);
    }

    {
        Capture capture;
        const auto result = agent_q::deliver_signing_retry_response(
            "req_sign",
            retry_result(
                agent_q::AgentQSigningRetryDeliveryStatus::match,
                strlen(stored)),
            stored,
            capture_response,
            &capture);
        assert(result == agent_q::AgentQSigningRetryResponseResult::replayed_result);
        assert(capture.calls == 1);
        JsonDocument document = parse_json(capture.json);
        assert(strcmp(document["type"], "sign_result") == 0);
        assert(strcmp(document["id"], "req_sign") == 0);
        assert(strcmp(document["status"], "signed") == 0);
    }

    {
        Capture capture;
        const auto result = agent_q::deliver_signing_retry_response(
            "req_sign",
            retry_result(
                agent_q::AgentQSigningRetryDeliveryStatus::request_id_conflict,
                0,
                "request_id_conflict",
                "Request id is already bound to a different signing request."),
            stored,
            capture_response,
            &capture);
        assert(result == agent_q::AgentQSigningRetryResponseResult::error_response);
        JsonDocument document = parse_json(capture.json);
        assert(strcmp(document["type"], "error") == 0);
        assert(strcmp(document["id"], "req_sign") == 0);
        assert(strcmp(document["error"]["code"], "request_id_conflict") == 0);
    }

    {
        Capture capture;
        const auto result = agent_q::deliver_signing_retry_response(
            "req_sign",
            retry_result(
                agent_q::AgentQSigningRetryDeliveryStatus::lookup_error,
                0,
                "protocol_error",
                "Stored signing result lookup failed."),
            stored,
            capture_response,
            &capture);
        assert(result == agent_q::AgentQSigningRetryResponseResult::error_response);
        JsonDocument document = parse_json(capture.json);
        assert(strcmp(document["type"], "error") == 0);
        assert(strcmp(document["error"]["code"], "protocol_error") == 0);
    }

    {
        Capture capture;
        const char malformed[] = "{not-json";
        const auto result = agent_q::deliver_signing_retry_response(
            "req_sign",
            retry_result(
                agent_q::AgentQSigningRetryDeliveryStatus::match,
                strlen(malformed)),
            malformed,
            capture_response,
            &capture);
        assert(result == agent_q::AgentQSigningRetryResponseResult::invalid_stored_result);
        assert(capture.calls == 0);
    }

    {
        Capture capture;
        capture.fail = true;
        const auto result = agent_q::deliver_signing_retry_response(
            "req_sign",
            retry_result(
                agent_q::AgentQSigningRetryDeliveryStatus::match,
                strlen(stored)),
            stored,
            capture_response,
            &capture);
        assert(result == agent_q::AgentQSigningRetryResponseResult::replay_write_failed);
        assert(capture.calls == 1);
    }

    {
        Capture capture;
        capture.fail = true;
        const auto result = agent_q::deliver_signing_retry_response(
            "req_sign",
            retry_result(
                agent_q::AgentQSigningRetryDeliveryStatus::request_id_conflict,
                0,
                "request_id_conflict",
                "Request id is already bound to a different signing request."),
            stored,
            capture_response,
            &capture);
        assert(result == agent_q::AgentQSigningRetryResponseResult::error_write_failed);
        assert(capture.calls == 1);
    }

    printf("Signing retry response tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_retry_response.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
