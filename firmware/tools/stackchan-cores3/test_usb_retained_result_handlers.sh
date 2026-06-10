#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_retained_result_handlers.sh

Compiles extracted USB retained-result handlers and verifies get_result and
ack_result validation/replay behavior. It does not require hardware.
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
  "${AGENT_Q_DIR}/agent_q_usb_retained_result_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_retained_result_handlers.h" \
  "${AGENT_Q_DIR}/agent_q_signing_result_store.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_result_store.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-retained-result-handlers.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_signing_result_store.h"
#include "agent_q_usb_retained_result_handlers.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_require_session_calls = 0;
int g_write_json_calls = 0;
int g_ack_result_calls = 0;
bool g_material_ready = true;
bool g_session_valid = true;
bool g_ack_write_ok = true;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;
const char* g_last_error_message = nullptr;
char g_last_json_status[32] = {};
char g_last_json_signature[160] = {};

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_require_session_calls = 0;
    g_write_json_calls = 0;
    g_ack_result_calls = 0;
    g_material_ready = true;
    g_session_valid = true;
    g_ack_write_ok = true;
    g_last_id = nullptr;
    g_last_session = nullptr;
    g_last_error_code = nullptr;
    g_last_error_message = nullptr;
    g_last_json_status[0] = '\0';
    g_last_json_signature[0] = '\0';
    agent_q::signing_result_clear_all();
}

bool write_error(const char* id, const char* code, const char* message)
{
    g_write_error_calls += 1;
    g_last_id = id;
    g_last_error_code = code;
    g_last_error_message = message;
    return true;
}

}  // namespace

namespace agent_q {

bool usb_response_write_json(JsonDocument& response)
{
    g_write_json_calls += 1;
    snprintf(g_last_json_status, sizeof(g_last_json_status), "%s", response["status"] | "");
    snprintf(g_last_json_signature, sizeof(g_last_json_signature), "%s", response["signature"] | "");
    return true;
}

bool usb_response_write_ack_result(const char* id)
{
    g_ack_result_calls += 1;
    g_last_id = id;
    return g_ack_write_ok;
}

}  // namespace agent_q

namespace {

void log_write_failure(const char* response_type, const char* id)
{
    (void)response_type;
    g_log_write_failure_calls += 1;
    g_last_id = id;
}

bool material_ready()
{
    return g_material_ready;
}

bool require_session(const char* id, const char* session_id)
{
    g_require_session_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    return g_session_valid;
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

agent_q::AgentQUsbRetainedResultHandlerOps make_ops()
{
    return agent_q::AgentQUsbRetainedResultHandlerOps{
        material_ready,
        require_session,
    };
}

JsonDocument parse_request(const char* json)
{
    JsonDocument request;
    const DeserializationError error = deserializeJson(request, json);
    assert(!error);
    return request;
}

void store_result(const char* session_id, const char* request_id)
{
    const uint8_t identity[agent_q::kAgentQSignRequestIdentitySize] = {1};
    const char* const result =
        "{\"id\":\"req\",\"version\":1,\"type\":\"sign_result\",\"status\":\"signed\","
        "\"authorization\":\"user\",\"chain\":\"sui\",\"method\":\"sign_transaction\","
        "\"signature\":\"sig\"}";
    const agent_q::SigningResultStoreOutcome outcome = agent_q::signing_result_store(
        session_id,
        request_id,
        identity,
        sizeof(identity),
        result,
        strlen(result));
    assert(outcome == agent_q::SigningResultStoreOutcome::stored);
}

void store_malformed_result(const char* session_id, const char* request_id)
{
    const uint8_t identity[agent_q::kAgentQSignRequestIdentitySize] = {2};
    const char* const result = "{";
    const agent_q::SigningResultStoreOutcome outcome = agent_q::signing_result_store(
        session_id,
        request_id,
        identity,
        sizeof(identity),
        result,
        strlen(result));
    assert(outcome == agent_q::SigningResultStoreOutcome::stored);
}

}  // namespace

int main()
{
    {
        reset_state();
        g_material_ready = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_result\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_result_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_require_session_calls == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_result\",\"sessionId\":7}");
        agent_q::handle_usb_get_result_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_require_session_calls == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_result\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_result_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_require_session_calls == 1);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_result\",\"sessionId\":\"session\",\"extra\":1}");
        agent_q::handle_usb_get_result_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "get_result request contains unsupported fields.") == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        store_result("session", "req");
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_result\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_result_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_require_session_calls == 1);
        assert(strcmp(g_last_session, "session") == 0);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_status, "signed") == 0);
        assert(strcmp(g_last_json_signature, "sig") == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_result\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_result_request("req", request, make_writer(), make_ops());
        assert(g_write_json_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
    }

    {
        reset_state();
        store_malformed_result("session", "req");
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_result\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_result_request("req", request, make_writer(), make_ops());
        assert(g_write_json_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"ack_result\",\"sessionId\":\"session\",\"extra\":1}");
        agent_q::handle_usb_ack_result_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "ack_result request contains unsupported fields.") == 0);
        assert(g_ack_result_calls == 0);
    }

    {
        reset_state();
        store_result("session", "req");
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"ack_result\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_ack_result_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_ack_result_calls == 1);
        assert(strcmp(g_last_session, "session") == 0);
        assert(strcmp(g_last_id, "req") == 0);
        char out[agent_q::kSigningResultMaxSize];
        size_t out_len = 0;
        assert(!agent_q::signing_result_find("session", "req", out, sizeof(out), &out_len));
    }

    {
        reset_state();
        store_result("session", "req");
        g_ack_write_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"ack_result\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_ack_result_request("req", request, make_writer(), make_ops());
        assert(g_ack_result_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(strcmp(g_last_id, "req") == 0);
        char out[agent_q::kSigningResultMaxSize];
        size_t out_len = 0;
        assert(!agent_q::signing_result_find("session", "req", out, sizeof(out), &out_len));
    }

    printf("USB retained-result handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${AGENT_Q_DIR}/../../common/agent_q" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_retained_result_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_result_store.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
