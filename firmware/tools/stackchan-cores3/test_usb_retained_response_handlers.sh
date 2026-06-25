#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_retained_response_handlers.sh

Compiles extracted USB retained-response handlers and verifies get_result and
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
  "${AGENT_Q_DIR}/agent_q_usb_retained_response_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_retained_response_handlers.h" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.h" \
  "${AGENT_Q_DIR}/agent_q_signing_response_store.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_response_store.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-retained-response-handlers.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_signing_response_store.h"
#include "agent_q_usb_retained_response_handlers.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_payload_admission_calls = 0;
int g_require_session_calls = 0;
int g_write_json_calls = 0;
int g_ack_result_calls = 0;
bool g_material_ready = true;
bool g_payload_admission_error = false;
bool g_session_valid = true;
bool g_ack_write_ok = true;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;
const char* g_last_method = nullptr;
char g_last_json_status[32] = {};
char g_last_json_signature[160] = {};

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_payload_admission_calls = 0;
    g_require_session_calls = 0;
    g_write_json_calls = 0;
    g_ack_result_calls = 0;
    g_material_ready = true;
    g_payload_admission_error = false;
    g_session_valid = true;
    g_ack_write_ok = true;
    g_last_id = nullptr;
    g_last_session = nullptr;
    g_last_error_code = nullptr;
    g_last_method = nullptr;
    g_last_json_status[0] = '\0';
    g_last_json_signature[0] = '\0';
    agent_q::signing_response_clear_all();
}

bool write_error(const char* id, const char* code)
{
    g_write_error_calls += 1;
    g_last_id = id;
    g_last_error_code = code;
    return true;
}

bool write_method_error(const char* id, const char* method, const char* code)
{
    g_last_method = method;
    return write_error(id, code);
}

}  // namespace

namespace agent_q {

bool usb_response_write_success_result(const char* id, const char* method, JsonObjectConst result)
{
    g_write_json_calls += 1;
    g_last_id = id;
    g_last_method = method;
    snprintf(g_last_json_status, sizeof(g_last_json_status), "%s", result["status"] | "");
    snprintf(g_last_json_signature, sizeof(g_last_json_signature), "%s", result["signature"] | "");
    return true;
}

bool usb_response_write_method_error(
    const char* id,
    const char* method,
    const char* code)
{
    return write_method_error(id, method, code);
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

bool write_payload_admission_error(
    const char* id,
    agent_q::AgentQUsbOperationType operation,
    const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    assert(operation == agent_q::AgentQUsbOperationType::get_result ||
           operation == agent_q::AgentQUsbOperationType::ack_result);
    g_payload_admission_calls += 1;
    g_last_id = id;
    if (!g_payload_admission_error) {
        return false;
    }
    return writer.write_error(id, "busy");
}

bool require_session(
    const char* id,
    const char* session_id,
    const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    g_require_session_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    if (!g_session_valid) {
        writer.write_error(id, "invalid_session");
    }
    return g_session_valid;
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_method_error,
        log_write_failure,
    };
}

agent_q::AgentQUsbOperationResponseWriter make_writer_for(const char* method)
{
    return make_writer().for_method(method);
}

agent_q::AgentQUsbRetainedResponseHandlerOps make_ops()
{
    return agent_q::AgentQUsbRetainedResponseHandlerOps{
        material_ready,
        write_payload_admission_error,
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

void store_response(const char* session_id, const char* request_id)
{
    const uint8_t identity[agent_q::kAgentQSignRequestIdentitySize] = {1};
    const char* const result =
        "{\"id\":\"req\",\"version\":1,\"success\":true,\"method\":\"sign_transaction\","
        "\"result\":{\"authorization\":\"user\",\"chain\":\"sui\","
        "\"method\":\"sign_transaction\",\"signature\":\"sig\",\"status\":\"signed\"}}";
    const agent_q::SigningResponseStoreOutcome outcome = agent_q::signing_response_store(
        session_id,
        request_id,
        identity,
        sizeof(identity),
        result,
        strlen(result));
    assert(outcome == agent_q::SigningResponseStoreOutcome::stored);
}

void store_malformed_result(const char* session_id, const char* request_id)
{
    const uint8_t identity[agent_q::kAgentQSignRequestIdentitySize] = {2};
    const char* const result = "{";
    const agent_q::SigningResponseStoreOutcome outcome = agent_q::signing_response_store(
        session_id,
        request_id,
        identity,
        sizeof(identity),
        result,
        strlen(result));
    assert(outcome == agent_q::SigningResponseStoreOutcome::stored);
}

}  // namespace

int main()
{
    {
        reset_state();
        g_material_ready = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_result\",\"sessionId\":\"session\",\"payload\":{\"retainedRequestId\":\"req\"}}");
        agent_q::handle_usb_get_result_request("req", request, make_writer_for("get_result"), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(strcmp(g_last_method, "get_result") == 0);
        assert(g_payload_admission_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        g_payload_admission_error = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_result\",\"sessionId\":\"session\",\"payload\":{\"retainedRequestId\":\"req\"}}");
        agent_q::handle_usb_get_result_request("req", request, make_writer_for("get_result"), make_ops());
        assert(g_payload_admission_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(g_require_session_calls == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_result\",\"sessionId\":7,\"payload\":{\"retainedRequestId\":\"req\"}}");
        agent_q::handle_usb_get_result_request("req", request, make_writer_for("get_result"), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_payload_admission_calls == 1);
        assert(g_require_session_calls == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_result\",\"sessionId\":\"session\",\"payload\":{\"retainedRequestId\":\"req\"}}");
        agent_q::handle_usb_get_result_request("req", request, make_writer_for("get_result"), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(strcmp(g_last_method, "get_result") == 0);
        assert(g_require_session_calls == 1);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_result\",\"sessionId\":\"session\",\"payload\":{\"retainedRequestId\":\"req\"},\"extra\":1}");
        agent_q::handle_usb_get_result_request("req", request, make_writer_for("get_result"), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        store_response("session", "req");
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_result\",\"sessionId\":\"session\",\"payload\":{\"retainedRequestId\":\"req\"}}");
        agent_q::handle_usb_get_result_request("req", request, make_writer_for("get_result"), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_require_session_calls == 1);
        assert(strcmp(g_last_session, "session") == 0);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_method, "get_result") == 0);
        assert(strcmp(g_last_json_status, "signed") == 0);
        assert(strcmp(g_last_json_signature, "sig") == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_result\",\"sessionId\":\"session\",\"payload\":{\"retainedRequestId\":\"req\"}}");
        agent_q::handle_usb_get_result_request("req", request, make_writer_for("get_result"), make_ops());
        assert(g_write_json_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
    }

    {
        reset_state();
        store_malformed_result("session", "req");
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_result\",\"sessionId\":\"session\",\"payload\":{\"retainedRequestId\":\"req\"}}");
        agent_q::handle_usb_get_result_request("req", request, make_writer_for("get_result"), make_ops());
        assert(g_write_json_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"ack_result\",\"sessionId\":\"session\",\"payload\":{\"retainedRequestId\":\"req\"},\"extra\":1}");
        agent_q::handle_usb_ack_result_request("req", request, make_writer_for("ack_result"), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_payload_admission_calls == 1);
        assert(g_ack_result_calls == 0);
    }

    {
        reset_state();
        g_payload_admission_error = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"ack_result\",\"sessionId\":\"session\",\"payload\":{\"retainedRequestId\":\"req\"}}");
        agent_q::handle_usb_ack_result_request("req", request, make_writer_for("ack_result"), make_ops());
        assert(g_payload_admission_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(g_require_session_calls == 0);
        assert(g_ack_result_calls == 0);
    }

    {
        reset_state();
        store_response("session", "req");
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"ack_result\",\"sessionId\":\"session\",\"payload\":{\"retainedRequestId\":\"req\"}}");
        agent_q::handle_usb_ack_result_request("req", request, make_writer_for("ack_result"), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_ack_result_calls == 1);
        assert(strcmp(g_last_session, "session") == 0);
        assert(strcmp(g_last_id, "req") == 0);
        char out[agent_q::kSigningResponseMaxSize];
        size_t out_len = 0;
        assert(!agent_q::signing_response_find("session", "req", out, sizeof(out), &out_len));
    }

    {
        reset_state();
        store_response("session", "req");
        g_ack_write_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"ack_result\",\"sessionId\":\"session\",\"payload\":{\"retainedRequestId\":\"req\"}}");
        agent_q::handle_usb_ack_result_request("req", request, make_writer_for("ack_result"), make_ops());
        assert(g_ack_result_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(strcmp(g_last_id, "req") == 0);
        char out[agent_q::kSigningResponseMaxSize];
        size_t out_len = 0;
        assert(!agent_q::signing_response_find("session", "req", out, sizeof(out), &out_len));
    }

    printf("USB retained-response handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${AGENT_Q_DIR}/../../common/agent_q" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_retained_response_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_response_store.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
