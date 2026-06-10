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

#include "agent_q_usb_retained_result_handlers.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_require_session_calls = 0;
int g_deliver_calls = 0;
int g_ack_calls = 0;
bool g_material_ready = true;
bool g_session_valid = true;
bool g_deliver_ok = false;
bool g_ack_write_ok = true;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;
const char* g_last_error_message = nullptr;

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_require_session_calls = 0;
    g_deliver_calls = 0;
    g_ack_calls = 0;
    g_material_ready = true;
    g_session_valid = true;
    g_deliver_ok = false;
    g_ack_write_ok = true;
    g_last_id = nullptr;
    g_last_session = nullptr;
    g_last_error_code = nullptr;
    g_last_error_message = nullptr;
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

bool usb_response_write_ack_result(const char* id)
{
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

bool deliver_stored_result(const char* session_id, const char* request_id)
{
    g_deliver_calls += 1;
    g_last_session = session_id;
    g_last_id = request_id;
    return g_deliver_ok;
}

void ack_stored_result(const char* session_id, const char* request_id)
{
    g_ack_calls += 1;
    g_last_session = session_id;
    g_last_id = request_id;
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
        deliver_stored_result,
        ack_stored_result,
    };
}

JsonDocument parse_request(const char* json)
{
    JsonDocument request;
    const DeserializationError error = deserializeJson(request, json);
    assert(!error);
    return request;
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
        assert(g_deliver_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_result\",\"sessionId\":7}");
        agent_q::handle_usb_get_result_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_require_session_calls == 0);
        assert(g_deliver_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_result\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_result_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_require_session_calls == 1);
        assert(g_deliver_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_result\",\"sessionId\":\"session\",\"extra\":1}");
        agent_q::handle_usb_get_result_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "get_result request contains unsupported fields.") == 0);
        assert(g_deliver_calls == 0);
    }

    {
        reset_state();
        g_deliver_ok = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_result\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_result_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_require_session_calls == 1);
        assert(g_deliver_calls == 1);
        assert(strcmp(g_last_session, "session") == 0);
        assert(strcmp(g_last_id, "req") == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_result\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_result_request("req", request, make_writer(), make_ops());
        assert(g_deliver_calls == 1);
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
        assert(g_ack_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"ack_result\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_ack_result_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_ack_calls == 1);
        assert(strcmp(g_last_session, "session") == 0);
        assert(strcmp(g_last_id, "req") == 0);
    }

    {
        reset_state();
        g_ack_write_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"ack_result\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_ack_result_request("req", request, make_writer(), make_ops());
        assert(g_ack_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(strcmp(g_last_id, "req") == 0);
    }

    printf("USB retained-result handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_retained_result_handlers.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
