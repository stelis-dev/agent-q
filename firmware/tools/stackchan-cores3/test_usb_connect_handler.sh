#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_connect_handler.sh

Compiles the extracted USB connect handler and verifies state, params,
clientName validation, approval begin, queue reset, UI entry, and failure
response behavior. It does not require hardware.
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
  "${AGENT_Q_DIR}/agent_q_usb_connect_handler.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_connect_handler.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h" \
  "${AGENT_Q_DIR}/agent_q_connect_approval.h" \
  "${AGENT_Q_DIR}/agent_q_timeout_window.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-connect-handler.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/freertos"

cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_usb_connect_handler.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_material_calls = 0;
int g_busy_calls = 0;
int g_make_window_calls = 0;
int g_begin_calls = 0;
int g_write_rejected_calls = 0;
int g_show_unavailable_calls = 0;
int g_reset_queue_calls = 0;
int g_show_review_calls = 0;
int g_record_waiting_calls = 0;
bool g_material_ready = true;
bool g_busy = false;
bool g_begin_ok = true;
const char* g_last_id = nullptr;
const char* g_last_client_name = nullptr;
const char* g_last_error_code = nullptr;
const char* g_last_error_message = nullptr;
const char* g_last_rejected_code = nullptr;
const char* g_last_rejected_message = nullptr;
agent_q::AgentQTimeoutWindow g_last_window = {};

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_material_calls = 0;
    g_busy_calls = 0;
    g_make_window_calls = 0;
    g_begin_calls = 0;
    g_write_rejected_calls = 0;
    g_show_unavailable_calls = 0;
    g_reset_queue_calls = 0;
    g_show_review_calls = 0;
    g_record_waiting_calls = 0;
    g_material_ready = true;
    g_busy = false;
    g_begin_ok = true;
    g_last_id = nullptr;
    g_last_client_name = nullptr;
    g_last_error_code = nullptr;
    g_last_error_message = nullptr;
    g_last_rejected_code = nullptr;
    g_last_rejected_message = nullptr;
    g_last_window = agent_q::AgentQTimeoutWindow{0, 0};
}

bool write_error(const char* id, const char* code, const char* message)
{
    g_write_error_calls += 1;
    g_last_id = id;
    g_last_error_code = code;
    g_last_error_message = message;
    return true;
}

void log_write_failure(const char* response_type, const char* id)
{
    (void)response_type;
    g_log_write_failure_calls += 1;
    g_last_id = id;
}

bool material_ready()
{
    g_material_calls += 1;
    return g_material_ready;
}

bool write_busy(const char* id)
{
    g_busy_calls += 1;
    g_last_id = id;
    return g_busy;
}

agent_q::AgentQTimeoutWindow make_window()
{
    g_make_window_calls += 1;
    return agent_q::AgentQTimeoutWindow{11, 29};
}

bool begin_connect(const char* request_id, const char* client_name, agent_q::AgentQTimeoutWindow window)
{
    g_begin_calls += 1;
    g_last_id = request_id;
    g_last_client_name = client_name;
    g_last_window = window;
    return g_begin_ok;
}

}  // namespace

namespace agent_q {

bool usb_response_write_connect_rejected(const char* id, const char* code, const char* message)
{
    g_write_rejected_calls += 1;
    g_last_id = id;
    g_last_rejected_code = code;
    g_last_rejected_message = message;
    return true;
}

}  // namespace agent_q

namespace {

void show_unavailable()
{
    g_show_unavailable_calls += 1;
}

void reset_queue()
{
    g_reset_queue_calls += 1;
}

void show_review()
{
    g_show_review_calls += 1;
}

void record_waiting(const char* id, const char* client_name)
{
    g_record_waiting_calls += 1;
    g_last_id = id;
    g_last_client_name = client_name;
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

agent_q::AgentQUsbConnectHandlerOps make_ops()
{
    return agent_q::AgentQUsbConnectHandlerOps{
        material_ready,
        write_busy,
        make_window,
        begin_connect,
        show_unavailable,
        reset_queue,
        show_review,
        record_waiting,
    };
}

JsonDocument parse_request(const char* json)
{
    JsonDocument request;
    const DeserializationError error = deserializeJson(request, json);
    assert(!error);
    return request;
}

const char* valid_request()
{
    return "{\"id\":\"req\",\"version\":1,\"type\":\"connect\",\"params\":{\"clientName\":\"Agent-Q\"}}";
}

}  // namespace

int main()
{
    {
        reset_state();
        g_material_ready = false;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_busy_calls == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_busy = true;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_busy_calls == 1);
        assert(g_write_error_calls == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"connect\",\"params\":{\"clientName\":\"Agent-Q\"},\"sessionId\":\"bad\"}");
        agent_q::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "connect request contains unsupported fields.") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"connect\",\"params\":7}");
        agent_q::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "connect params contain unsupported fields.") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"connect\",\"params\":{\"clientName\":\"Agent-Q\",\"extra\":true}}");
        agent_q::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "connect params contain unsupported fields.") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"connect\",\"params\":{}}");
        agent_q::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_client_name") == 0);
        assert(strcmp(g_last_error_message, "clientName must be 1-64 printable ASCII characters.") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"connect\",\"params\":{\"clientName\":\"\"}}");
        agent_q::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_client_name") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"connect\",\"params\":{\"clientName\":\"bad\\nname\"}}");
        agent_q::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_client_name") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        char long_name[80] = {};
        memset(long_name, 'A', 65);
        JsonDocument request;
        request["id"] = "req";
        request["version"] = 1;
        request["type"] = "connect";
        request["params"]["clientName"] = long_name;
        agent_q::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_client_name") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_begin_ok = false;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_make_window_calls == 1);
        assert(g_begin_calls == 1);
        assert(strcmp(g_last_client_name, "Agent-Q") == 0);
        assert(g_last_window.started_at == 11);
        assert(g_last_window.deadline == 29);
        assert(g_write_rejected_calls == 1);
        assert(strcmp(g_last_rejected_code, "invalid_state") == 0);
        assert(strcmp(g_last_rejected_message, "Connect is unavailable.") == 0);
        assert(g_show_unavailable_calls == 1);
        assert(g_reset_queue_calls == 0);
        assert(g_show_review_calls == 0);
        assert(g_record_waiting_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_make_window_calls == 1);
        assert(g_begin_calls == 1);
        assert(strcmp(g_last_client_name, "Agent-Q") == 0);
        assert(g_reset_queue_calls == 1);
        assert(g_show_review_calls == 1);
        assert(g_record_waiting_calls == 1);
        assert(g_write_error_calls == 0);
        assert(g_write_rejected_calls == 0);
    }

    printf("USB connect handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_connect_handler.cpp" \
  -o "${TMP_DIR}/test_usb_connect_handler"

"${TMP_DIR}/test_usb_connect_handler"
