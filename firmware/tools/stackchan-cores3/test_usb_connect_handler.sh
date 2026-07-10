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
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_TRANSPORT_DIR="${COMMON_ROOT}/transport"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${COMMON_TRANSPORT_DIR}/usb_connect_handler.cpp" \
  "${COMMON_TRANSPORT_DIR}/usb_connect_handler.h" \
  "${COMMON_ROOT}/protocol/usb_operation_response_writer.h" \
  "${COMMON_ROOT}/transport/timeout_window.h" \
  "${COMMON_ROOT}/protocol/request_id.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-connect-handler.XXXXXX")"
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

#include "transport/usb_connect_handler.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_material_calls = 0;
int g_busy_calls = 0;
int g_make_window_calls = 0;
int g_begin_calls = 0;
int g_existing_session_calls = 0;
int g_show_unavailable_calls = 0;
int g_reset_queue_calls = 0;
int g_show_review_calls = 0;
int g_record_waiting_calls = 0;
signing::TimeoutTick g_current_tick = 17;
signing::TimeoutTick g_last_make_window_now = 0;
signing::TimeoutTick g_last_begin_now = 0;
bool g_material_ready = true;
bool g_busy = false;
bool g_begin_ok = true;
bool g_existing_session = false;
const char* g_last_id = nullptr;
const char* g_last_client_name = nullptr;
const char* g_last_error_code = nullptr;
signing::TimeoutWindow g_last_window = {};

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_material_calls = 0;
    g_busy_calls = 0;
    g_make_window_calls = 0;
    g_begin_calls = 0;
    g_existing_session_calls = 0;
    g_show_unavailable_calls = 0;
    g_reset_queue_calls = 0;
    g_show_review_calls = 0;
    g_record_waiting_calls = 0;
    g_current_tick = 17;
    g_last_make_window_now = 0;
    g_last_begin_now = 0;
    g_material_ready = true;
    g_busy = false;
    g_begin_ok = true;
    g_existing_session = false;
    g_last_id = nullptr;
    g_last_client_name = nullptr;
    g_last_error_code = nullptr;
    g_last_window = signing::TimeoutWindow{0, 0};
}

bool write_error(const char* id, const char* code)
{
    g_write_error_calls += 1;
    g_last_id = id;
    g_last_error_code = code;
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

bool write_busy(const char* id, const signing::UsbOperationResponseWriter& writer)
{
    g_busy_calls += 1;
    g_last_id = id;
    if (g_busy) {
        writer.write_error(id, "busy");
    }
    return g_busy;
}

bool write_existing_session(
    const char* id,
    const signing::UsbOperationResponseWriter& writer)
{
    g_existing_session_calls += 1;
    g_last_id = id;
    if (!g_existing_session) {
        return false;
    }
    return writer.write_error(id, "existing_session_writer");
}

signing::TimeoutTick current_tick()
{
    return g_current_tick;
}

signing::TimeoutWindow make_window(signing::TimeoutTick now)
{
    g_make_window_calls += 1;
    g_last_make_window_now = now;
    return signing::TimeoutWindow{now, now + 18};
}

bool begin_connect(
    const char* request_id,
    const char* client_name,
    signing::TimeoutTick now,
    signing::TimeoutWindow window)
{
    g_begin_calls += 1;
    g_last_id = request_id;
    g_last_client_name = client_name;
    g_last_begin_now = now;
    g_last_window = window;
    return g_begin_ok;
}

}  // namespace

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

signing::UsbOperationResponseWriter make_writer()
{
    return signing::UsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

signing::UsbConnectHandlerOps make_ops()
{
    return signing::UsbConnectHandlerOps{
        material_ready,
        write_busy,
        write_existing_session,
        current_tick,
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
    return "{\"id\":\"req\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"Agent-Q\"}}";
}

}  // namespace

int main()
{
    {
        reset_state();
        g_material_ready = false;
        g_existing_session = true;
        JsonDocument request = parse_request(valid_request());
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_material_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_busy_calls == 0);
        assert(g_existing_session_calls == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_busy = true;
        JsonDocument request = parse_request(valid_request());
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_busy_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"Agent-Q\"},\"sessionId\":\"bad\"}");
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_request") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"connect\",\"payload\":7}");
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"Agent-Q\",\"extra\":true}}");
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"connect\",\"payload\":{}}");
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"\"}}");
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"bad\\nname\"}}");
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        char long_name[80] = {};
        memset(long_name, 'A', 65);
        JsonDocument request;
        request["id"] = "req";
        request["version"] = 1;
        request["method"] = "connect";
        request["payload"]["clientName"] = long_name;
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_existing_session = true;
        JsonDocument request = parse_request(valid_request());
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_existing_session_calls == 1);
        assert(g_begin_calls == 0);
        assert(g_reset_queue_calls == 0);
        assert(g_show_review_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "existing_session_writer") == 0);
    }

    {
        reset_state();
        g_existing_session = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"Agent-Q\",\"extra\":true}}");
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_existing_session_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_begin_ok = false;
        JsonDocument request = parse_request(valid_request());
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_make_window_calls == 1);
        assert(g_begin_calls == 1);
        assert(strcmp(g_last_client_name, "Agent-Q") == 0);
        assert(g_last_make_window_now == g_current_tick);
        assert(g_last_begin_now == g_current_tick);
        assert(g_last_window.started_at == g_current_tick);
        assert(g_last_window.deadline == g_current_tick + 18);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_show_unavailable_calls == 1);
        assert(g_reset_queue_calls == 0);
        assert(g_show_review_calls == 0);
        assert(g_record_waiting_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(valid_request());
        signing::handle_usb_connect_request("req", request, make_writer(), make_ops());
        assert(g_make_window_calls == 1);
        assert(g_begin_calls == 1);
        assert(strcmp(g_last_client_name, "Agent-Q") == 0);
        assert(g_last_make_window_now == g_current_tick);
        assert(g_last_begin_now == g_current_tick);
        assert(g_last_window.started_at == g_current_tick);
        assert(g_last_window.deadline == g_current_tick + 18);
        assert(g_reset_queue_calls == 1);
        assert(g_show_review_calls == 1);
        assert(g_record_waiting_calls == 1);
        assert(g_write_error_calls == 0);
    }

    printf("USB connect handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_TRANSPORT_DIR}/usb_connect_handler.cpp" \
  -o "${TMP_DIR}/test_usb_connect_handler"

"${TMP_DIR}/test_usb_connect_handler"
