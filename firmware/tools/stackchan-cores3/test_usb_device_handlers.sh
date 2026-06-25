#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_device_handlers.sh

Compiles extracted USB device operation handlers and verifies get_status and
identify_device request validation/response behavior. It does not require
hardware.
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
  "${AGENT_Q_DIR}/agent_q_usb_device_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_device_handlers.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-device-handlers.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_usb_device_handlers.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_refresh_calls = 0;
int g_payload_admission_calls = 0;
int g_write_json_calls = 0;
int g_busy_calls = 0;
int g_show_calls = 0;
bool g_busy = false;
bool g_payload_admission_error = false;
bool g_safe_code = true;
bool g_write_json_ok = true;
const char* g_last_id = nullptr;
const char* g_last_error_code = nullptr;
const char* g_last_code = nullptr;
uint32_t g_last_duration_ms = 0;
char g_last_json_type[32] = {};
char g_last_json_code[8] = {};
char g_last_json_device_state[32] = {};
char g_last_json_provisioning_state[32] = {};

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_refresh_calls = 0;
    g_payload_admission_calls = 0;
    g_write_json_calls = 0;
    g_busy_calls = 0;
    g_show_calls = 0;
    g_busy = false;
    g_payload_admission_error = false;
    g_safe_code = true;
    g_write_json_ok = true;
    g_last_id = nullptr;
    g_last_error_code = nullptr;
    g_last_code = nullptr;
    g_last_duration_ms = 0;
    g_last_json_type[0] = '\0';
    g_last_json_code[0] = '\0';
    g_last_json_device_state[0] = '\0';
    g_last_json_provisioning_state[0] = '\0';
}

}  // namespace

namespace agent_q {

void usb_response_write_device_fields(
    JsonObject device,
    const AgentQUsbDeviceResponseInfo& info)
{
    device["deviceId"] = info.device_id;
    device["state"] = info.device_state;
    device["firmwareName"] = info.firmware_name;
    device["hardware"] = info.hardware;
    device["firmwareVersion"] = info.firmware_version;
}

bool usb_response_write_json(JsonDocument& response)
{
    g_write_json_calls += 1;
    JsonObjectConst result = response["result"].as<JsonObjectConst>();
    const char* type = response["method"] | "";
    const char* code = result["code"] | "";
    const char* device_state = result["device"]["state"] | "";
    const char* provisioning_state = result["provisioning"]["state"] | "";
    snprintf(g_last_json_type, sizeof(g_last_json_type), "%s", type);
    snprintf(g_last_json_code, sizeof(g_last_json_code), "%s", code);
    snprintf(g_last_json_device_state, sizeof(g_last_json_device_state), "%s", device_state);
    snprintf(
        g_last_json_provisioning_state,
        sizeof(g_last_json_provisioning_state),
        "%s",
        provisioning_state);
    return g_write_json_ok;
}

bool usb_response_write_success_result(const char* id, const char* method, JsonObjectConst result)
{
    (void)id;
    g_write_json_calls += 1;
    const char* type = method != nullptr ? method : "";
    const char* code = result["code"] | "";
    const char* device_state = result["device"]["state"] | "";
    const char* provisioning_state = result["provisioning"]["state"] | "";
    snprintf(g_last_json_type, sizeof(g_last_json_type), "%s", type);
    snprintf(g_last_json_code, sizeof(g_last_json_code), "%s", code);
    snprintf(g_last_json_device_state, sizeof(g_last_json_device_state), "%s", device_state);
    snprintf(
        g_last_json_provisioning_state,
        sizeof(g_last_json_provisioning_state),
        "%s",
        provisioning_state);
    return g_write_json_ok;
}

}  // namespace agent_q

namespace {

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

bool write_busy(const char* id, const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    g_busy_calls += 1;
    g_last_id = id;
    if (g_busy) {
        writer.write_error(id, "busy");
    }
    return g_busy;
}

bool write_payload_admission_error(
    const char* id,
    agent_q::AgentQUsbOperationType operation,
    const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    assert(operation == agent_q::AgentQUsbOperationType::get_status);
    g_payload_admission_calls += 1;
    g_last_id = id;
    if (!g_payload_admission_error) {
        return false;
    }
    return writer.write_error(id, "busy");
}

bool is_safe_code(const char* value)
{
    g_last_code = value;
    return g_safe_code;
}

void show_code(const char* code, uint32_t duration_ms)
{
    g_show_calls += 1;
    g_last_code = code;
    g_last_duration_ms = duration_ms;
}

bool refresh_material()
{
    g_refresh_calls += 1;
    return true;
}

agent_q::AgentQUsbDeviceResponseInfo device_info()
{
    return agent_q::AgentQUsbDeviceResponseInfo{
        "device-1",
        "idle",
        "Agent-Q Firmware",
        "stackchan-cores3",
        "0.0.0",
        "provisioned",
    };
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

agent_q::AgentQUsbGetStatusHandlerOps make_status_ops()
{
    return agent_q::AgentQUsbGetStatusHandlerOps{
        refresh_material,
        write_payload_admission_error,
        device_info,
    };
}

agent_q::AgentQUsbIdentifyDeviceHandlerOps make_identify_ops()
{
    return agent_q::AgentQUsbIdentifyDeviceHandlerOps{
        write_busy,
        is_safe_code,
        show_code,
        device_info,
        1234,
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
        JsonDocument request = parse_request("{\"id\":\"req_status\",\"version\":1,\"method\":\"get_status\"}");
        agent_q::handle_usb_get_status_request("req_status", request, make_writer(), make_status_ops());
        assert(g_payload_admission_calls == 1);
        assert(g_refresh_calls == 1);
        assert(g_write_json_calls == 1);
        assert(g_write_error_calls == 0);
        assert(strcmp(g_last_json_type, "get_status") == 0);
        assert(strcmp(g_last_json_device_state, "idle") == 0);
        assert(strcmp(g_last_json_provisioning_state, "provisioned") == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req_status\",\"version\":1,\"method\":\"get_status\",\"extra\":1}");
        agent_q::handle_usb_get_status_request("req_status", request, make_writer(), make_status_ops());
        assert(g_write_json_calls == 0);
        assert(g_write_error_calls == 1);
        assert(g_payload_admission_calls == 0);
        assert(g_refresh_calls == 0);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
    }

    {
        reset_state();
        g_payload_admission_error = true;
        JsonDocument request = parse_request("{\"id\":\"req_status\",\"version\":1,\"method\":\"get_status\"}");
        agent_q::handle_usb_get_status_request("req_status", request, make_writer(), make_status_ops());
        assert(g_payload_admission_calls == 1);
        assert(g_refresh_calls == 0);
        assert(g_write_json_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
    }

    {
        reset_state();
        g_busy = true;
        JsonDocument request = parse_request("{\"id\":\"req_id\",\"version\":1,\"method\":\"identify_device\",\"payload\":{\"code\":\"1234\"}}");
        agent_q::handle_usb_identify_device_request("req_id", request, make_writer(), make_identify_ops());
        assert(g_busy_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(g_show_calls == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req_id\",\"version\":1,\"method\":\"identify_device\",\"payload\":{\"code\":\"1234\"},\"extra\":1}");
        agent_q::handle_usb_identify_device_request("req_id", request, make_writer(), make_identify_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req_id\",\"version\":1,\"method\":\"identify_device\",\"payload\":{\"code\":\"1234\",\"extra\":1}}");
        agent_q::handle_usb_identify_device_request("req_id", request, make_writer(), make_identify_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
    }

    {
        reset_state();
        g_safe_code = false;
        JsonDocument request = parse_request("{\"id\":\"req_id\",\"version\":1,\"method\":\"identify_device\",\"payload\":{\"code\":\"abcd\"}}");
        agent_q::handle_usb_identify_device_request("req_id", request, make_writer(), make_identify_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_show_calls == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req_id\",\"version\":1,\"method\":\"identify_device\",\"payload\":{\"code\":\"1234\"}}");
        agent_q::handle_usb_identify_device_request("req_id", request, make_writer(), make_identify_ops());
        assert(g_write_error_calls == 0);
        assert(g_show_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_type, "identify_device") == 0);
        assert(strcmp(g_last_json_code, "1234") == 0);
        assert(strcmp(g_last_json_device_state, "idle") == 0);
        assert(g_last_duration_ms == 1234);
    }

    {
        reset_state();
        g_write_json_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req_id\",\"version\":1,\"method\":\"identify_device\",\"payload\":{\"code\":\"1234\"}}");
        agent_q::handle_usb_identify_device_request("req_id", request, make_writer(), make_identify_ops());
        assert(g_show_calls == 1);
        assert(g_write_json_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(strcmp(g_last_id, "req_id") == 0);
    }

    printf("USB device handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_device_handlers.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
