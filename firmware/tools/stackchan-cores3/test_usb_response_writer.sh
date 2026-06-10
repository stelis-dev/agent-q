#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_response_writer.sh

Compiles the USB response writer with host stubs and verifies state-independent
response JSON shapes. It does not require hardware.
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
  "${AGENT_Q_DIR}/agent_q_protocol_constants.h" \
  "${AGENT_Q_DIR}/agent_q_usb_response_writer.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_response_writer.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-response-writer.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/driver" "${TMP_DIR}/freertos"

cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/freertos/task.h" <<'H'
#pragma once

#include "freertos/FreeRTOS.h"

inline void vTaskDelay(TickType_t)
{
}
H

cat >"${TMP_DIR}/esp_err.h" <<'H'
#pragma once

typedef int esp_err_t;
#define ESP_OK 0
H

cat >"${TMP_DIR}/esp_log.h" <<'H'
#pragma once

#define ESP_LOGW(tag, fmt, ...) ((void)0)
H

cat >"${TMP_DIR}/driver/usb_serial_jtag.h" <<'H'
#pragma once

#include <stddef.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"

int usb_serial_jtag_write_bytes(const char* data, size_t length, TickType_t timeout_ticks);
esp_err_t usb_serial_jtag_wait_tx_done(TickType_t timeout_ticks);
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_protocol_constants.h"
#include "agent_q_usb_response_writer.h"
#include "driver/usb_serial_jtag.h"

namespace {

char g_written[4096] = {};
size_t g_written_size = 0;

void reset_written()
{
    memset(g_written, 0, sizeof(g_written));
    g_written_size = 0;
}

JsonDocument parse_written_json()
{
    JsonDocument parsed;
    const DeserializationError error = deserializeJson(parsed, g_written);
    assert(!error);
    return parsed;
}

}  // namespace

int usb_serial_jtag_write_bytes(const char* data, size_t length, TickType_t)
{
    assert(data != nullptr);
    assert(g_written_size + length < sizeof(g_written));
    memcpy(g_written + g_written_size, data, length);
    g_written_size += length;
    g_written[g_written_size] = '\0';
    return static_cast<int>(length);
}

esp_err_t usb_serial_jtag_wait_tx_done(TickType_t)
{
    return ESP_OK;
}

int main()
{
    {
        reset_written();
        const agent_q::AgentQUsbDeviceResponseInfo info{
            "device-1",
            "idle",
            "Agent-Q Firmware",
            "stackchan-cores3",
            "0.0.0",
            nullptr,
        };
        assert(agent_q::usb_response_write_connect_approved(
            "req",
            "session_aaaaaaaaaaaaaaaa",
            30000,
            info));
        JsonDocument parsed = parse_written_json();
        assert(strcmp(parsed["id"] | "", "req") == 0);
        assert(parsed["version"].as<int>() == agent_q::kAgentQProtocolVersion);
        assert(strcmp(parsed["type"] | "", "connect_result") == 0);
        assert(strcmp(parsed["status"] | "", "approved") == 0);
        assert(strcmp(parsed["sessionId"] | "", "session_aaaaaaaaaaaaaaaa") == 0);
        assert(parsed["sessionTtlMs"].as<int>() == 30000);
        assert(strcmp(parsed["device"]["deviceId"] | "", "device-1") == 0);
        assert(strcmp(parsed["device"]["state"] | "", "idle") == 0);
        assert(strcmp(parsed["device"]["firmwareName"] | "", "Agent-Q Firmware") == 0);
        assert(strcmp(parsed["device"]["hardware"] | "", "stackchan-cores3") == 0);
        assert(strcmp(parsed["device"]["firmwareVersion"] | "", "0.0.0") == 0);
    }

    {
        reset_written();
        assert(agent_q::usb_response_write_connect_rejected(
            "req",
            "rejected",
            "Connection rejected."));
        JsonDocument parsed = parse_written_json();
        assert(strcmp(parsed["type"] | "", "connect_result") == 0);
        assert(strcmp(parsed["status"] | "", "rejected") == 0);
        assert(strcmp(parsed["error"]["code"] | "", "rejected") == 0);
        assert(strcmp(parsed["error"]["message"] | "", "Connection rejected.") == 0);
    }

    printf("USB response writer tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_response_writer.cpp" \
  -o "${TMP_DIR}/test_usb_response_writer"

"${TMP_DIR}/test_usb_response_writer"
