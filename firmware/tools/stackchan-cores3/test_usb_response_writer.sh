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
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.h" \
  "${COMMON_ROOT}/protocol/protocol_constants.h" \
  "${RUNTIME_DIR}/usb_response_writer.cpp" \
  "${RUNTIME_DIR}/usb_response_writer.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-response-writer.XXXXXX")"
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

#include "protocol/protocol_constants.h"
#include "usb_response_writer.h"
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
        const signing::UsbDeviceResponseInfo info{
            "device-1",
            "idle",
            "Agent-Q Firmware",
            "stackchan-cores3",
            "0.0.0",
            nullptr,
        };
        assert(signing::usb_response_write_connect_approved(
            "req",
            "session_aaaaaaaaaaaaaaaa",
            30000,
            info));
        JsonDocument parsed = parse_written_json();
        assert(strcmp(parsed["id"] | "", "req") == 0);
        assert(parsed["version"].as<int>() == signing::kProtocolVersion);
        assert(parsed["success"].as<bool>());
        assert(strcmp(parsed["method"] | "", "connect") == 0);
        assert(strcmp(parsed["result"]["sessionId"] | "", "session_aaaaaaaaaaaaaaaa") == 0);
        assert(parsed["result"]["sessionTtlMs"].as<int>() == 30000);
        assert(strcmp(parsed["result"]["device"]["deviceId"] | "", "device-1") == 0);
        assert(strcmp(parsed["result"]["device"]["state"] | "", "idle") == 0);
        assert(strcmp(parsed["result"]["device"]["firmwareName"] | "", "Agent-Q Firmware") == 0);
        assert(strcmp(parsed["result"]["device"]["hardware"] | "", "stackchan-cores3") == 0);
        assert(strcmp(parsed["result"]["device"]["firmwareVersion"] | "", "0.0.0") == 0);
    }

    {
        reset_written();
        assert(signing::usb_response_write_method_error(
            "req",
            "connect",
            "user_rejected"));
        JsonDocument parsed = parse_written_json();
        assert(strcmp(parsed["id"] | "", "req") == 0);
        assert(parsed["version"].as<int>() == signing::kProtocolVersion);
        assert(!(parsed["success"] | true));
        assert(strcmp(parsed["method"] | "", "connect") == 0);
        assert(strcmp(parsed["error"]["code"] | "", "user_rejected") == 0);
        assert(strcmp(parsed["error"]["message"] | "", "The signing request was rejected on the device.") == 0);
        assert(!parsed["error"]["retryable"].as<bool>());
    }

    printf("USB response writer tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/usb_response_writer.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  -o "${TMP_DIR}/test_usb_response_writer"

"${TMP_DIR}/test_usb_response_writer"
