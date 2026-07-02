#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/common/test_device_response.sh

Compiles the common DeviceResponse helper with a host C++ compiler and verifies
the protocol response envelope and device-field JSON shape. This test does not
require ESP-IDF or hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.h" \
  "${COMMON_ROOT}/protocol/device_response.cpp" \
  "${COMMON_ROOT}/protocol/device_response.h" \
  "${COMMON_ROOT}/protocol/protocol_constants.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run a firmware target build first when cache sources are missing, or set FIRMWARE_ARDUINOJSON_ROOT." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-device-response.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/device_response.h"
#include "protocol/protocol_constants.h"

int main()
{
    {
        const signing::DeviceResponseDeviceFields info{
            "device-1",
            "idle",
            "Test Firmware",
            "stackchan-cores3",
            "0.0.0",
        };
        JsonDocument result;
        signing::device_response_write_device_fields(result["device"].to<JsonObject>(), info);
        result["provisioning"]["state"] = "provisioned";

        JsonDocument response;
        assert(signing::device_response_prepare_success_result(
            response,
            "req",
            "get_status",
            result.as<JsonObjectConst>()));
        assert(strcmp(response["id"] | "", "req") == 0);
        assert(response["version"].as<int>() == signing::kProtocolVersion);
        assert(response["success"].as<bool>());
        assert(strcmp(response["method"] | "", "get_status") == 0);
        assert(strcmp(response["result"]["device"]["deviceId"] | "", "device-1") == 0);
        assert(strcmp(response["result"]["device"]["state"] | "", "idle") == 0);
        assert(strcmp(response["result"]["device"]["firmwareName"] | "", "Test Firmware") == 0);
        assert(strcmp(response["result"]["device"]["hardware"] | "", "stackchan-cores3") == 0);
        assert(strcmp(response["result"]["device"]["firmwareVersion"] | "", "0.0.0") == 0);
        assert(strcmp(response["result"]["provisioning"]["state"] | "", "provisioned") == 0);
    }

    {
        JsonDocument response;
        assert(signing::device_response_prepare_method_error(
            response,
            "req",
            "connect",
            "invalid_state"));
        assert(strcmp(response["id"] | "", "req") == 0);
        assert(response["version"].as<int>() == signing::kProtocolVersion);
        assert(!(response["success"] | true));
        assert(strcmp(response["method"] | "", "connect") == 0);
        assert(strcmp(response["error"]["code"] | "", "invalid_state") == 0);
        assert(strcmp(response["error"]["message"] | "", "Device state does not allow this request.") == 0);
        assert(!response["error"]["retryable"].as<bool>());
    }

    {
        JsonDocument response;
        assert(signing::device_response_prepare_method_error(
            response,
            nullptr,
            nullptr,
            "not-a-real-code"));
        assert(!response["id"].is<const char*>());
        assert(response["version"].as<int>() == signing::kProtocolVersion);
        assert(!(response["success"] | true));
        assert(!response["method"].is<const char*>());
        assert(strcmp(response["error"]["code"] | "", "unknown_error") == 0);
    }

    printf("DeviceResponse common tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_response.cpp" \
  -o "${TMP_DIR}/test_device_response"

"${TMP_DIR}/test_device_response"
