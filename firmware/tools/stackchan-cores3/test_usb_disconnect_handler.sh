#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_disconnect_handler.sh

Compiles the extracted USB disconnect handler and verifies session validation,
pending-flow cleanup, busy handling, and disconnect response behavior. It does
not require hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_DIR="${REPO_ROOT}/firmware/src/common"
USB_RESPONSE_WRITER_SOURCE="${RUNTIME_DIR}/usb_response_writer.cpp"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${RUNTIME_DIR}/usb_disconnect_handler.cpp" \
  "${RUNTIME_DIR}/usb_disconnect_handler.h" \
  "${USB_RESPONSE_WRITER_SOURCE}" \
  "${RUNTIME_DIR}/usb_operation_response_writer.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

if ! grep -q 'usb_response_write_empty_success_result' "${USB_RESPONSE_WRITER_SOURCE}"; then
  echo "usb_response_writer must route empty success results through a shared helper." >&2
  exit 1
fi
if ! grep -q 'JsonObject object = result.to<JsonObject>();' "${USB_RESPONSE_WRITER_SOURCE}"; then
  echo "empty success helper must create a real empty JSON object before response preparation." >&2
  exit 1
fi
if ! grep -q 'return usb_response_write_empty_success_result(id, "ack_result");' "${USB_RESPONSE_WRITER_SOURCE}"; then
  echo "ack_result must use the empty success helper." >&2
  exit 1
fi
if ! grep -q 'return usb_response_write_empty_success_result(id, "disconnect");' "${USB_RESPONSE_WRITER_SOURCE}"; then
  echo "disconnect must use the empty success helper." >&2
  exit 1
fi

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-disconnect-handler.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "usb_disconnect_handler.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_require_session_calls = 0;
int g_policy_cleanup_calls = 0;
int g_sui_zklogin_cleanup_calls = 0;
int g_user_signing_cleanup_calls = 0;
int g_busy_calls = 0;
int g_payload_admission_calls = 0;
int g_clear_session_calls = 0;
int g_write_disconnect_calls = 0;
bool g_session_valid = true;
bool g_policy_cleanup_consumed = false;
bool g_sui_zklogin_cleanup_consumed = false;
bool g_user_signing_cleanup_consumed = false;
bool g_busy = false;
bool g_payload_admission_blocks = false;
bool g_write_disconnect_ok = true;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_require_session_calls = 0;
    g_policy_cleanup_calls = 0;
    g_sui_zklogin_cleanup_calls = 0;
    g_user_signing_cleanup_calls = 0;
    g_busy_calls = 0;
    g_payload_admission_calls = 0;
    g_clear_session_calls = 0;
    g_write_disconnect_calls = 0;
    g_session_valid = true;
    g_policy_cleanup_consumed = false;
    g_sui_zklogin_cleanup_consumed = false;
    g_user_signing_cleanup_consumed = false;
    g_busy = false;
    g_payload_admission_blocks = false;
    g_write_disconnect_ok = true;
    g_last_id = nullptr;
    g_last_session = nullptr;
    g_last_error_code = nullptr;
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

bool require_session(
    const char* id,
    const char* session_id,
    const signing::UsbOperationResponseWriter& writer)
{
    g_require_session_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    if (!g_session_valid) {
        writer.write_error(id, "invalid_session");
    }
    return g_session_valid;
}

bool disconnect_policy(const char* id, const char* session_id)
{
    g_policy_cleanup_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    return g_policy_cleanup_consumed;
}

bool disconnect_sui_zklogin(const char* id, const char* session_id)
{
    g_sui_zklogin_cleanup_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    return g_sui_zklogin_cleanup_consumed;
}

bool disconnect_user_signing(const char* id, const char* session_id)
{
    g_user_signing_cleanup_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    return g_user_signing_cleanup_consumed;
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

bool write_payload_admission_error(
    const char* id,
    signing::UsbOperationType operation,
    const signing::UsbOperationResponseWriter& writer)
{
    assert(operation == signing::UsbOperationType::disconnect);
    g_payload_admission_calls += 1;
    g_last_id = id;
    if (g_payload_admission_blocks) {
        writer.write_error(id, "busy");
    }
    return g_payload_admission_blocks;
}

void clear_session()
{
    g_clear_session_calls += 1;
}

}  // namespace

namespace signing {

bool usb_response_write_disconnect_success(const char* id)
{
    g_write_disconnect_calls += 1;
    g_last_id = id;
    return g_write_disconnect_ok;
}

}  // namespace signing

namespace {

signing::UsbOperationResponseWriter make_writer()
{
    return signing::UsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

signing::UsbDisconnectHandlerOps make_ops()
{
    return signing::UsbDisconnectHandlerOps{
        require_session,
        disconnect_policy,
        disconnect_sui_zklogin,
        disconnect_user_signing,
        write_busy,
        write_payload_admission_error,
        clear_session,
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
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":7}");
        signing::handle_usb_disconnect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_require_session_calls == 0);
        assert(g_clear_session_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session\"}");
        signing::handle_usb_disconnect_request("req", request, make_writer(), make_ops());
        assert(g_require_session_calls == 1);
        assert(strcmp(g_last_session, "session") == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_policy_cleanup_calls == 0);
        assert(g_sui_zklogin_cleanup_calls == 0);
        assert(g_clear_session_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session\",\"extra\":1}");
        signing::handle_usb_disconnect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_policy_cleanup_calls == 0);
        assert(g_clear_session_calls == 0);
    }

    {
        reset_state();
        g_policy_cleanup_consumed = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session\"}");
        signing::handle_usb_disconnect_request("req", request, make_writer(), make_ops());
        assert(g_policy_cleanup_calls == 1);
        assert(g_sui_zklogin_cleanup_calls == 0);
        assert(g_user_signing_cleanup_calls == 0);
        assert(g_busy_calls == 0);
        assert(g_clear_session_calls == 0);
        assert(g_write_disconnect_calls == 0);
    }

    {
        reset_state();
        g_sui_zklogin_cleanup_consumed = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session\"}");
        signing::handle_usb_disconnect_request("req", request, make_writer(), make_ops());
        assert(g_policy_cleanup_calls == 1);
        assert(g_sui_zklogin_cleanup_calls == 1);
        assert(g_user_signing_cleanup_calls == 0);
        assert(g_busy_calls == 0);
        assert(g_clear_session_calls == 0);
        assert(g_write_disconnect_calls == 0);
    }

    {
        reset_state();
        g_user_signing_cleanup_consumed = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session\"}");
        signing::handle_usb_disconnect_request("req", request, make_writer(), make_ops());
        assert(g_policy_cleanup_calls == 1);
        assert(g_sui_zklogin_cleanup_calls == 1);
        assert(g_user_signing_cleanup_calls == 1);
        assert(g_busy_calls == 0);
        assert(g_clear_session_calls == 0);
        assert(g_write_disconnect_calls == 0);
    }

    {
        reset_state();
        g_busy = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session\"}");
        signing::handle_usb_disconnect_request("req", request, make_writer(), make_ops());
        assert(g_policy_cleanup_calls == 1);
        assert(g_sui_zklogin_cleanup_calls == 1);
        assert(g_user_signing_cleanup_calls == 1);
        assert(g_busy_calls == 1);
        assert(g_payload_admission_calls == 0);
        assert(g_clear_session_calls == 0);
        assert(g_write_disconnect_calls == 0);
    }

    {
        reset_state();
        g_payload_admission_blocks = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session\"}");
        signing::handle_usb_disconnect_request("req", request, make_writer(), make_ops());
        assert(g_policy_cleanup_calls == 1);
        assert(g_sui_zklogin_cleanup_calls == 1);
        assert(g_user_signing_cleanup_calls == 1);
        assert(g_busy_calls == 1);
        assert(g_payload_admission_calls == 1);
        assert(g_clear_session_calls == 0);
        assert(g_write_disconnect_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session\"}");
        signing::handle_usb_disconnect_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_payload_admission_calls == 1);
        assert(g_clear_session_calls == 1);
        assert(g_write_disconnect_calls == 1);
        assert(g_log_write_failure_calls == 0);
        assert(strcmp(g_last_id, "req") == 0);
    }

    {
        reset_state();
        g_write_disconnect_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session\"}");
        signing::handle_usb_disconnect_request("req", request, make_writer(), make_ops());
        assert(g_clear_session_calls == 1);
        assert(g_write_disconnect_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(strcmp(g_last_id, "req") == 0);
    }

    printf("USB disconnect handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${COMMON_DIR}" \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/usb_disconnect_handler.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
