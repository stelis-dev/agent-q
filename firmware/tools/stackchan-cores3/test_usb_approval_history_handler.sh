#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_approval_history_handler.sh

Compiles the extracted USB approval-history handler and verifies state/session,
field, paging parameter, and history response behavior. It does not require
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
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${AGENT_Q_DIR}/agent_q_usb_approval_history_handler.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_approval_history_handler.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h" \
  "${AGENT_Q_DIR}/agent_q_approval_history.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-approval-history-handler.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent_q_usb_approval_history_handler.h"

namespace agent_q {

bool approval_history_parse_sequence(const char* value, uint64_t* output)
{
    if (value == nullptr || output == nullptr || value[0] == '\0') {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == nullptr || *end != '\0') {
        return false;
    }
    *output = static_cast<uint64_t>(parsed);
    return true;
}

}  // namespace agent_q

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_material_calls = 0;
int g_busy_calls = 0;
int g_require_session_calls = 0;
int g_write_history_calls = 0;
bool g_material_ready = true;
bool g_busy = false;
bool g_session_valid = true;
bool g_write_history_ok = true;
size_t g_last_limit = 0;
uint64_t g_last_before = 0;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;
const char* g_last_error_message = nullptr;

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_material_calls = 0;
    g_busy_calls = 0;
    g_require_session_calls = 0;
    g_write_history_calls = 0;
    g_material_ready = true;
    g_busy = false;
    g_session_valid = true;
    g_write_history_ok = true;
    g_last_limit = 0;
    g_last_before = 0;
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

bool require_session(const char* id, const char* session_id)
{
    g_require_session_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    return g_session_valid;
}

bool write_history_response(const char* id, uint64_t before_sequence, size_t limit)
{
    g_write_history_calls += 1;
    g_last_id = id;
    g_last_before = before_sequence;
    g_last_limit = limit;
    return g_write_history_ok;
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

agent_q::AgentQUsbApprovalHistoryHandlerOps make_ops()
{
    return agent_q::AgentQUsbApprovalHistoryHandlerOps{
        material_ready,
        write_busy,
        require_session,
        write_history_response,
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
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_approval_history\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_busy_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_write_history_calls == 0);
    }

    {
        reset_state();
        g_busy = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_approval_history\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_material_calls == 1);
        assert(g_busy_calls == 1);
        assert(g_write_error_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_write_history_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_approval_history\",\"sessionId\":7}");
        agent_q::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_require_session_calls == 0);
        assert(g_write_history_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_approval_history\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_require_session_calls == 1);
        assert(g_write_error_calls == 0);
        assert(g_write_history_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_approval_history\",\"sessionId\":\"session\",\"extra\":1}");
        agent_q::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "get_approval_history request contains unsupported fields.") == 0);
        assert(g_write_history_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_approval_history\",\"sessionId\":\"session\",\"params\":7}");
        agent_q::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "Approval history params are invalid.") == 0);
        assert(g_write_history_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_approval_history\",\"sessionId\":\"session\",\"params\":{\"limit\":0}}");
        agent_q::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_write_history_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_approval_history\",\"sessionId\":\"session\",\"params\":{\"beforeSeq\":7}}");
        agent_q::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_write_history_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_approval_history\",\"sessionId\":\"session\",\"params\":{\"limit\":2,\"beforeSeq\":\"42\"}}");
        agent_q::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_write_history_calls == 1);
        assert(g_last_limit == 2);
        assert(g_last_before == 42);
        assert(strcmp(g_last_id, "req") == 0);
    }

    {
        reset_state();
        g_write_history_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_approval_history\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_history_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "history_error") == 0);
        assert(strcmp(g_last_error_message, "Approval history is unavailable.") == 0);
    }

    printf("USB approval-history handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${TMP_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_approval_history_handler.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
