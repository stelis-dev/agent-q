#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_session_read_handlers.sh

Compiles extracted USB session-scoped read handlers and verifies
get_capabilities, get_accounts, and policy_get validation/response behavior. It
does not require hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_AGENT_Q_DIR="${REPO_ROOT}/firmware/src/common/agent_q"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${COMMON_AGENT_Q_DIR}/agent_q_sign_route.h" \
  "${AGENT_Q_DIR}/agent_q_usb_session_read_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_session_read_handlers.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-session-read-handlers.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_usb_session_read_handlers.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_material_calls = 0;
int g_busy_calls = 0;
int g_require_session_calls = 0;
int g_read_mode_calls = 0;
int g_write_accounts_calls = 0;
int g_write_policy_calls = 0;
int g_record_policy_unavailable_calls = 0;
int g_write_json_calls = 0;
bool g_material_ready = true;
bool g_busy = false;
bool g_session_valid = true;
bool g_read_mode_ok = true;
bool g_write_accounts_ok = true;
bool g_write_json_ok = true;
agent_q::AgentQUsbPolicyResponseWriteResult g_policy_result =
    agent_q::AgentQUsbPolicyResponseWriteResult::ok;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;
const char* g_last_error_message = nullptr;
char g_last_json_type[32] = {};
char g_last_json_auth[16] = {};
size_t g_last_json_signing_method_count = 0;

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_material_calls = 0;
    g_busy_calls = 0;
    g_require_session_calls = 0;
    g_read_mode_calls = 0;
    g_write_accounts_calls = 0;
    g_write_policy_calls = 0;
    g_record_policy_unavailable_calls = 0;
    g_write_json_calls = 0;
    g_material_ready = true;
    g_busy = false;
    g_session_valid = true;
    g_read_mode_ok = true;
    g_write_accounts_ok = true;
    g_write_json_ok = true;
    g_policy_result = agent_q::AgentQUsbPolicyResponseWriteResult::ok;
    g_last_id = nullptr;
    g_last_session = nullptr;
    g_last_error_code = nullptr;
    g_last_error_message = nullptr;
    g_last_json_type[0] = '\0';
    g_last_json_auth[0] = '\0';
    g_last_json_signing_method_count = 0;
}

}  // namespace

namespace agent_q {

const char* signing_authorization_mode_name(AgentQSigningAuthorizationMode mode)
{
    return mode == AgentQSigningAuthorizationMode::policy ? "policy" : "user";
}

bool usb_response_write_json(JsonDocument& response)
{
    g_write_json_calls += 1;
    const char* type = response["type"] | "";
    snprintf(g_last_json_type, sizeof(g_last_json_type), "%s", type);
    const char* authorization = response["signing"]["authorization"] | "";
    snprintf(g_last_json_auth, sizeof(g_last_json_auth), "%s", authorization);
    JsonArray methods = response["signing"]["methods"].as<JsonArray>();
    g_last_json_signing_method_count = methods.size();
    return g_write_json_ok;
}

}  // namespace agent_q

namespace {

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

bool read_signing_mode(agent_q::AgentQSigningAuthorizationMode* mode)
{
    g_read_mode_calls += 1;
    *mode = agent_q::AgentQSigningAuthorizationMode::policy;
    return g_read_mode_ok;
}

bool write_accounts_response(const char* id)
{
    g_write_accounts_calls += 1;
    g_last_id = id;
    return g_write_accounts_ok;
}

agent_q::AgentQUsbPolicyResponseWriteResult write_policy_response(const char* id)
{
    g_write_policy_calls += 1;
    g_last_id = id;
    return g_policy_result;
}

void record_policy_unavailable()
{
    g_record_policy_unavailable_calls += 1;
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

agent_q::AgentQUsbSessionReadHandlerOps make_ops()
{
    return agent_q::AgentQUsbSessionReadHandlerOps{
        material_ready,
        write_busy,
        require_session,
        read_signing_mode,
        write_accounts_response,
        write_policy_response,
        record_policy_unavailable,
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
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_busy_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        g_busy = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_material_calls == 1);
        assert(g_busy_calls == 1);
        assert(g_write_error_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":7}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_require_session_calls == 1);
        assert(g_write_error_calls == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\",\"extra\":1}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "get_capabilities request contains unsupported fields.") == 0);
        assert(g_read_mode_calls == 0);
    }

    {
        reset_state();
        g_read_mode_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_read_mode_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_read_mode_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_type, "capabilities") == 0);
        assert(strcmp(g_last_json_auth, "policy") == 0);
        assert(g_last_json_signing_method_count == 1);
    }

    {
        reset_state();
        g_write_json_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_capabilities\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_capabilities_request("req", request, make_writer(), make_ops());
        assert(g_write_json_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(g_write_error_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_accounts\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_write_accounts_calls == 1);
    }

    {
        reset_state();
        g_write_accounts_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_accounts\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_write_accounts_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "account_error") == 0);
        assert(strcmp(g_last_error_message, "Could not derive accounts.") == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_accounts\",\"sessionId\":\"session\",\"extra\":1}");
        agent_q::handle_usb_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "get_accounts request contains unsupported fields.") == 0);
        assert(g_write_accounts_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_write_policy_calls == 1);
        assert(g_record_policy_unavailable_calls == 0);
    }

    {
        reset_state();
        g_policy_result = agent_q::AgentQUsbPolicyResponseWriteResult::active_policy_unavailable;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_write_policy_calls == 1);
        assert(g_record_policy_unavailable_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "policy_error") == 0);
        assert(strcmp(g_last_error_message, "Active policy is unavailable.") == 0);
    }

    {
        reset_state();
        g_policy_result = agent_q::AgentQUsbPolicyResponseWriteResult::response_write_failed;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_write_policy_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(g_write_error_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\",\"extra\":1}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "policy_get request contains unsupported fields.") == 0);
        assert(g_write_policy_calls == 0);
    }

    printf("USB session-read handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_session_read_handlers.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
