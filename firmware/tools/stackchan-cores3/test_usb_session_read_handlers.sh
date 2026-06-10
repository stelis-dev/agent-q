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
mkdir -p "${TMP_DIR}/stubs"

cat >"${TMP_DIR}/stubs/byte_conversions.h" <<'H'
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

inline int bytes_to_base64(
    const uint8_t* input,
    size_t input_size,
    char* output,
    size_t output_size)
{
    (void)input;
    (void)input_size;
    if (output == nullptr || output_size < 24) {
        return -1;
    }
    snprintf(output, output_size, "test-public-key-b64");
    return 0;
}
H

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
int g_derive_account_calls = 0;
int g_record_root_material_unreadable_calls = 0;
int g_read_policy_calls = 0;
int g_record_policy_unavailable_calls = 0;
int g_write_json_calls = 0;
bool g_material_ready = true;
bool g_busy = false;
bool g_session_valid = true;
bool g_read_mode_ok = true;
agent_q::SuiAccountDerivationResult g_account_result =
    agent_q::SuiAccountDerivationResult::ok;
bool g_read_policy_ok = true;
bool g_policy_has_document = true;
bool g_write_json_ok = true;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;
const char* g_last_error_message = nullptr;
char g_last_json_type[32] = {};
char g_last_json_auth[16] = {};
char g_last_json_account_address[80] = {};
char g_last_json_account_public_key[64] = {};
char g_last_json_policy_id[80] = {};
size_t g_last_json_signing_method_count = 0;
size_t g_last_json_policy_rule_count = 0;

agent_q::AgentQPolicyDocument g_policy_document = {};

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_material_calls = 0;
    g_busy_calls = 0;
    g_require_session_calls = 0;
    g_read_mode_calls = 0;
    g_derive_account_calls = 0;
    g_record_root_material_unreadable_calls = 0;
    g_read_policy_calls = 0;
    g_record_policy_unavailable_calls = 0;
    g_write_json_calls = 0;
    g_material_ready = true;
    g_busy = false;
    g_session_valid = true;
    g_read_mode_ok = true;
    g_account_result = agent_q::SuiAccountDerivationResult::ok;
    g_read_policy_ok = true;
    g_policy_has_document = true;
    g_write_json_ok = true;
    g_last_id = nullptr;
    g_last_session = nullptr;
    g_last_error_code = nullptr;
    g_last_error_message = nullptr;
    g_last_json_type[0] = '\0';
    g_last_json_auth[0] = '\0';
    g_last_json_account_address[0] = '\0';
    g_last_json_account_public_key[0] = '\0';
    g_last_json_policy_id[0] = '\0';
    g_last_json_signing_method_count = 0;
    g_last_json_policy_rule_count = 0;
    g_policy_document = agent_q::AgentQPolicyDocument{
        0,
        agent_q::AgentQPolicyAction::reject,
        nullptr,
        0,
    };
}

}  // namespace

namespace agent_q {

const char* signing_authorization_mode_name(AgentQSigningAuthorizationMode mode)
{
    return mode == AgentQSigningAuthorizationMode::policy ? "policy" : "user";
}

const char* agent_q_policy_action_name(AgentQPolicyAction action)
{
    return action == AgentQPolicyAction::sign ? "sign" : "reject";
}

const char* agent_q_policy_operator_name(AgentQPolicyOperator op)
{
    switch (op) {
        case AgentQPolicyOperator::eq:
            return "eq";
        case AgentQPolicyOperator::in:
            return "in";
        case AgentQPolicyOperator::lte:
            return "lte";
        default:
            return "";
    }
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
    const char* account_address = response["accounts"][0]["address"] | "";
    snprintf(g_last_json_account_address, sizeof(g_last_json_account_address), "%s", account_address);
    const char* account_public_key = response["accounts"][0]["publicKey"] | "";
    snprintf(g_last_json_account_public_key, sizeof(g_last_json_account_public_key), "%s", account_public_key);
    const char* policy_id = response["policy"]["policyId"] | "";
    snprintf(g_last_json_policy_id, sizeof(g_last_json_policy_id), "%s", policy_id);
    g_last_json_policy_rule_count = response["policy"]["ruleCount"] | 0;
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

agent_q::SuiAccountDerivationResult derive_sui_account(
    uint8_t public_key_out[agent_q::kSuiEd25519PublicKeyBytes],
    char* address_out,
    size_t address_out_size)
{
    g_derive_account_calls += 1;
    memset(public_key_out, 7, agent_q::kSuiEd25519PublicKeyBytes);
    snprintf(address_out, address_out_size, "0x1234");
    return g_account_result;
}

void record_root_material_unreadable()
{
    g_record_root_material_unreadable_calls += 1;
}

bool read_active_policy(
    const char** schema,
    char* policy_id_out,
    size_t policy_id_out_size,
    const char** default_action,
    size_t* rule_count,
    const agent_q::AgentQPolicyDocument** document)
{
    g_read_policy_calls += 1;
    if (!g_read_policy_ok) {
        return false;
    }
    *schema = "agentq.policy.v0";
    snprintf(policy_id_out, policy_id_out_size, "sha256:test");
    *default_action = "reject";
    *rule_count = 0;
    *document = g_policy_has_document ? &g_policy_document : nullptr;
    return true;
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
        derive_sui_account,
        record_root_material_unreadable,
        read_active_policy,
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
        assert(g_derive_account_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_type, "accounts") == 0);
        assert(strcmp(g_last_json_account_address, "0x1234") == 0);
        assert(strcmp(g_last_json_account_public_key, "test-public-key-b64") == 0);
    }

    {
        reset_state();
        g_account_result = agent_q::SuiAccountDerivationResult::derivation_error;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_accounts\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_derive_account_calls == 1);
        assert(g_record_root_material_unreadable_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "account_error") == 0);
        assert(strcmp(g_last_error_message, "Could not derive accounts.") == 0);
    }

    {
        reset_state();
        g_account_result = agent_q::SuiAccountDerivationResult::root_material_unavailable;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_accounts\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_derive_account_calls == 1);
        assert(g_record_root_material_unreadable_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "account_error") == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"get_accounts\",\"sessionId\":\"session\",\"extra\":1}");
        agent_q::handle_usb_get_accounts_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "get_accounts request contains unsupported fields.") == 0);
        assert(g_derive_account_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_read_policy_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_type, "policy") == 0);
        assert(strcmp(g_last_json_policy_id, "sha256:test") == 0);
        assert(g_last_json_policy_rule_count == 0);
        assert(g_record_policy_unavailable_calls == 0);
    }

    {
        reset_state();
        g_read_policy_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_read_policy_calls == 1);
        assert(g_record_policy_unavailable_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "policy_error") == 0);
        assert(strcmp(g_last_error_message, "Active policy is unavailable.") == 0);
    }

    {
        reset_state();
        g_policy_has_document = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_read_policy_calls == 1);
        assert(g_record_policy_unavailable_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "policy_error") == 0);
    }

    {
        reset_state();
        g_write_json_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_get\",\"sessionId\":\"session\"}");
        agent_q::handle_usb_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_read_policy_calls == 1);
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
        assert(g_read_policy_calls == 0);
    }

    printf("USB session-read handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_session_read_handlers.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
