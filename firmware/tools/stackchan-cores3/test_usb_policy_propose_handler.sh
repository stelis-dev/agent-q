#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_policy_propose_handler.sh

Compiles the extracted USB policy_propose handler and verifies state/session,
field, policy-begin, UI-entry, and terminal-error behavior. It does not require
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
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${AGENT_Q_DIR}/agent_q_usb_policy_propose_handler.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_policy_propose_handler.h" \
  "${AGENT_Q_DIR}/agent_q_usb_policy_propose_result_writer.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_policy_propose_result_writer.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h" \
  "${AGENT_Q_DIR}/agent_q_usb_response_writer.h" \
  "${AGENT_Q_DIR}/agent_q_policy_update_flow.h" \
  "${AGENT_Q_DIR}/agent_q_timeout_window.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-policy-propose-handler.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/agent_q_common"
mkdir -p "${TMP_DIR}/freertos"
ln -s "${COMMON_POLICY_DIR}" "${TMP_DIR}/agent_q_common/policy"

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

#include "agent_q_usb_policy_propose_handler.h"
#include "agent_q_usb_policy_propose_result_writer.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_material_calls = 0;
int g_busy_calls = 0;
int g_require_session_calls = 0;
int g_make_window_calls = 0;
int g_begin_calls = 0;
int g_reason_calls = 0;
int g_json_write_calls = 0;
int g_show_review_calls = 0;
int g_record_ui_error_calls = 0;
int g_finish_terminal_calls = 0;
int g_record_waiting_calls = 0;
bool g_material_ready = true;
bool g_busy = false;
bool g_session_valid = true;
bool g_json_write_ok = true;
bool g_show_review_ok = true;
agent_q::AgentQPolicyUpdateFlowBeginResult g_begin_result =
    agent_q::AgentQPolicyUpdateFlowBeginResult::ok;
agent_q::AgentQPolicyUpdateFlowTerminalResult g_ui_error_result =
    agent_q::AgentQPolicyUpdateFlowTerminalResult::ui_error;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;
const char* g_last_error_message = nullptr;
char g_last_response_id[32] = {};
char g_last_response_type[40] = {};
char g_last_policy_status[40] = {};
char g_last_policy_reason[40] = {};
bool g_last_policy_included = false;
char g_last_policy_hash[80] = {};
size_t g_last_policy_rule_count = 0;
char g_last_policy_highest_action[16] = {};
agent_q::AgentQTimeoutWindow g_last_window = {};

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_material_calls = 0;
    g_busy_calls = 0;
    g_require_session_calls = 0;
    g_make_window_calls = 0;
    g_begin_calls = 0;
    g_reason_calls = 0;
    g_json_write_calls = 0;
    g_show_review_calls = 0;
    g_record_ui_error_calls = 0;
    g_finish_terminal_calls = 0;
    g_record_waiting_calls = 0;
    g_material_ready = true;
    g_busy = false;
    g_session_valid = true;
    g_json_write_ok = true;
    g_show_review_ok = true;
    g_begin_result = agent_q::AgentQPolicyUpdateFlowBeginResult::ok;
    g_ui_error_result = agent_q::AgentQPolicyUpdateFlowTerminalResult::ui_error;
    g_last_id = nullptr;
    g_last_session = nullptr;
    g_last_error_code = nullptr;
    g_last_error_message = nullptr;
    g_last_response_id[0] = '\0';
    g_last_response_type[0] = '\0';
    g_last_policy_status[0] = '\0';
    g_last_policy_reason[0] = '\0';
    g_last_policy_included = false;
    g_last_policy_hash[0] = '\0';
    g_last_policy_rule_count = 0;
    g_last_policy_highest_action[0] = '\0';
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
    assert(strcmp(response_type, "policy_propose_result") == 0);
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

agent_q::AgentQTimeoutWindow make_review_window()
{
    g_make_window_calls += 1;
    return agent_q::AgentQTimeoutWindow{10, 20};
}

agent_q::AgentQPolicyUpdateFlowBeginResult begin_policy_update(
    JsonVariantConst policy,
    const char* request_id,
    const char* session_id,
    agent_q::AgentQTimeoutWindow review_window)
{
    g_begin_calls += 1;
    assert(!policy.isNull());
    g_last_id = request_id;
    g_last_session = session_id;
    g_last_window = review_window;
    return g_begin_result;
}

const char* begin_result_reason(agent_q::AgentQPolicyUpdateFlowBeginResult result)
{
    g_reason_calls += 1;
    switch (result) {
        case agent_q::AgentQPolicyUpdateFlowBeginResult::too_large:
            return "too_large";
        case agent_q::AgentQPolicyUpdateFlowBeginResult::ok:
            return "ok";
        default:
            return "invalid_policy";
    }
}

bool show_policy_update_review()
{
    g_show_review_calls += 1;
    return g_show_review_ok;
}

agent_q::AgentQPolicyUpdateFlowTerminalResult record_ui_error()
{
    g_record_ui_error_calls += 1;
    return g_ui_error_result;
}

void finish_policy_update_terminal(
    const char* id,
    agent_q::AgentQPolicyUpdateFlowTerminalResult result)
{
    g_finish_terminal_calls += 1;
    g_last_id = id;
    assert(result == g_ui_error_result);
}

void record_waiting(const char* id)
{
    g_record_waiting_calls += 1;
    g_last_id = id;
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

agent_q::AgentQUsbPolicyProposeHandlerOps make_ops()
{
    return agent_q::AgentQUsbPolicyProposeHandlerOps{
        material_ready,
        write_busy,
        require_session,
        make_review_window,
        begin_policy_update,
        begin_result_reason,
        show_policy_update_review,
        record_ui_error,
        finish_policy_update_terminal,
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
    return "{\"id\":\"req\",\"version\":1,\"type\":\"policy_propose\",\"sessionId\":\"session\",\"params\":{\"policy\":{\"version\":1}}}";
}

}  // namespace

namespace agent_q {

bool usb_response_write_json(JsonDocument& response)
{
    g_json_write_calls += 1;
    snprintf(g_last_response_id, sizeof(g_last_response_id), "%s", response["id"].as<const char*>());
    snprintf(g_last_response_type, sizeof(g_last_response_type), "%s", response["type"].as<const char*>());
    snprintf(g_last_policy_status, sizeof(g_last_policy_status), "%s", response["status"].as<const char*>());
    snprintf(g_last_policy_reason, sizeof(g_last_policy_reason), "%s", response["reasonCode"].as<const char*>());
    g_last_policy_included = !response["policy"].isNull();
    if (g_last_policy_included) {
        JsonObject policy = response["policy"].as<JsonObject>();
        snprintf(g_last_policy_hash, sizeof(g_last_policy_hash), "%s", policy["policyHash"].as<const char*>());
        g_last_policy_rule_count = policy["ruleCount"].as<size_t>();
        snprintf(g_last_policy_highest_action, sizeof(g_last_policy_highest_action), "%s", policy["highestAction"].as<const char*>());
    }
    return g_json_write_ok;
}

}  // namespace agent_q

int main()
{
    {
        reset_state();
        g_material_ready = false;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_busy_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_busy = true;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_busy_calls == 1);
        assert(g_write_error_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_propose\",\"sessionId\":7,\"params\":{\"policy\":{}}}");
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_require_session_calls == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_require_session_calls == 1);
        assert(strcmp(g_last_session, "session") == 0);
        assert(g_write_error_calls == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_propose\",\"sessionId\":\"session\",\"params\":{\"policy\":{}},\"extra\":true}");
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_require_session_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "policy_propose request contains unsupported fields.") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_propose\",\"sessionId\":\"session\",\"params\":7}");
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "Policy update params must be an object.") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_propose\",\"sessionId\":\"session\",\"params\":{\"policy\":{},\"extra\":true}}");
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "Policy update params require policy.") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"type\":\"policy_propose\",\"sessionId\":\"session\",\"params\":{}}");
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(strcmp(g_last_error_message, "Policy update params require policy.") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_begin_result = agent_q::AgentQPolicyUpdateFlowBeginResult::too_large;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_make_window_calls == 1);
        assert(g_begin_calls == 1);
        assert(g_reason_calls == 1);
        assert(g_json_write_calls == 1);
        assert(strcmp(g_last_response_id, "req") == 0);
        assert(strcmp(g_last_response_type, "policy_propose_result") == 0);
        assert(strcmp(g_last_policy_status, "invalid_policy") == 0);
        assert(strcmp(g_last_policy_reason, "too_large") == 0);
        assert(!g_last_policy_included);
        assert(g_show_review_calls == 0);
        assert(g_finish_terminal_calls == 0);
    }

    {
        reset_state();
        g_begin_result = agent_q::AgentQPolicyUpdateFlowBeginResult::invalid_policy;
        g_json_write_ok = false;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_json_write_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(g_show_review_calls == 0);
    }

    {
        reset_state();
        const agent_q::AgentQPolicyUpdateFlowSnapshot snapshot{
            true,
            agent_q::AgentQPolicyUpdateFlowStage::committing,
            "req",
            "session",
            agent_q::AgentQTimeoutWindow{10, 20},
            "sha256:policy",
            3,
            "reject",
            "reject",
            "policy_update",
            "Update policy",
        };
        assert(agent_q::usb_policy_propose_result_write("req", "applied", "applied", &snapshot));
        assert(g_json_write_calls == 1);
        assert(strcmp(g_last_response_id, "req") == 0);
        assert(strcmp(g_last_response_type, "policy_propose_result") == 0);
        assert(strcmp(g_last_policy_status, "applied") == 0);
        assert(strcmp(g_last_policy_reason, "applied") == 0);
        assert(g_last_policy_included);
        assert(strcmp(g_last_policy_hash, "sha256:policy") == 0);
        assert(g_last_policy_rule_count == 3);
        assert(strcmp(g_last_policy_highest_action, "reject") == 0);
    }

    {
        reset_state();
        g_show_review_ok = false;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_begin_calls == 1);
        assert(g_show_review_calls == 1);
        assert(g_record_ui_error_calls == 1);
        assert(g_finish_terminal_calls == 1);
        assert(g_record_waiting_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_begin_calls == 1);
        assert(g_last_window.started_at == 10);
        assert(g_last_window.deadline == 20);
        assert(g_show_review_calls == 1);
        assert(g_record_waiting_calls == 1);
        assert(g_write_error_calls == 0);
        assert(g_json_write_calls == 0);
        assert(g_finish_terminal_calls == 0);
    }

    printf("usb_policy_propose_handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_policy_propose_handler.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_policy_propose_result_writer.cpp" \
  -o "${TMP_DIR}/test_usb_policy_propose_handler"

"${TMP_DIR}/test_usb_policy_propose_handler"
