#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_request_line_handler.sh

Compiles the USB request line handler and verifies public line-level envelope,
error, and operation-dispatch behavior. It does not require hardware.
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
  "${AGENT_Q_DIR}/agent_q_usb_request_line_handler.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_request_line_handler.h" \
  "${AGENT_Q_DIR}/agent_q_usb_request_envelope.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_request_envelope.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_dispatch.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_dispatch.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_type.h" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-request-line-handler.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_usb_request_line_handler.h"

namespace {

enum class HandlerSlot {
    none,
    get_status,
    sign_transaction,
    policy_propose,
    credential_prepare,
    credential_propose,
};

HandlerSlot g_last_handler = HandlerSlot::none;
int g_handler_calls = 0;
char g_last_id[96] = {};
int g_write_error_calls = 0;
char g_last_error_id[96] = {};
const char* g_last_error_code = nullptr;
const char* g_last_error_message = nullptr;
int g_log_write_failure_calls = 0;

void reset_state()
{
    g_last_handler = HandlerSlot::none;
    g_handler_calls = 0;
    g_last_id[0] = '\0';
    g_write_error_calls = 0;
    g_last_error_id[0] = '\0';
    g_last_error_code = nullptr;
    g_last_error_message = nullptr;
    g_log_write_failure_calls = 0;
}

bool write_error(const char* id, const char* code, const char* message)
{
    g_write_error_calls += 1;
    snprintf(g_last_error_id, sizeof(g_last_error_id), "%s", id == nullptr ? "" : id);
    g_last_error_code = code;
    g_last_error_message = message;
    return true;
}

void log_write_failure(const char* response_type, const char* id)
{
    (void)response_type;
    (void)id;
    g_log_write_failure_calls += 1;
}

void handle_get_status(
    const char* id,
    JsonDocument& request,
    const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    (void)writer;
    const char* type = request["type"] | "";
    assert(strcmp(type, "get_status") == 0);
    g_last_handler = HandlerSlot::get_status;
    g_handler_calls += 1;
    snprintf(g_last_id, sizeof(g_last_id), "%s", id == nullptr ? "" : id);
}

void handle_sign_transaction(
    const char* id,
    JsonDocument& request,
    const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    (void)writer;
    const char* type = request["type"] | "";
    assert(strcmp(type, "sign_transaction") == 0);
    g_last_handler = HandlerSlot::sign_transaction;
    g_handler_calls += 1;
    snprintf(g_last_id, sizeof(g_last_id), "%s", id == nullptr ? "" : id);
}

void handle_policy_propose(
    const char* id,
    JsonDocument& request,
    const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    (void)writer;
    const char* type = request["type"] | "";
    const char* condition_field =
        request["params"]["policy"]["blockchains"][0]["networks"][0]["policies"][0]["conditions"][0]["field"] | "";
    assert(strcmp(type, "policy_propose") == 0);
    assert(strcmp(condition_field, "sui.token_sources.source") == 0);
    g_last_handler = HandlerSlot::policy_propose;
    g_handler_calls += 1;
    snprintf(g_last_id, sizeof(g_last_id), "%s", id == nullptr ? "" : id);
}

void handle_credential_prepare(
    const char* id,
    JsonDocument& request,
    const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    (void)writer;
    const char* type = request["type"] | "";
    const char* credential = request["params"]["credential"] | "";
    assert(strcmp(type, "credential_prepare") == 0);
    assert(strcmp(credential, "zklogin") == 0);
    g_last_handler = HandlerSlot::credential_prepare;
    g_handler_calls += 1;
    snprintf(g_last_id, sizeof(g_last_id), "%s", id == nullptr ? "" : id);
}

void handle_credential_propose(
    const char* id,
    JsonDocument& request,
    const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    (void)writer;
    const char* type = request["type"] | "";
    const char* credential = request["params"]["credential"] | "";
    assert(strcmp(type, "credential_propose") == 0);
    assert(strcmp(credential, "zklogin") == 0);
    g_last_handler = HandlerSlot::credential_propose;
    g_handler_calls += 1;
    snprintf(g_last_id, sizeof(g_last_id), "%s", id == nullptr ? "" : id);
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

agent_q::AgentQUsbOperationHandlers make_handlers()
{
    agent_q::AgentQUsbOperationHandlers handlers = {};
    handlers.get_status = handle_get_status;
    handlers.sign_transaction = handle_sign_transaction;
    handlers.policy_propose = handle_policy_propose;
    handlers.credential_prepare = handle_credential_prepare;
    handlers.credential_propose = handle_credential_propose;
    return handlers;
}

void expect_error(
    const char* line,
    const char* expected_id,
    const char* expected_code,
    const char* expected_message)
{
    reset_state();
    agent_q::handle_usb_request_line(line, make_writer(), make_handlers());
    assert(g_handler_calls == 0);
    assert(g_write_error_calls == 1);
    if (expected_id == nullptr) {
        assert(g_last_error_id[0] == '\0');
    } else {
        assert(strcmp(g_last_error_id, expected_id) == 0);
    }
    assert(strcmp(g_last_error_code, expected_code) == 0);
    assert(strcmp(g_last_error_message, expected_message) == 0);
}

void expect_handler(
    const char* line,
    HandlerSlot expected_handler,
    const char* expected_id)
{
    reset_state();
    agent_q::handle_usb_request_line(line, make_writer(), make_handlers());
    assert(g_handler_calls == 1);
    assert(g_last_handler == expected_handler);
    assert(strcmp(g_last_id, expected_id) == 0);
    assert(g_write_error_calls == 0);
}

}  // namespace

int main()
{
    expect_handler(
        "{\"id\":\"req_status\",\"version\":1,\"type\":\"get_status\"}",
        HandlerSlot::get_status,
        "req_status");
    expect_handler(
        "{\"id\":\"req_sign\",\"version\":1,\"type\":\"sign_transaction\",\"chain\":\"sui\"}",
        HandlerSlot::sign_transaction,
        "req_sign");
    expect_handler(
        "{\"id\":\"req_policy\",\"version\":1,\"type\":\"policy_propose\",\"sessionId\":\"session_abc\",\"params\":{\"policy\":{\"schema\":\"agentq.policy\",\"defaultAction\":\"reject\",\"blockchains\":[{\"blockchain\":\"sui\",\"networks\":[{\"network\":\"testnet\",\"policies\":[{\"id\":\"reject-source\",\"action\":\"reject\",\"conditions\":[{\"field\":\"sui.token_sources.source\",\"op\":\"eq\",\"value\":\"gas_coin\"}]}]}]}]}}}",
        HandlerSlot::policy_propose,
        "req_policy");
    expect_handler(
        "{\"id\":\"req_credential_prepare\",\"version\":1,\"type\":\"credential_prepare\",\"sessionId\":\"session_abc\",\"params\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}",
        HandlerSlot::credential_prepare,
        "req_credential_prepare");
    expect_handler(
        "{\"id\":\"req_credential_propose\",\"version\":1,\"type\":\"credential_propose\",\"sessionId\":\"session_abc\",\"params\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}",
        HandlerSlot::credential_propose,
        "req_credential_propose");

    expect_error("{not-json", nullptr, "invalid_json", "Invalid JSON.");
    expect_error(
        "{\"version\":1,\"type\":\"get_status\"}",
        nullptr,
        "invalid_id",
        "Invalid request id.");
    expect_error(
        "{\"id\":\"req_version\",\"version\":2,\"type\":\"get_status\"}",
        "req_version",
        "unsupported_version",
        "Unsupported protocol version.");
    expect_error(
        "{\"id\":\"req_unknown\",\"version\":1,\"type\":\"unknown\"}",
        "req_unknown",
        "unsupported_type",
        "Unsupported request type.");
    expect_error(
        "{\"id\":\"req_missing_handler\",\"version\":1,\"type\":\"connect\"}",
        "req_missing_handler",
        "protocol_error",
        "USB operation handler is unavailable.");

    printf("USB request line handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_request_line_handler.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_request_envelope.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_dispatch.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
