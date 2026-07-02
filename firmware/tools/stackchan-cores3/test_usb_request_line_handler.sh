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
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${RUNTIME_DIR}/usb_request_line_handler.cpp" \
  "${RUNTIME_DIR}/usb_request_line_handler.h" \
  "${RUNTIME_DIR}/usb_request_envelope.cpp" \
  "${RUNTIME_DIR}/usb_request_envelope.h" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.h" \
  "${RUNTIME_DIR}/usb_operation_dispatch.cpp" \
  "${RUNTIME_DIR}/usb_operation_dispatch.h" \
  "${RUNTIME_DIR}/usb_operation_manifest.cpp" \
  "${RUNTIME_DIR}/usb_operation_manifest.h" \
  "${RUNTIME_DIR}/usb_operation_response_writer.h" \
  "${RUNTIME_DIR}/usb_operation_type.h" \
  "${RUNTIME_DIR}/session.cpp" \
  "${COMMON_ROOT}/protocol/request_id.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-request-line-handler.XXXXXX")"
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

#include "usb_request_line_handler.h"

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
char g_last_error_method[96] = {};
const char* g_last_error_code = nullptr;
int g_log_write_failure_calls = 0;

void reset_state()
{
    g_last_handler = HandlerSlot::none;
    g_handler_calls = 0;
    g_last_id[0] = '\0';
    g_write_error_calls = 0;
    g_last_error_id[0] = '\0';
    g_last_error_method[0] = '\0';
    g_last_error_code = nullptr;
    g_log_write_failure_calls = 0;
}

bool write_method_error(const char* id, const char* method, const char* code)
{
    g_write_error_calls += 1;
    snprintf(g_last_error_id, sizeof(g_last_error_id), "%s", id == nullptr ? "" : id);
    snprintf(g_last_error_method, sizeof(g_last_error_method), "%s", method == nullptr ? "" : method);
    g_last_error_code = code;
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
    const signing::UsbOperationResponseWriter& writer)
{
    (void)writer;
    const char* method = request["method"] | "";
    assert(strcmp(method, "get_status") == 0);
    g_last_handler = HandlerSlot::get_status;
    g_handler_calls += 1;
    snprintf(g_last_id, sizeof(g_last_id), "%s", id == nullptr ? "" : id);
}

void handle_sign_transaction(
    const char* id,
    JsonDocument& request,
    const signing::UsbOperationResponseWriter& writer)
{
    (void)writer;
    const char* method = request["method"] | "";
    assert(strcmp(method, "sign_transaction") == 0);
    g_last_handler = HandlerSlot::sign_transaction;
    g_handler_calls += 1;
    snprintf(g_last_id, sizeof(g_last_id), "%s", id == nullptr ? "" : id);
}

void handle_policy_propose(
    const char* id,
    JsonDocument& request,
    const signing::UsbOperationResponseWriter& writer)
{
    (void)writer;
    const char* method = request["method"] | "";
    const char* condition_field =
        request["payload"]["policy"]["blockchains"][0]["networks"][0]["policies"][0]["conditions"][0]["field"] | "";
    assert(strcmp(method, "policy_propose") == 0);
    assert(strcmp(condition_field, "sui.token_sources.source") == 0);
    g_last_handler = HandlerSlot::policy_propose;
    g_handler_calls += 1;
    snprintf(g_last_id, sizeof(g_last_id), "%s", id == nullptr ? "" : id);
}

void handle_credential_prepare(
    const char* id,
    JsonDocument& request,
    const signing::UsbOperationResponseWriter& writer)
{
    (void)writer;
    const char* method = request["method"] | "";
    const char* credential = request["payload"]["credential"] | "";
    assert(strcmp(method, "credential_prepare") == 0);
    assert(strcmp(credential, "zklogin") == 0);
    g_last_handler = HandlerSlot::credential_prepare;
    g_handler_calls += 1;
    snprintf(g_last_id, sizeof(g_last_id), "%s", id == nullptr ? "" : id);
}

void handle_credential_propose(
    const char* id,
    JsonDocument& request,
    const signing::UsbOperationResponseWriter& writer)
{
    (void)writer;
    const char* method = request["method"] | "";
    const char* credential = request["payload"]["credential"] | "";
    assert(strcmp(method, "credential_propose") == 0);
    assert(strcmp(credential, "zklogin") == 0);
    g_last_handler = HandlerSlot::credential_propose;
    g_handler_calls += 1;
    snprintf(g_last_id, sizeof(g_last_id), "%s", id == nullptr ? "" : id);
}

signing::UsbOperationResponseWriter make_writer()
{
    return signing::UsbOperationResponseWriter{
        write_method_error,
        log_write_failure,
    };
}

signing::UsbOperationHandlers make_handlers()
{
    signing::UsbOperationHandlers handlers = {};
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
    const char* expected_method,
    const char* expected_code)
{
    reset_state();
    signing::handle_usb_request_line(line, 100, make_writer(), make_handlers());
    assert(g_handler_calls == 0);
    assert(g_write_error_calls == 1);
    if (expected_id == nullptr) {
        assert(g_last_error_id[0] == '\0');
    } else {
        assert(strcmp(g_last_error_id, expected_id) == 0);
    }
    if (expected_method == nullptr) {
        assert(g_last_error_method[0] == '\0');
    } else {
        assert(strcmp(g_last_error_method, expected_method) == 0);
    }
    assert(strcmp(g_last_error_code, expected_code) == 0);
}

void expect_handler(
    const char* line,
    HandlerSlot expected_handler,
    const char* expected_id)
{
    reset_state();
    signing::handle_usb_request_line(line, 100, make_writer(), make_handlers());
    assert(g_handler_calls == 1);
    assert(g_last_handler == expected_handler);
    assert(strcmp(g_last_id, expected_id) == 0);
    assert(g_write_error_calls == 0);
}

}  // namespace

namespace signing {

void wipe_sensitive_buffer(void* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    memset(data, 0, size);
}

}  // namespace signing

int main()
{
    expect_handler(
        "{\"id\":\"req_status\",\"version\":1,\"method\":\"get_status\"}",
        HandlerSlot::get_status,
        "req_status");
    expect_handler(
        "{\"id\":\"req_sign\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"txBytes\":\"AA==\"}}",
        HandlerSlot::sign_transaction,
        "req_sign");
    expect_handler(
        "{\"id\":\"req_policy\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"payload\":{\"policy\":{\"schema\":\"signing.policy\",\"defaultAction\":\"reject\",\"blockchains\":[{\"blockchain\":\"sui\",\"networks\":[{\"network\":\"testnet\",\"policies\":[{\"id\":\"reject-source\",\"action\":\"reject\",\"conditions\":[{\"field\":\"sui.token_sources.source\",\"op\":\"eq\",\"value\":\"gas_coin\"}]}]}]}]}}}",
        HandlerSlot::policy_propose,
        "req_policy");
    expect_handler(
        "{\"id\":\"req_credential_prepare\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}",
        HandlerSlot::credential_prepare,
        "req_credential_prepare");
    expect_handler(
        "{\"id\":\"req_credential_propose\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\",\"network\":\"testnet\",\"address\":\"0x00\",\"publicKey\":\"AA==\",\"maxEpoch\":\"1\",\"inputs\":{}}}",
        HandlerSlot::credential_propose,
        "req_credential_propose");

    expect_error("{not-json", nullptr, nullptr, "invalid_request");
    expect_error(
        "{\"version\":1,\"type\":\"get_status\"}",
        nullptr,
        nullptr,
        "invalid_request");
    expect_error(
        "{\"id\":\"req_missing_version\",\"method\":\"get_status\"}",
        "req_missing_version",
        nullptr,
        "invalid_request");
    expect_error(
        "{\"id\":\"req_string_version\",\"version\":\"1\",\"method\":\"get_status\"}",
        "req_string_version",
        nullptr,
        "invalid_request");
    expect_error(
        "{\"id\":\"req_bool_version\",\"version\":true,\"method\":\"get_status\"}",
        "req_bool_version",
        nullptr,
        "invalid_request");
    expect_error(
        "{\"id\":\"req_missing_method\",\"version\":1}",
        "req_missing_method",
        nullptr,
        "invalid_request");
    expect_error(
        "{\"id\":\"req_bad_method_type\",\"version\":1,\"method\":7}",
        "req_bad_method_type",
        nullptr,
        "invalid_request");
    expect_error(
        "{\"id\":\"req_version\",\"version\":2,\"method\":\"get_status\"}",
        "req_version",
        nullptr,
        "unsupported_version");
    expect_error(
        "{\"id\":\"req_unknown\",\"version\":1,\"method\":\"unknown\"}",
        "req_unknown",
        nullptr,
        "unsupported_method");
    expect_error(
        "{\"id\":\"req_session_missing\",\"version\":1,\"method\":\"get_accounts\"}",
        "req_session_missing",
        "get_accounts",
        "invalid_session");
    expect_error(
        "{\"id\":\"req_missing_handler\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"Agent\"}}",
        "req_missing_handler",
        "connect",
        "internal_output_error");

    printf("USB request line handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/usb_request_line_handler.cpp" \
  "${RUNTIME_DIR}/usb_request_envelope.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${RUNTIME_DIR}/usb_operation_dispatch.cpp" \
  "${RUNTIME_DIR}/usb_operation_manifest.cpp" \
  "${RUNTIME_DIR}/session.cpp" \
  "${COMMON_ROOT}/protocol/request_id.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
