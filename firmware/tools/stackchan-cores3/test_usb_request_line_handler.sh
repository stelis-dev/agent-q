#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_request_line_handler.sh

Compiles the shared protocol request-line handler and verifies transport-neutral
envelope, error, and operation-dispatch behavior. It does not require hardware.
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
COMMON_PROTOCOL_DIR="${COMMON_ROOT}/protocol"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${COMMON_PROTOCOL_DIR}/request_line_handler.cpp" \
  "${COMMON_PROTOCOL_DIR}/request_line_handler.h" \
  "${COMMON_PROTOCOL_DIR}/request_envelope.cpp" \
  "${COMMON_PROTOCOL_DIR}/request_envelope.h" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.h" \
  "${COMMON_PROTOCOL_DIR}/operation_dispatch.cpp" \
  "${COMMON_PROTOCOL_DIR}/operation_dispatch.h" \
  "${COMMON_PROTOCOL_DIR}/operation_manifest.cpp" \
  "${COMMON_PROTOCOL_DIR}/operation_manifest.h" \
  "${COMMON_ROOT}/protocol/response_writer.h" \
  "${COMMON_ROOT}/protocol/operation_type.cpp" \
  "${COMMON_ROOT}/protocol/operation_type.h" \
  "${COMMON_ROOT}/protocol/session_state.cpp" \
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

#include "protocol/request_line_handler.h"

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
signing::ProtocolTransport g_last_writer_transport =
    signing::ProtocolTransport::none;
signing::ProtocolTransport g_last_handler_transport =
    signing::ProtocolTransport::none;

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
    g_last_writer_transport = signing::ProtocolTransport::none;
    g_last_handler_transport = signing::ProtocolTransport::none;
}

bool record_method_error(
    signing::ProtocolTransport transport,
    const char* id,
    const char* method,
    const char* code)
{
    g_last_writer_transport = transport;
    g_write_error_calls += 1;
    snprintf(g_last_error_id, sizeof(g_last_error_id), "%s", id == nullptr ? "" : id);
    snprintf(g_last_error_method, sizeof(g_last_error_method), "%s", method == nullptr ? "" : method);
    g_last_error_code = code;
    return true;
}

bool write_usb_method_error(const char* id, const char* method, const char* code)
{
    return record_method_error(
        signing::ProtocolTransport::usb, id, method, code);
}

bool write_local_method_error(const char* id, const char* method, const char* code)
{
    return record_method_error(
        signing::ProtocolTransport::local_transport, id, method, code);
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
    const signing::ResponseWriter& writer)
{
    g_last_handler_transport =
        writer.write_method_error_fn == write_local_method_error
            ? signing::ProtocolTransport::local_transport
            : signing::ProtocolTransport::usb;
    const char* method = request["method"] | "";
    assert(strcmp(method, "get_status") == 0);
    g_last_handler = HandlerSlot::get_status;
    g_handler_calls += 1;
    snprintf(g_last_id, sizeof(g_last_id), "%s", id == nullptr ? "" : id);
}

void handle_sign_transaction(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
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
    const signing::ResponseWriter& writer)
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
    const signing::ResponseWriter& writer)
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
    const signing::ResponseWriter& writer)
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

signing::ResponseWriter make_writer(signing::ProtocolTransport transport)
{
    return signing::ResponseWriter{
        transport == signing::ProtocolTransport::local_transport
            ? write_local_method_error
            : write_usb_method_error,
        log_write_failure,
    };
}

bool write_bytes(const char*, size_t, void*)
{
    return true;
}

signing::ProtocolTransportRoute make_route(signing::ProtocolTransport transport)
{
    static const signing::ProtocolTransportEndpoint usb_endpoint{
        signing::ProtocolTransport::usb,
        make_writer(signing::ProtocolTransport::usb),
        signing::JsonResponseWriteOps{write_bytes, nullptr, nullptr},
    };
    static const signing::ProtocolTransportEndpoint local_endpoint{
        signing::ProtocolTransport::local_transport,
        make_writer(signing::ProtocolTransport::local_transport),
        signing::JsonResponseWriteOps{write_bytes, nullptr, nullptr},
    };
    return signing::ProtocolTransportRoute(
        transport == signing::ProtocolTransport::local_transport
            ? local_endpoint
            : usb_endpoint);
}

signing::OperationHandlers make_handlers()
{
    signing::OperationHandlers handlers = {};
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
    const char* expected_code,
    signing::ProtocolTransport transport = signing::ProtocolTransport::usb)
{
    reset_state();
    signing::handle_protocol_request_line(
        line, 100, make_route(transport), make_handlers());
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
    assert(g_last_writer_transport == transport);
}

void expect_handler(
    const char* line,
    HandlerSlot expected_handler,
    const char* expected_id,
    signing::ProtocolTransport transport = signing::ProtocolTransport::usb)
{
    reset_state();
    signing::handle_protocol_request_line(
        line, 100, make_route(transport), make_handlers());
    assert(g_handler_calls == 1);
    assert(g_last_handler == expected_handler);
    assert(strcmp(g_last_id, expected_id) == 0);
    assert(g_write_error_calls == 0);
    if (expected_handler == HandlerSlot::get_status) {
        assert(g_last_handler_transport == transport);
    }
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
        "{\"id\":\"req_status_local\",\"version\":1,\"method\":\"get_status\"}",
        HandlerSlot::get_status,
        "req_status_local",
        signing::ProtocolTransport::local_transport);
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
        "{not-json",
        nullptr,
        nullptr,
        "invalid_request",
        signing::ProtocolTransport::local_transport);
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

    reset_state();
    signing::handle_protocol_request_line(
        "{\"id\":\"req_unbound\",\"version\":1,\"method\":\"get_status\"}",
        100,
        signing::ProtocolTransportRoute{},
        make_handlers());
    assert(g_handler_calls == 0);
    assert(g_write_error_calls == 0);
    assert(g_last_writer_transport == signing::ProtocolTransport::none);

    printf("Protocol request line handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_PROTOCOL_DIR}/request_line_handler.cpp" \
  "${COMMON_PROTOCOL_DIR}/request_envelope.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_PROTOCOL_DIR}/operation_dispatch.cpp" \
  "${COMMON_PROTOCOL_DIR}/operation_manifest.cpp" \
  "${COMMON_ROOT}/protocol/operation_type.cpp" \
  "${COMMON_ROOT}/protocol/session_state.cpp" \
  "${COMMON_ROOT}/protocol/request_id.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
