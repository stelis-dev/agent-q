#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_operation_dispatch.sh

Compiles the USB operation dispatch helper and verifies every public operation
type routes to the configured handler. It does not require hardware.
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
  "${AGENT_Q_DIR}/agent_q_usb_operation_dispatch.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_dispatch.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_type.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-operation-dispatch.XXXXXX")"
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

#include "agent_q_usb_operation_dispatch.h"

namespace {

enum class HandlerSlot {
    none,
    get_status,
    identify_device,
    connect,
    sign_transaction,
    sign_personal_message,
    get_result,
    ack_result,
    disconnect,
    get_capabilities,
    get_accounts,
    policy_get,
    get_approval_history,
    policy_propose,
    credential_prepare,
    credential_propose,
    payload_transfer_begin,
    payload_transfer_chunk,
    payload_transfer_finish,
    payload_transfer_abort,
};

HandlerSlot g_last_handler = HandlerSlot::none;
int g_handler_calls = 0;
const char* g_last_id = nullptr;
int g_write_error_calls = 0;
const char* g_last_error_code = nullptr;

void reset_state()
{
    g_last_handler = HandlerSlot::none;
    g_handler_calls = 0;
    g_last_id = nullptr;
    g_write_error_calls = 0;
    g_last_error_code = nullptr;
}

void record_handler(HandlerSlot slot, const char* id)
{
    g_last_handler = slot;
    g_handler_calls += 1;
    g_last_id = id;
}

bool write_error(const char* id, const char* code)
{
    g_last_id = id;
    g_write_error_calls += 1;
    g_last_error_code = code;
    return true;
}

void log_write_failure(const char* response_type, const char* id)
{
    (void)response_type;
    (void)id;
}

#define DEFINE_HANDLER(name, slot) \
    void name(const char* id, JsonDocument& request, const agent_q::AgentQUsbOperationResponseWriter& writer) \
    { \
        (void)request; \
        (void)writer; \
        record_handler(slot, id); \
    }

DEFINE_HANDLER(handle_get_status, HandlerSlot::get_status)
DEFINE_HANDLER(handle_identify_device, HandlerSlot::identify_device)
DEFINE_HANDLER(handle_connect, HandlerSlot::connect)
DEFINE_HANDLER(handle_sign_transaction, HandlerSlot::sign_transaction)
DEFINE_HANDLER(handle_sign_personal_message, HandlerSlot::sign_personal_message)
DEFINE_HANDLER(handle_get_result, HandlerSlot::get_result)
DEFINE_HANDLER(handle_ack_result, HandlerSlot::ack_result)
DEFINE_HANDLER(handle_disconnect, HandlerSlot::disconnect)
DEFINE_HANDLER(handle_get_capabilities, HandlerSlot::get_capabilities)
DEFINE_HANDLER(handle_get_accounts, HandlerSlot::get_accounts)
DEFINE_HANDLER(handle_policy_get, HandlerSlot::policy_get)
DEFINE_HANDLER(handle_get_approval_history, HandlerSlot::get_approval_history)
DEFINE_HANDLER(handle_policy_propose, HandlerSlot::policy_propose)
DEFINE_HANDLER(handle_credential_prepare, HandlerSlot::credential_prepare)
DEFINE_HANDLER(handle_credential_propose, HandlerSlot::credential_propose)
DEFINE_HANDLER(handle_payload_transfer_begin, HandlerSlot::payload_transfer_begin)
DEFINE_HANDLER(handle_payload_transfer_chunk, HandlerSlot::payload_transfer_chunk)
DEFINE_HANDLER(handle_payload_transfer_finish, HandlerSlot::payload_transfer_finish)
DEFINE_HANDLER(handle_payload_transfer_abort, HandlerSlot::payload_transfer_abort)

#undef DEFINE_HANDLER

agent_q::AgentQUsbOperationHandlers make_handlers()
{
    return agent_q::AgentQUsbOperationHandlers{
        handle_get_status,
        handle_identify_device,
        handle_connect,
        handle_sign_transaction,
        handle_sign_personal_message,
        handle_get_result,
        handle_ack_result,
        handle_disconnect,
        handle_get_capabilities,
        handle_get_accounts,
        handle_policy_get,
        handle_get_approval_history,
        handle_policy_propose,
        handle_credential_prepare,
        handle_credential_propose,
        handle_payload_transfer_begin,
        handle_payload_transfer_chunk,
        handle_payload_transfer_finish,
        handle_payload_transfer_abort,
    };
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

void expect_dispatch(
    agent_q::AgentQUsbOperationType operation_type,
    HandlerSlot expected_handler)
{
    reset_state();
    JsonDocument request;
    const auto writer = make_writer();
    const auto handlers = make_handlers();
    const bool handled = agent_q::dispatch_usb_operation(
        "req_dispatch",
        operation_type,
        request,
        writer,
        handlers);
    assert(handled);
    assert(g_handler_calls == 1);
    assert(g_last_handler == expected_handler);
    assert(strcmp(g_last_id, "req_dispatch") == 0);
    assert(g_write_error_calls == 0);
}

}  // namespace

int main()
{
    using Type = agent_q::AgentQUsbOperationType;

    expect_dispatch(Type::get_status, HandlerSlot::get_status);
    expect_dispatch(Type::identify_device, HandlerSlot::identify_device);
    expect_dispatch(Type::connect, HandlerSlot::connect);
    expect_dispatch(Type::sign_transaction, HandlerSlot::sign_transaction);
    expect_dispatch(Type::sign_personal_message, HandlerSlot::sign_personal_message);
    expect_dispatch(Type::get_result, HandlerSlot::get_result);
    expect_dispatch(Type::ack_result, HandlerSlot::ack_result);
    expect_dispatch(Type::disconnect, HandlerSlot::disconnect);
    expect_dispatch(Type::get_capabilities, HandlerSlot::get_capabilities);
    expect_dispatch(Type::get_accounts, HandlerSlot::get_accounts);
    expect_dispatch(Type::policy_get, HandlerSlot::policy_get);
    expect_dispatch(Type::get_approval_history, HandlerSlot::get_approval_history);
    expect_dispatch(Type::policy_propose, HandlerSlot::policy_propose);
    expect_dispatch(Type::credential_prepare, HandlerSlot::credential_prepare);
    expect_dispatch(Type::credential_propose, HandlerSlot::credential_propose);
    expect_dispatch(Type::payload_transfer_begin, HandlerSlot::payload_transfer_begin);
    expect_dispatch(Type::payload_transfer_chunk, HandlerSlot::payload_transfer_chunk);
    expect_dispatch(Type::payload_transfer_finish, HandlerSlot::payload_transfer_finish);
    expect_dispatch(Type::payload_transfer_abort, HandlerSlot::payload_transfer_abort);

    {
        reset_state();
        JsonDocument request;
        const bool handled = agent_q::dispatch_usb_operation(
            "req_unsupported",
            Type::unsupported,
            request,
            make_writer(),
            make_handlers());
        assert(!handled);
        assert(g_handler_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_id, "req_unsupported") == 0);
        assert(strcmp(g_last_error_code, "unsupported_method") == 0);
    }

    {
        reset_state();
        JsonDocument request;
        auto handlers = make_handlers();
        handlers.sign_transaction = nullptr;
        const bool handled = agent_q::dispatch_usb_operation(
            "req_missing_handler",
            Type::sign_transaction,
            request,
            make_writer(),
            handlers);
        assert(!handled);
        assert(g_handler_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_id, "req_missing_handler") == 0);
        assert(strcmp(g_last_error_code, "internal_output_error") == 0);
    }

    printf("USB operation dispatch tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_dispatch.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
