#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_signing_handlers.sh

Compiles the extracted USB signing handlers and verifies preflight response
mapping, policy/user branch dispatch, prepared-payload cleanup, and UI-entry
failure cleanup. It does not require hardware.
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
  "${AGENT_Q_DIR}/agent_q_usb_signing_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_signing_handlers.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h" \
  "${AGENT_Q_DIR}/agent_q_signing_preflight.h" \
  "${AGENT_Q_DIR}/agent_q_policy_signing_execution.h" \
  "${COMMON_ROOT}/sui/agent_q_sui_transaction_facts.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-signing-handler.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/agent_q_common"
mkdir -p "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"

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

#include "agent_q_usb_signing_handlers.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_material_calls = 0;
int g_busy_calls = 0;
int g_validate_session_calls = 0;
int g_read_mode_calls = 0;
int g_retry_calls = 0;
int g_tx_preflight_calls = 0;
int g_pm_preflight_calls = 0;
int g_record_runtime_failure_calls = 0;
int g_policy_eval_calls = 0;
int g_policy_execute_calls = 0;
int g_policy_response_calls = 0;
int g_clear_policy_execution_calls = 0;
int g_clear_policy_runtime_calls = 0;
int g_make_window_calls = 0;
int g_begin_tx_calls = 0;
int g_begin_pm_calls = 0;
int g_clear_tx_prepared_calls = 0;
int g_clear_pm_prepared_calls = 0;
int g_show_review_calls = 0;
int g_clear_flow_calls = 0;
int g_display_error_calls = 0;
int g_waiting_calls = 0;
int g_notice_calls = 0;
int g_log_policy_rejected_calls = 0;
int g_log_policy_failed_calls = 0;
int g_log_policy_signed_calls = 0;

agent_q::AgentQSigningAuthorizationMode g_mode =
    agent_q::AgentQSigningAuthorizationMode::user;
agent_q::AgentQSigningPreflightResult g_tx_preflight_result =
    agent_q::AgentQSigningPreflightResult::ok;
agent_q::AgentQSigningPreflightResult g_pm_preflight_result =
    agent_q::AgentQSigningPreflightResult::ok;
agent_q::AgentQSignTransactionUserIngressResult g_tx_ingress_result =
    agent_q::AgentQSignTransactionUserIngressResult::ok;
agent_q::AgentQSignPersonalMessageUserIngressResult g_pm_ingress_result =
    agent_q::AgentQSignPersonalMessageUserIngressResult::ok;
agent_q::AgentQSuiSigningPreparationResult g_preparation_result =
    agent_q::AgentQSuiSigningPreparationResult::ok;
agent_q::AgentQSignTransactionPolicyRuntimeStatus g_policy_status =
    agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_authorized;
agent_q::AgentQPolicySigningExecutionStatus g_execution_status =
    agent_q::AgentQPolicySigningExecutionStatus::signed_success;
agent_q::AgentQUserSigningFlowBeginResult g_begin_result =
    agent_q::AgentQUserSigningFlowBeginResult::ok;
bool g_policy_response_ok = true;
bool g_show_review_ok = true;
const char* g_policy_code = "policy_signed";
const char* g_policy_message = "Policy authorized signing.";

const char* g_last_id = nullptr;
const char* g_last_error_code = nullptr;
const char* g_last_error_message = nullptr;
const char* g_last_policy_response_code = nullptr;
const char* g_last_policy_response_message = nullptr;
const char* g_last_notice_message = nullptr;
agent_q::AgentQSigningRoute g_last_waiting_route =
    agent_q::AgentQSigningRoute::sui_sign_transaction;
agent_q::AgentQUsbSigningNoticeKind g_last_notice_kind =
    agent_q::AgentQUsbSigningNoticeKind::info;

char g_retry_buffer[512] = {};

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_material_calls = 0;
    g_busy_calls = 0;
    g_validate_session_calls = 0;
    g_read_mode_calls = 0;
    g_retry_calls = 0;
    g_tx_preflight_calls = 0;
    g_pm_preflight_calls = 0;
    g_record_runtime_failure_calls = 0;
    g_policy_eval_calls = 0;
    g_policy_execute_calls = 0;
    g_policy_response_calls = 0;
    g_clear_policy_execution_calls = 0;
    g_clear_policy_runtime_calls = 0;
    g_make_window_calls = 0;
    g_begin_tx_calls = 0;
    g_begin_pm_calls = 0;
    g_clear_tx_prepared_calls = 0;
    g_clear_pm_prepared_calls = 0;
    g_show_review_calls = 0;
    g_clear_flow_calls = 0;
    g_display_error_calls = 0;
    g_waiting_calls = 0;
    g_notice_calls = 0;
    g_log_policy_rejected_calls = 0;
    g_log_policy_failed_calls = 0;
    g_log_policy_signed_calls = 0;
    g_mode = agent_q::AgentQSigningAuthorizationMode::user;
    g_tx_preflight_result = agent_q::AgentQSigningPreflightResult::ok;
    g_pm_preflight_result = agent_q::AgentQSigningPreflightResult::ok;
    g_tx_ingress_result = agent_q::AgentQSignTransactionUserIngressResult::ok;
    g_pm_ingress_result = agent_q::AgentQSignPersonalMessageUserIngressResult::ok;
    g_preparation_result = agent_q::AgentQSuiSigningPreparationResult::ok;
    g_policy_status = agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_authorized;
    g_execution_status = agent_q::AgentQPolicySigningExecutionStatus::signed_success;
    g_begin_result = agent_q::AgentQUserSigningFlowBeginResult::ok;
    g_policy_response_ok = true;
    g_show_review_ok = true;
    g_policy_code = "policy_signed";
    g_policy_message = "Policy authorized signing.";
    g_last_id = nullptr;
    g_last_error_code = nullptr;
    g_last_error_message = nullptr;
    g_last_policy_response_code = nullptr;
    g_last_policy_response_message = nullptr;
    g_last_notice_message = nullptr;
    g_last_waiting_route = agent_q::AgentQSigningRoute::sui_sign_transaction;
    g_last_notice_kind = agent_q::AgentQUsbSigningNoticeKind::info;
    memset(g_retry_buffer, 0, sizeof(g_retry_buffer));
}

bool write_error(const char* id, const char* code, const char* message)
{
    g_write_error_calls += 1;
    g_last_id = id;
    g_last_error_code = code;
    g_last_error_message = message;
    return true;
}
void log_write_failure(const char*, const char* id)
{
    g_log_write_failure_calls += 1;
    g_last_id = id;
}

bool material_ready()
{
    g_material_calls += 1;
    return true;
}

bool busy()
{
    g_busy_calls += 1;
    return false;
}

agent_q::AgentQPayloadDeliveryAdmissionDecision admit_tx_payload_delivery(
    const agent_q::AgentQPayloadDeliverySignTransactionAdmissionInput&,
    void*)
{
    return {
        agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
        agent_q::AgentQPayloadDeliveryAdmissionReason::idle_passthrough,
    };
}

agent_q::AgentQSessionValidationResult validate_session(const char*, void*)
{
    g_validate_session_calls += 1;
    return agent_q::AgentQSessionValidationResult::ok;
}

bool read_mode(agent_q::AgentQSigningAuthorizationMode* mode, void*)
{
    g_read_mode_calls += 1;
    *mode = g_mode;
    return true;
}

agent_q::AgentQSigningPreflightRetryDisposition retry_responder(
    const char*,
    const agent_q::AgentQSigningRetryDeliveryResult&,
    const char*,
    void*)
{
    g_retry_calls += 1;
    return agent_q::AgentQSigningPreflightRetryDisposition::continue_preflight;
}

void fill_tx_preflight_output(agent_q::AgentQSignTransactionPreflightOutput* output)
{
    memset(output, 0, sizeof(*output));
    output->route = agent_q::AgentQSigningRoute::sui_sign_transaction;
    output->ingress_result = g_tx_ingress_result;
    output->preparation_result = g_preparation_result;
    output->signing_mode = g_mode;
    strncpy(output->ingress.envelope.request_id, "req-1", sizeof(output->ingress.envelope.request_id) - 1);
    strncpy(output->ingress.session.session_id, "session-1", sizeof(output->ingress.session.session_id) - 1);
    output->request_identity[0] = 0x42;
}

void fill_pm_preflight_output(agent_q::AgentQSignPersonalMessagePreflightOutput* output)
{
    memset(output, 0, sizeof(*output));
    output->route = agent_q::AgentQSigningRoute::sui_sign_personal_message;
    output->ingress_result = g_pm_ingress_result;
    output->preparation_result = g_preparation_result;
    output->signing_mode = g_mode;
    strncpy(output->ingress.envelope.request_id, "req-2", sizeof(output->ingress.envelope.request_id) - 1);
    strncpy(output->ingress.session.session_id, "session-2", sizeof(output->ingress.session.session_id) - 1);
    output->request_identity[0] = 0x43;
}

agent_q::AgentQSigningPreflightResult evaluate_tx_preflight(
    JsonDocument&,
    const agent_q::AgentQSignTransactionUserIngressState& state,
    const agent_q::AgentQSigningPreflightRuntime& runtime,
    agent_q::AgentQSignTransactionPreflightOutput* output)
{
    g_tx_preflight_calls += 1;
    assert(state.material_ready);
    assert(!state.busy);
    assert(state.validate_session != nullptr);
    assert(state.admit_payload_delivery == admit_tx_payload_delivery);
    assert(runtime.read_signing_mode != nullptr);
    assert(runtime.retry_responder != nullptr);
    assert(runtime.retry_stored_result == g_retry_buffer);
    fill_tx_preflight_output(output);
    return g_tx_preflight_result;
}

agent_q::AgentQSigningPreflightResult evaluate_pm_preflight(
    JsonDocument&,
    const agent_q::AgentQSignPersonalMessageUserIngressState& state,
    const agent_q::AgentQSigningPreflightRuntime& runtime,
    agent_q::AgentQSignPersonalMessagePreflightOutput* output)
{
    g_pm_preflight_calls += 1;
    assert(state.material_ready);
    assert(!state.busy);
    assert(state.validate_session != nullptr);
    assert(runtime.read_signing_mode != nullptr);
    assert(runtime.retry_responder != nullptr);
    assert(runtime.retry_stored_result == g_retry_buffer);
    fill_pm_preflight_output(output);
    return g_pm_preflight_result;
}

void record_runtime_failure()
{
    g_record_runtime_failure_calls += 1;
}

agent_q::AgentQSignTransactionPolicyRuntimeResult evaluate_policy(
    const agent_q::AgentQSuiPreparedSignTransaction&)
{
    g_policy_eval_calls += 1;
    agent_q::AgentQSignTransactionPolicyRuntimeResult result = {};
    result.status = g_policy_status;
    result.code = g_policy_code;
    result.message = g_policy_message;
    strncpy(result.chain, "sui", sizeof(result.chain) - 1);
    strncpy(result.method, "sign_transaction", sizeof(result.method) - 1);
    strncpy(result.rule_ref, "rule-1", sizeof(result.rule_ref) - 1);
    return result;
}

agent_q::AgentQPolicySigningExecutionResult execute_policy(
    const agent_q::AgentQSignTransactionPolicyRuntimeResult& policy_result)
{
    g_policy_execute_calls += 1;
    agent_q::AgentQPolicySigningExecutionResult result = {};
    result.status = g_execution_status;
    result.code = policy_result.code;
    result.message = policy_result.message;
    return result;
}

bool write_policy_response(
    const char* id,
    const uint8_t* request_identity,
    const agent_q::AgentQPolicySigningExecutionResult& result)
{
    g_policy_response_calls += 1;
    assert(strcmp(id, "id-1") == 0);
    assert(request_identity[0] == 0x42);
    g_last_policy_response_code = result.code;
    g_last_policy_response_message = result.message;
    return g_policy_response_ok;
}

void clear_policy_execution(agent_q::AgentQPolicySigningExecutionResult*)
{
    g_clear_policy_execution_calls += 1;
}

void clear_policy_runtime(agent_q::AgentQSignTransactionPolicyRuntimeResult*)
{
    g_clear_policy_runtime_calls += 1;
}

agent_q::AgentQTimeoutWindow make_window(agent_q::AgentQTimeoutTick now)
{
    g_make_window_calls += 1;
    return agent_q::AgentQTimeoutWindow{now, static_cast<agent_q::AgentQTimeoutTick>(now + 10)};
}

agent_q::AgentQUserSigningFlowBeginResult begin_tx(
    agent_q::AgentQTimeoutTick now,
    const agent_q::AgentQUserSigningTransactionBeginInput& input)
{
    g_begin_tx_calls += 1;
    assert(now == 10);
    assert(strcmp(input.request_id, "req-1") == 0);
    assert(strcmp(input.session_id, "session-1") == 0);
    assert(input.request_identity[0] == 0x42);
    assert(input.route == agent_q::AgentQSigningRoute::sui_sign_transaction);
    assert(input.prepared != nullptr);
    assert(input.request_window.started_at == 10);
    return g_begin_result;
}

agent_q::AgentQUserSigningFlowBeginResult begin_pm(
    agent_q::AgentQTimeoutTick now,
    const agent_q::AgentQUserSigningPersonalMessageBeginInput& input)
{
    g_begin_pm_calls += 1;
    assert(now == 10);
    assert(strcmp(input.request_id, "req-2") == 0);
    assert(strcmp(input.session_id, "session-2") == 0);
    assert(input.request_identity[0] == 0x43);
    assert(input.route == agent_q::AgentQSigningRoute::sui_sign_personal_message);
    assert(input.prepared != nullptr);
    assert(input.request_window.deadline == 20);
    return g_begin_result;
}

void clear_tx_prepared(agent_q::AgentQSuiPreparedSignTransaction*)
{
    g_clear_tx_prepared_calls += 1;
}

void clear_pm_prepared(agent_q::AgentQSuiPreparedPersonalMessage*)
{
    g_clear_pm_prepared_calls += 1;
}

bool show_review()
{
    g_show_review_calls += 1;
    return g_show_review_ok;
}

void clear_flow()
{
    g_clear_flow_calls += 1;
}

void show_display_error()
{
    g_display_error_calls += 1;
}

void record_waiting(const char* id, agent_q::AgentQSigningRoute route)
{
    g_waiting_calls += 1;
    g_last_id = id;
    g_last_waiting_route = route;
}

void show_notice(const char* message, agent_q::AgentQUsbSigningNoticeKind kind)
{
    g_notice_calls += 1;
    g_last_notice_message = message;
    g_last_notice_kind = kind;
}

void log_policy_rejected(const char*, const char*, const char*, const char*)
{
    g_log_policy_rejected_calls += 1;
}

void log_policy_failed(const char*, const char*, const char*)
{
    g_log_policy_failed_calls += 1;
}

void log_policy_signed(const char*, const char*, const char*, const char*)
{
    g_log_policy_signed_calls += 1;
}

agent_q::AgentQTimeoutTick current_tick()
{
    return 10;
}

agent_q::AgentQUsbSigningHandlerOps make_ops()
{
    return agent_q::AgentQUsbSigningHandlerOps{
        material_ready,
        busy,
        busy,
        current_tick,
        validate_session,
        nullptr,
        admit_tx_payload_delivery,
        nullptr,
        read_mode,
        nullptr,
        retry_responder,
        nullptr,
        g_retry_buffer,
        sizeof(g_retry_buffer),
        evaluate_tx_preflight,
        evaluate_pm_preflight,
        record_runtime_failure,
        evaluate_policy,
        execute_policy,
        write_policy_response,
        clear_policy_execution,
        clear_policy_runtime,
        make_window,
        begin_tx,
        begin_pm,
        clear_tx_prepared,
        clear_pm_prepared,
        show_review,
        clear_flow,
        show_display_error,
        record_waiting,
        show_notice,
        log_policy_rejected,
        log_policy_failed,
        log_policy_signed,
        log_write_failure,
    };
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

void test_unavailable_ops()
{
    reset_state();
    JsonDocument request;
    agent_q::AgentQUsbSigningHandlerOps ops = {};
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), ops);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "protocol_error") == 0);
    assert(g_tx_preflight_calls == 0);
}

void test_transaction_ingress_error_mapping()
{
    reset_state();
    g_tx_preflight_result = agent_q::AgentQSigningPreflightResult::transaction_ingress_error;
    g_tx_ingress_result = agent_q::AgentQSignTransactionUserIngressResult::invalid_tx_bytes;
    JsonDocument request;
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_tx_preflight_calls == 1);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "invalid_params") == 0);
    assert(strcmp(g_last_error_message, "Signing txBytes are invalid.") == 0);
    assert(g_clear_tx_prepared_calls == 2);
}

void test_personal_message_ingress_error_mapping()
{
    reset_state();
    g_pm_preflight_result = agent_q::AgentQSigningPreflightResult::personal_message_ingress_error;
    g_pm_ingress_result = agent_q::AgentQSignPersonalMessageUserIngressResult::invalid_message;
    JsonDocument request;
    agent_q::handle_usb_sign_personal_message_request("id-2", request, make_writer(), make_ops());
    assert(g_pm_preflight_calls == 1);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "invalid_params") == 0);
    assert(strcmp(g_last_error_message, "Signing message is invalid.") == 0);
    assert(g_clear_pm_prepared_calls == 0);
}

void test_preparation_account_failure_mapping()
{
    reset_state();
    g_tx_preflight_result = agent_q::AgentQSigningPreflightResult::transaction_preparation_error;
    g_preparation_result = agent_q::AgentQSuiSigningPreparationResult::account_unavailable;
    JsonDocument request;
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_record_runtime_failure_calls == 1);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "account_error") == 0);
    assert(g_notice_calls == 0);
}

void test_personal_message_preparation_account_failure_mapping()
{
    reset_state();
    g_pm_preflight_result =
        agent_q::AgentQSigningPreflightResult::personal_message_preparation_error;
    g_preparation_result = agent_q::AgentQSuiSigningPreparationResult::account_unavailable;
    JsonDocument request;
    agent_q::handle_usb_sign_personal_message_request("id-2", request, make_writer(), make_ops());
    assert(g_record_runtime_failure_calls == 1);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "account_error") == 0);
    assert(g_notice_calls == 0);
}

void test_transaction_preparation_unsupported_notifies()
{
    reset_state();
    g_tx_preflight_result =
        agent_q::AgentQSigningPreflightResult::transaction_preparation_error;
    g_preparation_result = agent_q::AgentQSuiSigningPreparationResult::unsupported_transaction;
    JsonDocument request;
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "unsupported_transaction") == 0);
    assert(strcmp(g_last_error_message, "Transaction shape is not supported.") == 0);
    assert(g_notice_calls == 1);
    assert(g_last_notice_kind == agent_q::AgentQUsbSigningNoticeKind::error);
    assert(strcmp(g_last_notice_message, "Unsupported transaction") == 0);
    assert(g_begin_tx_calls == 0);
}

void test_transaction_preparation_payload_too_large_notifies()
{
    reset_state();
    g_tx_preflight_result =
        agent_q::AgentQSigningPreflightResult::transaction_preparation_error;
    g_preparation_result = agent_q::AgentQSuiSigningPreparationResult::unsupported_payload_size;
    JsonDocument request;
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "unsupported_payload_size") == 0);
    assert(strcmp(g_last_error_message, "Signing payload exceeds the current Sui adapter capacity.") == 0);
    assert(g_notice_calls == 1);
    assert(g_last_notice_kind == agent_q::AgentQUsbSigningNoticeKind::error);
    assert(strcmp(g_last_notice_message, "Payload too large") == 0);
    assert(g_begin_tx_calls == 0);
}

void test_retry_consumed_writes_no_error()
{
    reset_state();
    g_tx_preflight_result = agent_q::AgentQSigningPreflightResult::retry_consumed;
    JsonDocument request;
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_tx_preflight_calls == 1);
    assert(g_write_error_calls == 0);
    assert(g_begin_tx_calls == 0);
}

void test_policy_signed_path_cleans_outputs()
{
    reset_state();
    g_mode = agent_q::AgentQSigningAuthorizationMode::policy;
    g_execution_status = agent_q::AgentQPolicySigningExecutionStatus::signed_success;
    JsonDocument request;
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_policy_eval_calls == 1);
    assert(g_policy_execute_calls == 1);
    assert(g_policy_response_calls == 1);
    assert(g_log_policy_signed_calls == 1);
    assert(g_notice_calls == 2);
    assert(g_last_notice_kind == agent_q::AgentQUsbSigningNoticeKind::success);
    assert(g_clear_policy_execution_calls == 1);
    assert(g_clear_policy_runtime_calls == 1);
    assert(g_clear_tx_prepared_calls == 2);
    assert(g_begin_tx_calls == 0);
}

void test_policy_response_failure_logs_and_cleans()
{
    reset_state();
    g_mode = agent_q::AgentQSigningAuthorizationMode::policy;
    g_execution_status = agent_q::AgentQPolicySigningExecutionStatus::policy_rejected;
    g_policy_response_ok = false;
    JsonDocument request;
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_policy_response_calls == 1);
    assert(g_log_write_failure_calls == 1);
    assert(g_notice_calls == 2);
    assert(g_last_notice_kind == agent_q::AgentQUsbSigningNoticeKind::error);
    assert(g_clear_policy_execution_calls == 1);
    assert(g_clear_policy_runtime_calls == 1);
    assert(g_clear_tx_prepared_calls == 2);
}

void test_policy_signing_failed_path_cleans_outputs()
{
    reset_state();
    g_mode = agent_q::AgentQSigningAuthorizationMode::policy;
    g_execution_status = agent_q::AgentQPolicySigningExecutionStatus::signing_failed;
    JsonDocument request;
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_policy_eval_calls == 1);
    assert(g_policy_execute_calls == 1);
    assert(g_policy_response_calls == 1);
    assert(g_log_policy_failed_calls == 1);
    assert(g_notice_calls == 2);
    assert(g_last_notice_kind == agent_q::AgentQUsbSigningNoticeKind::error);
    assert(g_clear_policy_execution_calls == 1);
    assert(g_clear_policy_runtime_calls == 1);
    assert(g_clear_tx_prepared_calls == 2);
    assert(g_begin_tx_calls == 0);
}

void test_policy_unsupported_transaction_notifies()
{
    reset_state();
    g_mode = agent_q::AgentQSigningAuthorizationMode::policy;
    g_policy_status = agent_q::AgentQSignTransactionPolicyRuntimeStatus::unsupported_transaction;
    g_execution_status = agent_q::AgentQPolicySigningExecutionStatus::request_error;
    g_policy_code = "unsupported_transaction";
    g_policy_message = "Policy cannot evaluate this transaction.";
    JsonDocument request;
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_policy_eval_calls == 1);
    assert(g_policy_execute_calls == 1);
    assert(g_policy_response_calls == 1);
    assert(strcmp(g_last_policy_response_code, "unsupported_transaction") == 0);
    assert(strcmp(g_last_policy_response_message, "Policy cannot evaluate this transaction.") == 0);
    assert(g_notice_calls == 1);
    assert(g_last_notice_kind == agent_q::AgentQUsbSigningNoticeKind::error);
    assert(strcmp(g_last_notice_message, "Policy cannot evaluate") == 0);
    assert(g_clear_policy_execution_calls == 1);
    assert(g_clear_policy_runtime_calls == 1);
    assert(g_clear_tx_prepared_calls == 2);
    assert(g_begin_tx_calls == 0);
}

void test_transaction_user_success()
{
    reset_state();
    JsonDocument request;
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_begin_tx_calls == 1);
    assert(g_clear_tx_prepared_calls == 2);
    assert(g_show_review_calls == 1);
    assert(g_waiting_calls == 1);
    assert(g_last_waiting_route == agent_q::AgentQSigningRoute::sui_sign_transaction);
    assert(g_write_error_calls == 0);
}

void test_transaction_begin_failure_cleans_prepared()
{
    reset_state();
    g_begin_result = agent_q::AgentQUserSigningFlowBeginResult::malformed_transaction;
    JsonDocument request;
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_begin_tx_calls == 1);
    assert(g_clear_tx_prepared_calls == 2);
    assert(g_show_review_calls == 0);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "malformed_transaction") == 0);
    assert(g_notice_calls == 1);
    assert(g_last_notice_kind == agent_q::AgentQUsbSigningNoticeKind::error);
    assert(strcmp(g_last_notice_message, "Malformed transaction") == 0);
}

void test_transaction_ui_failure_cleans_flow()
{
    reset_state();
    g_show_review_ok = false;
    JsonDocument request;
    agent_q::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_begin_tx_calls == 1);
    assert(g_clear_tx_prepared_calls == 2);
    assert(g_show_review_calls == 1);
    assert(g_clear_flow_calls == 1);
    assert(g_display_error_calls == 1);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "ui_error") == 0);
    assert(g_waiting_calls == 0);
}

void test_personal_message_policy_mode_error()
{
    reset_state();
    g_pm_preflight_result = agent_q::AgentQSigningPreflightResult::personal_message_policy_mode;
    JsonDocument request;
    agent_q::handle_usb_sign_personal_message_request("id-2", request, make_writer(), make_ops());
    assert(g_pm_preflight_calls == 1);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "unsupported_method") == 0);
    assert(g_clear_pm_prepared_calls == 0);
}

void test_personal_message_user_success()
{
    reset_state();
    JsonDocument request;
    agent_q::handle_usb_sign_personal_message_request("id-2", request, make_writer(), make_ops());
    assert(g_begin_pm_calls == 1);
    assert(g_clear_pm_prepared_calls == 1);
    assert(g_show_review_calls == 1);
    assert(g_waiting_calls == 1);
    assert(g_last_waiting_route == agent_q::AgentQSigningRoute::sui_sign_personal_message);
    assert(g_write_error_calls == 0);
}

}  // namespace

int main()
{
    test_unavailable_ops();
    test_transaction_ingress_error_mapping();
    test_personal_message_ingress_error_mapping();
    test_preparation_account_failure_mapping();
    test_personal_message_preparation_account_failure_mapping();
    test_transaction_preparation_unsupported_notifies();
    test_transaction_preparation_payload_too_large_notifies();
    test_retry_consumed_writes_no_error();
    test_policy_signed_path_cleans_outputs();
    test_policy_response_failure_logs_and_cleans();
    test_policy_signing_failed_path_cleans_outputs();
    test_policy_unsupported_transaction_notifies();
    test_transaction_user_success();
    test_transaction_begin_failure_cleans_prepared();
    test_transaction_ui_failure_cleans_flow();
    test_personal_message_policy_mode_error();
    test_personal_message_user_success();
    puts("usb signing handler tests passed");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_signing_handlers.cpp" \
  -o "${TMP_DIR}/test_usb_signing_handlers"

"${TMP_DIR}/test_usb_signing_handlers"
