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
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${RUNTIME_DIR}/usb_signing_handlers.cpp" \
  "${RUNTIME_DIR}/usb_signing_handlers.h" \
  "${RUNTIME_DIR}/usb_operation_response_writer.h" \
  "${RUNTIME_DIR}/signing_preflight.h" \
  "${RUNTIME_DIR}/sign_personal_message_limits.h" \
  "${RUNTIME_DIR}/signing_response_store.h" \
  "${RUNTIME_DIR}/sui_signing_service.h" \
  "${RUNTIME_DIR}/policy_signing_execution.h" \
  "${COMMON_ROOT}/sui/transaction_facts.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-signing-handler.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/firmware_common"
mkdir -p "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/firmware_common/sui"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"

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

#include <string>

#include "sign_personal_message_limits.h"
#include "signing_response_store.h"
#include "sui_signing_service.h"
#include "usb_signing_handlers.h"

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

signing::AuthorizationMode g_mode =
    signing::AuthorizationMode::user;
signing::PreflightResult g_tx_preflight_result =
    signing::PreflightResult::ok;
signing::PreflightResult g_pm_preflight_result =
    signing::PreflightResult::ok;
signing::SignTransactionUserIngressResult g_tx_ingress_result =
    signing::SignTransactionUserIngressResult::ok;
signing::SignPersonalMessageUserIngressResult g_pm_ingress_result =
    signing::SignPersonalMessageUserIngressResult::ok;
signing::SuiSigningPreparationResult g_preparation_result =
    signing::SuiSigningPreparationResult::ok;
signing::SignTransactionPolicyRuntimeStatus g_policy_status =
    signing::SignTransactionPolicyRuntimeStatus::policy_authorized;
signing::PolicySigningExecutionStatus g_execution_status =
    signing::PolicySigningExecutionStatus::signed_success;
signing::UserSigningFlowBeginResult g_begin_result =
    signing::UserSigningFlowBeginResult::ok;
bool g_policy_response_ok = true;
bool g_show_review_ok = true;
const char* g_policy_code = "policy_signed";
const char* g_policy_message = "Policy authorized signing.";

const char* g_last_id = nullptr;
const char* g_last_error_code = nullptr;
const char* g_last_policy_response_code = nullptr;
const char* g_last_policy_response_message = nullptr;
const char* g_last_notice_message = nullptr;
signing::Route g_last_waiting_route =
    signing::Route::sui_sign_transaction;
signing::UsbSigningNoticeKind g_last_notice_kind =
    signing::UsbSigningNoticeKind::info;

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
    g_mode = signing::AuthorizationMode::user;
    g_tx_preflight_result = signing::PreflightResult::ok;
    g_pm_preflight_result = signing::PreflightResult::ok;
    g_tx_ingress_result = signing::SignTransactionUserIngressResult::ok;
    g_pm_ingress_result = signing::SignPersonalMessageUserIngressResult::ok;
    g_preparation_result = signing::SuiSigningPreparationResult::ok;
    g_policy_status = signing::SignTransactionPolicyRuntimeStatus::policy_authorized;
    g_execution_status = signing::PolicySigningExecutionStatus::signed_success;
    g_begin_result = signing::UserSigningFlowBeginResult::ok;
    g_policy_response_ok = true;
    g_show_review_ok = true;
    g_policy_code = "policy_signed";
    g_policy_message = "Policy authorized signing.";
    g_last_id = nullptr;
    g_last_error_code = nullptr;
    g_last_policy_response_code = nullptr;
    g_last_policy_response_message = nullptr;
    g_last_notice_message = nullptr;
    g_last_waiting_route = signing::Route::sui_sign_transaction;
    g_last_notice_kind = signing::UsbSigningNoticeKind::info;
    memset(g_retry_buffer, 0, sizeof(g_retry_buffer));
}

bool write_error(const char* id, const char* code)
{
    g_write_error_calls += 1;
    g_last_id = id;
    g_last_error_code = code;
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

signing::PayloadDeliveryAdmissionDecision admit_tx_payload_delivery(
    const signing::PayloadDeliveryOperationAdmissionInput&)
{
    return {
        signing::PayloadDeliveryAdmissionResult::ok,
        signing::PayloadDeliveryAdmissionReason::idle_passthrough,
    };
}

signing::SessionValidationResult validate_session(const char*, void*)
{
    g_validate_session_calls += 1;
    return signing::SessionValidationResult::ok;
}

bool read_mode(signing::AuthorizationMode* mode, void*)
{
    g_read_mode_calls += 1;
    *mode = g_mode;
    return true;
}

signing::PreflightRetryDisposition retry_responder(
    const char*,
    const char*,
    const signing::RetryDeliveryResult&,
    const char*,
    void*)
{
    g_retry_calls += 1;
    return signing::PreflightRetryDisposition::continue_preflight;
}

void fill_tx_preflight_output(signing::SignTransactionPreflightOutput* output)
{
    memset(output, 0, sizeof(*output));
    output->route = signing::Route::sui_sign_transaction;
    output->ingress_result = g_tx_ingress_result;
    output->preparation_result = g_preparation_result;
    output->signing_mode = g_mode;
    strncpy(output->ingress.envelope.request_id, "req-1", sizeof(output->ingress.envelope.request_id) - 1);
    strncpy(output->ingress.session.session_id, "session-1", sizeof(output->ingress.session.session_id) - 1);
    output->request_identity[0] = 0x42;
}

void fill_pm_preflight_output(signing::SignPersonalMessagePreflightOutput* output)
{
    memset(output, 0, sizeof(*output));
    output->route = signing::Route::sui_sign_personal_message;
    output->ingress_result = g_pm_ingress_result;
    output->preparation_result = g_preparation_result;
    output->signing_mode = g_mode;
    strncpy(output->ingress.envelope.request_id, "req-2", sizeof(output->ingress.envelope.request_id) - 1);
    strncpy(output->ingress.session.session_id, "session-2", sizeof(output->ingress.session.session_id) - 1);
    output->request_identity[0] = 0x43;
}

signing::PreflightResult evaluate_tx_preflight(
    JsonDocument&,
    const signing::SignTransactionUserIngressState& state,
    const signing::PreflightRuntime& runtime,
    signing::SignTransactionPreflightOutput* output)
{
    g_tx_preflight_calls += 1;
    assert(state.material_ready);
    assert(!state.busy);
    assert(state.validate_session != nullptr);
    assert(state.admit_payload_delivery == admit_tx_payload_delivery);
    assert(runtime.read_signing_mode != nullptr);
    assert(runtime.retry_responder != nullptr);
    assert(runtime.retry_stored_response == g_retry_buffer);
    fill_tx_preflight_output(output);
    return g_tx_preflight_result;
}

signing::PreflightResult evaluate_pm_preflight(
    JsonDocument&,
    const signing::SignPersonalMessageUserIngressState& state,
    const signing::PreflightRuntime& runtime,
    signing::SignPersonalMessagePreflightOutput* output)
{
    g_pm_preflight_calls += 1;
    assert(state.material_ready);
    assert(!state.busy);
    assert(state.validate_session != nullptr);
    assert(runtime.read_signing_mode != nullptr);
    assert(runtime.retry_responder != nullptr);
    assert(runtime.retry_stored_response == g_retry_buffer);
    fill_pm_preflight_output(output);
    return g_pm_preflight_result;
}

void record_runtime_failure()
{
    g_record_runtime_failure_calls += 1;
}

signing::SignTransactionPolicyRuntimeResult evaluate_policy(
    const signing::SuiPreparedSignTransaction&)
{
    g_policy_eval_calls += 1;
    signing::SignTransactionPolicyRuntimeResult result = {};
    result.status = g_policy_status;
    result.code = g_policy_code;
    result.message = g_policy_message;
    strncpy(result.chain, "sui", sizeof(result.chain) - 1);
    strncpy(result.method, "sign_transaction", sizeof(result.method) - 1);
    strncpy(result.rule_ref, "rule-1", sizeof(result.rule_ref) - 1);
    return result;
}

signing::PolicySigningExecutionResult execute_policy(
    const signing::SignTransactionPolicyRuntimeResult& policy_result)
{
    g_policy_execute_calls += 1;
    signing::PolicySigningExecutionResult result = {};
    result.status = g_execution_status;
    result.code = policy_result.code;
    result.message = policy_result.message;
    return result;
}

bool write_policy_response(
    const char* id,
    const uint8_t* request_identity,
    const signing::PolicySigningExecutionResult& result)
{
    g_policy_response_calls += 1;
    assert(strcmp(id, "id-1") == 0);
    assert(request_identity[0] == 0x42);
    g_last_policy_response_code = result.code;
    g_last_policy_response_message = result.message;
    return g_policy_response_ok;
}

void clear_policy_execution(signing::PolicySigningExecutionResult*)
{
    g_clear_policy_execution_calls += 1;
}

void clear_policy_runtime(signing::SignTransactionPolicyRuntimeResult*)
{
    g_clear_policy_runtime_calls += 1;
}

signing::TimeoutWindow make_window(signing::TimeoutTick now)
{
    g_make_window_calls += 1;
    return signing::TimeoutWindow{now, static_cast<signing::TimeoutTick>(now + 10)};
}

signing::UserSigningFlowBeginResult begin_tx(
    signing::TimeoutTick now,
    const signing::UserSigningTransactionBeginInput& input)
{
    g_begin_tx_calls += 1;
    assert(now == 10);
    assert(strcmp(input.request_id, "req-1") == 0);
    assert(strcmp(input.session_id, "session-1") == 0);
    assert(input.request_identity[0] == 0x42);
    assert(input.route == signing::Route::sui_sign_transaction);
    assert(input.prepared != nullptr);
    assert(input.request_window.started_at == 10);
    return g_begin_result;
}

signing::UserSigningFlowBeginResult begin_pm(
    signing::TimeoutTick now,
    const signing::UserSigningPersonalMessageBeginInput& input)
{
    g_begin_pm_calls += 1;
    assert(now == 10);
    assert(strcmp(input.request_id, "req-2") == 0);
    assert(strcmp(input.session_id, "session-2") == 0);
    assert(input.request_identity[0] == 0x43);
    assert(input.route == signing::Route::sui_sign_personal_message);
    assert(input.prepared != nullptr);
    assert(input.request_window.deadline == 20);
    return g_begin_result;
}

void clear_tx_prepared(signing::SuiPreparedSignTransaction*)
{
    g_clear_tx_prepared_calls += 1;
}

void clear_pm_prepared(signing::SuiPreparedPersonalMessage*)
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

void record_waiting(const char* id, signing::Route route)
{
    g_waiting_calls += 1;
    g_last_id = id;
    g_last_waiting_route = route;
}

void show_notice(const char* message, signing::UsbSigningNoticeKind kind)
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

signing::TimeoutTick current_tick()
{
    return 10;
}

signing::UsbSigningHandlerOps make_ops()
{
    return signing::UsbSigningHandlerOps{
        material_ready,
        busy,
        busy,
        current_tick,
        validate_session,
        nullptr,
        admit_tx_payload_delivery,
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

signing::UsbOperationResponseWriter make_writer()
{
    return signing::UsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

void test_unavailable_ops()
{
    reset_state();
    JsonDocument request;
    signing::UsbSigningHandlerOps ops = {};
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), ops);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "internal_output_error") == 0);
    assert(g_tx_preflight_calls == 0);
}

void test_transaction_ingress_error_mapping()
{
    reset_state();
    g_tx_preflight_result = signing::PreflightResult::transaction_ingress_error;
    g_tx_ingress_result = signing::SignTransactionUserIngressResult::invalid_tx_bytes;
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_tx_preflight_calls == 1);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "invalid_params") == 0);
    assert(g_clear_tx_prepared_calls == 2);
}

void test_personal_message_ingress_error_mapping()
{
    reset_state();
    g_pm_preflight_result = signing::PreflightResult::personal_message_ingress_error;
    g_pm_ingress_result = signing::SignPersonalMessageUserIngressResult::invalid_message;
    JsonDocument request;
    signing::handle_usb_sign_personal_message_request("id-2", request, make_writer(), make_ops());
    assert(g_pm_preflight_calls == 1);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "invalid_params") == 0);
    assert(g_clear_pm_prepared_calls == 0);
}

void test_personal_message_capacity_ingress_error_mapping()
{
    reset_state();
    g_pm_preflight_result = signing::PreflightResult::personal_message_ingress_error;
    g_pm_ingress_result = signing::SignPersonalMessageUserIngressResult::message_too_large;
    JsonDocument request;
    signing::handle_usb_sign_personal_message_request("id-2", request, make_writer(), make_ops());
    assert(g_pm_preflight_calls == 1);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "payload_too_large") == 0);
    assert(g_clear_pm_prepared_calls == 0);
}

void test_max_personal_message_success_response_fits_retained_budget()
{
    JsonDocument result;
    result["authorization"] = "user";
    result["chain"] = "sui";
    result["method"] = "sign_personal_message";
    result["signature"] = std::string(signing::kSuiSignatureEnvelopeBase64MaxChars, 'A');
    result["messageBytes"] = std::string(signing::kSuiSignPersonalMessageMaxBase64Size, 'A');

    JsonDocument response;
    response["id"] = "req_sign_budget";
    response["version"] = 1;
    response["success"] = true;
    response["method"] = "sign_personal_message";
    response["result"].set(result.as<JsonObjectConst>());

    std::string serialized;
    serializeJson(response, serialized);
    assert(serialized.size() < signing::kResponseMaxSize);
}

void test_preparation_account_failure_mapping()
{
    reset_state();
    g_tx_preflight_result = signing::PreflightResult::transaction_preparation_error;
    g_preparation_result = signing::SuiSigningPreparationResult::account_unavailable;
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_record_runtime_failure_calls == 1);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "account_unavailable") == 0);
    assert(g_notice_calls == 0);
}

void test_preparation_active_identity_failure_mapping()
{
    reset_state();
    g_tx_preflight_result = signing::PreflightResult::transaction_preparation_error;
    g_preparation_result = signing::SuiSigningPreparationResult::active_identity_unavailable;
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_record_runtime_failure_calls == 0);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "account_unavailable") == 0);
    assert(g_notice_calls == 0);
}

void test_preparation_invalid_account_mapping()
{
    reset_state();
    g_tx_preflight_result = signing::PreflightResult::transaction_preparation_error;
    g_preparation_result = signing::SuiSigningPreparationResult::invalid_account;
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_record_runtime_failure_calls == 0);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "account_unavailable") == 0);
    assert(g_notice_calls == 0);
}

void test_personal_message_preparation_account_failure_mapping()
{
    reset_state();
    g_pm_preflight_result =
        signing::PreflightResult::personal_message_preparation_error;
    g_preparation_result = signing::SuiSigningPreparationResult::account_unavailable;
    JsonDocument request;
    signing::handle_usb_sign_personal_message_request("id-2", request, make_writer(), make_ops());
    assert(g_record_runtime_failure_calls == 1);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "account_unavailable") == 0);
    assert(g_notice_calls == 0);
}

void test_transaction_preparation_unsupported_notifies()
{
    reset_state();
    g_tx_preflight_result =
        signing::PreflightResult::transaction_preparation_error;
    g_preparation_result = signing::SuiSigningPreparationResult::unsupported_transaction;
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "unsupported_transaction") == 0);
    assert(g_notice_calls == 1);
    assert(g_last_notice_kind == signing::UsbSigningNoticeKind::error);
    assert(strcmp(g_last_notice_message, "Unsupported transaction") == 0);
    assert(g_begin_tx_calls == 0);
}

void test_transaction_preparation_payload_too_large_notifies()
{
    reset_state();
    g_tx_preflight_result =
        signing::PreflightResult::transaction_preparation_error;
    g_preparation_result = signing::SuiSigningPreparationResult::payload_too_large;
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "payload_too_large") == 0);
    assert(g_notice_calls == 1);
    assert(g_last_notice_kind == signing::UsbSigningNoticeKind::error);
    assert(strcmp(g_last_notice_message, "Payload too large") == 0);
    assert(g_begin_tx_calls == 0);
}

void test_retry_consumed_writes_no_error()
{
    reset_state();
    g_tx_preflight_result = signing::PreflightResult::retry_consumed;
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_tx_preflight_calls == 1);
    assert(g_write_error_calls == 0);
    assert(g_begin_tx_calls == 0);
}

void test_policy_signed_path_cleans_outputs()
{
    reset_state();
    g_mode = signing::AuthorizationMode::policy;
    g_execution_status = signing::PolicySigningExecutionStatus::signed_success;
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_policy_eval_calls == 1);
    assert(g_policy_execute_calls == 1);
    assert(g_policy_response_calls == 1);
    assert(g_log_policy_signed_calls == 1);
    assert(g_notice_calls == 2);
    assert(g_last_notice_kind == signing::UsbSigningNoticeKind::success);
    assert(g_clear_policy_execution_calls == 1);
    assert(g_clear_policy_runtime_calls == 1);
    assert(g_clear_tx_prepared_calls == 2);
    assert(g_begin_tx_calls == 0);
}

void test_policy_response_failure_logs_and_cleans()
{
    reset_state();
    g_mode = signing::AuthorizationMode::policy;
    g_execution_status = signing::PolicySigningExecutionStatus::policy_rejected;
    g_policy_response_ok = false;
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_policy_response_calls == 1);
    assert(g_log_write_failure_calls == 1);
    assert(g_notice_calls == 2);
    assert(g_last_notice_kind == signing::UsbSigningNoticeKind::error);
    assert(g_clear_policy_execution_calls == 1);
    assert(g_clear_policy_runtime_calls == 1);
    assert(g_clear_tx_prepared_calls == 2);
}

void test_policy_signing_failed_path_cleans_outputs()
{
    reset_state();
    g_mode = signing::AuthorizationMode::policy;
    g_execution_status = signing::PolicySigningExecutionStatus::signing_failed;
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_policy_eval_calls == 1);
    assert(g_policy_execute_calls == 1);
    assert(g_policy_response_calls == 1);
    assert(g_log_policy_failed_calls == 1);
    assert(g_notice_calls == 2);
    assert(g_last_notice_kind == signing::UsbSigningNoticeKind::error);
    assert(g_clear_policy_execution_calls == 1);
    assert(g_clear_policy_runtime_calls == 1);
    assert(g_clear_tx_prepared_calls == 2);
    assert(g_begin_tx_calls == 0);
}

void test_policy_unsupported_transaction_notifies()
{
    reset_state();
    g_mode = signing::AuthorizationMode::policy;
    g_policy_status = signing::SignTransactionPolicyRuntimeStatus::unsupported_transaction;
    g_execution_status = signing::PolicySigningExecutionStatus::request_error;
    g_policy_code = "unsupported_transaction";
    g_policy_message = "Policy cannot evaluate this transaction.";
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_policy_eval_calls == 1);
    assert(g_policy_execute_calls == 1);
    assert(g_policy_response_calls == 1);
    assert(strcmp(g_last_policy_response_code, "unsupported_transaction") == 0);
    assert(strcmp(g_last_policy_response_message, "Policy cannot evaluate this transaction.") == 0);
    assert(g_notice_calls == 1);
    assert(g_last_notice_kind == signing::UsbSigningNoticeKind::error);
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
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_begin_tx_calls == 1);
    assert(g_clear_tx_prepared_calls == 2);
    assert(g_show_review_calls == 1);
    assert(g_waiting_calls == 1);
    assert(g_last_waiting_route == signing::Route::sui_sign_transaction);
    assert(g_write_error_calls == 0);
}

void test_transaction_begin_failure_cleans_prepared()
{
    reset_state();
    g_begin_result = signing::UserSigningFlowBeginResult::malformed_transaction;
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
    assert(g_begin_tx_calls == 1);
    assert(g_clear_tx_prepared_calls == 2);
    assert(g_show_review_calls == 0);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "malformed_transaction") == 0);
    assert(g_notice_calls == 1);
    assert(g_last_notice_kind == signing::UsbSigningNoticeKind::error);
    assert(strcmp(g_last_notice_message, "Malformed transaction") == 0);
}

void test_transaction_ui_failure_cleans_flow()
{
    reset_state();
    g_show_review_ok = false;
    JsonDocument request;
    signing::handle_usb_sign_transaction_request("id-1", request, make_writer(), make_ops());
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
    g_pm_preflight_result = signing::PreflightResult::personal_message_policy_mode;
    JsonDocument request;
    signing::handle_usb_sign_personal_message_request("id-2", request, make_writer(), make_ops());
    assert(g_pm_preflight_calls == 1);
    assert(g_write_error_calls == 1);
    assert(strcmp(g_last_error_code, "unsupported_method") == 0);
    assert(g_clear_pm_prepared_calls == 0);
}

void test_personal_message_user_success()
{
    reset_state();
    JsonDocument request;
    signing::handle_usb_sign_personal_message_request("id-2", request, make_writer(), make_ops());
    assert(g_begin_pm_calls == 1);
    assert(g_clear_pm_prepared_calls == 1);
    assert(g_show_review_calls == 1);
    assert(g_waiting_calls == 1);
    assert(g_last_waiting_route == signing::Route::sui_sign_personal_message);
    assert(g_write_error_calls == 0);
}

}  // namespace

int main()
{
    test_unavailable_ops();
    test_transaction_ingress_error_mapping();
    test_personal_message_ingress_error_mapping();
    test_personal_message_capacity_ingress_error_mapping();
    test_max_personal_message_success_response_fits_retained_budget();
    test_preparation_account_failure_mapping();
    test_preparation_active_identity_failure_mapping();
    test_preparation_invalid_account_mapping();
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
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/usb_signing_handlers.cpp" \
  -o "${TMP_DIR}/test_usb_signing_handlers"

"${TMP_DIR}/test_usb_signing_handlers"
