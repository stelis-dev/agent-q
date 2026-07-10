#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime"
COMMON_DIR="${REPO_ROOT}/firmware/src/common"
CRYPTO_ROOT="${SIGNING_CRYPTO_ROOT:-${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib}"
MICROSUI_CORE="${CRYPTO_ROOT}/src/microsui_core"
IDF_PATH="${FIRMWARE_IDF_PATH:-${REPO_ROOT}/.WORK/toolchains/esp-idf-v5.5.4}"
MBEDTLS_ROOT="${IDF_PATH}/components/mbedtls/mbedtls"
MBEDTLS_INCLUDE_DIR="${MBEDTLS_ROOT}/include"
MBEDTLS_LIBRARY_DIR="${MBEDTLS_ROOT}/library"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stopwatch-esp32s3/M5StopWatch-UserDemo/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${MICROSUI_CORE}/byte_conversions.c" \
  "${MICROSUI_CORE}/key_management.c" \
  "${MICROSUI_CORE}/lib/monocypher/monocypher.c" \
  "${MBEDTLS_INCLUDE_DIR}/mbedtls/sha256.h" \
  "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  "${COMMON_DIR}/policy/evaluator.h" \
  "${COMMON_DIR}/policy/policy_handlers.cpp" \
  "${COMMON_DIR}/policy/policy_handlers.h" \
  "${COMMON_DIR}/protocol/base64.cpp" \
  "${COMMON_DIR}/protocol/device_contract.cpp" \
  "${COMMON_DIR}/protocol/device_response.cpp" \
  "${COMMON_DIR}/protocol/active_session_request_guard.cpp" \
  "${COMMON_DIR}/protocol/active_session_request_guard.h" \
  "${COMMON_DIR}/protocol/json_response.cpp" \
  "${COMMON_DIR}/protocol/json_response.h" \
  "${COMMON_DIR}/protocol/operation_dispatch.cpp" \
  "${COMMON_DIR}/protocol/operation_dispatch.h" \
  "${COMMON_DIR}/protocol/operation_manifest.cpp" \
  "${COMMON_DIR}/protocol/operation_manifest.h" \
  "${COMMON_DIR}/protocol/operation_type.cpp" \
  "${COMMON_DIR}/protocol/operation_type.h" \
  "${COMMON_DIR}/protocol/request_envelope.cpp" \
  "${COMMON_DIR}/protocol/request_envelope.h" \
  "${COMMON_DIR}/protocol/request_line_handler.cpp" \
  "${COMMON_DIR}/protocol/request_line_handler.h" \
  "${COMMON_DIR}/protocol/sui_zklogin_credential_handlers.cpp" \
  "${COMMON_DIR}/protocol/sui_zklogin_credential_handlers.h" \
  "${COMMON_DIR}/protocol/request_id.cpp" \
  "${COMMON_DIR}/protocol/request_line.cpp" \
  "${COMMON_DIR}/protocol/sign_request_identity.cpp" \
  "${COMMON_DIR}/protocol/signing_response_store.cpp" \
  "${COMMON_DIR}/protocol/approval_history_handler.cpp" \
  "${COMMON_DIR}/protocol/device_handlers.cpp" \
  "${COMMON_DIR}/protocol/json_response.cpp" \
  "${COMMON_DIR}/policy/policy_handlers.cpp" \
  "${COMMON_DIR}/protocol/active_session_request_guard.cpp" \
  "${COMMON_DIR}/protocol/operation_dispatch.cpp" \
  "${COMMON_DIR}/protocol/operation_manifest.cpp" \
  "${COMMON_DIR}/protocol/operation_type.cpp" \
  "${COMMON_DIR}/protocol/request_envelope.cpp" \
  "${COMMON_DIR}/protocol/request_line_handler.cpp" \
  "${COMMON_DIR}/signing/policy_signing_execution_result.cpp" \
  "${COMMON_DIR}/signing/sign_personal_message_user_ingress.cpp" \
  "${COMMON_DIR}/signing/sign_personal_message_user_validation.cpp" \
  "${COMMON_DIR}/signing/sign_transaction_user_ingress.cpp" \
  "${COMMON_DIR}/signing/sign_transaction_user_validation.cpp" \
	  "${COMMON_DIR}/signing/sign_transaction_policy_runtime.cpp" \
	  "${COMMON_DIR}/signing/signing_preflight.cpp" \
	  "${COMMON_DIR}/signing/signing_retry_response.cpp" \
	  "${COMMON_DIR}/signing/signing_retry_delivery.cpp" \
	  "${COMMON_DIR}/signing/signing_handlers.cpp" \
	  "${COMMON_DIR}/signing/signing_outcome_writer.cpp" \
	  "${COMMON_DIR}/signing/protocol_transport_loss.cpp" \
	  "${COMMON_DIR}/signing/user_signing_critical_section.cpp" \
  "${COMMON_DIR}/signing/user_signing_flow.cpp" \
  "${COMMON_DIR}/sui/offline_policy_facts.h" \
  "${COMMON_DIR}/sui/bcs_reader.cpp" \
  "${COMMON_DIR}/sui/account_binding.cpp" \
  "${COMMON_DIR}/sui/sign_transaction_adapter.cpp" \
  "${COMMON_DIR}/sui/signing_preparation.cpp" \
  "${COMMON_DIR}/sui/signing_payload.cpp" \
  "${COMMON_DIR}/sui/transaction_facts.cpp" \
  "${COMMON_DIR}/sui/zklogin_credential_outcome.cpp" \
  "${COMMON_DIR}/sui/zklogin_credential_payload.cpp" \
  "${COMMON_DIR}/sui/zklogin_proof_payload.cpp" \
  "${COMMON_DIR}/sui/zklogin_proof_record.cpp" \
  "${RUNTIME_DIR}/credential_preparation_state.cpp" \
  "${RUNTIME_DIR}/local_auth.cpp" \
  "${COMMON_DIR}/transport/connect_approval.cpp" \
  "${COMMON_DIR}/transport/connect_approval.h" \
  "${COMMON_DIR}/transport/connect_review_response_flow.cpp" \
  "${COMMON_DIR}/transport/connect_review_response_flow.h" \
  "${COMMON_DIR}/transport/payload_delivery_primitives.cpp" \
  "${COMMON_DIR}/transport/payload_delivery_store.cpp" \
  "${COMMON_DIR}/transport/payload_delivery_resolution.cpp" \
  "${COMMON_DIR}/transport/payload_transfer_handlers.cpp" \
  "${RUNTIME_DIR}/protocol_input_encoding.cpp" \
  "${COMMON_DIR}/protocol/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/state_projection.cpp" \
  "${RUNTIME_DIR}/device_reset.cpp" \
  "${RUNTIME_DIR}/sui_public_material.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_credential_store.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_proposal_state.cpp" \
  "${RUNTIME_DIR}/protocol_runtime.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stopwatch-esp32s3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-usb-credential-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p \
  "${TMP_DIR}/driver" \
  "${TMP_DIR}/freertos" \
  "${TMP_DIR}/firmware_common/protocol"

cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/freertos/task.h" <<'H'
#pragma once
#include <stdint.h>
void vTaskDelay(uint32_t ticks);
uint32_t xTaskGetTickCount();
H

cat >"${TMP_DIR}/driver/usb_serial_jtag.h" <<'H'
#pragma once
#include <stddef.h>
#include <stdint.h>
typedef int esp_err_t;
typedef struct {
    int rx_buffer_size;
    int tx_buffer_size;
} usb_serial_jtag_driver_config_t;
#define USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT() usb_serial_jtag_driver_config_t{256, 256}
esp_err_t usb_serial_jtag_driver_install(const usb_serial_jtag_driver_config_t* config);
bool usb_serial_jtag_is_driver_installed(void);
bool usb_serial_jtag_is_connected(void);
int usb_serial_jtag_read_bytes(void* buffer, size_t length, uint32_t ticks_to_wait);
int usb_serial_jtag_write_bytes(const void* buffer, size_t length, uint32_t ticks_to_wait);
esp_err_t usb_serial_jtag_wait_tx_done(uint32_t ticks_to_wait);
H

cat >"${TMP_DIR}/driver/usb_serial_jtag_vfs.h" <<'H'
#pragma once
void usb_serial_jtag_vfs_use_driver(void);
H

cat >"${TMP_DIR}/esp_err.h" <<'H'
#pragma once
typedef int esp_err_t;
constexpr esp_err_t ESP_OK = 0;
const char* esp_err_to_name(esp_err_t err);
H

cat >"${TMP_DIR}/esp_log.h" <<'H'
#pragma once
#define ESP_LOGE(tag, fmt, ...)
#define ESP_LOGW(tag, fmt, ...)
#define ESP_LOGI(tag, fmt, ...)
H

cat >"${TMP_DIR}/esp_mac.h" <<'H'
#pragma once
#include <stdint.h>
#include "esp_err.h"
esp_err_t esp_efuse_mac_get_default(uint8_t mac[6]);
H

cat >"${TMP_DIR}/esp_timer.h" <<'H'
#pragma once
#include <stdint.h>
int64_t esp_timer_get_time(void);
H

cat >"${TMP_DIR}/firmware_common/protocol/request_id.h" <<H
#pragma once
#include "${COMMON_DIR}/protocol/request_id.h"
H

cat >"${TMP_DIR}/protocol_runtime_credential_flow_test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "esp_err.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "policy/evaluator.h"

extern "C" {
#include "byte_conversions.h"
}

namespace {
char g_written[8192] = {};
size_t g_written_size = 0;
int64_t g_now_us = 1000 * 1000;
uint8_t g_secure_random_next = 0x40;
}

esp_err_t usb_serial_jtag_driver_install(const usb_serial_jtag_driver_config_t*)
{
    return ESP_OK;
}

bool usb_serial_jtag_is_connected(void)
{
    return true;
}

bool usb_serial_jtag_is_driver_installed(void)
{
    return true;
}

int usb_serial_jtag_read_bytes(void*, size_t, uint32_t)
{
    return 0;
}

int usb_serial_jtag_write_bytes(const void* buffer, size_t length, uint32_t)
{
    if (buffer == nullptr || g_written_size + length >= sizeof(g_written)) {
        return -1;
    }
    memcpy(g_written + g_written_size, buffer, length);
    g_written_size += length;
    g_written[g_written_size] = '\0';
    return static_cast<int>(length);
}

esp_err_t usb_serial_jtag_wait_tx_done(uint32_t)
{
    return ESP_OK;
}

void usb_serial_jtag_vfs_use_driver(void) {}

void vTaskDelay(uint32_t) {}

uint32_t xTaskGetTickCount()
{
    return static_cast<uint32_t>(g_now_us / 1000);
}

const char* esp_err_to_name(esp_err_t)
{
    return "ESP_ERR_TEST";
}

esp_err_t esp_efuse_mac_get_default(uint8_t mac[6])
{
    for (size_t index = 0; index < 6; ++index) {
        mac[index] = static_cast<uint8_t>(index);
    }
    return ESP_OK;
}

int64_t esp_timer_get_time(void)
{
    return g_now_us;
}

#include "device_reset.h"
#include "local_auth.h"
#include "protocol_runtime.cpp"

namespace stopwatch_target {

bool local_transport_pairing_begin(TickType_t)
{
    return false;
}

void local_transport_pairing_cancel() {}
void local_transport_pairing_handle_display_loss() {}
void local_transport_pairing_poll(TickType_t, LocalTransportRequestHandler) {}

signing::LocalTransportPairingSnapshot local_transport_pairing_snapshot()
{
    return {};
}

bool local_transport_pairing_active()
{
    return false;
}

bool local_transport_pairing_established()
{
    return false;
}

bool local_transport_pairing_connected()
{
    return false;
}

bool local_transport_pairing_wipe_identity()
{
    return true;
}

bool local_transport_pairing_take_event(signing::LocalTransportPairingEvent*)
{
    return false;
}

}  // namespace stopwatch_target

namespace signing {

AuthorizationMode g_signing_mode = AuthorizationMode::user;
AuthorizationModeStatus g_signing_mode_status = AuthorizationModeStatus::active;
bool g_policy_available = false;
PolicyStoreStatus g_policy_status = PolicyStoreStatus::active;
ApprovalHistoryStorageStatus g_approval_history_status = ApprovalHistoryStorageStatus::missing;
PolicyUpdateMarkerStatus g_policy_update_marker_status = PolicyUpdateMarkerStatus::clear;
CurrentPolicyDocument g_policy_document = {};
CurrentPolicyEvaluationStatus g_policy_evaluation_status =
    CurrentPolicyEvaluationStatus::authorized;
const char* g_policy_reason_code = "policy_authorized";
const char* g_policy_rule_ref = "rule-1";
bool g_policy_facts_complete = true;
bool g_large_history_response = false;
int g_authorization_mode_status_calls = 0;
int g_policy_status_calls = 0;
int g_approval_history_status_calls = 0;
int g_policy_update_marker_status_calls = 0;

const char* authorization_mode_name(AuthorizationMode mode)
{
    return mode == AuthorizationMode::policy ? "policy" : "user";
}

bool read_signing_authorization_mode(AuthorizationMode* mode)
{
    if (g_signing_mode_status != AuthorizationModeStatus::active) {
        return false;
    }
    if (mode != nullptr) {
        *mode = g_signing_mode;
    }
    return mode != nullptr;
}

bool wipe_signing_authorization_mode()
{
    g_signing_mode_status = AuthorizationModeStatus::missing;
    return true;
}

AuthorizationModeStatus authorization_mode_status()
{
    ++g_authorization_mode_status_calls;
    return g_signing_mode_status;
}

bool read_active_policy_document(StoredPolicyDocument* output)
{
    if (!g_policy_available || output == nullptr) {
        return false;
    }
    memset(output, 0, sizeof(*output));
    output->schema = kCurrentPolicySchema;
    strcpy(
        output->policy_id,
        "sha256:1111111111111111111111111111111111111111111111111111111111111111");
    output->default_action = "reject";
    output->document = &g_policy_document;
    return true;
}

bool read_active_policy_summary(StoredPolicySummary* output)
{
    if (!g_policy_available || output == nullptr) {
        return false;
    }
    snprintf(
        output->policy_id,
        sizeof(output->policy_id),
        "%s",
        "policy-test");
    return true;
}

PolicyStoreStatus active_policy_status()
{
    ++g_policy_status_calls;
    return g_policy_status;
}

bool policy_store_write_policy_json(JsonObject, const StoredPolicyDocument&)
{
    return false;
}

bool wipe_policy()
{
    g_policy_available = false;
    g_policy_status = PolicyStoreStatus::missing;
    return true;
}

SuiTransactionFactsResult parse_sui_offline_policy_condition_facts(
    const uint8_t* tx_bytes,
    size_t tx_len,
    SuiOfflinePolicyConditionFacts* output)
{
    if (tx_bytes == nullptr || tx_len == 0 || output == nullptr) {
        return SuiTransactionFactsResult::malformed;
    }
    memset(output, 0, sizeof(*output));
    output->valid_transaction_data = true;
    output->completeness = g_policy_facts_complete
                               ? SuiOfflinePolicyFactsCompleteness::complete
                               : SuiOfflinePolicyFactsCompleteness::incomplete;
    return SuiTransactionFactsResult::ok;
}

CurrentPolicyEvaluationResult evaluate_current_policy_for_sui_sign_transaction(
    const CurrentPolicyDocument&,
    const char*,
    const SuiOfflinePolicyConditionFacts&)
{
    return CurrentPolicyEvaluationResult{
        g_policy_evaluation_status,
        g_policy_reason_code,
        g_policy_rule_ref,
    };
}

bool approval_history_digest_payload(
    const uint8_t*,
    size_t,
    char* output,
    size_t output_size)
{
    if (output == nullptr || output_size != kApprovalHistoryDigestSize) {
        return false;
    }
    snprintf(
        output,
        output_size,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000");
    return true;
}

bool approval_history_parse_sequence(const char* value, uint64_t* output)
{
    if (value == nullptr || output == nullptr) {
        return false;
    }
    uint64_t parsed = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
        parsed = parsed * 10 + static_cast<uint64_t>(*cursor - '0');
    }
    *output = parsed;
    return true;
}

ApprovalHistoryReadResult approval_history_read_page(
    uint64_t,
    size_t,
    ApprovalHistoryPage* output)
{
    if (output == nullptr) {
        return ApprovalHistoryReadResult::invalid;
    }
    memset(output, 0, sizeof(*output));
    if (g_large_history_response) {
        output->count = 4;
        output->has_more = false;
    }
    return ApprovalHistoryReadResult::ok;
}

bool approval_history_write_page_json(JsonObject result, const ApprovalHistoryPage& page)
{
    JsonArray records = result["records"].to<JsonArray>();
    if (g_large_history_response) {
        for (size_t index = 0; index < page.count; ++index) {
            JsonObject record = records.add<JsonObject>();
            record["seq"] = static_cast<unsigned>(index + 1);
            record["uptimeMs"] = static_cast<unsigned>(1000 + index);
            record["timeSource"] = "uptime";
            record["eventKind"] = "signing";
            record["recordKind"] = "terminal";
            record["authorization"] = "policy";
            record["chain"] = "sui";
            record["method"] = "sign_transaction";
            record["terminalResult"] = "policy_rejected";
            record["reasonCode"] = "policy_rejected";
            record["payloadDigest"] =
                "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            record["policyHash"] =
                "sha256:1111111111111111111111111111111111111111111111111111111111111111";
            record["ruleRef"] = "reject-all-default-rule-for-response-size-regression";
        }
    }
    result["hasMore"] = page.has_more;
    return true;
}

bool approval_history_append_required_signing(const HistoryAppendInput&, uint64_t)
{
    return true;
}

bool approval_history_append_budgeted_signing(const HistoryAppendInput&, uint64_t)
{
    return true;
}

bool approval_history_wipe()
{
    g_approval_history_status = ApprovalHistoryStorageStatus::missing;
    return true;
}

ApprovalHistoryStorageStatus approval_history_status()
{
    ++g_approval_history_status_calls;
    return g_approval_history_status;
}

bool policy_update_flow_active()
{
    return false;
}

void policy_update_flow_clear() {}

bool policy_update_marker_clear()
{
    g_policy_update_marker_status = PolicyUpdateMarkerStatus::clear;
    return true;
}

PolicyUpdateMarkerStatus policy_update_marker_status()
{
    ++g_policy_update_marker_status_calls;
    return g_policy_update_marker_status;
}

PolicyUpdateFlowSnapshot policy_update_flow_snapshot()
{
    return PolicyUpdateFlowSnapshot{};
}

PolicyUpdateFlowBeginResult policy_update_flow_begin(
    JsonVariantConst,
    const char*,
    const char*,
    TickType_t,
    TimeoutWindow)
{
    return PolicyUpdateFlowBeginResult::invalid_policy;
}

PolicyUpdateFlowTransitionResult policy_update_flow_mark_pin_verifying()
{
    return PolicyUpdateFlowTransitionResult::wrong_stage;
}

bool policy_update_flow_review_deadline_reached(TickType_t)
{
    return false;
}

PolicyUpdateFlowTerminalResult policy_update_flow_record_rejected(uint64_t)
{
    return PolicyUpdateFlowTerminalResult::rejected;
}

PolicyUpdateFlowTerminalResult policy_update_flow_record_timed_out(uint64_t)
{
    return PolicyUpdateFlowTerminalResult::timed_out;
}

PolicyUpdateFlowTerminalResult policy_update_flow_record_ui_error()
{
    return PolicyUpdateFlowTerminalResult::ui_error;
}

PolicyUpdateFlowTerminalResult policy_update_flow_commit(uint64_t)
{
    return PolicyUpdateFlowTerminalResult::invalid_state;
}

const char* policy_update_flow_begin_result_reason(PolicyUpdateFlowBeginResult)
{
    return "invalid_policy";
}

const char* policy_update_flow_terminal_status(PolicyUpdateFlowTerminalResult result)
{
    return result == PolicyUpdateFlowTerminalResult::applied ? "applied" : "rejected";
}

const char* policy_update_flow_terminal_reason(PolicyUpdateFlowTerminalResult)
{
    return "ui_error";
}

}  // namespace signing

namespace stopwatch_target {

bool secure_random_fill(void* output, size_t size)
{
    if (output == nullptr) {
        return false;
    }
    uint8_t* cursor = static_cast<uint8_t*>(output);
    for (size_t index = 0; index < size; ++index) {
        cursor[index] = static_cast<uint8_t>(g_secure_random_next++);
    }
    return true;
}

SuiZkLoginSigningResult sign_sui_zklogin_personal_message(
    const uint8_t*,
    size_t,
    uint8_t* signature_out,
    size_t* signature_size_out)
{
    if (signature_out == nullptr || signature_size_out == nullptr) {
        return SuiZkLoginSigningResult::invalid_input;
    }
    memset(signature_out, 0, signing::kSuiSignatureEnvelopeMaxBytes);
    signature_out[0] = signing::kSuiSignatureSchemeFlagZkLogin;
    *signature_size_out = signing::kSuiEd25519SignatureBytes + 1;
    return SuiZkLoginSigningResult::ok;
}

SuiZkLoginSigningResult sign_sui_zklogin_transaction(
    const uint8_t*,
    size_t,
    uint8_t* signature_out,
    size_t* signature_size_out)
{
    if (signature_out == nullptr || signature_size_out == nullptr) {
        return SuiZkLoginSigningResult::invalid_input;
    }
    memset(signature_out, 0, signing::kSuiSignatureEnvelopeMaxBytes);
    signature_out[0] = signing::kSuiSignatureSchemeFlagZkLogin;
    *signature_size_out = signing::kSuiEd25519SignatureBytes + 1;
    return SuiZkLoginSigningResult::ok;
}

}  // namespace stopwatch_target

using namespace stopwatch_target;

namespace {

bool fill_session_random(void* output, size_t size, void*)
{
    if (output == nullptr) {
        return false;
    }
    uint8_t* bytes = static_cast<uint8_t*>(output);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = static_cast<uint8_t>(index);
    }
    return true;
}

void reset_written()
{
    g_written_size = 0;
    g_written[0] = '\0';
}

void expect_written_contains(const char* needle)
{
    if (strstr(g_written, needle) == nullptr) {
        fprintf(stderr, "missing expected response fragment: %s\nresponse buffer:\n%s\n", needle, g_written);
        assert(false);
    }
}

void expect_written_not_contains(const char* needle)
{
    if (strstr(g_written, needle) != nullptr) {
        fprintf(stderr, "unexpected response fragment: %s\nresponse buffer:\n%s\n", needle, g_written);
        assert(false);
    }
}

void expect_no_response()
{
    if (g_written_size != 0) {
        fprintf(stderr, "expected no response, got:\n%s\n", g_written);
        assert(false);
    }
}

void expect_policy_rejected_notice()
{
    const SigningNotice notice = protocol_runtime_signing_notice();
    assert(notice.active);
    assert(notice.kind == SigningNoticeKind::rejected);
    assert(strcmp(notice.message, "Policy rejected") == 0);
}

void add_proof_point_vector(JsonArray array, size_t count, unsigned start)
{
    for (size_t index = 0; index < count; ++index) {
        char value[8] = {};
        snprintf(value, sizeof(value), "%u", start + static_cast<unsigned>(index));
        array.add(value);
    }
}

void add_valid_inputs(JsonObject inputs)
{
    JsonObject proof_points = inputs["proofPoints"].to<JsonObject>();
    add_proof_point_vector(
        proof_points["a"].to<JsonArray>(),
        stopwatch_target::kSuiZkLoginProofPointACount,
        1);
    JsonArray b = proof_points["b"].to<JsonArray>();
    for (size_t row = 0; row < stopwatch_target::kSuiZkLoginProofPointBOuterCount; ++row) {
        add_proof_point_vector(
            b.add<JsonArray>(),
            stopwatch_target::kSuiZkLoginProofPointBInnerCount,
            10 + static_cast<unsigned>(row * stopwatch_target::kSuiZkLoginProofPointBInnerCount));
    }
    add_proof_point_vector(
        proof_points["c"].to<JsonArray>(),
        stopwatch_target::kSuiZkLoginProofPointCCount,
        20);

    JsonObject details = inputs["issBase64Details"].to<JsonObject>();
    details["value"] = "ImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSJ9";
    details["indexMod4"] = 0;
    inputs["headerBase64"] = "eyJhbGciOiJSUzI1NiJ9";
    inputs["addressSeed"] = "1";
}

void build_payload_json(char* output, size_t output_size, const char* network)
{
    using namespace signing;
    JsonDocument payload;
    JsonObject object = payload.to<JsonObject>();
    object["chain"] = "sui";
    object["credential"] = "zklogin";
    object["network"] = network;
    object["maxEpoch"] = "123";

    constexpr const char* issuer = "https://accounts.google.com";
    uint8_t public_key[kSuiZkLoginPublicKeyMaxBytes] = {};
    const size_t issuer_len = strlen(issuer);
    public_key[0] = kSuiSignatureSchemeFlagZkLogin;
    public_key[1] = static_cast<uint8_t>(issuer_len);
    memcpy(public_key + 2, issuer, issuer_len);
    public_key[2 + issuer_len + 31] = 1;
    const size_t public_key_size = 2 + issuer_len + 32;

    char address[kSuiAddressBufferSize] = {};
    assert(derive_sui_address_from_scheme_prefixed_public_key(
        public_key,
        public_key_size,
        address,
        sizeof(address)));
    object["address"] = address;

    char public_key_base64[((kSuiZkLoginPublicKeyMaxBytes + 2) / 3) * 4 + 1] = {};
    assert(bytes_to_base64(public_key, public_key_size, public_key_base64, sizeof(public_key_base64)) == 0);
    object["publicKey"] = public_key_base64;
    add_valid_inputs(object["inputs"].to<JsonObject>());

    const size_t written = serializeJson(payload, output, output_size);
    assert(written > 0 && written < output_size);
}

void build_valid_payload_json(char* output, size_t output_size)
{
    build_payload_json(output, output_size, "testnet");
}

void build_invalid_network_payload_json(char* output, size_t output_size)
{
    build_payload_json(output, output_size, "unsupported");
}

void send_line(const char* line)
{
    stopwatch_target::handle_protocol_request_line(
        line,
        signing::ProtocolTransportRoute(
            stopwatch_target::usb_protocol_transport_endpoint()));
}

void send_payload_transfer_sequence(
    const char* session_id,
    const char* payload_json,
    const char* expected_transfer_id,
    const char* expected_payload_ref)
{
    using namespace signing;
    char digest[signing::kApprovalHistoryDigestSize] = {};
    assert(signing::approval_history_digest_payload(
        reinterpret_cast<const uint8_t*>(payload_json),
        strlen(payload_json),
        digest,
        sizeof(digest)));

    char line[4096] = {};
    snprintf(
        line,
        sizeof(line),
        "{\"id\":\"req_pt_begin\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"%s\",\"totalBytes\":\"%zu\",\"payloadDigest\":\"%s\"}",
        session_id,
        strlen(payload_json),
        digest);
    reset_written();
    send_line(line);
    expect_written_contains("\"id\":\"req_pt_begin\"");
    expect_written_contains("\"success\":true");
    expect_written_contains(expected_transfer_id);

    char chunk[((4096 + 2) / 3) * 4 + 1] = {};
    assert(strlen(payload_json) < 4096);
    assert(bytes_to_base64(
               reinterpret_cast<const uint8_t*>(payload_json),
               strlen(payload_json),
               chunk,
               sizeof(chunk)) == 0);
    snprintf(
        line,
        sizeof(line),
        "{\"id\":\"req_pt_chunk\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\",\"sessionId\":\"%s\",\"transferId\":\"%s\",\"offsetBytes\":\"0\",\"chunk\":\"%s\"}",
        session_id,
        expected_transfer_id,
        chunk);
    reset_written();
    send_line(line);
    expect_written_contains("\"id\":\"req_pt_chunk\"");
    expect_written_contains("\"success\":true");

    snprintf(
        line,
        sizeof(line),
        "{\"id\":\"req_pt_finish\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"finish\",\"sessionId\":\"%s\",\"transferId\":\"%s\"}",
        session_id,
        expected_transfer_id);
    reset_written();
    send_line(line);
    expect_written_contains("\"id\":\"req_pt_finish\"");
    expect_written_contains("\"success\":true");
    expect_written_contains(expected_payload_ref);
}

void create_finalized_payload_for_current_session(const char* payload_json)
{
    using namespace signing;
    char digest[signing::kApprovalHistoryDigestSize] = {};
    assert(signing::approval_history_digest_payload(
        reinterpret_cast<const uint8_t*>(payload_json),
        strlen(payload_json),
        digest,
        sizeof(digest)));

    const uint32_t now_ms = static_cast<uint32_t>(g_now_us / 1000ULL);
    signing::PayloadDeliveryBeginOutput begin = {};
    assert(signing::payload_delivery_begin(
               now_ms,
               signing::PayloadDeliveryBeginInput{
                   signing::session_id(),
                   strlen(payload_json),
                   digest,
                   signing::PayloadDeliveryLimits{
                       signing::kPayloadDeliveryDefaultChunkMaxBytes,
                       signing::kPayloadDeliveryDefaultMaxBytes,
                   },
                   signing::timeout_window_from_deadline(
                       now_ms,
                       now_ms + signing::payload_delivery_timeout_window_ms_for_size(
                                    strlen(payload_json))),
               },
               &begin) == signing::PayloadDeliveryResult::ok);

    size_t received = 0;
    assert(signing::payload_delivery_append_chunk(
               now_ms,
               signing::PayloadDeliveryChunkInput{
                   signing::session_id(),
                   begin.transfer_id,
                   0,
                   reinterpret_cast<const uint8_t*>(payload_json),
                   strlen(payload_json),
               },
               &received) == signing::PayloadDeliveryResult::ok);
    assert(received == strlen(payload_json));

    signing::PayloadDeliveryFinishOutput finish = {};
    assert(signing::payload_delivery_finish(
               now_ms,
               signing::PayloadDeliveryFinishInput{
                  signing::session_id(),
                  begin.transfer_id,
                  signing::approval_history_digest_payload,
               },
               &finish) == signing::PayloadDeliveryResult::ok);
    assert(signing::payload_delivery_advance_and_snapshot(now_ms).state ==
           signing::PayloadDeliveryState::finalized);
}

void configure_current_setup_for_usb_test()
{
    assert(local_auth_store_new_code("1234", 4));
    signing::g_policy_status = signing::PolicyStoreStatus::active;
    signing::g_signing_mode_status = signing::AuthorizationModeStatus::active;
    protocol_runtime_set_state(ProtocolRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });
}

void reset_projection_status_counters()
{
    signing::g_authorization_mode_status_calls = 0;
    signing::g_policy_status_calls = 0;
    signing::g_approval_history_status_calls = 0;
    signing::g_policy_update_marker_status_calls = 0;
}

void expect_projection_status_counters(int expected)
{
    assert(signing::g_authorization_mode_status_calls == expected);
    assert(signing::g_policy_status_calls == expected);
    assert(signing::g_approval_history_status_calls == expected);
    assert(signing::g_policy_update_marker_status_calls == expected);
}

}  // namespace

int main()
{
    using namespace signing;

    signing::session_init();
    signing::payload_delivery_store_reset();
    credential_preparation_state_init();
    sui_zklogin_credential_test_reset_store();
    sui_zklogin_proposal_state_init();
    protocol_runtime_init();

    assert(signing::session_replace(fill_session_random, nullptr) == signing::SessionStartResult::ok);
    g_active_session_transport = signing::ProtocolTransport::usb;
    assert(strcmp(signing::session_id(), "session_0001020304050607") == 0);
    configure_current_setup_for_usb_test();

    reset_projection_status_counters();
    assert(!protocol_runtime_projected_device_state_is_error());
    assert(!protocol_runtime_projected_device_state_is_error());
    expect_projection_status_counters(1);
    protocol_runtime_invalidate_projected_state_cache();
    assert(!protocol_runtime_projected_device_state_is_error());
    expect_projection_status_counters(2);

    reset_written();
    send_line(
        "{\"id\":\"req_prepare_missing_session\",\"version\":1,\"method\":\"credential_prepare\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
    expect_written_contains("\"id\":\"req_prepare_missing_session\"");
    expect_written_contains("\"method\":\"credential_prepare\"");
    expect_written_contains("\"code\":\"invalid_session\"");
    assert(!credential_preparation_snapshot().active);

    reset_written();
    send_line(
        "{\"id\":\"req_prepare_bad_session\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"session_badg\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
    expect_written_contains("\"id\":\"req_prepare_bad_session\"");
    expect_written_contains("\"method\":\"credential_prepare\"");
    expect_written_contains("\"code\":\"invalid_session\"");
    assert(!credential_preparation_snapshot().active);

    reset_written();
    send_line(
        "{\"id\":\"req_propose_missing_session\",\"version\":1,\"method\":\"credential_propose\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
    expect_written_contains("\"id\":\"req_propose_missing_session\"");
    expect_written_contains("\"method\":\"credential_propose\"");
    expect_written_contains("\"code\":\"invalid_session\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);
    assert(!sui_zklogin_proposal_state_active());

    reset_written();
    send_line(
        "{\"id\":\"req_propose_bad_session\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session_badg\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
    expect_written_contains("\"id\":\"req_propose_bad_session\"");
    expect_written_contains("\"method\":\"credential_propose\"");
    expect_written_contains("\"code\":\"invalid_session\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);
    assert(!sui_zklogin_proposal_state_active());

    reset_written();
    send_line(
        "{\"id\":\"req_prepare\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
    expect_written_contains("\"id\":\"req_prepare\"");
    expect_written_contains("\"method\":\"credential_prepare\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"credential\":\"zklogin\"");
    expect_written_contains("\"keyScheme\":\"ed25519\"");

    CredentialPreparationSnapshot preparation = credential_preparation_snapshot();
    assert(preparation.active);
    assert(strcmp(preparation.session_id, "session_0001020304050607") == 0);
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::missing);

    char payload_json[2048] = {};
    build_valid_payload_json(payload_json, sizeof(payload_json));
    send_payload_transfer_sequence(
        "session_0001020304050607",
        payload_json,
        "transfer_0000000000000001",
        "\"payloadRef\":\"payload_0000000000000001\"");

    reset_written();
    send_line(
        "{\"id\":\"req_propose\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"payloadRef\":\"payload_0000000000000001\"}}");
    expect_no_response();

    PendingRequest pending = protocol_runtime_pending_request();
    assert(pending.kind == PendingRequestKind::credential_propose);
    assert(strcmp(pending.id, "req_propose") == 0);
    SuiZkLoginProposalSnapshot proposal = sui_zklogin_proposal_state_snapshot();
    assert(proposal.active);
    assert(proposal.stage == SuiZkLoginProposalStage::reviewing);
    assert(strcmp(proposal.session_id, "session_0001020304050607") == 0);

    reset_written();
    send_line(
        "{\"id\":\"req_accounts_busy\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session_0001020304050607\"}");
    expect_written_contains("\"id\":\"req_accounts_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    assert(sui_zklogin_proposal_continue_to_auth(static_cast<uint32_t>(g_now_us / 1000ULL) + 1) ==
           SuiZkLoginProposalTransitionResult::ok);
    reset_written();
    assert(protocol_runtime_approve_pending_request());
    expect_written_contains("\"id\":\"req_propose\"");
    expect_written_contains("\"method\":\"credential_propose\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"status\":\"activated\"");
    expect_written_contains("\"reasonCode\":\"device_confirmed\"");
    expect_written_contains("\"sessionEnded\":true");

    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);
    assert(!signing::session_active());
    assert(!credential_preparation_snapshot().active);
    assert(!sui_zklogin_proposal_state_active());
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::active);

    reset_written();
    send_line(
        "{\"id\":\"req_status_active_proof\",\"version\":1,\"method\":\"get_status\"}");
    expect_written_contains("\"id\":\"req_status_active_proof\"");
    expect_written_contains("\"method\":\"get_status\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"provisioning\":{\"state\":\"provisioned\"}");

    signing::g_policy_status = signing::PolicyStoreStatus::missing;
    reset_written();
    send_line(
        "{\"id\":\"req_status_missing_settings\",\"version\":1,\"method\":\"get_status\"}");
    expect_written_contains("\"id\":\"req_status_missing_settings\"");
    expect_written_contains("\"method\":\"get_status\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"device\":{\"deviceId\":\"");
    expect_written_contains("\"state\":\"error\"");
    expect_written_contains("\"provisioning\":{\"state\":\"error\"}");

    reset_written();
    send_line(
        "{\"id\":\"req_connect_missing_settings\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"credential-flow-test\"}}");
    expect_written_contains("\"id\":\"req_connect_missing_settings\"");
    expect_written_contains("\"method\":\"connect\"");
    expect_written_contains("\"code\":\"invalid_state\"");
    assert(!signing::session_active());
    signing::g_policy_status = signing::PolicyStoreStatus::active;

    signing::g_approval_history_status = signing::ApprovalHistoryStorageStatus::invalid;
    reset_written();
    send_line(
        "{\"id\":\"req_status_invalid_history\",\"version\":1,\"method\":\"get_status\"}");
    expect_written_contains("\"id\":\"req_status_invalid_history\"");
    expect_written_contains("\"method\":\"get_status\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"state\":\"error\"");
    expect_written_contains("\"provisioning\":{\"state\":\"error\"}");

    reset_written();
    send_line(
        "{\"id\":\"req_connect_invalid_history\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"credential-flow-test\"}}");
    expect_written_contains("\"id\":\"req_connect_invalid_history\"");
    expect_written_contains("\"method\":\"connect\"");
    expect_written_contains("\"code\":\"invalid_state\"");
    assert(!signing::session_active());
    signing::g_approval_history_status = signing::ApprovalHistoryStorageStatus::missing;

    signing::g_policy_update_marker_status = signing::PolicyUpdateMarkerStatus::pending;
    reset_written();
    send_line(
        "{\"id\":\"req_connect_pending_policy_marker\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"credential-flow-test\"}}");
    expect_written_contains("\"id\":\"req_connect_pending_policy_marker\"");
    expect_written_contains("\"method\":\"connect\"");
    expect_written_contains("\"code\":\"invalid_state\"");
    assert(!signing::session_active());
    signing::g_policy_update_marker_status = signing::PolicyUpdateMarkerStatus::clear;

    reset_written();
    send_line(
        "{\"id\":\"req_accounts_ended_session\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session_0001020304050607\"}");
    expect_written_contains("\"id\":\"req_accounts_ended_session\"");
    expect_written_contains("\"code\":\"invalid_session\"");

    reset_written();
    send_line(
        "{\"id\":\"req_connect_active\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"credential-flow-test\"}}");
    expect_no_response();
    pending = protocol_runtime_pending_request();
    assert(pending.kind == PendingRequestKind::connect);
    assert(strcmp(pending.id, "req_connect_active") == 0);
    assert(signing::timeout_window_active(pending.request_window));

    g_now_us += 30001LL * 1000LL;
    reset_written();
    protocol_runtime_poll();
    expect_written_contains("\"id\":\"req_connect_active\"");
    expect_written_contains("\"method\":\"connect\"");
    expect_written_contains("\"code\":\"timeout\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    reset_written();
    send_line(
        "{\"id\":\"req_connect_active_retry\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"credential-flow-test\"}}");
    expect_no_response();
    pending = protocol_runtime_pending_request();
    assert(pending.kind == PendingRequestKind::connect);
    assert(strcmp(pending.id, "req_connect_active_retry") == 0);

    reset_written();
    assert(protocol_runtime_approve_pending_request());
    protocol_runtime_poll();
    expect_written_contains("\"id\":\"req_connect_active_retry\"");
    expect_written_contains("\"method\":\"connect\"");
    expect_written_contains("\"success\":true");
    assert(signing::session_active());

    char history_line[256] = {};
    snprintf(
        history_line,
        sizeof(history_line),
        "{\"id\":\"req_history_large\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"%s\",\"payload\":{\"limit\":4}}",
        signing::session_id());
    signing::g_large_history_response = true;
    reset_written();
    send_line(history_line);
    expect_written_contains("\"id\":\"req_history_large\"");
    expect_written_contains("\"method\":\"get_approval_history\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"records\":[");
    assert(g_written_size > 1024);
    signing::g_large_history_response = false;

    char accounts_line[256] = {};
    snprintf(
        accounts_line,
        sizeof(accounts_line),
        "{\"id\":\"req_accounts_active\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"%s\"}",
        signing::session_id());
    reset_written();
    send_line(accounts_line);
    expect_written_contains("\"id\":\"req_accounts_active\"");
    expect_written_contains("\"method\":\"get_accounts\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"chain\":\"sui\"");
    expect_written_contains("\"keyScheme\":\"zklogin\"");
    expect_written_contains("\"sponsoredTransactions\":{\"acceptGasSponsor\":false}");

    char caps_line[256] = {};
    snprintf(
        caps_line,
        sizeof(caps_line),
        "{\"id\":\"req_caps_active\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"%s\"}",
        signing::session_id());
    reset_written();
    send_line(caps_line);
    expect_written_contains("\"id\":\"req_caps_active\"");
    expect_written_contains("\"method\":\"get_capabilities\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"signing\":{\"authorization\":\"user\",\"methods\":[{\"chain\":\"sui\",\"method\":\"sign_transaction\"},{\"chain\":\"sui\",\"method\":\"sign_personal_message\"}]");
    expect_written_contains("\"credentials\":[]");
    expect_written_not_contains("\"credential_prepare\"");
    expect_written_not_contains("\"credential_propose\"");

    signing::g_signing_mode = signing::AuthorizationMode::policy;
    reset_written();
    send_line(caps_line);
    expect_written_contains("\"id\":\"req_caps_active\"");
    expect_written_contains("\"method\":\"get_capabilities\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"signing\":{\"authorization\":\"policy\",\"methods\":[{\"chain\":\"sui\",\"method\":\"sign_transaction\"}]");
    expect_written_not_contains("sign_personal_message");

    char policy_mode_message_line[512] = {};
    snprintf(
        policy_mode_message_line,
        sizeof(policy_mode_message_line),
        "{\"id\":\"req_policy_mode_msg\",\"version\":1,\"method\":\"sign_personal_message\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"message\":\"aGk=\"}}",
        signing::session_id());
    reset_written();
    send_line(policy_mode_message_line);
    expect_written_contains("\"id\":\"req_policy_mode_msg\"");
    expect_written_contains("\"method\":\"sign_personal_message\"");
    expect_written_contains("\"code\":\"unsupported_method\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    char policy_mode_tx_line[512] = {};
    snprintf(
        policy_mode_tx_line,
        sizeof(policy_mode_tx_line),
        "{\"id\":\"req_policy_mode_tx\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"txBytes\":\"AA==\"}}",
        signing::session_id());
    reset_written();
    send_line(policy_mode_tx_line);
    expect_written_contains("\"id\":\"req_policy_mode_tx\"");
    expect_written_contains("\"method\":\"sign_transaction\"");
    expect_written_contains("\"code\":\"malformed_transaction\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    signing::g_signing_mode = signing::AuthorizationMode::user;

    char sign_personal_line[512] = {};
    snprintf(
        sign_personal_line,
        sizeof(sign_personal_line),
        "{\"id\":\"req_sign_reject\",\"version\":1,\"method\":\"sign_personal_message\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"message\":\"aGk=\"}}",
        signing::session_id());
    reset_written();
    send_line(sign_personal_line);
    expect_no_response();
    pending = protocol_runtime_pending_request();
    assert(pending.kind == PendingRequestKind::sign_personal_message);
    assert(strcmp(pending.id, "req_sign_reject") == 0);
    reset_written();
    assert(protocol_runtime_reject_pending_request("user_rejected"));
    expect_written_contains("\"id\":\"req_sign_reject\"");
    expect_written_contains("\"method\":\"sign_personal_message\"");
    expect_written_contains("\"code\":\"user_rejected\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    snprintf(
        sign_personal_line,
        sizeof(sign_personal_line),
        "{\"id\":\"req_sign_ok\",\"version\":1,\"method\":\"sign_personal_message\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"message\":\"aGk=\"}}",
        signing::session_id());
    reset_written();
    send_line(sign_personal_line);
    expect_no_response();
    pending = protocol_runtime_pending_request();
    assert(pending.kind == PendingRequestKind::sign_personal_message);
    reset_written();
    assert(protocol_runtime_approve_pending_request());
    expect_written_contains("\"id\":\"req_sign_ok\"");
    expect_written_contains("\"method\":\"sign_personal_message\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"authorization\":\"user\"");
    expect_written_contains("\"messageBytes\":\"aGk=\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    char sign_personal_wrong_network_line[256] = {};
    snprintf(
        sign_personal_wrong_network_line,
        sizeof(sign_personal_wrong_network_line),
        "{\"id\":\"req_sign_wrong_network\",\"version\":1,\"method\":\"sign_personal_message\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"devnet\",\"message\":\"aGk=\"}}",
        signing::session_id());
    reset_written();
    send_line(sign_personal_wrong_network_line);
    expect_written_contains("\"id\":\"req_sign_wrong_network\"");
    expect_written_contains("\"method\":\"sign_personal_message\"");
    expect_written_contains("\"code\":\"invalid_params\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    // Synthetic SDK fixture. The sender is the deterministic zkLogin address
    // derived by build_payload_json() from issuer + addressSeed=1, not a
    // hardware capture or user account.
    constexpr const char* kValidSuiTransferTxBase64 =
        "AAACAAgBAAAAAAAAAAAg1Bx8vAy8y556twE3PztfCCzAAkCY8qtWH/NCEHuRSR8CAgABAQAAAQEDAAAAAAEBANQcfLwMvMueercBNz87XwgswAJAmPKrVh/zQhB7kUkfASIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUHHy8DLzLnnq3ATc/O18ILMACQJjyq1Yf80IQe5FJH+gDAAAAAAAAgJaYAAAAAAAA";
    constexpr const char* kMismatchedSenderTransferTxBase64 =
        "AAACAAhAQg8AAAAAAAAgu7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7sCAgABAQAAAQEDAAAAAAEBAKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAczMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMBwAAAAAAAAAg3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d2qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqugDAAAAAAAAgPD6AgAAAAAA";
    char sign_transaction_line[768] = {};
    snprintf(
        sign_transaction_line,
        sizeof(sign_transaction_line),
        "{\"id\":\"req_tx_ok\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"txBytes\":\"%s\"}}",
        signing::session_id(),
        kValidSuiTransferTxBase64);
    reset_written();
    send_line(sign_transaction_line);
    expect_no_response();
    pending = protocol_runtime_pending_request();
    assert(pending.kind == PendingRequestKind::sign_transaction);
    assert(strstr(pending.label, "Sui tx") != nullptr);
    assert(strstr(pending.label, "Sender") != nullptr);
    assert(strstr(pending.label, "Gas") != nullptr);
    assert(strstr(pending.label, "Cmds") != nullptr);
    reset_written();
    assert(protocol_runtime_approve_pending_request());
    expect_written_contains("\"id\":\"req_tx_ok\"");
    expect_written_contains("\"method\":\"sign_transaction\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"authorization\":\"user\"");
    expect_written_not_contains("\"messageBytes\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    reset_written();
    send_line(sign_transaction_line);
    expect_written_contains("\"id\":\"req_tx_ok\"");
    expect_written_contains("\"method\":\"sign_transaction\"");
    expect_written_contains("\"success\":true");
    expect_written_not_contains("\"messageBytes\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    char mismatched_sender_line[768] = {};
    snprintf(
        mismatched_sender_line,
        sizeof(mismatched_sender_line),
        "{\"id\":\"req_tx_account_mismatch\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"txBytes\":\"%s\"}}",
        signing::session_id(),
        kMismatchedSenderTransferTxBase64);
    reset_written();
    send_line(mismatched_sender_line);
    expect_written_contains("\"id\":\"req_tx_account_mismatch\"");
    expect_written_contains("\"method\":\"sign_transaction\"");
    expect_written_contains("\"code\":\"account_unavailable\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    char wrong_network_transaction_line[768] = {};
    snprintf(
        wrong_network_transaction_line,
        sizeof(wrong_network_transaction_line),
        "{\"id\":\"req_tx_wrong_network\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"devnet\",\"txBytes\":\"%s\"}}",
        signing::session_id(),
        kValidSuiTransferTxBase64);
    reset_written();
    send_line(wrong_network_transaction_line);
    expect_written_contains("\"id\":\"req_tx_wrong_network\"");
    expect_written_contains("\"method\":\"sign_transaction\"");
    expect_written_contains("\"code\":\"invalid_params\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    char malformed_transaction_line[512] = {};
    snprintf(
        malformed_transaction_line,
        sizeof(malformed_transaction_line),
        "{\"id\":\"req_tx_bad\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"txBytes\":\"AA==\"}}",
        signing::session_id());
    reset_written();
    send_line(malformed_transaction_line);
    expect_written_contains("\"id\":\"req_tx_bad\"");
    expect_written_contains("\"method\":\"sign_transaction\"");
    expect_written_contains("\"code\":\"malformed_transaction\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    reset_written();
    send_line(sign_personal_line);
    expect_written_contains("\"id\":\"req_sign_ok\"");
    expect_written_contains("\"method\":\"sign_personal_message\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"messageBytes\":\"aGk=\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    char retained_get_line[256] = {};
    snprintf(
        retained_get_line,
        sizeof(retained_get_line),
        "{\"id\":\"req_get_result\",\"version\":1,\"method\":\"get_result\",\"sessionId\":\"%s\",\"payload\":{\"retainedRequestId\":\"req_sign_ok\"}}",
        signing::session_id());
    reset_written();
    send_line(retained_get_line);
    expect_written_contains("\"id\":\"req_get_result\"");
    expect_written_contains("\"method\":\"get_result\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"messageBytes\":\"aGk=\"");

    char retained_ack_line[256] = {};
    snprintf(
        retained_ack_line,
        sizeof(retained_ack_line),
        "{\"id\":\"req_ack_result\",\"version\":1,\"method\":\"ack_result\",\"sessionId\":\"%s\",\"payload\":{\"retainedRequestId\":\"req_sign_ok\"}}",
        signing::session_id());
    reset_written();
    send_line(retained_ack_line);
    expect_written_contains("\"id\":\"req_ack_result\"");
    expect_written_contains("\"method\":\"ack_result\"");
    expect_written_contains("\"success\":true");

    reset_written();
    send_line(retained_get_line);
    expect_written_contains("\"id\":\"req_get_result\"");
    expect_written_contains("\"method\":\"get_result\"");
    expect_written_contains("\"code\":\"unknown_request\"");

    signing::g_signing_mode = signing::AuthorizationMode::policy;
    signing::g_policy_available = true;
    signing::g_policy_facts_complete = false;
    char policy_transaction_line[768] = {};
    snprintf(
        policy_transaction_line,
        sizeof(policy_transaction_line),
        "{\"id\":\"req_policy_incomplete\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"txBytes\":\"%s\"}}",
        signing::session_id(),
        kValidSuiTransferTxBase64);
    reset_written();
    send_line(policy_transaction_line);
    expect_written_contains("\"id\":\"req_policy_incomplete\"");
    expect_written_contains("\"method\":\"sign_transaction\"");
    expect_written_contains("\"code\":\"policy_rejected\"");
    expect_policy_rejected_notice();
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    signing::g_policy_facts_complete = true;
    signing::g_policy_evaluation_status = signing::CurrentPolicyEvaluationStatus::rejected;
    signing::g_policy_reason_code = "policy_limit";
    snprintf(
        policy_transaction_line,
        sizeof(policy_transaction_line),
        "{\"id\":\"req_policy_rejected\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"txBytes\":\"%s\"}}",
        signing::session_id(),
        kValidSuiTransferTxBase64);
    reset_written();
    send_line(policy_transaction_line);
    expect_written_contains("\"id\":\"req_policy_rejected\"");
    expect_written_contains("\"method\":\"sign_transaction\"");
    expect_written_contains("\"code\":\"policy_rejected\"");
    expect_policy_rejected_notice();
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    char policy_wrong_network_line[768] = {};
    snprintf(
        policy_wrong_network_line,
        sizeof(policy_wrong_network_line),
        "{\"id\":\"req_policy_wrong_network\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"devnet\",\"txBytes\":\"%s\"}}",
        signing::session_id(),
        kValidSuiTransferTxBase64);
    reset_written();
    send_line(policy_wrong_network_line);
    expect_written_contains("\"id\":\"req_policy_wrong_network\"");
    expect_written_contains("\"method\":\"sign_transaction\"");
    expect_written_contains("\"code\":\"invalid_params\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    signing::g_policy_evaluation_status = signing::CurrentPolicyEvaluationStatus::authorized;
    signing::g_policy_reason_code = "policy_authorized";
    snprintf(
        policy_transaction_line,
        sizeof(policy_transaction_line),
        "{\"id\":\"req_policy_signed\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"txBytes\":\"%s\"}}",
        signing::session_id(),
        kValidSuiTransferTxBase64);
    reset_written();
    send_line(policy_transaction_line);
    expect_written_contains("\"id\":\"req_policy_signed\"");
    expect_written_contains("\"method\":\"sign_transaction\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"authorization\":\"policy\"");
    expect_written_not_contains("\"messageBytes\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    reset_written();
    send_line(policy_transaction_line);
    expect_written_contains("\"id\":\"req_policy_signed\"");
    expect_written_contains("\"method\":\"sign_transaction\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"authorization\":\"policy\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    char policy_mismatch_line[768] = {};
    snprintf(
        policy_mismatch_line,
        sizeof(policy_mismatch_line),
        "{\"id\":\"req_policy_account_mismatch\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"txBytes\":\"%s\"}}",
        signing::session_id(),
        kMismatchedSenderTransferTxBase64);
    reset_written();
    send_line(policy_mismatch_line);
    expect_written_contains("\"id\":\"req_policy_account_mismatch\"");
    expect_written_contains("\"method\":\"sign_transaction\"");
    expect_written_contains("\"code\":\"account_unavailable\"");
    expect_written_not_contains("\"success\":true");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    signing::g_signing_mode = signing::AuthorizationMode::user;

    char prepare_again_line[256] = {};
    snprintf(
        prepare_again_line,
        sizeof(prepare_again_line),
        "{\"id\":\"req_prepare_active\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}",
        signing::session_id());
    reset_written();
    send_line(prepare_again_line);
    expect_written_contains("\"id\":\"req_prepare_active\"");
    expect_written_contains("\"code\":\"invalid_state\"");

    char propose_again_line[4096] = {};
    snprintf(
        propose_again_line,
        sizeof(propose_again_line),
        "{\"id\":\"req_propose_active\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"%s\",\"payload\":%s}",
        signing::session_id(),
        payload_json);
    reset_written();
    send_line(propose_again_line);
    expect_written_contains("\"id\":\"req_propose_active\"");
    expect_written_contains("\"code\":\"invalid_state\"");

    send_payload_transfer_sequence(
        signing::session_id(),
        payload_json,
        "transfer_0000000000000002",
        "\"payloadRef\":\"payload_0000000000000002\"");

    char propose_ref_active_line[512] = {};
    snprintf(
        propose_ref_active_line,
        sizeof(propose_ref_active_line),
        "{\"id\":\"req_propose_active_ref\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"%s\",\"payload\":{\"payloadRef\":\"payload_0000000000000002\"}}",
        signing::session_id());
    reset_written();
    send_line(propose_ref_active_line);
    expect_written_contains("\"id\":\"req_propose_active_ref\"");
    expect_written_contains("\"code\":\"invalid_state\"");
    assert(signing::payload_delivery_advance_and_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).state ==
           signing::PayloadDeliveryState::idle);

    char abort_finalized_line[256] = {};
    snprintf(
        abort_finalized_line,
        sizeof(abort_finalized_line),
        "{\"id\":\"req_abort_finalized\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"%s\",\"payloadRef\":\"payload_0000000000000002\"}",
        signing::session_id());
    reset_written();
    send_line(abort_finalized_line);
    expect_written_contains("\"id\":\"req_abort_finalized\"");
    expect_written_contains("\"code\":\"unknown_request\"");
    assert(signing::payload_delivery_advance_and_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).state ==
           signing::PayloadDeliveryState::idle);

    assert(device_reset_all());
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::missing);
    assert(local_auth_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).status ==
           LocalAuthStoreStatus::missing);
    assert(!signing::session_active());
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    reset_written();
    send_line(
        "{\"id\":\"req_status_after_clear\",\"version\":1,\"method\":\"get_status\"}");
    expect_written_contains("\"id\":\"req_status_after_clear\"");
    expect_written_contains("\"method\":\"get_status\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"provisioning\":{\"state\":\"unprovisioned\"}");

    reset_written();
    send_line(accounts_line);
    expect_written_contains("\"id\":\"req_accounts_active\"");
    expect_written_contains("\"code\":\"invalid_state\"");

    reset_written();
    send_line(
        "{\"id\":\"req_connect_after_clear\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"credential-flow-test\"}}");
    expect_written_contains("\"id\":\"req_connect_after_clear\"");
    expect_written_contains("\"code\":\"invalid_state\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);

    configure_current_setup_for_usb_test();
    reset_written();
    send_line(
        "{\"id\":\"req_connect_after_setup\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"credential-flow-test\"}}");
    expect_no_response();
    pending = protocol_runtime_pending_request();
    assert(pending.kind == PendingRequestKind::connect);
    assert(strcmp(pending.id, "req_connect_after_setup") == 0);

    reset_written();
    assert(protocol_runtime_approve_pending_request());
    protocol_runtime_poll();
    expect_written_contains("\"id\":\"req_connect_after_setup\"");
    expect_written_contains("\"method\":\"connect\"");
    expect_written_contains("\"success\":true");
    assert(signing::session_active());

    snprintf(
        caps_line,
        sizeof(caps_line),
        "{\"id\":\"req_caps_after_clear\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"%s\"}",
        signing::session_id());
    reset_written();
    send_line(caps_line);
    expect_written_contains("\"id\":\"req_caps_after_clear\"");
    expect_written_contains("\"method\":\"get_capabilities\"");
    expect_written_contains("\"success\":true");
    expect_written_not_contains("\"signing\"");
    expect_written_contains("\"accounts\":[]");
    expect_written_contains("\"credentials\":[{\"chain\":\"sui\",\"credential\":\"zklogin\",\"operations\":[\"credential_prepare\",\"credential_propose\"]}]");

    char idle_chunk_bad_transfer_line[256] = {};
    snprintf(
        idle_chunk_bad_transfer_line,
        sizeof(idle_chunk_bad_transfer_line),
        "{\"id\":\"req_pt_idle_chunk_bad_transfer\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\",\"sessionId\":\"%s\",\"transferId\":7,\"offsetBytes\":\"0\",\"chunk\":\"AA==\"}",
        signing::session_id());
    reset_written();
    send_line(idle_chunk_bad_transfer_line);
    expect_written_contains("\"id\":\"req_pt_idle_chunk_bad_transfer\"");
    expect_written_contains("\"code\":\"unknown_request\"");

    char idle_finish_bad_transfer_line[256] = {};
    snprintf(
        idle_finish_bad_transfer_line,
        sizeof(idle_finish_bad_transfer_line),
        "{\"id\":\"req_pt_idle_finish_bad_transfer\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"finish\",\"sessionId\":\"%s\",\"transferId\":7}",
        signing::session_id());
    reset_written();
    send_line(idle_finish_bad_transfer_line);
    expect_written_contains("\"id\":\"req_pt_idle_finish_bad_transfer\"");
    expect_written_contains("\"code\":\"unknown_request\"");

    char idle_abort_missing_ref_line[192] = {};
    snprintf(
        idle_abort_missing_ref_line,
        sizeof(idle_abort_missing_ref_line),
        "{\"id\":\"req_pt_idle_abort_missing_ref\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"%s\"}",
        signing::session_id());
    reset_written();
    send_line(idle_abort_missing_ref_line);
    expect_written_contains("\"id\":\"req_pt_idle_abort_missing_ref\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    char too_large_begin_line[512] = {};
    snprintf(
        too_large_begin_line,
        sizeof(too_large_begin_line),
        "{\"id\":\"req_pt_too_large\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"%s\",\"totalBytes\":\"%u\",\"payloadDigest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"}",
        signing::session_id(),
        static_cast<unsigned>(signing::kPayloadDeliveryDefaultMaxBytes + 1));
    reset_written();
    send_line(too_large_begin_line);
    expect_written_contains("\"id\":\"req_pt_too_large\"");
    expect_written_contains("\"code\":\"payload_too_large\"");
    assert(signing::payload_delivery_advance_and_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).state ==
           signing::PayloadDeliveryState::idle);

    create_finalized_payload_for_current_session(payload_json);
    char finalized_begin_bad_size_line[512] = {};
    snprintf(
        finalized_begin_bad_size_line,
        sizeof(finalized_begin_bad_size_line),
        "{\"id\":\"req_pt_finalized_begin_bad_size\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"%s\",\"totalBytes\":7,\"payloadDigest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"}",
        signing::session_id());
    reset_written();
    send_line(finalized_begin_bad_size_line);
    expect_written_contains("\"id\":\"req_pt_finalized_begin_bad_size\"");
    expect_written_contains("\"code\":\"busy\"");

    char finalized_chunk_bad_transfer_line[256] = {};
    snprintf(
        finalized_chunk_bad_transfer_line,
        sizeof(finalized_chunk_bad_transfer_line),
        "{\"id\":\"req_pt_finalized_chunk_bad_transfer\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\",\"sessionId\":\"%s\",\"transferId\":7,\"offsetBytes\":\"0\",\"chunk\":\"AA==\"}",
        signing::session_id());
    reset_written();
    send_line(finalized_chunk_bad_transfer_line);
    expect_written_contains("\"id\":\"req_pt_finalized_chunk_bad_transfer\"");
    expect_written_contains("\"code\":\"busy\"");

    g_now_us += static_cast<int64_t>(signing::kPayloadDeliveryMaxWindowMs + 1) * 1000;
    snprintf(
        caps_line,
        sizeof(caps_line),
        "{\"id\":\"req_caps_clears_expired_payload\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"%s\"}",
        signing::session_id());
    reset_written();
    send_line(caps_line);
    expect_written_contains("\"id\":\"req_caps_clears_expired_payload\"");
    expect_written_contains("\"method\":\"get_capabilities\"");
    expect_written_contains("\"success\":true");
    assert(signing::payload_delivery_advance_and_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).state ==
           signing::PayloadDeliveryState::idle);

    char prepare_after_clear_line[256] = {};
    snprintf(
        prepare_after_clear_line,
        sizeof(prepare_after_clear_line),
        "{\"id\":\"req_prepare_after_clear\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}",
        signing::session_id());
    reset_written();
    send_line(prepare_after_clear_line);
    expect_written_contains("\"id\":\"req_prepare_after_clear\"");
    expect_written_contains("\"method\":\"credential_prepare\"");
    expect_written_contains("\"success\":true");

    char propose_missing_fields_line[256] = {};
    snprintf(
        propose_missing_fields_line,
        sizeof(propose_missing_fields_line),
        "{\"id\":\"req_propose_missing_fields\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}",
        signing::session_id());
    reset_written();
    send_line(propose_missing_fields_line);
    expect_written_contains("\"id\":\"req_propose_missing_fields\"");
    expect_written_contains("\"code\":\"invalid_params\"");
    assert(!sui_zklogin_proposal_state_active());

    char invalid_payload_json[2048] = {};
    build_invalid_network_payload_json(invalid_payload_json, sizeof(invalid_payload_json));
    send_payload_transfer_sequence(
        signing::session_id(),
        invalid_payload_json,
        "transfer_0000000000000002",
        "\"payloadRef\":\"payload_0000000000000002\"");

    char invalid_propose_line[512] = {};
    snprintf(
        invalid_propose_line,
        sizeof(invalid_propose_line),
        "{\"id\":\"req_propose_invalid_proof\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"%s\",\"payload\":{\"payloadRef\":\"payload_0000000000000002\"}}",
        signing::session_id());
    protocol_runtime_set_state(ProtocolRuntimeState{
        LocalAuthProjectionStatus::active,
        false,
        false,
    });
    reset_written();
    send_line(invalid_propose_line);
    expect_written_contains("\"id\":\"req_propose_invalid_proof\"");
    expect_written_contains("\"method\":\"credential_propose\"");
    expect_written_contains("\"code\":\"auth_unavailable\"");
    assert(signing::payload_delivery_advance_and_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).state ==
           signing::PayloadDeliveryState::idle);

    protocol_runtime_set_state(ProtocolRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });
    send_payload_transfer_sequence(
        signing::session_id(),
        invalid_payload_json,
        "transfer_0000000000000003",
        "\"payloadRef\":\"payload_0000000000000003\"");
    snprintf(
        invalid_propose_line,
        sizeof(invalid_propose_line),
        "{\"id\":\"req_propose_invalid_proof_retry\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"%s\",\"payload\":{\"payloadRef\":\"payload_0000000000000003\"}}",
        signing::session_id());
    reset_written();
    send_line(invalid_propose_line);
    expect_written_contains("\"id\":\"req_propose_invalid_proof_retry\"");
    expect_written_contains("\"method\":\"credential_propose\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"status\":\"invalid_proof\"");
    expect_written_contains("\"reasonCode\":\"invalid_proof\"");
    expect_written_contains("\"sessionEnded\":false");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);
    assert(!credential_preparation_snapshot().active);
    assert(!sui_zklogin_proposal_state_active());
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::missing);
    assert(signing::payload_delivery_advance_and_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).state ==
           signing::PayloadDeliveryState::idle);

    char prepare_consistency_line[256] = {};
    snprintf(
        prepare_consistency_line,
        sizeof(prepare_consistency_line),
        "{\"id\":\"req_prepare_consistency\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}",
        signing::session_id());
    reset_written();
    send_line(prepare_consistency_line);
    expect_written_contains("\"id\":\"req_prepare_consistency\"");
    expect_written_contains("\"method\":\"credential_prepare\"");
    expect_written_contains("\"success\":true");

    char consistency_payload_json[2048] = {};
    build_valid_payload_json(consistency_payload_json, sizeof(consistency_payload_json));
    send_payload_transfer_sequence(
        signing::session_id(),
        consistency_payload_json,
        "transfer_0000000000000004",
        "\"payloadRef\":\"payload_0000000000000004\"");

    char consistency_propose_line[512] = {};
    snprintf(
        consistency_propose_line,
        sizeof(consistency_propose_line),
        "{\"id\":\"req_propose_consistency\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"%s\",\"payload\":{\"payloadRef\":\"payload_0000000000000004\"}}",
        signing::session_id());
    reset_written();
    send_line(consistency_propose_line);
    expect_no_response();
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::credential_propose);
    assert(sui_zklogin_proposal_state_active());

    reset_written();
    assert(protocol_runtime_reject_pending_request("auth_unavailable"));
    expect_written_contains("\"id\":\"req_propose_consistency\"");
    expect_written_contains("\"method\":\"credential_propose\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"status\":\"consistency_error\"");
    expect_written_contains("\"reasonCode\":\"consistency_error\"");
    expect_written_contains("\"sessionEnded\":true");
    expect_written_not_contains("\"code\":\"auth_unavailable\"");
    assert(protocol_runtime_pending_request().kind == PendingRequestKind::none);
    assert(!credential_preparation_snapshot().active);
    assert(!sui_zklogin_proposal_state_active());
    assert(!signing::session_active());
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::missing);

    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${MICROSUI_CORE}" \
  -c "${MICROSUI_CORE}/byte_conversions.c" \
  -o "${TMP_DIR}/byte_conversions.o"
"${CC_BIN}" -std=c99 -I"${MICROSUI_CORE}" \
  -c "${MICROSUI_CORE}/key_management.c" \
  -o "${TMP_DIR}/key_management.o"
"${CC_BIN}" -std=c99 -I"${MICROSUI_CORE}" \
  -c "${MICROSUI_CORE}/lib/monocypher/monocypher.c" \
  -o "${TMP_DIR}/monocypher.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror -Wno-unused-variable -ffunction-sections -fdata-sections \
  -DSTOPWATCH_ZKLOGIN_CREDENTIAL_STORE_HOST_TEST \
  -DSTOPWATCH_LOCAL_AUTH_HOST_TEST \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_DIR}" \
  -I"${MICROSUI_CORE}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/protocol_runtime_credential_flow_test.cpp" \
  "${RUNTIME_DIR}/credential_preparation_state.cpp" \
  "${RUNTIME_DIR}/local_auth.cpp" \
  "${COMMON_DIR}/transport/payload_delivery_store.cpp" \
  "${RUNTIME_DIR}/protocol_input_encoding.cpp" \
  "${COMMON_DIR}/protocol/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/state_projection.cpp" \
  "${RUNTIME_DIR}/device_reset.cpp" \
  "${RUNTIME_DIR}/sui_public_material.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_credential_store.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_proposal_state.cpp" \
  "${COMMON_DIR}/protocol/base64.cpp" \
  "${COMMON_DIR}/protocol/device_contract.cpp" \
  "${COMMON_DIR}/protocol/device_response.cpp" \
  "${COMMON_DIR}/protocol/request_id.cpp" \
  "${COMMON_DIR}/protocol/request_line.cpp" \
  "${COMMON_DIR}/protocol/sign_request_identity.cpp" \
  "${COMMON_DIR}/protocol/signing_response_store.cpp" \
  "${COMMON_DIR}/protocol/approval_history_handler.cpp" \
  "${COMMON_DIR}/protocol/device_handlers.cpp" \
  "${COMMON_DIR}/protocol/json_response.cpp" \
  "${COMMON_DIR}/protocol/operation_dispatch.cpp" \
  "${COMMON_DIR}/protocol/operation_manifest.cpp" \
  "${COMMON_DIR}/protocol/operation_type.cpp" \
  "${COMMON_DIR}/protocol/request_envelope.cpp" \
  "${COMMON_DIR}/protocol/request_line_handler.cpp" \
  "${COMMON_DIR}/protocol/session_read_handlers.cpp" \
  "${COMMON_DIR}/protocol/sui_zklogin_credential_handlers.cpp" \
  "${COMMON_DIR}/policy/policy_handlers.cpp" \
  "${COMMON_DIR}/protocol/active_session_request_guard.cpp" \
  "${COMMON_DIR}/signing/policy_signing_execution_result.cpp" \
  "${COMMON_DIR}/signing/sign_personal_message_user_ingress.cpp" \
  "${COMMON_DIR}/signing/sign_personal_message_user_validation.cpp" \
  "${COMMON_DIR}/signing/sign_transaction_user_ingress.cpp" \
  "${COMMON_DIR}/signing/sign_transaction_user_validation.cpp" \
	  "${COMMON_DIR}/signing/sign_transaction_policy_runtime.cpp" \
	  "${COMMON_DIR}/signing/signing_preflight.cpp" \
	  "${COMMON_DIR}/signing/signing_retry_response.cpp" \
	  "${COMMON_DIR}/signing/signing_retry_delivery.cpp" \
	  "${COMMON_DIR}/signing/signing_handlers.cpp" \
	  "${COMMON_DIR}/signing/signing_outcome_writer.cpp" \
	  "${COMMON_DIR}/signing/protocol_transport_loss.cpp" \
	  "${COMMON_DIR}/signing/user_signing_critical_section.cpp" \
  "${COMMON_DIR}/signing/user_signing_flow.cpp" \
  "${COMMON_DIR}/sui/bcs_reader.cpp" \
  "${COMMON_DIR}/sui/account_binding.cpp" \
  "${COMMON_DIR}/sui/sign_transaction_adapter.cpp" \
  "${COMMON_DIR}/sui/signing_preparation.cpp" \
  "${COMMON_DIR}/sui/signing_payload.cpp" \
  "${COMMON_DIR}/sui/transaction_facts.cpp" \
  "${COMMON_DIR}/sui/zklogin_credential_outcome.cpp" \
  "${COMMON_DIR}/sui/zklogin_credential_payload.cpp" \
  "${COMMON_DIR}/sui/zklogin_proof_payload.cpp" \
  "${COMMON_DIR}/sui/zklogin_proof_record.cpp" \
  "${COMMON_DIR}/transport/connect_approval.cpp" \
  "${COMMON_DIR}/transport/connect_review_response_flow.cpp" \
  "${COMMON_DIR}/transport/payload_delivery_admission.cpp" \
  "${COMMON_DIR}/transport/payload_delivery_primitives.cpp" \
  "${COMMON_DIR}/transport/payload_delivery_resolution.cpp" \
  "${COMMON_DIR}/transport/connect_handler.cpp" \
  "${COMMON_DIR}/transport/disconnect_handler.cpp" \
  "${COMMON_DIR}/transport/payload_transfer_handlers.cpp" \
  "${COMMON_DIR}/transport/retained_response_handlers.cpp" \
  "${COMMON_DIR}/transport/usb_link_state.cpp" \
  "${COMMON_DIR}/transport/usb_session_grace.cpp" \
  "${TMP_DIR}/byte_conversions.o" \
  "${TMP_DIR}/key_management.o" \
  "${TMP_DIR}/monocypher.o" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -Wl,-dead_strip \
  -o "${TMP_DIR}/protocol_runtime_credential_flow_test"

"${TMP_DIR}/protocol_runtime_credential_flow_test"
echo "StopWatch protocol runtime credential flow tests passed"
