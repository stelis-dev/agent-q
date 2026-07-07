#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
IDF_PATH="${FIRMWARE_IDF_PATH:-${REPO_ROOT}/.WORK/toolchains/esp-idf-v5.5.4}"
MBEDTLS_ROOT="${IDF_PATH}/components/mbedtls/mbedtls"
MBEDTLS_INCLUDE_DIR="${MBEDTLS_ROOT}/include"
MBEDTLS_LIBRARY_DIR="${MBEDTLS_ROOT}/library"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stopwatch-esp32s3/M5StopWatch-UserDemo/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${MBEDTLS_INCLUDE_DIR}/mbedtls/sha256.h" \
  "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  "${RUNTIME_DIR}/usb_transport.cpp" \
  "${COMMON_ROOT}/protocol/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/state_projection.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_response.cpp" \
  "${COMMON_ROOT}/protocol/base64.cpp" \
  "${COMMON_ROOT}/protocol/request_line.cpp" \
  "${COMMON_ROOT}/protocol/request_id.cpp" \
  "${COMMON_ROOT}/protocol/signing_response_store.cpp" \
  "${COMMON_ROOT}/protocol/usb_active_session_request_guard.cpp" \
  "${COMMON_ROOT}/protocol/usb_active_session_request_guard.h" \
  "${COMMON_ROOT}/protocol/usb_sui_zklogin_credential_handlers.cpp" \
  "${COMMON_ROOT}/protocol/usb_sui_zklogin_credential_handlers.h" \
  "${COMMON_ROOT}/policy/usb_policy_handlers.cpp" \
  "${COMMON_ROOT}/policy/usb_policy_handlers.h" \
  "${COMMON_ROOT}/signing/policy_signing_execution_result.cpp" \
  "${COMMON_ROOT}/signing/sign_personal_message_user_ingress.cpp" \
  "${COMMON_ROOT}/signing/sign_personal_message_user_validation.cpp" \
  "${COMMON_ROOT}/signing/sign_transaction_user_ingress.cpp" \
  "${COMMON_ROOT}/signing/sign_transaction_user_validation.cpp" \
	  "${COMMON_ROOT}/signing/sign_transaction_policy_runtime.cpp" \
	  "${COMMON_ROOT}/signing/signing_preflight.cpp" \
	  "${COMMON_ROOT}/signing/signing_retry_response.cpp" \
	  "${COMMON_ROOT}/signing/signing_retry_delivery.cpp" \
	  "${COMMON_ROOT}/signing/usb_signing_handlers.cpp" \
	  "${COMMON_ROOT}/signing/usb_signing_outcome_writer.cpp" \
	  "${COMMON_ROOT}/signing/user_signing_critical_section.cpp" \
  "${COMMON_ROOT}/signing/user_signing_flow.cpp" \
  "${COMMON_ROOT}/policy/evaluator.h" \
  "${COMMON_ROOT}/sui/offline_policy_facts.h" \
  "${COMMON_ROOT}/sui/bcs_reader.cpp" \
  "${COMMON_ROOT}/sui/account_binding.cpp" \
  "${COMMON_ROOT}/sui/sign_transaction_adapter.cpp" \
  "${COMMON_ROOT}/sui/signing_preparation.cpp" \
  "${COMMON_ROOT}/sui/signing_payload.cpp" \
  "${COMMON_ROOT}/sui/transaction_facts.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_admission.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_primitives.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_resolution.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_store.cpp" \
  "${COMMON_ROOT}/transport/connect_approval.cpp" \
  "${COMMON_ROOT}/transport/connect_approval.h" \
  "${COMMON_ROOT}/transport/connect_review_response_flow.cpp" \
  "${COMMON_ROOT}/transport/connect_review_response_flow.h" \
  "${COMMON_ROOT}/transport/usb_connect_handler.cpp" \
  "${COMMON_ROOT}/transport/usb_disconnect_handler.cpp" \
  "${COMMON_ROOT}/transport/usb_payload_transfer_handlers.cpp" \
  "${COMMON_ROOT}/transport/usb_retained_response_handlers.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_outcome.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_payload.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_outcome.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stopwatch-esp32s3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-usb-transport-cleanup.XXXXXX")"
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

cat >"${TMP_DIR}/byte_conversions.h" <<'H'
#pragma once
#include <stddef.h>
#include <stdint.h>
int bytes_to_base64(const uint8_t* input, size_t input_size, char* output, size_t output_size);
int base64_to_bytes(const char* input, size_t input_size, uint8_t* output, size_t output_size);
H

cat >"${TMP_DIR}/firmware_common/protocol/request_id.h" <<H
#pragma once
#include "${COMMON_ROOT}/protocol/request_id.h"
H

cat >"${TMP_DIR}/usb_transport_session_cleanup_test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "esp_err.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "policy/evaluator.h"
#include "transport/payload_delivery_store.h"
#include "sui_zklogin_credential_store.h"

namespace {
char g_written[4096] = {};
size_t g_written_size = 0;
bool g_usb_connected = true;
uint32_t g_now_ms = 0;
stopwatch_target::SuiZkLoginCredentialStatus g_credential_status =
    stopwatch_target::SuiZkLoginCredentialStatus::missing;
}

esp_err_t usb_serial_jtag_driver_install(const usb_serial_jtag_driver_config_t*)
{
    return ESP_OK;
}

bool usb_serial_jtag_is_connected(void)
{
    return g_usb_connected;
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
    return static_cast<int64_t>(g_now_ms) * 1000;
}

extern "C" {

int bytes_to_base64(const uint8_t*, size_t, char* output, size_t output_size)
{
    if (output == nullptr || output_size < 5) {
        return -1;
    }
    snprintf(output, output_size, "AA==");
    return 0;
}

int base64_to_bytes(const char*, size_t, uint8_t* output, size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return -1;
    }
    output[0] = 0;
    return 0;
}

}  // extern "C"

#include "usb_transport.cpp"

namespace signing {

bool sign_request_identity(
    SupportedSignRoute,
    const char*,
    const char*,
    uint8_t* output,
    size_t output_size)
{
    if (output == nullptr || output_size != kSignRequestIdentitySize) {
        return false;
    }
    memset(output, 0x5a, output_size);
    return true;
}

const char* authorization_mode_name(AuthorizationMode mode)
{
    return mode == AuthorizationMode::policy ? "policy" : "user";
}

bool read_signing_authorization_mode(AuthorizationMode* mode)
{
    if (mode != nullptr) {
        *mode = AuthorizationMode::user;
    }
    return mode != nullptr;
}

AuthorizationModeStatus authorization_mode_status()
{
    return AuthorizationModeStatus::active;
}

bool read_active_policy_document(StoredPolicyDocument*)
{
    return false;
}

bool read_active_policy_summary(StoredPolicySummary* output)
{
    if (output == nullptr) {
        return false;
    }
    snprintf(output->policy_id, sizeof(output->policy_id), "%s", "policy-test");
    return true;
}

PolicyStoreStatus active_policy_status()
{
    return PolicyStoreStatus::active;
}

bool policy_store_write_policy_json(JsonObject, const StoredPolicyDocument&)
{
    return false;
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
    output->completeness = SuiOfflinePolicyFactsCompleteness::complete;
    return SuiTransactionFactsResult::ok;
}

CurrentPolicyEvaluationResult evaluate_current_policy_for_sui_sign_transaction(
    const CurrentPolicyDocument&,
    const char*,
    const SuiOfflinePolicyConditionFacts&)
{
    return CurrentPolicyEvaluationResult{
        CurrentPolicyEvaluationStatus::authorized,
        "policy_authorized",
        "rule-1",
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
    return ApprovalHistoryReadResult::ok;
}

bool approval_history_write_page_json(JsonObject result, const ApprovalHistoryPage& page)
{
    result["records"].to<JsonArray>();
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

ApprovalHistoryStorageStatus approval_history_status()
{
    return ApprovalHistoryStorageStatus::missing;
}

bool policy_update_flow_active()
{
    return false;
}

void policy_update_flow_clear() {}

PolicyUpdateMarkerStatus policy_update_marker_status()
{
    return PolicyUpdateMarkerStatus::clear;
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

int g_credential_preparation_clear_calls = 0;
int g_sui_zklogin_proposal_clear_calls = 0;

void credential_preparation_state_clear()
{
    g_credential_preparation_clear_calls += 1;
}

SuiZkLoginCredentialStatus sui_zklogin_credential_status()
{
    return g_credential_status;
}
SuiZkLoginAccountProjection sui_zklogin_account_projection()
{
    return {};
}
bool validate_sui_zklogin_credential_record(const SuiZkLoginCredentialRecord*)
{
    return false;
}
SuiZkLoginCredentialStatus read_sui_zklogin_credential(SuiZkLoginCredentialRecord*)
{
    return SuiZkLoginCredentialStatus::missing;
}
SuiZkLoginCredentialWriteResult store_sui_zklogin_credential(const SuiZkLoginCredentialRecord*)
{
    return SuiZkLoginCredentialWriteResult::storage_error;
}
bool wipe_sui_zklogin_credential()
{
    return true;
}
CredentialPreparationBeginResult credential_preparation_begin(
    const char*,
    CredentialPreparationRandomFn,
    void*)
{
    return CredentialPreparationBeginResult::rng_error;
}
CredentialPreparationSnapshot credential_preparation_snapshot()
{
    return {};
}
bool credential_preparation_copy_seed_for_session(
    const char*,
    uint8_t[kSuiEd25519SeedBytes])
{
    return false;
}

bool secure_random_fill(void*, size_t)
{
    return false;
}
bool decode_canonical_base64_input(const char*, size_t, uint8_t*, size_t, size_t*)
{
    return false;
}
void sui_zklogin_proposal_state_clear()
{
    g_sui_zklogin_proposal_clear_calls += 1;
}
bool sui_zklogin_proposal_state_active()
{
    return false;
}
SuiZkLoginProposalSnapshot sui_zklogin_proposal_state_snapshot()
{
    return {};
}
SuiZkLoginProposalBeginResult sui_zklogin_proposal_state_begin(
    JsonVariantConst,
    const char*,
    const char*,
    uint32_t,
    signing::TimeoutWindow,
    const uint8_t[kSuiEd25519SeedBytes])
{
    return SuiZkLoginProposalBeginResult::invalid_proof;
}
SuiZkLoginProposalTransitionResult sui_zklogin_proposal_mark_auth_verifying()
{
    return SuiZkLoginProposalTransitionResult::inactive;
}
bool sui_zklogin_proposal_deadline_reached(uint32_t)
{
    return false;
}
SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_rejected()
{
    return SuiZkLoginProposalTerminalResult::rejected;
}
SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_timed_out()
{
    return SuiZkLoginProposalTerminalResult::timed_out;
}
SuiZkLoginProposalTerminalResult sui_zklogin_proposal_commit()
{
    return SuiZkLoginProposalTerminalResult::invalid_state;
}

}  // namespace stopwatch_target

using namespace stopwatch_target;

namespace {

bool fill_random(void* output, size_t size, void*)
{
    uint8_t* bytes = static_cast<uint8_t*>(output);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = static_cast<uint8_t>(index);
    }
    return true;
}

ArduinoJson::JsonDocument parse_request(const char* line)
{
    ArduinoJson::JsonDocument request;
    const ArduinoJson::DeserializationError error = deserializeJson(request, line);
    assert(!error);
    return request;
}

void handle_request_document(ArduinoJson::JsonDocument& request)
{
    char line[4096] = {};
    const size_t written = serializeJson(request, line, sizeof(line));
    assert(written > 0);
    assert(written < sizeof(line));
    handle_request_line(line);
}

void handle_request_document_as_line(
    const char*,
    const char*,
    ArduinoJson::JsonDocument& request)
{
    handle_request_document(request);
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

void seed_finalized_payload_for_current_session()
{
    constexpr const char* kPayload = "{}";
    char digest[signing::kApprovalHistoryDigestSize] = {};
    assert(signing::approval_history_digest_payload(
        reinterpret_cast<const uint8_t*>(kPayload),
        strlen(kPayload),
        digest,
        sizeof(digest)));
    signing::PayloadDeliveryBeginOutput begin = {};
    assert(signing::payload_delivery_begin(
               g_now_ms,
               signing::PayloadDeliveryBeginInput{
                   signing::session_id(),
                   strlen(kPayload),
                   digest,
                   signing::PayloadDeliveryLimits{
                       signing::kPayloadDeliveryDefaultChunkMaxBytes,
                       signing::kPayloadDeliveryDefaultMaxBytes,
                   },
                   signing::timeout_window_from_deadline(
                       g_now_ms,
                       g_now_ms + signing::payload_delivery_timeout_window_ms_for_size(strlen(kPayload))),
               },
               &begin) == signing::PayloadDeliveryResult::ok);
    size_t received = 0;
    assert(signing::payload_delivery_append_chunk(
               g_now_ms,
               signing::PayloadDeliveryChunkInput{
                   signing::session_id(),
                   begin.transfer_id,
                   0,
                   reinterpret_cast<const uint8_t*>(kPayload),
                   strlen(kPayload),
               },
               &received) == signing::PayloadDeliveryResult::ok);
    assert(received == strlen(kPayload));
    signing::PayloadDeliveryFinishOutput finish = {};
    assert(signing::payload_delivery_finish(
               g_now_ms,
               signing::PayloadDeliveryFinishInput{
                  signing::session_id(),
                  begin.transfer_id,
                  signing::approval_history_digest_payload,
               },
               &finish) == signing::PayloadDeliveryResult::ok);
    assert(signing::payload_delivery_advance_and_snapshot(g_now_ms).state ==
           signing::PayloadDeliveryState::finalized);
}

}  // namespace

int main()
{
    using namespace signing;

    signing::session_init();
    signing::payload_delivery_store_reset();
    assert(signing::session_replace(fill_random, nullptr) == signing::SessionStartResult::ok);
    assert(strcmp(signing::session_id(), "session_0001020304050607") == 0);
    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        true,
    });
    assert(usb_transport_init());

    ArduinoJson::JsonDocument accounts_while_busy = parse_request(
        "{\"id\":\"req_accounts_busy\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session_0001020304050607\"}");
    reset_written();
    handle_get_accounts_request("req_accounts_busy", accounts_while_busy);
    expect_written_contains("\"id\":\"req_accounts_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    ArduinoJson::JsonDocument payload_while_busy = parse_request(
        "{\"id\":\"req_payload_busy\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    reset_written();
    handle_request_document(payload_while_busy);
    expect_written_contains("\"id\":\"req_payload_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });

    seed_finalized_payload_for_current_session();
    ArduinoJson::JsonDocument connect_while_payload_pending = parse_request(
        "{\"id\":\"req_connect_payload_busy\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"core\"}}");
    reset_written();
    handle_connect_request("req_connect_payload_busy", connect_while_payload_pending);
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_connect_payload_busy\"");
    expect_written_contains("\"method\":\"connect\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"sessionId\":\"session_0001020304050607\"");

    signing::session_clear();
    ArduinoJson::JsonDocument connect_without_session_while_payload_pending = parse_request(
        "{\"id\":\"req_connect_payload_no_session_busy\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"core\"}}");
    reset_written();
    handle_connect_request("req_connect_payload_no_session_busy", connect_without_session_while_payload_pending);
    assert(!signing::session_active());
    expect_written_contains("\"id\":\"req_connect_payload_no_session_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    assert(signing::session_replace(fill_random, nullptr) == signing::SessionStartResult::ok);
    ArduinoJson::JsonDocument propose_while_payload_pending = parse_request(
        "{\"id\":\"req_propose_payload_busy\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"unexpected\":true}}");
    reset_written();
    handle_credential_propose_request("req_propose_payload_busy", propose_while_payload_pending);
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_propose_payload_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_identify_payload_busy\",\"version\":1,\"method\":\"identify_device\",\"payload\":{\"code\":\"1234\"}}");
    expect_written_contains("\"id\":\"req_identify_payload_busy\"");
    expect_written_contains("\"code\":\"busy\"");
    assert(!usb_transport_identification_display().active);

    ArduinoJson::JsonDocument policy_get_while_payload_pending = parse_request(
        "{\"id\":\"req_policy_get_payload_pending\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":\"session_0001020304050607\"}");
    reset_written();
    handle_request_document_as_line(
        "req_policy_get_payload_pending",
        "policy_get",
        policy_get_while_payload_pending);
    expect_written_contains("\"id\":\"req_policy_get_payload_pending\"");
    expect_written_contains("\"code\":\"policy_unavailable\"");

    ArduinoJson::JsonDocument history_while_payload_pending = parse_request(
        "{\"id\":\"req_history_payload_pending\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"limit\":1}}");
    reset_written();
    handle_request_document_as_line(
        "req_history_payload_pending",
        "get_approval_history",
        history_while_payload_pending);
    expect_written_contains("\"id\":\"req_history_payload_pending\"");
    expect_written_contains("\"method\":\"get_approval_history\"");
    expect_written_contains("\"success\":true");

    ArduinoJson::JsonDocument history_bad_limit = parse_request(
        "{\"id\":\"req_history_bad_limit\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"limit\":0}}");
    reset_written();
    handle_request_document_as_line(
        "req_history_bad_limit",
        "get_approval_history",
        history_bad_limit);
    expect_written_contains("\"id\":\"req_history_bad_limit\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument history_bad_before = parse_request(
        "{\"id\":\"req_history_bad_before\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"beforeSeq\":\"not-number\"}}");
    reset_written();
    handle_request_document_as_line(
        "req_history_bad_before",
        "get_approval_history",
        history_bad_before);
    expect_written_contains("\"id\":\"req_history_bad_before\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument get_result_while_payload_pending = parse_request(
        "{\"id\":\"req_get_result_payload_pending\",\"version\":1,\"method\":\"get_result\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"retainedRequestId\":\"req_retained\"}}");
    reset_written();
    handle_request_document_as_line(
        "req_get_result_payload_pending",
        "get_result",
        get_result_while_payload_pending);
    expect_written_contains("\"id\":\"req_get_result_payload_pending\"");
    expect_written_contains("\"code\":\"unknown_request\"");

    ArduinoJson::JsonDocument ack_result_while_payload_pending = parse_request(
        "{\"id\":\"req_ack_result_payload_pending\",\"version\":1,\"method\":\"ack_result\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"retainedRequestId\":\"req_retained\"}}");
    reset_written();
    handle_request_document_as_line(
        "req_ack_result_payload_pending",
        "ack_result",
        ack_result_while_payload_pending);
    expect_written_contains("\"id\":\"req_ack_result_payload_pending\"");
    expect_written_contains("\"method\":\"ack_result\"");
    expect_written_contains("\"success\":true");

    ArduinoJson::JsonDocument get_result_bad_payload = parse_request(
        "{\"id\":\"req_get_result_bad_payload\",\"version\":1,\"method\":\"get_result\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"retainedRequestId\":\"bad id\"}}");
    reset_written();
    handle_request_document_as_line(
        "req_get_result_bad_payload",
        "get_result",
        get_result_bad_payload);
    expect_written_contains("\"id\":\"req_get_result_bad_payload\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument ack_result_bad_payload = parse_request(
        "{\"id\":\"req_ack_result_bad_payload\",\"version\":1,\"method\":\"ack_result\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"retainedRequestId\":\"bad id\"}}");
    reset_written();
    handle_request_document_as_line(
        "req_ack_result_bad_payload",
        "ack_result",
        ack_result_bad_payload);
    expect_written_contains("\"id\":\"req_ack_result_bad_payload\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument policy_propose_while_payload_pending = parse_request(
        "{\"id\":\"req_policy_propose_payload_busy\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"policy\":{}}}");
    reset_written();
    handle_request_document_as_line(
        "req_policy_propose_payload_busy",
        "policy_propose",
        policy_propose_while_payload_pending);
    expect_written_contains("\"id\":\"req_policy_propose_payload_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    ArduinoJson::JsonDocument sign_transaction_while_payload_pending = parse_request(
        "{\"id\":\"req_sign_tx_payload_busy\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"txBytes\":\"AA==\"}}");
    reset_written();
    handle_request_document_as_line(
        "req_sign_tx_payload_busy",
        "sign_transaction",
        sign_transaction_while_payload_pending);
    expect_written_contains("\"id\":\"req_sign_tx_payload_busy\"");
    expect_written_contains("\"code\":\"account_unavailable\"");

    ArduinoJson::JsonDocument sign_message_while_payload_pending = parse_request(
        "{\"id\":\"req_sign_msg_payload_busy\",\"version\":1,\"method\":\"sign_personal_message\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"message\":\"AA==\"}}");
    reset_written();
    handle_request_document_as_line(
        "req_sign_msg_payload_busy",
        "sign_personal_message",
        sign_message_while_payload_pending);
    expect_written_contains("\"id\":\"req_sign_msg_payload_busy\"");
    expect_written_contains("\"code\":\"account_unavailable\"");

    signing::payload_delivery_clear_all();

    ArduinoJson::JsonDocument policy_propose_valid_wrapper = parse_request(
        "{\"id\":\"req_policy_propose_unavailable\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"policy\":{}}}");
    reset_written();
    handle_request_document_as_line(
        "req_policy_propose_unavailable",
        "policy_propose",
        policy_propose_valid_wrapper);
    expect_written_contains("\"id\":\"req_policy_propose_unavailable\"");
    expect_written_contains("\"method\":\"policy_propose\"");
    expect_written_contains("\"status\":\"invalid_policy\"");

    ArduinoJson::JsonDocument policy_propose_bad_payload = parse_request(
        "{\"id\":\"req_policy_propose_bad_payload\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":7}");
    reset_written();
    handle_request_document_as_line(
        "req_policy_propose_bad_payload",
        "policy_propose",
        policy_propose_bad_payload);
    expect_written_contains("\"id\":\"req_policy_propose_bad_payload\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument policy_propose_extra_payload = parse_request(
        "{\"id\":\"req_policy_propose_extra_payload\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"policy\":{},\"extra\":true}}");
    reset_written();
    handle_request_document_as_line(
        "req_policy_propose_extra_payload",
        "policy_propose",
        policy_propose_extra_payload);
    expect_written_contains("\"id\":\"req_policy_propose_extra_payload\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument policy_propose_missing_policy = parse_request(
        "{\"id\":\"req_policy_propose_missing_policy\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{}}");
    reset_written();
    handle_request_document_as_line(
        "req_policy_propose_missing_policy",
        "policy_propose",
        policy_propose_missing_policy);
    expect_written_contains("\"id\":\"req_policy_propose_missing_policy\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument policy_propose_scalar_policy = parse_request(
        "{\"id\":\"req_policy_propose_scalar_policy\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"policy\":7}}");
    reset_written();
    handle_request_document_as_line(
        "req_policy_propose_scalar_policy",
        "policy_propose",
        policy_propose_scalar_policy);
    expect_written_contains("\"id\":\"req_policy_propose_scalar_policy\"");
    expect_written_contains("\"status\":\"invalid_policy\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_identify_bad_code\",\"version\":1,\"method\":\"identify_device\",\"payload\":{\"code\":\"abcd\"}}");
    expect_written_contains("\"id\":\"req_identify_bad_code\"");
    expect_written_contains("\"code\":\"invalid_params\"");
    assert(!usb_transport_identification_display().active);

    reset_written();
    handle_request_line(
        "{\"id\":\"req_identify_extra_payload\",\"version\":1,\"method\":\"identify_device\",\"payload\":{\"code\":\"1234\",\"extra\":1}}");
    expect_written_contains("\"id\":\"req_identify_extra_payload\"");
    expect_written_contains("\"code\":\"invalid_params\"");
    assert(!usb_transport_identification_display().active);

    reset_written();
    handle_request_line(
        "{\"id\":\"req_identify_ok\",\"version\":1,\"method\":\"identify_device\",\"payload\":{\"code\":\"1234\"}}");
    expect_written_contains("\"id\":\"req_identify_ok\"");
    expect_written_contains("\"method\":\"identify_device\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"code\":\"1234\"");
    {
        const UsbIdentificationDisplay identification = usb_transport_identification_display();
        assert(identification.active);
        assert(strcmp(identification.code, "1234") == 0);
    }

    reset_written();
    handle_request_line(
        "{\"id\":\"req_payload_type_non_string\",\"version\":1,\"type\":7,\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_payload_type_non_string\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_payload_missing_version\",\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_payload_missing_version\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_payload_string_version\",\"version\":\"1\",\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_payload_string_version\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_payload_float_version\",\"version\":1.5,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_payload_float_version\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_payload_bool_version\",\"version\":true,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_payload_bool_version\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_payload_type_empty\",\"version\":1,\"type\":\"\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_payload_type_empty\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        false,
        false,
    });

    ArduinoJson::JsonDocument accounts_while_locked = parse_request(
        "{\"id\":\"req_accounts_locked\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session_0001020304050607\"}");
    reset_written();
    handle_get_accounts_request("req_accounts_locked", accounts_while_locked);
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_accounts_locked\"");
    expect_written_contains("\"code\":\"auth_unavailable\"");

    ArduinoJson::JsonDocument prepare_while_locked_without_payload = parse_request(
        "{\"id\":\"req_prepare_locked_no_payload\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"session_0001020304050607\"}");
    reset_written();
    handle_credential_prepare_request("req_prepare_locked_no_payload", prepare_while_locked_without_payload);
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_prepare_locked_no_payload\"");
    expect_written_contains("\"code\":\"auth_unavailable\"");

    ArduinoJson::JsonDocument payload_while_locked = parse_request(
        "{\"id\":\"req_payload_locked\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    reset_written();
    handle_request_document(payload_while_locked);
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_payload_locked\"");
    expect_written_contains("\"code\":\"auth_unavailable\"");

    ArduinoJson::JsonDocument payload_bad_session_while_locked = parse_request(
        "{\"id\":\"req_payload_bad_session_locked\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_badg\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    reset_written();
    handle_request_document(payload_bad_session_while_locked);
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_payload_bad_session_locked\"");
    expect_written_contains("\"code\":\"invalid_session\"");

    ArduinoJson::JsonDocument payload_missing_session_while_locked = parse_request(
        "{\"id\":\"req_payload_missing_session_locked\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    reset_written();
    handle_request_document(payload_missing_session_while_locked);
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_payload_missing_session_locked\"");
    expect_written_contains("\"code\":\"invalid_session\"");

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::missing,
        false,
        false,
    });
    ArduinoJson::JsonDocument payload_bad_session_while_unprovisioned = parse_request(
        "{\"id\":\"req_payload_bad_session_unprovisioned\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_badg\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    reset_written();
    handle_request_document(payload_bad_session_while_unprovisioned);
    expect_written_contains("\"id\":\"req_payload_bad_session_unprovisioned\"");
    expect_written_contains("\"code\":\"invalid_session\"");

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });
    assert(signing::session_replace(fill_random, nullptr) == signing::SessionStartResult::ok);
    ArduinoJson::JsonDocument payload_bad_session_while_unlocked = parse_request(
        "{\"id\":\"req_payload_bad_session_unlocked\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_badg\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    reset_written();
    handle_request_document(payload_bad_session_while_unlocked);
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_payload_bad_session_unlocked\"");
    expect_written_contains("\"code\":\"invalid_session\"");

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        false,
        false,
    });
    ArduinoJson::JsonDocument connect_while_locked_with_session = parse_request(
        "{\"id\":\"req_connect_locked_session\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"core\"}}");
    reset_written();
    handle_connect_request("req_connect_locked_session", connect_while_locked_with_session);
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_connect_locked_session\"");
    expect_written_contains("\"method\":\"connect\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"sessionId\":\"session_0001020304050607\"");

    g_credential_status = SuiZkLoginCredentialStatus::storage_error;
    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });
    ArduinoJson::JsonDocument connect_credential_error_with_session = parse_request(
        "{\"id\":\"req_connect_credential_error\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"core\"}}");
    reset_written();
    handle_connect_request("req_connect_credential_error", connect_credential_error_with_session);
    assert(!signing::session_active());
    expect_written_contains("\"id\":\"req_connect_credential_error\"");
    expect_written_contains("\"code\":\"invalid_state\"");

    assert(signing::session_replace(fill_random, nullptr) == signing::SessionStartResult::ok);
    g_credential_status = SuiZkLoginCredentialStatus::missing;
    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::storage_error,
        true,
        false,
    });
    ArduinoJson::JsonDocument connect_auth_storage_error_without_payload = parse_request(
        "{\"id\":\"req_connect_auth_storage_error\",\"version\":1,\"method\":\"connect\"}");
    reset_written();
    handle_connect_request("req_connect_auth_storage_error", connect_auth_storage_error_without_payload);
    assert(!signing::session_active());
    expect_written_contains("\"id\":\"req_connect_auth_storage_error\"");
    expect_written_contains("\"code\":\"invalid_state\"");

    assert(signing::session_replace(fill_random, nullptr) == signing::SessionStartResult::ok);
    reset_written();
    handle_request_line(
        "{\"id\":\"req_connect_extra_storage_error\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"core\"},\"extra\":1}");
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_connect_extra_storage_error\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_connect_no_payload_storage_error\",\"version\":1,\"method\":\"connect\"}");
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_connect_no_payload_storage_error\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        false,
        false,
    });

    reset_written();
    handle_request_line(
        "{\"id\":\"req_prepare_locked_no_session\",\"version\":1,\"method\":\"credential_prepare\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_prepare_locked_no_session\"");
    expect_written_contains("\"code\":\"invalid_session\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_status_forbidden_session\",\"version\":1,\"method\":\"get_status\",\"sessionId\":\"session_0001020304050607\"}");
    assert(signing::session_active());
    expect_written_contains("\"id\":\"req_status_forbidden_session\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    ArduinoJson::JsonDocument disconnect_while_locked = parse_request(
        "{\"id\":\"req_disconnect_locked\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session_0001020304050607\"}");
    reset_written();
    handle_disconnect_request("req_disconnect_locked", disconnect_while_locked);
    assert(!signing::session_active());
    expect_written_contains("\"id\":\"req_disconnect_locked\"");
    expect_written_contains("\"success\":true");

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });

    assert(signing::connect_approval_begin(
        "req_connect_pending_owner",
        "core",
        1,
        {1, 100}));
    ArduinoJson::JsonDocument connect_while_pending_no_session = parse_request(
        "{\"id\":\"req_connect_pending_busy\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"core\"}}");
    reset_written();
    handle_connect_request("req_connect_pending_busy", connect_while_pending_no_session);
    assert(!signing::session_active());
    assert(usb_transport_pending_request().kind == UsbPendingRequestKind::connect);
    expect_written_contains("\"id\":\"req_connect_pending_busy\"");
    expect_written_contains("\"code\":\"busy\"");
    signing::connect_approval_clear();

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        true,
    });
    ArduinoJson::JsonDocument connect_while_ui_busy = parse_request(
        "{\"id\":\"req_connect_ui_busy\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"core\"}}");
    reset_written();
    handle_connect_request("req_connect_ui_busy", connect_while_ui_busy);
    assert(!signing::session_active());
    assert(g_pending_request.kind == UsbPendingRequestKind::none);
    expect_written_contains("\"id\":\"req_connect_ui_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });
    assert(signing::session_replace(fill_random, nullptr) == signing::SessionStartResult::ok);

    g_pending_request.kind = UsbPendingRequestKind::credential_propose;
    snprintf(g_pending_request.id, sizeof(g_pending_request.id), "req_propose");
    snprintf(g_pending_request.label, sizeof(g_pending_request.label), "zkLogin proof");

    ArduinoJson::JsonDocument caps_while_pending = parse_request(
        "{\"id\":\"req_caps_pending\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"session_0001020304050607\"}");
    reset_written();
    handle_get_capabilities_request("req_caps_pending", caps_while_pending);
    expect_written_contains("\"id\":\"req_caps_pending\"");
    expect_written_contains("\"code\":\"busy\"");

    ArduinoJson::JsonDocument disconnect = parse_request(
        "{\"id\":\"req_disconnect\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session_0001020304050607\"}");
    reset_written();
    handle_disconnect_request("req_disconnect", disconnect);

    assert(g_pending_request.kind == UsbPendingRequestKind::none);
    assert(!signing::session_active());
    expect_written_contains("\"id\":\"req_propose\"");
    expect_written_contains("\"code\":\"invalid_session\"");
    expect_written_contains("\"id\":\"req_disconnect\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"method\":\"disconnect\"");

    assert(signing::session_replace(fill_random, nullptr) == signing::SessionStartResult::ok);
    g_pending_request.kind = UsbPendingRequestKind::none;
    ArduinoJson::JsonDocument disconnect_without_pending = parse_request(
        "{\"id\":\"req_disconnect_2\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session_0001020304050607\"}");
    reset_written();
    handle_disconnect_request("req_disconnect_2", disconnect_without_pending);
    assert(g_pending_request.kind == UsbPendingRequestKind::none);
    assert(!signing::session_active());
    expect_written_contains("\"id\":\"req_disconnect_2\"");
    expect_written_contains("\"success\":true");

    assert(signing::session_replace(fill_random, nullptr) == signing::SessionStartResult::ok);
    assert(strcmp(signing::session_id(), "session_0001020304050607") == 0);
    g_pending_request.kind = UsbPendingRequestKind::credential_propose;
    snprintf(g_pending_request.id, sizeof(g_pending_request.id), "req_propose_missing_session");
    snprintf(g_pending_request.label, sizeof(g_pending_request.label), "zkLogin proof");
    g_credential_preparation_clear_calls = 0;
    g_sui_zklogin_proposal_clear_calls = 0;
    signing::session_clear();

    ArduinoJson::JsonDocument accounts_after_hidden_session_loss = parse_request(
        "{\"id\":\"req_accounts_after_session_loss\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session_0001020304050607\"}");
    reset_written();
    handle_get_accounts_request("req_accounts_after_session_loss", accounts_after_hidden_session_loss);
    assert(g_pending_request.kind == UsbPendingRequestKind::none);
    assert(g_credential_preparation_clear_calls > 0);
    assert(g_sui_zklogin_proposal_clear_calls > 0);
    expect_written_contains("\"id\":\"req_propose_missing_session\"");
    expect_written_contains("\"id\":\"req_accounts_after_session_loss\"");
    expect_written_contains("\"code\":\"invalid_session\"");

    assert(signing::session_replace(fill_random, nullptr) == signing::SessionStartResult::ok);
    g_pending_request.kind = UsbPendingRequestKind::credential_propose;
    snprintf(g_pending_request.id, sizeof(g_pending_request.id), "req_propose_usb_drop");
    snprintf(g_pending_request.label, sizeof(g_pending_request.label), "zkLogin proof");
    g_credential_preparation_clear_calls = 0;
    g_sui_zklogin_proposal_clear_calls = 0;
    reset_written();
    g_now_ms = 900;
    g_usb_connected = true;
    assert(usb_transport_status().connected);
    g_now_ms = 1000;
    g_usb_connected = false;
    const UsbStatus disconnected_status = usb_transport_status();
    assert(!disconnected_status.connected);
    assert(g_pending_request.kind == UsbPendingRequestKind::credential_propose);
    assert(signing::session_active());
    assert(g_credential_preparation_clear_calls == 0);
    assert(g_sui_zklogin_proposal_clear_calls == 0);
    g_now_ms = 3000;
    const UsbStatus confirmed_disconnected_status = usb_transport_status();
    assert(!confirmed_disconnected_status.connected);
    assert(g_pending_request.kind == UsbPendingRequestKind::none);
    assert(!signing::session_active());
    assert(g_credential_preparation_clear_calls > 0);
    assert(g_sui_zklogin_proposal_clear_calls > 0);
    assert(g_written_size == 0);
    g_usb_connected = true;

    assert(usb_transport_init());
    assert(signing::session_replace(fill_random, nullptr) == signing::SessionStartResult::ok);
    g_pending_request.kind = UsbPendingRequestKind::credential_propose;
    snprintf(g_pending_request.id, sizeof(g_pending_request.id), "req_propose_usb_drop_poll");
    snprintf(g_pending_request.label, sizeof(g_pending_request.label), "zkLogin proof");
    g_credential_preparation_clear_calls = 0;
    g_sui_zklogin_proposal_clear_calls = 0;
    reset_written();
    g_now_ms = 3900;
    g_usb_connected = true;
    assert(usb_transport_status().connected);
    g_now_ms = 4000;
    g_usb_connected = false;
    usb_transport_poll();
    assert(g_pending_request.kind == UsbPendingRequestKind::credential_propose);
    assert(signing::session_active());
    assert(g_credential_preparation_clear_calls == 0);
    assert(g_sui_zklogin_proposal_clear_calls == 0);
    g_now_ms = 6000;
    usb_transport_poll();
    assert(g_pending_request.kind == UsbPendingRequestKind::none);
    assert(!signing::session_active());
    assert(g_credential_preparation_clear_calls > 0);
    assert(g_sui_zklogin_proposal_clear_calls > 0);
    assert(g_written_size == 0);
    g_usb_connected = true;

    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/usb_transport_session_cleanup_test.cpp" \
  "${COMMON_ROOT}/protocol/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/state_projection.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_response.cpp" \
  "${COMMON_ROOT}/protocol/base64.cpp" \
  "${COMMON_ROOT}/protocol/request_line.cpp" \
  "${COMMON_ROOT}/protocol/request_id.cpp" \
  "${COMMON_ROOT}/protocol/signing_response_store.cpp" \
  "${COMMON_ROOT}/protocol/usb_active_session_request_guard.cpp" \
  "${COMMON_ROOT}/protocol/usb_approval_history_handler.cpp" \
  "${COMMON_ROOT}/protocol/usb_device_handlers.cpp" \
  "${COMMON_ROOT}/protocol/usb_json_response.cpp" \
  "${COMMON_ROOT}/protocol/usb_operation_dispatch.cpp" \
  "${COMMON_ROOT}/protocol/usb_operation_manifest.cpp" \
  "${COMMON_ROOT}/protocol/usb_operation_type.cpp" \
  "${COMMON_ROOT}/protocol/usb_request_envelope.cpp" \
  "${COMMON_ROOT}/protocol/usb_request_line_handler.cpp" \
  "${COMMON_ROOT}/protocol/usb_session_read_handlers.cpp" \
  "${COMMON_ROOT}/protocol/usb_sui_zklogin_credential_handlers.cpp" \
  "${COMMON_ROOT}/policy/usb_policy_handlers.cpp" \
  "${COMMON_ROOT}/signing/policy_signing_execution_result.cpp" \
  "${COMMON_ROOT}/signing/sign_personal_message_user_ingress.cpp" \
  "${COMMON_ROOT}/signing/sign_personal_message_user_validation.cpp" \
  "${COMMON_ROOT}/signing/sign_transaction_user_ingress.cpp" \
  "${COMMON_ROOT}/signing/sign_transaction_user_validation.cpp" \
	  "${COMMON_ROOT}/signing/sign_transaction_policy_runtime.cpp" \
	  "${COMMON_ROOT}/signing/signing_preflight.cpp" \
	  "${COMMON_ROOT}/signing/signing_retry_response.cpp" \
	  "${COMMON_ROOT}/signing/signing_retry_delivery.cpp" \
	  "${COMMON_ROOT}/signing/usb_signing_handlers.cpp" \
	  "${COMMON_ROOT}/signing/usb_signing_outcome_writer.cpp" \
	  "${COMMON_ROOT}/signing/user_signing_critical_section.cpp" \
  "${COMMON_ROOT}/signing/user_signing_flow.cpp" \
  "${COMMON_ROOT}/sui/bcs_reader.cpp" \
  "${COMMON_ROOT}/sui/account_binding.cpp" \
  "${COMMON_ROOT}/sui/sign_transaction_adapter.cpp" \
  "${COMMON_ROOT}/sui/signing_preparation.cpp" \
  "${COMMON_ROOT}/sui/signing_payload.cpp" \
  "${COMMON_ROOT}/sui/transaction_facts.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_admission.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_primitives.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_resolution.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_store.cpp" \
  "${COMMON_ROOT}/transport/connect_approval.cpp" \
  "${COMMON_ROOT}/transport/connect_review_response_flow.cpp" \
  "${COMMON_ROOT}/transport/usb_connect_handler.cpp" \
  "${COMMON_ROOT}/transport/usb_disconnect_handler.cpp" \
  "${COMMON_ROOT}/transport/usb_payload_transfer_handlers.cpp" \
  "${COMMON_ROOT}/transport/usb_retained_response_handlers.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_outcome.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_payload.cpp" \
  "${COMMON_ROOT}/transport/usb_link_state.cpp" \
  "${COMMON_ROOT}/transport/usb_session_grace.cpp" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -Wl,-dead_strip \
  -o "${TMP_DIR}/usb_transport_session_cleanup_test"

"${TMP_DIR}/usb_transport_session_cleanup_test"
echo "StopWatch USB transport session cleanup tests passed"
