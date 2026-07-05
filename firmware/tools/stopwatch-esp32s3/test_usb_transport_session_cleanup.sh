#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stopwatch-esp32s3/M5StopWatch-UserDemo/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${RUNTIME_DIR}/usb_transport.cpp" \
  "${RUNTIME_DIR}/payload_transfer_request.cpp" \
  "${RUNTIME_DIR}/payload_transfer_request.h" \
  "${RUNTIME_DIR}/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/state_projection.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_response.cpp" \
  "${COMMON_ROOT}/protocol/base64.cpp" \
  "${COMMON_ROOT}/protocol/request_line.cpp" \
  "${COMMON_ROOT}/protocol/request_id.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_primitives.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_outcome.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_payload.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_outcome.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stopwatch-esp32s3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

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
#include "payload_transfer_state.h"
#include "sui_zklogin_credential_store.h"

namespace {
char g_written[4096] = {};
size_t g_written_size = 0;
bool g_usb_connected = true;
uint32_t g_now_ms = 0;
stopwatch_target::PayloadTransferAdmissionDecision g_payload_admission = {
    stopwatch_target::PayloadTransferAdmissionResult::ok,
    stopwatch_target::PayloadTransferAdmissionReason::idle_passthrough,
};
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

namespace stopwatch_target {

int g_credential_preparation_clear_calls = 0;
int g_sui_zklogin_proposal_clear_calls = 0;

void credential_preparation_state_clear()
{
    g_credential_preparation_clear_calls += 1;
}
void payload_transfer_clear_all() {}
bool payload_transfer_clear_expired(uint32_t) { return false; }
PayloadTransferAdmissionDecision payload_transfer_admit_operation(
    uint32_t,
    PayloadTransferAdmissionOperation operation)
{
    if (g_payload_admission.result == PayloadTransferAdmissionResult::busy) {
        if (operation == PayloadTransferAdmissionOperation::safe_read) {
            return {
                PayloadTransferAdmissionResult::ok,
                PayloadTransferAdmissionReason::finalized_safe_read,
            };
        }
        if (operation == PayloadTransferAdmissionOperation::disconnect) {
            return {
                PayloadTransferAdmissionResult::ok,
                PayloadTransferAdmissionReason::finalized_disconnect_cleanup,
            };
        }
    }
    return g_payload_admission;
}
bool payload_transfer_admission_blocks_sensitive_flow(const PayloadTransferAdmissionDecision& decision)
{
    return decision.result == PayloadTransferAdmissionResult::busy &&
           (decision.reason == PayloadTransferAdmissionReason::blocked_incomplete_transfer ||
            decision.reason == PayloadTransferAdmissionReason::blocked_pending_finalized_payload ||
            decision.reason == PayloadTransferAdmissionReason::blocked_unrelated_sensitive_flow);
}
PayloadTransferResult payload_transfer_take(uint32_t, const char*, const char*, PayloadTransferOwnedPayload*)
{
    return PayloadTransferResult::not_found;
}
void payload_transfer_wipe_owned_payload(PayloadTransferOwnedPayload*) {}
PayloadTransferResult payload_transfer_begin(
    uint32_t,
    const char*,
    size_t,
    const char*,
    PayloadTransferBeginOutput*)
{
    return PayloadTransferResult::invalid_state;
}
PayloadTransferResult payload_transfer_append_chunk(
    uint32_t,
    const char*,
    const char*,
    size_t,
    const uint8_t*,
    size_t,
    size_t*)
{
    return PayloadTransferResult::invalid_state;
}
PayloadTransferResult payload_transfer_finish(
    uint32_t,
    const char*,
    const char*,
    PayloadDigestFn,
    PayloadTransferFinishOutput*)
{
    return PayloadTransferResult::invalid_state;
}
PayloadTransferResult payload_transfer_abort(uint32_t, const char*, const char*, const char*)
{
    return PayloadTransferResult::invalid_state;
}
PayloadTransferResult payload_transfer_reject_chunk_too_large(uint32_t, const char*, const char*)
{
    return PayloadTransferResult::chunk_too_large;
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
bool payload_digest_sha256(const uint8_t*, size_t, char[kPayloadDigestSize])
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

}  // namespace

int main()
{
    using namespace stopwatch_target;

    session_state_init();
    assert(session_state_replace(fill_random, nullptr) == SessionStartResult::ok);
    assert(strcmp(session_state_id(), "session_0001020304050607") == 0);
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
    handle_payload_transfer_line(payload_while_busy);
    expect_written_contains("\"id\":\"req_payload_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });

    g_payload_admission = {
        PayloadTransferAdmissionResult::busy,
        PayloadTransferAdmissionReason::blocked_pending_finalized_payload,
    };
    ArduinoJson::JsonDocument connect_while_payload_pending = parse_request(
        "{\"id\":\"req_connect_payload_busy\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"core\"}}");
    reset_written();
    handle_connect_request("req_connect_payload_busy", connect_while_payload_pending);
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_connect_payload_busy\"");
    expect_written_contains("\"method\":\"connect\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"sessionId\":\"session_0001020304050607\"");

    session_state_clear();
    ArduinoJson::JsonDocument connect_without_session_while_payload_pending = parse_request(
        "{\"id\":\"req_connect_payload_no_session_busy\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"core\"}}");
    reset_written();
    handle_connect_request("req_connect_payload_no_session_busy", connect_without_session_while_payload_pending);
    assert(!session_state_active());
    expect_written_contains("\"id\":\"req_connect_payload_no_session_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    assert(session_state_replace(fill_random, nullptr) == SessionStartResult::ok);
    ArduinoJson::JsonDocument propose_while_payload_pending = parse_request(
        "{\"id\":\"req_propose_payload_busy\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"unexpected\":true}}");
    reset_written();
    handle_credential_propose_request("req_propose_payload_busy", propose_while_payload_pending);
    assert(session_state_active());
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
    handle_session_unavailable_method(
        "req_policy_get_payload_pending",
        "policy_get",
        policy_get_while_payload_pending);
    expect_written_contains("\"id\":\"req_policy_get_payload_pending\"");
    expect_written_contains("\"code\":\"policy_unavailable\"");

    ArduinoJson::JsonDocument history_while_payload_pending = parse_request(
        "{\"id\":\"req_history_payload_pending\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"limit\":1}}");
    reset_written();
    handle_session_unavailable_method(
        "req_history_payload_pending",
        "get_approval_history",
        history_while_payload_pending);
    expect_written_contains("\"id\":\"req_history_payload_pending\"");
    expect_written_contains("\"code\":\"history_unavailable\"");

    ArduinoJson::JsonDocument history_bad_limit = parse_request(
        "{\"id\":\"req_history_bad_limit\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"limit\":0}}");
    reset_written();
    handle_session_unavailable_method(
        "req_history_bad_limit",
        "get_approval_history",
        history_bad_limit);
    expect_written_contains("\"id\":\"req_history_bad_limit\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument history_bad_before = parse_request(
        "{\"id\":\"req_history_bad_before\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"beforeSeq\":\"not-number\"}}");
    reset_written();
    handle_session_unavailable_method(
        "req_history_bad_before",
        "get_approval_history",
        history_bad_before);
    expect_written_contains("\"id\":\"req_history_bad_before\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument get_result_while_payload_pending = parse_request(
        "{\"id\":\"req_get_result_payload_pending\",\"version\":1,\"method\":\"get_result\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"retainedRequestId\":\"req_retained\"}}");
    reset_written();
    handle_session_unavailable_method(
        "req_get_result_payload_pending",
        "get_result",
        get_result_while_payload_pending);
    expect_written_contains("\"id\":\"req_get_result_payload_pending\"");
    expect_written_contains("\"code\":\"unknown_request\"");

    ArduinoJson::JsonDocument ack_result_while_payload_pending = parse_request(
        "{\"id\":\"req_ack_result_payload_pending\",\"version\":1,\"method\":\"ack_result\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"retainedRequestId\":\"req_retained\"}}");
    reset_written();
    handle_session_unavailable_method(
        "req_ack_result_payload_pending",
        "ack_result",
        ack_result_while_payload_pending);
    expect_written_contains("\"id\":\"req_ack_result_payload_pending\"");
    expect_written_contains("\"code\":\"unknown_request\"");

    ArduinoJson::JsonDocument get_result_bad_payload = parse_request(
        "{\"id\":\"req_get_result_bad_payload\",\"version\":1,\"method\":\"get_result\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"retainedRequestId\":\"bad id\"}}");
    reset_written();
    handle_session_unavailable_method(
        "req_get_result_bad_payload",
        "get_result",
        get_result_bad_payload);
    expect_written_contains("\"id\":\"req_get_result_bad_payload\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument ack_result_bad_payload = parse_request(
        "{\"id\":\"req_ack_result_bad_payload\",\"version\":1,\"method\":\"ack_result\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"retainedRequestId\":\"bad id\"}}");
    reset_written();
    handle_session_unavailable_method(
        "req_ack_result_bad_payload",
        "ack_result",
        ack_result_bad_payload);
    expect_written_contains("\"id\":\"req_ack_result_bad_payload\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument policy_propose_while_payload_pending = parse_request(
        "{\"id\":\"req_policy_propose_payload_busy\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"policy\":{}}}");
    reset_written();
    handle_session_unavailable_method(
        "req_policy_propose_payload_busy",
        "policy_propose",
        policy_propose_while_payload_pending);
    expect_written_contains("\"id\":\"req_policy_propose_payload_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    ArduinoJson::JsonDocument sign_transaction_while_payload_pending = parse_request(
        "{\"id\":\"req_sign_tx_payload_busy\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"txBytes\":\"AA==\"}}");
    reset_written();
    handle_session_unavailable_method(
        "req_sign_tx_payload_busy",
        "sign_transaction",
        sign_transaction_while_payload_pending);
    expect_written_contains("\"id\":\"req_sign_tx_payload_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    ArduinoJson::JsonDocument sign_message_while_payload_pending = parse_request(
        "{\"id\":\"req_sign_msg_payload_busy\",\"version\":1,\"method\":\"sign_personal_message\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"chain\":\"sui\",\"network\":\"testnet\",\"message\":\"AA==\"}}");
    reset_written();
    handle_session_unavailable_method(
        "req_sign_msg_payload_busy",
        "sign_personal_message",
        sign_message_while_payload_pending);
    expect_written_contains("\"id\":\"req_sign_msg_payload_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    g_payload_admission = {
        PayloadTransferAdmissionResult::ok,
        PayloadTransferAdmissionReason::idle_passthrough,
    };

    ArduinoJson::JsonDocument policy_propose_valid_wrapper = parse_request(
        "{\"id\":\"req_policy_propose_unavailable\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"policy\":{}}}");
    reset_written();
    handle_session_unavailable_method(
        "req_policy_propose_unavailable",
        "policy_propose",
        policy_propose_valid_wrapper);
    expect_written_contains("\"id\":\"req_policy_propose_unavailable\"");
    expect_written_contains("\"code\":\"policy_unavailable\"");

    ArduinoJson::JsonDocument policy_propose_bad_payload = parse_request(
        "{\"id\":\"req_policy_propose_bad_payload\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":7}");
    reset_written();
    handle_session_unavailable_method(
        "req_policy_propose_bad_payload",
        "policy_propose",
        policy_propose_bad_payload);
    expect_written_contains("\"id\":\"req_policy_propose_bad_payload\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument policy_propose_extra_payload = parse_request(
        "{\"id\":\"req_policy_propose_extra_payload\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"policy\":{},\"extra\":true}}");
    reset_written();
    handle_session_unavailable_method(
        "req_policy_propose_extra_payload",
        "policy_propose",
        policy_propose_extra_payload);
    expect_written_contains("\"id\":\"req_policy_propose_extra_payload\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument policy_propose_missing_policy = parse_request(
        "{\"id\":\"req_policy_propose_missing_policy\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{}}");
    reset_written();
    handle_session_unavailable_method(
        "req_policy_propose_missing_policy",
        "policy_propose",
        policy_propose_missing_policy);
    expect_written_contains("\"id\":\"req_policy_propose_missing_policy\"");
    expect_written_contains("\"code\":\"invalid_params\"");

    ArduinoJson::JsonDocument policy_propose_scalar_policy = parse_request(
        "{\"id\":\"req_policy_propose_scalar_policy\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"policy\":7}}");
    reset_written();
    handle_session_unavailable_method(
        "req_policy_propose_scalar_policy",
        "policy_propose",
        policy_propose_scalar_policy);
    expect_written_contains("\"id\":\"req_policy_propose_scalar_policy\"");
    expect_written_contains("\"code\":\"invalid_params\"");

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
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_payload_type_non_string\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_payload_missing_version\",\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_payload_missing_version\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_payload_string_version\",\"version\":\"1\",\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_payload_string_version\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_payload_float_version\",\"version\":1.5,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_payload_float_version\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_payload_bool_version\",\"version\":true,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_payload_bool_version\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_payload_type_empty\",\"version\":1,\"type\":\"\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    assert(session_state_active());
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
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_accounts_locked\"");
    expect_written_contains("\"code\":\"auth_unavailable\"");

    ArduinoJson::JsonDocument prepare_while_locked_without_payload = parse_request(
        "{\"id\":\"req_prepare_locked_no_payload\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"session_0001020304050607\"}");
    reset_written();
    handle_credential_prepare_request("req_prepare_locked_no_payload", prepare_while_locked_without_payload);
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_prepare_locked_no_payload\"");
    expect_written_contains("\"code\":\"auth_unavailable\"");

    ArduinoJson::JsonDocument payload_while_locked = parse_request(
        "{\"id\":\"req_payload_locked\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_0001020304050607\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    reset_written();
    handle_payload_transfer_line(payload_while_locked);
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_payload_locked\"");
    expect_written_contains("\"code\":\"auth_unavailable\"");

    ArduinoJson::JsonDocument payload_bad_session_while_locked = parse_request(
        "{\"id\":\"req_payload_bad_session_locked\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_badg\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    reset_written();
    handle_payload_transfer_line(payload_bad_session_while_locked);
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_payload_bad_session_locked\"");
    expect_written_contains("\"code\":\"invalid_session\"");

    ArduinoJson::JsonDocument payload_missing_session_while_locked = parse_request(
        "{\"id\":\"req_payload_missing_session_locked\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    reset_written();
    handle_payload_transfer_line(payload_missing_session_while_locked);
    assert(session_state_active());
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
    handle_payload_transfer_line(payload_bad_session_while_unprovisioned);
    expect_written_contains("\"id\":\"req_payload_bad_session_unprovisioned\"");
    expect_written_contains("\"code\":\"invalid_session\"");

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });
    assert(session_state_replace(fill_random, nullptr) == SessionStartResult::ok);
    ArduinoJson::JsonDocument payload_bad_session_while_unlocked = parse_request(
        "{\"id\":\"req_payload_bad_session_unlocked\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_badg\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    reset_written();
    handle_payload_transfer_line(payload_bad_session_while_unlocked);
    assert(session_state_active());
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
    assert(session_state_active());
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
    assert(!session_state_active());
    expect_written_contains("\"id\":\"req_connect_credential_error\"");
    expect_written_contains("\"code\":\"invalid_state\"");

    assert(session_state_replace(fill_random, nullptr) == SessionStartResult::ok);
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
    assert(!session_state_active());
    expect_written_contains("\"id\":\"req_connect_auth_storage_error\"");
    expect_written_contains("\"code\":\"invalid_state\"");

    assert(session_state_replace(fill_random, nullptr) == SessionStartResult::ok);
    reset_written();
    handle_request_line(
        "{\"id\":\"req_connect_extra_storage_error\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"core\"},\"extra\":1}");
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_connect_extra_storage_error\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_connect_no_payload_storage_error\",\"version\":1,\"method\":\"connect\"}");
    assert(session_state_active());
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
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_prepare_locked_no_session\"");
    expect_written_contains("\"code\":\"invalid_session\"");

    reset_written();
    handle_request_line(
        "{\"id\":\"req_status_forbidden_session\",\"version\":1,\"method\":\"get_status\",\"sessionId\":\"session_0001020304050607\"}");
    assert(session_state_active());
    expect_written_contains("\"id\":\"req_status_forbidden_session\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    ArduinoJson::JsonDocument disconnect_while_locked = parse_request(
        "{\"id\":\"req_disconnect_locked\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session_0001020304050607\"}");
    reset_written();
    handle_disconnect_request("req_disconnect_locked", disconnect_while_locked);
    assert(!session_state_active());
    expect_written_contains("\"id\":\"req_disconnect_locked\"");
    expect_written_contains("\"success\":true");

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });

    g_pending_request.kind = UsbPendingRequestKind::connect;
    snprintf(g_pending_request.id, sizeof(g_pending_request.id), "req_connect_pending_owner");
    snprintf(g_pending_request.label, sizeof(g_pending_request.label), "core");
    ArduinoJson::JsonDocument connect_while_pending_no_session = parse_request(
        "{\"id\":\"req_connect_pending_busy\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"core\"}}");
    reset_written();
    handle_connect_request("req_connect_pending_busy", connect_while_pending_no_session);
    assert(!session_state_active());
    assert(g_pending_request.kind == UsbPendingRequestKind::connect);
    expect_written_contains("\"id\":\"req_connect_pending_busy\"");
    expect_written_contains("\"code\":\"busy\"");
    clear_pending_request();

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        true,
    });
    ArduinoJson::JsonDocument connect_while_ui_busy = parse_request(
        "{\"id\":\"req_connect_ui_busy\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"core\"}}");
    reset_written();
    handle_connect_request("req_connect_ui_busy", connect_while_ui_busy);
    assert(!session_state_active());
    assert(g_pending_request.kind == UsbPendingRequestKind::none);
    expect_written_contains("\"id\":\"req_connect_ui_busy\"");
    expect_written_contains("\"code\":\"busy\"");

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });
    assert(session_state_replace(fill_random, nullptr) == SessionStartResult::ok);

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
    assert(!session_state_active());
    expect_written_contains("\"id\":\"req_propose\"");
    expect_written_contains("\"code\":\"invalid_session\"");
    expect_written_contains("\"id\":\"req_disconnect\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"method\":\"disconnect\"");

    assert(session_state_replace(fill_random, nullptr) == SessionStartResult::ok);
    g_pending_request.kind = UsbPendingRequestKind::none;
    ArduinoJson::JsonDocument disconnect_without_pending = parse_request(
        "{\"id\":\"req_disconnect_2\",\"version\":1,\"method\":\"disconnect\",\"sessionId\":\"session_0001020304050607\"}");
    reset_written();
    handle_disconnect_request("req_disconnect_2", disconnect_without_pending);
    assert(g_pending_request.kind == UsbPendingRequestKind::none);
    assert(!session_state_active());
    expect_written_contains("\"id\":\"req_disconnect_2\"");
    expect_written_contains("\"success\":true");

    assert(session_state_replace(fill_random, nullptr) == SessionStartResult::ok);
    assert(strcmp(session_state_id(), "session_0001020304050607") == 0);
    g_pending_request.kind = UsbPendingRequestKind::credential_propose;
    snprintf(g_pending_request.id, sizeof(g_pending_request.id), "req_propose_missing_session");
    snprintf(g_pending_request.label, sizeof(g_pending_request.label), "zkLogin proof");
    g_credential_preparation_clear_calls = 0;
    g_sui_zklogin_proposal_clear_calls = 0;
    session_state_clear();

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

    assert(session_state_replace(fill_random, nullptr) == SessionStartResult::ok);
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
    assert(session_state_active());
    assert(g_credential_preparation_clear_calls == 0);
    assert(g_sui_zklogin_proposal_clear_calls == 0);
    g_now_ms = 3000;
    const UsbStatus confirmed_disconnected_status = usb_transport_status();
    assert(!confirmed_disconnected_status.connected);
    assert(g_pending_request.kind == UsbPendingRequestKind::none);
    assert(!session_state_active());
    assert(g_credential_preparation_clear_calls > 0);
    assert(g_sui_zklogin_proposal_clear_calls > 0);
    assert(g_written_size == 0);
    g_usb_connected = true;

    assert(usb_transport_init());
    assert(session_state_replace(fill_random, nullptr) == SessionStartResult::ok);
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
    assert(session_state_active());
    assert(g_credential_preparation_clear_calls == 0);
    assert(g_sui_zklogin_proposal_clear_calls == 0);
    g_now_ms = 6000;
    usb_transport_poll();
    assert(g_pending_request.kind == UsbPendingRequestKind::none);
    assert(!session_state_active());
    assert(g_credential_preparation_clear_calls > 0);
    assert(g_sui_zklogin_proposal_clear_calls > 0);
    assert(g_written_size == 0);
    g_usb_connected = true;

    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/usb_transport_session_cleanup_test.cpp" \
  "${RUNTIME_DIR}/payload_transfer_request.cpp" \
  "${RUNTIME_DIR}/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/state_projection.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_response.cpp" \
  "${COMMON_ROOT}/protocol/base64.cpp" \
  "${COMMON_ROOT}/protocol/request_line.cpp" \
  "${COMMON_ROOT}/protocol/request_id.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_primitives.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_outcome.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_payload.cpp" \
  "${COMMON_ROOT}/transport/usb_link_state.cpp" \
  "${COMMON_ROOT}/transport/usb_session_grace.cpp" \
  -Wl,-dead_strip \
  -o "${TMP_DIR}/usb_transport_session_cleanup_test"

"${TMP_DIR}/usb_transport_session_cleanup_test"
echo "StopWatch USB transport session cleanup tests passed"
