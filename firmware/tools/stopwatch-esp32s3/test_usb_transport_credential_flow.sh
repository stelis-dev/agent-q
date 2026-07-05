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
  "${COMMON_DIR}/protocol/base64.cpp" \
  "${COMMON_DIR}/protocol/device_contract.cpp" \
  "${COMMON_DIR}/protocol/device_response.cpp" \
  "${COMMON_DIR}/protocol/request_id.cpp" \
  "${COMMON_DIR}/protocol/request_line.cpp" \
  "${COMMON_DIR}/sui/zklogin_credential_outcome.cpp" \
  "${COMMON_DIR}/sui/zklogin_credential_payload.cpp" \
  "${COMMON_DIR}/sui/zklogin_proof_record.cpp" \
  "${RUNTIME_DIR}/credential_preparation_state.cpp" \
  "${RUNTIME_DIR}/payload_digest.cpp" \
  "${RUNTIME_DIR}/payload_transfer_request.cpp" \
  "${RUNTIME_DIR}/payload_transfer_state.cpp" \
  "${RUNTIME_DIR}/protocol_input_encoding.cpp" \
  "${RUNTIME_DIR}/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/state_projection.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_credential_clear.cpp" \
  "${RUNTIME_DIR}/sui_public_material.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_credential_store.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_proposal_state.cpp" \
  "${RUNTIME_DIR}/usb_transport.cpp"; do
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

cat >"${TMP_DIR}/usb_transport_credential_flow_test.cpp" <<'CPP'
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

#include "sui_zklogin_credential_clear.h"
#include "usb_transport.cpp"

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

}  // namespace stopwatch_target

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
    using namespace stopwatch_target;
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
    stopwatch_target::handle_request_line(line);
}

void send_payload_transfer_sequence(
    const char* session_id,
    const char* payload_json,
    const char* expected_transfer_id,
    const char* expected_payload_ref)
{
    using namespace stopwatch_target;
    char digest[kPayloadDigestSize] = {};
    assert(payload_digest_sha256(
        reinterpret_cast<const uint8_t*>(payload_json),
        strlen(payload_json),
        digest));

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
    using namespace stopwatch_target;
    char digest[kPayloadDigestSize] = {};
    assert(payload_digest_sha256(
        reinterpret_cast<const uint8_t*>(payload_json),
        strlen(payload_json),
        digest));

    PayloadTransferBeginOutput begin = {};
    assert(payload_transfer_begin(
               static_cast<uint32_t>(g_now_us / 1000ULL),
               session_state_id(),
               strlen(payload_json),
               digest,
               &begin) == PayloadTransferResult::ok);

    size_t received = 0;
    assert(payload_transfer_append_chunk(
               static_cast<uint32_t>(g_now_us / 1000ULL),
               session_state_id(),
               begin.transfer_id,
               0,
               reinterpret_cast<const uint8_t*>(payload_json),
               strlen(payload_json),
               &received) == PayloadTransferResult::ok);
    assert(received == strlen(payload_json));

    PayloadTransferFinishOutput finish = {};
    assert(payload_transfer_finish(
               static_cast<uint32_t>(g_now_us / 1000ULL),
               session_state_id(),
               begin.transfer_id,
               payload_digest_sha256,
               &finish) == PayloadTransferResult::ok);
    assert(payload_transfer_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).status ==
           PayloadTransferStatus::finalized);
}

}  // namespace

int main()
{
    using namespace stopwatch_target;

    session_state_init();
    payload_transfer_state_init();
    credential_preparation_state_init();
    sui_zklogin_credential_test_reset_store();
    sui_zklogin_proposal_state_init();
    assert(usb_transport_init());

    assert(session_state_replace(fill_session_random, nullptr) == SessionStartResult::ok);
    assert(strcmp(session_state_id(), "session_0001020304050607") == 0);
    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });

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
    assert(usb_transport_pending_request().kind == UsbPendingRequestKind::none);
    assert(!sui_zklogin_proposal_state_active());

    reset_written();
    send_line(
        "{\"id\":\"req_propose_bad_session\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session_badg\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
    expect_written_contains("\"id\":\"req_propose_bad_session\"");
    expect_written_contains("\"method\":\"credential_propose\"");
    expect_written_contains("\"code\":\"invalid_session\"");
    assert(usb_transport_pending_request().kind == UsbPendingRequestKind::none);
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

    UsbPendingRequest pending = usb_transport_pending_request();
    assert(pending.kind == UsbPendingRequestKind::credential_propose);
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
    assert(usb_transport_approve_pending_request());
    expect_written_contains("\"id\":\"req_propose\"");
    expect_written_contains("\"method\":\"credential_propose\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"status\":\"activated\"");
    expect_written_contains("\"reasonCode\":\"device_confirmed\"");
    expect_written_contains("\"sessionEnded\":true");

    assert(usb_transport_pending_request().kind == UsbPendingRequestKind::none);
    assert(!session_state_active());
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

    reset_written();
    send_line(
        "{\"id\":\"req_accounts_ended_session\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"session_0001020304050607\"}");
    expect_written_contains("\"id\":\"req_accounts_ended_session\"");
    expect_written_contains("\"code\":\"invalid_session\"");

    reset_written();
    send_line(
        "{\"id\":\"req_connect_active\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"credential-flow-test\"}}");
    expect_no_response();
    pending = usb_transport_pending_request();
    assert(pending.kind == UsbPendingRequestKind::connect);
    assert(strcmp(pending.id, "req_connect_active") == 0);
    assert(signing::timeout_window_active(pending.request_window));

    g_now_us += 30001LL * 1000LL;
    reset_written();
    usb_transport_poll();
    expect_written_contains("\"id\":\"req_connect_active\"");
    expect_written_contains("\"method\":\"connect\"");
    expect_written_contains("\"code\":\"timeout\"");
    assert(usb_transport_pending_request().kind == UsbPendingRequestKind::none);

    reset_written();
    send_line(
        "{\"id\":\"req_connect_active_retry\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"credential-flow-test\"}}");
    expect_no_response();
    pending = usb_transport_pending_request();
    assert(pending.kind == UsbPendingRequestKind::connect);
    assert(strcmp(pending.id, "req_connect_active_retry") == 0);

    reset_written();
    assert(usb_transport_approve_pending_request());
    expect_written_contains("\"id\":\"req_connect_active_retry\"");
    expect_written_contains("\"method\":\"connect\"");
    expect_written_contains("\"success\":true");
    assert(session_state_active());

    char accounts_line[256] = {};
    snprintf(
        accounts_line,
        sizeof(accounts_line),
        "{\"id\":\"req_accounts_active\",\"version\":1,\"method\":\"get_accounts\",\"sessionId\":\"%s\"}",
        session_state_id());
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
        session_state_id());
    reset_written();
    send_line(caps_line);
    expect_written_contains("\"id\":\"req_caps_active\"");
    expect_written_contains("\"method\":\"get_capabilities\"");
    expect_written_contains("\"success\":true");
    expect_written_not_contains("\"signing\"");
    expect_written_contains("\"credentials\":[]");
    expect_written_not_contains("\"credential_prepare\"");
    expect_written_not_contains("\"credential_propose\"");

    char prepare_again_line[256] = {};
    snprintf(
        prepare_again_line,
        sizeof(prepare_again_line),
        "{\"id\":\"req_prepare_active\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}",
        session_state_id());
    reset_written();
    send_line(prepare_again_line);
    expect_written_contains("\"id\":\"req_prepare_active\"");
    expect_written_contains("\"code\":\"invalid_state\"");

    char propose_again_line[4096] = {};
    snprintf(
        propose_again_line,
        sizeof(propose_again_line),
        "{\"id\":\"req_propose_active\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"%s\",\"payload\":%s}",
        session_state_id(),
        payload_json);
    reset_written();
    send_line(propose_again_line);
    expect_written_contains("\"id\":\"req_propose_active\"");
    expect_written_contains("\"code\":\"invalid_state\"");

    send_payload_transfer_sequence(
        session_state_id(),
        payload_json,
        "transfer_0000000000000002",
        "\"payloadRef\":\"payload_0000000000000002\"");

    char propose_ref_active_line[512] = {};
    snprintf(
        propose_ref_active_line,
        sizeof(propose_ref_active_line),
        "{\"id\":\"req_propose_active_ref\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"%s\",\"payload\":{\"payloadRef\":\"payload_0000000000000002\"}}",
        session_state_id());
    reset_written();
    send_line(propose_ref_active_line);
    expect_written_contains("\"id\":\"req_propose_active_ref\"");
    expect_written_contains("\"code\":\"invalid_state\"");
    assert(payload_transfer_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).status ==
           PayloadTransferStatus::idle);

    char abort_finalized_line[256] = {};
    snprintf(
        abort_finalized_line,
        sizeof(abort_finalized_line),
        "{\"id\":\"req_abort_finalized\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"%s\",\"payloadRef\":\"payload_0000000000000002\"}",
        session_state_id());
    reset_written();
    send_line(abort_finalized_line);
    expect_written_contains("\"id\":\"req_abort_finalized\"");
    expect_written_contains("\"code\":\"unknown_request\"");
    assert(payload_transfer_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).status ==
           PayloadTransferStatus::idle);

    assert(sui_zklogin_clear_active_credential());
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::missing);
    assert(!session_state_active());
    assert(usb_transport_pending_request().kind == UsbPendingRequestKind::none);

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
    expect_written_contains("\"code\":\"invalid_session\"");

    reset_written();
    send_line(
        "{\"id\":\"req_connect_after_clear\",\"version\":1,\"method\":\"connect\",\"payload\":{\"clientName\":\"credential-flow-test\"}}");
    expect_no_response();
    pending = usb_transport_pending_request();
    assert(pending.kind == UsbPendingRequestKind::connect);
    assert(strcmp(pending.id, "req_connect_after_clear") == 0);

    reset_written();
    assert(usb_transport_approve_pending_request());
    expect_written_contains("\"id\":\"req_connect_after_clear\"");
    expect_written_contains("\"method\":\"connect\"");
    expect_written_contains("\"success\":true");
    assert(session_state_active());

    snprintf(
        caps_line,
        sizeof(caps_line),
        "{\"id\":\"req_caps_after_clear\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"%s\"}",
        session_state_id());
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
        session_state_id());
    reset_written();
    send_line(idle_chunk_bad_transfer_line);
    expect_written_contains("\"id\":\"req_pt_idle_chunk_bad_transfer\"");
    expect_written_contains("\"code\":\"unknown_request\"");

    char idle_finish_bad_transfer_line[256] = {};
    snprintf(
        idle_finish_bad_transfer_line,
        sizeof(idle_finish_bad_transfer_line),
        "{\"id\":\"req_pt_idle_finish_bad_transfer\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"finish\",\"sessionId\":\"%s\",\"transferId\":7}",
        session_state_id());
    reset_written();
    send_line(idle_finish_bad_transfer_line);
    expect_written_contains("\"id\":\"req_pt_idle_finish_bad_transfer\"");
    expect_written_contains("\"code\":\"unknown_request\"");

    char idle_abort_missing_ref_line[192] = {};
    snprintf(
        idle_abort_missing_ref_line,
        sizeof(idle_abort_missing_ref_line),
        "{\"id\":\"req_pt_idle_abort_missing_ref\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"%s\"}",
        session_state_id());
    reset_written();
    send_line(idle_abort_missing_ref_line);
    expect_written_contains("\"id\":\"req_pt_idle_abort_missing_ref\"");
    expect_written_contains("\"code\":\"invalid_request\"");

    char too_large_begin_line[512] = {};
    snprintf(
        too_large_begin_line,
        sizeof(too_large_begin_line),
        "{\"id\":\"req_pt_too_large\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"%s\",\"totalBytes\":\"%u\",\"payloadDigest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"}",
        session_state_id(),
        static_cast<unsigned>(kPayloadTransferMaxBytes + 1));
    reset_written();
    send_line(too_large_begin_line);
    expect_written_contains("\"id\":\"req_pt_too_large\"");
    expect_written_contains("\"code\":\"payload_too_large\"");
    assert(payload_transfer_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).status ==
           PayloadTransferStatus::idle);

    create_finalized_payload_for_current_session(payload_json);
    char finalized_begin_bad_size_line[512] = {};
    snprintf(
        finalized_begin_bad_size_line,
        sizeof(finalized_begin_bad_size_line),
        "{\"id\":\"req_pt_finalized_begin_bad_size\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"%s\",\"totalBytes\":7,\"payloadDigest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"}",
        session_state_id());
    reset_written();
    send_line(finalized_begin_bad_size_line);
    expect_written_contains("\"id\":\"req_pt_finalized_begin_bad_size\"");
    expect_written_contains("\"code\":\"busy\"");

    char finalized_chunk_bad_transfer_line[256] = {};
    snprintf(
        finalized_chunk_bad_transfer_line,
        sizeof(finalized_chunk_bad_transfer_line),
        "{\"id\":\"req_pt_finalized_chunk_bad_transfer\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\",\"sessionId\":\"%s\",\"transferId\":7,\"offsetBytes\":\"0\",\"chunk\":\"AA==\"}",
        session_state_id());
    reset_written();
    send_line(finalized_chunk_bad_transfer_line);
    expect_written_contains("\"id\":\"req_pt_finalized_chunk_bad_transfer\"");
    expect_written_contains("\"code\":\"busy\"");

    g_now_us += static_cast<int64_t>(kPayloadTransferMaxWindowMs + 1) * 1000;
    snprintf(
        caps_line,
        sizeof(caps_line),
        "{\"id\":\"req_caps_clears_expired_payload\",\"version\":1,\"method\":\"get_capabilities\",\"sessionId\":\"%s\"}",
        session_state_id());
    reset_written();
    send_line(caps_line);
    expect_written_contains("\"id\":\"req_caps_clears_expired_payload\"");
    expect_written_contains("\"method\":\"get_capabilities\"");
    expect_written_contains("\"success\":true");
    assert(payload_transfer_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).status ==
           PayloadTransferStatus::idle);

    char prepare_after_clear_line[256] = {};
    snprintf(
        prepare_after_clear_line,
        sizeof(prepare_after_clear_line),
        "{\"id\":\"req_prepare_after_clear\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}",
        session_state_id());
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
        session_state_id());
    reset_written();
    send_line(propose_missing_fields_line);
    expect_written_contains("\"id\":\"req_propose_missing_fields\"");
    expect_written_contains("\"code\":\"invalid_params\"");
    assert(!sui_zklogin_proposal_state_active());

    char invalid_payload_json[2048] = {};
    build_invalid_network_payload_json(invalid_payload_json, sizeof(invalid_payload_json));
    send_payload_transfer_sequence(
        session_state_id(),
        invalid_payload_json,
        "transfer_0000000000000004",
        "\"payloadRef\":\"payload_0000000000000004\"");

    char invalid_propose_line[512] = {};
    snprintf(
        invalid_propose_line,
        sizeof(invalid_propose_line),
        "{\"id\":\"req_propose_invalid_proof\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"%s\",\"payload\":{\"payloadRef\":\"payload_0000000000000004\"}}",
        session_state_id());
    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        false,
        false,
    });
    reset_written();
    send_line(invalid_propose_line);
    expect_written_contains("\"id\":\"req_propose_invalid_proof\"");
    expect_written_contains("\"method\":\"credential_propose\"");
    expect_written_contains("\"code\":\"auth_unavailable\"");
    assert(payload_transfer_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).status ==
           PayloadTransferStatus::idle);

    usb_transport_set_runtime_state(UsbRuntimeState{
        LocalAuthProjectionStatus::active,
        true,
        false,
    });
    send_payload_transfer_sequence(
        session_state_id(),
        invalid_payload_json,
        "transfer_0000000000000005",
        "\"payloadRef\":\"payload_0000000000000005\"");
    snprintf(
        invalid_propose_line,
        sizeof(invalid_propose_line),
        "{\"id\":\"req_propose_invalid_proof_retry\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"%s\",\"payload\":{\"payloadRef\":\"payload_0000000000000005\"}}",
        session_state_id());
    reset_written();
    send_line(invalid_propose_line);
    expect_written_contains("\"id\":\"req_propose_invalid_proof_retry\"");
    expect_written_contains("\"method\":\"credential_propose\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"status\":\"invalid_proof\"");
    expect_written_contains("\"reasonCode\":\"invalid_proof\"");
    expect_written_contains("\"sessionEnded\":false");
    assert(usb_transport_pending_request().kind == UsbPendingRequestKind::none);
    assert(!credential_preparation_snapshot().active);
    assert(!sui_zklogin_proposal_state_active());
    assert(sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::missing);
    assert(payload_transfer_snapshot(static_cast<uint32_t>(g_now_us / 1000ULL)).status ==
           PayloadTransferStatus::idle);

    char prepare_consistency_line[256] = {};
    snprintf(
        prepare_consistency_line,
        sizeof(prepare_consistency_line),
        "{\"id\":\"req_prepare_consistency\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"%s\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}",
        session_state_id());
    reset_written();
    send_line(prepare_consistency_line);
    expect_written_contains("\"id\":\"req_prepare_consistency\"");
    expect_written_contains("\"method\":\"credential_prepare\"");
    expect_written_contains("\"success\":true");

    char consistency_payload_json[2048] = {};
    build_valid_payload_json(consistency_payload_json, sizeof(consistency_payload_json));
    send_payload_transfer_sequence(
        session_state_id(),
        consistency_payload_json,
        "transfer_0000000000000006",
        "\"payloadRef\":\"payload_0000000000000006\"");

    char consistency_propose_line[512] = {};
    snprintf(
        consistency_propose_line,
        sizeof(consistency_propose_line),
        "{\"id\":\"req_propose_consistency\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"%s\",\"payload\":{\"payloadRef\":\"payload_0000000000000006\"}}",
        session_state_id());
    reset_written();
    send_line(consistency_propose_line);
    expect_no_response();
    assert(usb_transport_pending_request().kind == UsbPendingRequestKind::credential_propose);
    assert(sui_zklogin_proposal_state_active());

    reset_written();
    assert(usb_transport_reject_pending_request("auth_unavailable"));
    expect_written_contains("\"id\":\"req_propose_consistency\"");
    expect_written_contains("\"method\":\"credential_propose\"");
    expect_written_contains("\"success\":true");
    expect_written_contains("\"status\":\"consistency_error\"");
    expect_written_contains("\"reasonCode\":\"consistency_error\"");
    expect_written_contains("\"sessionEnded\":true");
    expect_written_not_contains("\"code\":\"auth_unavailable\"");
    assert(usb_transport_pending_request().kind == UsbPendingRequestKind::none);
    assert(!credential_preparation_snapshot().active);
    assert(!sui_zklogin_proposal_state_active());
    assert(!session_state_active());
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

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
  -DSTOPWATCH_ZKLOGIN_CREDENTIAL_STORE_HOST_TEST \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_DIR}" \
  -I"${MICROSUI_CORE}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/usb_transport_credential_flow_test.cpp" \
  "${RUNTIME_DIR}/credential_preparation_state.cpp" \
  "${RUNTIME_DIR}/payload_digest.cpp" \
  "${RUNTIME_DIR}/payload_transfer_request.cpp" \
  "${RUNTIME_DIR}/payload_transfer_state.cpp" \
  "${RUNTIME_DIR}/protocol_input_encoding.cpp" \
  "${RUNTIME_DIR}/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${RUNTIME_DIR}/state_projection.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_credential_clear.cpp" \
  "${RUNTIME_DIR}/sui_public_material.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_credential_store.cpp" \
  "${RUNTIME_DIR}/sui_zklogin_proposal_state.cpp" \
  "${COMMON_DIR}/protocol/base64.cpp" \
  "${COMMON_DIR}/protocol/device_contract.cpp" \
  "${COMMON_DIR}/protocol/device_response.cpp" \
  "${COMMON_DIR}/protocol/request_id.cpp" \
  "${COMMON_DIR}/protocol/request_line.cpp" \
  "${COMMON_DIR}/sui/zklogin_credential_outcome.cpp" \
  "${COMMON_DIR}/sui/zklogin_credential_payload.cpp" \
  "${COMMON_DIR}/sui/zklogin_proof_record.cpp" \
  "${COMMON_DIR}/transport/payload_delivery_admission.cpp" \
  "${COMMON_DIR}/transport/payload_delivery_primitives.cpp" \
  "${COMMON_DIR}/transport/usb_link_state.cpp" \
  "${COMMON_DIR}/transport/usb_session_grace.cpp" \
  "${TMP_DIR}/byte_conversions.o" \
  "${TMP_DIR}/key_management.o" \
  "${TMP_DIR}/monocypher.o" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -Wl,-dead_strip \
  -o "${TMP_DIR}/usb_transport_credential_flow_test"

"${TMP_DIR}/usb_transport_credential_flow_test"
echo "StopWatch USB transport credential flow tests passed"
