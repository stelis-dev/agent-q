#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_payload_transfer_handlers.sh

ESP-IDF must already be active in the shell so IDF_PATH points to the ESP-IDF
checkout. This host test compiles the USB payload transfer handlers with the real
volatile store and verifies guard ordering, route projection, chunk append,
finish, and abort behavior. It does NOT require hardware.
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
COMMON_TRANSPORT_DIR="${COMMON_ROOT}/transport"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

if [[ -z "${IDF_PATH:-}" ]]; then
  echo "IDF_PATH is not set. Source ESP-IDF v5.5.4 export.sh before running this test." >&2
  exit 1
fi

MBEDTLS_ROOT="${IDF_PATH}/components/mbedtls/mbedtls"
MBEDTLS_INCLUDE_DIR="${MBEDTLS_ROOT}/include"
MBEDTLS_LIBRARY_DIR="${MBEDTLS_ROOT}/library"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${MBEDTLS_INCLUDE_DIR}/mbedtls/sha256.h" \
  "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  "${COMMON_ROOT}/protocol/usb_active_session_request_guard.cpp" \
  "${COMMON_ROOT}/protocol/usb_active_session_request_guard.h" \
  "${COMMON_TRANSPORT_DIR}/usb_payload_transfer_handlers.cpp" \
  "${COMMON_TRANSPORT_DIR}/usb_payload_transfer_handlers.h" \
  "${COMMON_ROOT}/transport/payload_delivery_admission.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_admission.h" \
  "${COMMON_ROOT}/transport/payload_delivery_operation_kind.h" \
  "${COMMON_ROOT}/transport/payload_delivery_primitives.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_primitives.h" \
  "${COMMON_ROOT}/transport/payload_delivery_store.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_store.h" \
  "${COMMON_ROOT}/protocol/base64.cpp" \
  "${COMMON_ROOT}/protocol/session_state.cpp" \
  "${COMMON_ROOT}/protocol/sign_route.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-payload-transfer-handlers.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/firmware_common" "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"

cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
typedef uint32_t TickType_t;
H

cat >"${TMP_DIR}/stubs.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "protocol/approval_history.h"
#include "protocol/protocol_constants.h"

namespace {

char g_response_transfer_id[96] = {};
char g_response_payload_ref[96] = {};
char g_response_method[80] = {};
char g_response_received_bytes[24] = {};
char g_response_chunk_max_bytes[24] = {};
char g_response_status[24] = {};
char g_response_json[512] = {};
bool g_decode_should_fail_after_write = false;
uint8_t* g_last_decode_output = nullptr;
size_t g_last_decode_output_size = 0;
constexpr const uint8_t kSyntheticPayload[] = {
    19, 92, 165, 238, 55, 128, 201, 18, 91, 164, 237, 54, 127,
    200, 17, 90, 163, 236, 53, 126, 199, 16, 89, 162, 235, 52,
    125, 198, 15, 88, 161, 234, 51, 124, 197, 14, 87,
};
constexpr const char* kSyntheticPayloadBase64 =
    "E1yl7jeAyRJbpO02f8gRWqPsNX7HEFmi6zR9xg9YoeozfMUOVw==";
constexpr const char* kSyntheticPayloadDigest =
    "sha256:c1280277d943fff9680e04557dacee6b39f6b22e5b381430576269feb22b679e";

}  // namespace

extern "C" int base64_to_bytes(
    const char* input,
    size_t input_size,
    uint8_t* output,
    size_t output_size)
{
    g_last_decode_output = output;
    g_last_decode_output_size = output_size;
    if (g_decode_should_fail_after_write) {
        if (output != nullptr && output_size > 0) {
            memset(output, 0xA5, output_size);
        }
        return -1;
    }
    if (input == nullptr || output == nullptr ||
        input_size != strlen(kSyntheticPayloadBase64) ||
        output_size < sizeof(kSyntheticPayload) ||
        strcmp(input, kSyntheticPayloadBase64) != 0) {
        return -1;
    }
    memcpy(output, kSyntheticPayload, sizeof(kSyntheticPayload));
    return 0;
}

namespace signing {

void wipe_sensitive_buffer(void* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    for (size_t index = 0; index < size; ++index) {
        cursor[index] = 0;
    }
}

bool approval_history_digest_payload(
    const uint8_t* payload,
    size_t payload_size,
    char* output,
    size_t output_size)
{
    if (payload == nullptr || output == nullptr ||
        output_size != kApprovalHistoryDigestSize ||
        payload_size != sizeof(kSyntheticPayload) ||
        memcmp(payload, kSyntheticPayload, sizeof(kSyntheticPayload)) != 0) {
        return false;
    }
    snprintf(output, output_size, "%s", kSyntheticPayloadDigest);
    return true;
}

bool usb_response_write_json(JsonDocument& response)
{
    serializeJson(response, g_response_json, sizeof(g_response_json));
    snprintf(g_response_method, sizeof(g_response_method), "%s", response["method"] | "");
    snprintf(g_response_transfer_id, sizeof(g_response_transfer_id), "%s", response["result"]["transferId"] | "");
    snprintf(g_response_payload_ref, sizeof(g_response_payload_ref), "%s", response["result"]["payloadRef"] | "");
    snprintf(g_response_received_bytes, sizeof(g_response_received_bytes), "%s", response["result"]["receivedBytes"] | "");
    snprintf(g_response_chunk_max_bytes, sizeof(g_response_chunk_max_bytes), "%s", response["result"]["chunkMaxBytes"] | "");
    snprintf(g_response_status, sizeof(g_response_status), "%s", response["result"]["status"] | "");
    return true;
}

bool usb_response_write_success_result(const char* id, const char* method, JsonObjectConst result)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["success"] = true;
    response["method"] = method;
    response["result"].set(result);
    return usb_response_write_json(response);
}

bool usb_response_write_transport_success_result(const char* id, JsonObjectConst result)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["success"] = true;
    response["result"].set(result);
    return usb_response_write_json(response);
}

}  // namespace signing

const char* response_transfer_id() { return g_response_transfer_id; }
const char* response_payload_ref() { return g_response_payload_ref; }
const char* response_method() { return g_response_method; }
const char* response_received_bytes() { return g_response_received_bytes; }
const char* response_chunk_max_bytes() { return g_response_chunk_max_bytes; }
const char* response_status() { return g_response_status; }
const char* response_json() { return g_response_json; }
void set_decode_should_fail_after_write(bool value) { g_decode_should_fail_after_write = value; }
bool last_decode_output_wiped()
{
    if (g_last_decode_output == nullptr || g_last_decode_output_size == 0) {
        return false;
    }
    for (size_t index = 0; index < g_last_decode_output_size; ++index) {
        if (g_last_decode_output[index] != 0) {
            return false;
        }
    }
    return true;
}
CPP

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <string>

#include "transport/payload_delivery_store.h"
#include "transport/usb_payload_transfer_handlers.h"

extern const char* response_transfer_id();
extern const char* response_payload_ref();
extern const char* response_method();
extern const char* response_received_bytes();
extern const char* response_chunk_max_bytes();
extern const char* response_status();
extern const char* response_json();
extern void set_decode_should_fail_after_write(bool value);
extern bool last_decode_output_wiped();

namespace signing {
bool usb_response_write_success_result(const char* id, const char* method, JsonObjectConst result);
bool usb_response_write_transport_success_result(const char* id, JsonObjectConst result);
}

namespace {

int g_error_calls = 0;
int g_log_calls = 0;
int g_material_calls = 0;
int g_busy_calls = 0;
int g_session_calls = 0;
size_t g_last_deadline_size = 0;
signing::TimeoutTick g_current_tick = 0;
bool g_material_ready = true;
bool g_busy = false;
bool g_session_valid = true;
const char* g_last_error_code = nullptr;
const char* g_last_session = nullptr;

void assert_payload_transfer_response_has_no_method()
{
    assert(strcmp(response_method(), "") == 0);
    assert(strstr(response_json(), "\"method\"") == nullptr);
}

constexpr const char* kDigest =
    "sha256:c1280277d943fff9680e04557dacee6b39f6b22e5b381430576269feb22b679e";
constexpr const char* kPayloadChunk =
    "E1yl7jeAyRJbpO02f8gRWqPsNX7HEFmi6zR9xg9YoeozfMUOVw==";
constexpr const char* kPayloadSize = "37";
constexpr const char* kPayloadMaxSize = "131072";
constexpr const char* kPayloadMaxPlusOneSize = "131073";

std::string oversized_chunk_base64()
{
    const size_t decoded_size = signing::kPayloadDeliveryDefaultChunkMaxBytes + 1;
    std::string encoded(((decoded_size + 2) / 3) * 4, 'A');
    const size_t remainder = decoded_size % 3;
    if (remainder == 1) {
        encoded[encoded.size() - 1] = '=';
        encoded[encoded.size() - 2] = '=';
    } else if (remainder == 2) {
        encoded[encoded.size() - 1] = '=';
    }
    return encoded;
}

void reset_state()
{
    g_error_calls = 0;
    g_log_calls = 0;
    g_material_calls = 0;
    g_busy_calls = 0;
    g_session_calls = 0;
    g_last_deadline_size = 0;
    g_current_tick = 0;
    g_material_ready = true;
    g_busy = false;
    g_session_valid = true;
    g_last_error_code = nullptr;
    g_last_session = nullptr;
    set_decode_should_fail_after_write(false);
    signing::payload_delivery_store_reset();
}

bool write_method_error(const char*, const char*, const char* code)
{
    ++g_error_calls;
    g_last_error_code = code;
    return true;
}

void log_write_failure(const char*, const char*)
{
    ++g_log_calls;
}

bool material_ready()
{
    ++g_material_calls;
    return g_material_ready;
}

bool write_busy(const char* id, const signing::UsbOperationResponseWriter& writer)
{
    ++g_busy_calls;
    if (g_busy) {
        writer.write_error(id, "busy");
    }
    return g_busy;
}

bool require_session(
    const char* id,
    const char* session_id,
    const signing::UsbOperationResponseWriter& writer)
{
    ++g_session_calls;
    g_last_session = session_id;
    if (!g_session_valid) {
        writer.write_error(id, "invalid_session");
        return false;
    }
    return g_session_valid;
}

signing::TimeoutWindow timeout_window_for_size(size_t size_bytes)
{
    g_last_deadline_size = size_bytes;
    return signing::timeout_window_from_deadline(0, 99);
}

signing::TimeoutTick current_tick()
{
    return g_current_tick;
}

signing::UsbOperationResponseWriter make_writer()
{
    return signing::UsbOperationResponseWriter{
        write_method_error,
        signing::usb_response_write_success_result,
        signing::usb_response_write_transport_success_result,
        log_write_failure};
}

signing::UsbPayloadTransferHandlerOps make_ops()
{
    return signing::UsbPayloadTransferHandlerOps{
        material_ready,
        write_busy,
        require_session,
        current_tick,
        timeout_window_for_size,
    };
}

JsonDocument parse(const char* json)
{
    JsonDocument request;
    const DeserializationError error = deserializeJson(request, json);
    assert(!error);
    return request;
}

void begin_transfer()
{
    char request[512] = {};
    snprintf(
        request,
        sizeof(request),
        "{\"id\":\"req_begin\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
        "\"totalBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
        kPayloadSize,
        kDigest);
    JsonDocument doc = parse(request);
    signing::handle_usb_payload_transfer_begin_request("req_begin", doc, make_writer(), make_ops());
    assert(g_error_calls == 0);
    assert_payload_transfer_response_has_no_method();
    assert(strncmp(response_transfer_id(), "transfer_", 7) == 0);
    assert(strcmp(response_received_bytes(), "0") == 0);
    assert(strcmp(response_chunk_max_bytes(), "2700") == 0);
    assert(strstr(response_json(), "\"receivedBytes\":\"0\"") != nullptr);
    assert(strstr(response_json(), "\"chunkMaxBytes\":\"2700\"") != nullptr);
    assert(g_last_deadline_size == 37);
}

void begin_max_payload_transfer()
{
    char request[512] = {};
    snprintf(
        request,
        sizeof(request),
        "{\"id\":\"req_begin_max\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
        "\"totalBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
        kPayloadMaxSize,
        kDigest);
    JsonDocument doc = parse(request);
    signing::handle_usb_payload_transfer_begin_request(
        "req_begin_max",
        doc,
        make_writer(),
        make_ops());
    assert(g_error_calls == 0);
    assert_payload_transfer_response_has_no_method();
    assert(strncmp(response_transfer_id(), "transfer_", 7) == 0);
    assert(strcmp(response_received_bytes(), "0") == 0);
    assert(strcmp(response_chunk_max_bytes(), "2700") == 0);
    assert(g_last_deadline_size == 131072);
}

void begin_max_plus_one_payload_transfer_fails_closed()
{
    char request[512] = {};
    snprintf(
        request,
        sizeof(request),
        "{\"id\":\"req_begin_oversize\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
        "\"totalBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
        kPayloadMaxPlusOneSize,
        kDigest);
    JsonDocument doc = parse(request);
    signing::handle_usb_payload_transfer_begin_request(
        "req_begin_oversize",
        doc,
        make_writer(),
        make_ops());
    assert(g_error_calls == 1);
    assert(strcmp(g_last_error_code, "payload_too_large") == 0);
    assert(g_last_deadline_size == 131073);
    assert(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle);
}

void append_chunk()
{
    char request[256] = {};
    snprintf(
        request,
        sizeof(request),
        "{\"id\":\"req_chunk\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"%s\",\"offsetBytes\":\"0\","
        "\"chunk\":\"%s\"}",
        response_transfer_id(),
        kPayloadChunk);
    JsonDocument doc = parse(request);
    signing::handle_usb_payload_transfer_chunk_request("req_chunk", doc, make_writer(), make_ops());
    assert(g_error_calls == 0);
    assert_payload_transfer_response_has_no_method();
    assert(strcmp(response_received_bytes(), kPayloadSize) == 0);
    assert(strstr(response_json(), "\"receivedBytes\":\"37\"") != nullptr);
}

void append_oversized_decoded_chunk_wipes_matching_transfer()
{
    begin_transfer();
    char transfer_id[96] = {};
    snprintf(transfer_id, sizeof(transfer_id), "%s", response_transfer_id());
    const std::string chunk = oversized_chunk_base64();
    const std::string request =
        std::string("{\"id\":\"req_chunk_oversize\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\",") +
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"" + transfer_id +
        "\",\"offsetBytes\":\"0\",\"chunk\":\"" + chunk + "\"}";
    JsonDocument doc = parse(request.c_str());
    signing::handle_usb_payload_transfer_chunk_request(
        "req_chunk_oversize",
        doc,
        make_writer(),
        make_ops());
    assert(g_error_calls == 1);
    assert(strcmp(g_last_error_code, "invalid_params") == 0);
    assert(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle);
}

void append_oversized_decoded_chunk_preserves_wrong_session_transfer()
{
    begin_transfer();
    char transfer_id[96] = {};
    snprintf(transfer_id, sizeof(transfer_id), "%s", response_transfer_id());
    const std::string chunk = oversized_chunk_base64();
    const std::string request =
        std::string("{\"id\":\"req_chunk_oversize_wrong_session\",\"version\":1,") +
        "\"type\":\"payload_transfer\",\"action\":\"chunk\",\"sessionId\":\"session_bbbbbbbbbbbbbbbb\",\"transferId\":\"" +
        transfer_id + "\",\"offsetBytes\":\"0\",\"chunk\":\"" + chunk + "\"}";
    JsonDocument doc = parse(request.c_str());
    signing::handle_usb_payload_transfer_chunk_request(
        "req_chunk_oversize_wrong_session",
        doc,
        make_writer(),
        make_ops());
    assert(g_error_calls == 1);
    assert(strcmp(g_last_error_code, "invalid_session") == 0);
    assert(signing::payload_delivery_advance_and_snapshot(0).state ==
           signing::PayloadDeliveryState::receiving);
}

void finish_transfer()
{
    char request[256] = {};
    signing::PayloadDeliverySnapshot snapshot = signing::payload_delivery_advance_and_snapshot(0);
    snprintf(
        request,
        sizeof(request),
        "{\"id\":\"req_finish\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"finish\","
        "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"%s\"}",
        snapshot.transfer_id);
    JsonDocument doc = parse(request);
    signing::handle_usb_payload_transfer_finish_request("req_finish", doc, make_writer(), make_ops());
    assert(g_error_calls == 0);
    assert_payload_transfer_response_has_no_method();
    assert(strncmp(response_payload_ref(), "payload_", 8) == 0);
    assert(strstr(response_json(), "\"payloadRef\":\"payload_") != nullptr);
}

}  // namespace

int main()
{
    {
        reset_state();
        begin_max_payload_transfer();
        signing::payload_delivery_store_reset();
    }

    {
        reset_state();
        begin_max_plus_one_payload_transfer_fails_closed();
    }

    {
        reset_state();
        begin_transfer();
        append_chunk();
        finish_transfer();
        char payload_ref[96] = {};
        snprintf(payload_ref, sizeof(payload_ref), "%s", response_payload_ref());
        char request[256] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_abort_finalized\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"payloadRef\":\"%s\"}",
            payload_ref);
        JsonDocument doc = parse(request);
        signing::handle_usb_payload_transfer_abort_request(
            "req_abort_finalized",
            doc,
            make_writer(),
            make_ops());
        assert(g_error_calls == 0);
        assert_payload_transfer_response_has_no_method();
        assert(strcmp(response_status(), "") == 0);
        assert(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle);
    }

    {
        reset_state();
        begin_transfer();
        char transfer_id[96] = {};
        snprintf(transfer_id, sizeof(transfer_id), "%s", response_transfer_id());
        char request[256] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_abort\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"%s\"}",
            transfer_id);
        JsonDocument doc = parse(request);
        signing::handle_usb_payload_transfer_abort_request("req_abort", doc, make_writer(), make_ops());
        assert(g_error_calls == 0);
        assert_payload_transfer_response_has_no_method();
        assert(strcmp(response_status(), "") == 0);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_abort_both\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\","
            "\"payloadRef\":\"payload_0000000000000001\"}");
        signing::handle_usb_payload_transfer_abort_request("req_abort_both", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_request") == 0);
    }

    {
        reset_state();
        g_material_ready = false;
        JsonDocument doc = parse("{\"id\":\"req\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\"}");
        signing::handle_usb_payload_transfer_begin_request("req", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_busy_calls == 0);
        assert(g_session_calls == 0);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_chunk\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\","
            "\"offsetBytes\":\"0\",\"chunk\":\"E1yl7jeAyRJbpO02f8gRWqPsNX7HEFmi6zR9xg9YoeozfMUOVw==\"}");
        signing::handle_usb_payload_transfer_chunk_request("req_chunk", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(g_busy_calls == 1);
        assert(g_session_calls == 1);
        assert(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle);
    }

    {
        reset_state();
        begin_transfer();
        char transfer_id[96] = {};
        snprintf(transfer_id, sizeof(transfer_id), "%s", response_transfer_id());
        g_current_tick = 99;
        char request[256] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_chunk_expired\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"%s\","
            "\"offsetBytes\":\"0\",\"chunk\":\"%s\"}",
            transfer_id,
            kPayloadChunk);
        JsonDocument doc = parse(request);
        signing::handle_usb_payload_transfer_chunk_request(
            "req_chunk_expired",
            doc,
            make_writer(),
            make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_chunk\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\","
            "\"offsetBytes\":\"0\",\"chunk\":\"E1yl7jeAyRJbpO02f8gRWqPsNX7HEFmi6zR9xg9YoeozfMUOVw==\"}");
        signing::handle_usb_payload_transfer_chunk_request("req_chunk_missing_transfer", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(g_busy_calls == 1);
        assert(g_session_calls == 1);
        assert(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_finish\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"finish\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\"}");
        signing::handle_usb_payload_transfer_finish_request("req_finish", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(g_busy_calls == 1);
        assert(g_session_calls == 1);
        assert(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle);
    }

    {
        reset_state();
        begin_transfer();
        char transfer_id[96] = {};
        snprintf(transfer_id, sizeof(transfer_id), "%s", response_transfer_id());
        append_chunk();
        g_current_tick = 99;
        char request[256] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_finish_expired\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"finish\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"%s\"}",
            transfer_id);
        JsonDocument doc = parse(request);
        signing::handle_usb_payload_transfer_finish_request(
            "req_finish_expired",
            doc,
            make_writer(),
            make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_finish\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"finish\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\"}");
        signing::handle_usb_payload_transfer_finish_request("req_finish_missing_transfer", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(g_busy_calls == 1);
        assert(g_session_calls == 1);
        assert(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle);
    }

    {
        reset_state();
        begin_transfer();
        set_decode_should_fail_after_write(true);
        JsonDocument doc = parse(
            "{\"id\":\"req_chunk\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\","
            "\"offsetBytes\":\"0\",\"chunk\":\"E1yl7jeAyRJbpO02f8gRWqPsNX7HEFmi6zR9xg9YoeozfMUOVw==\"}");
        signing::handle_usb_payload_transfer_chunk_request("req_chunk", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(last_decode_output_wiped());
        assert(signing::payload_delivery_advance_and_snapshot(0).state ==
               signing::PayloadDeliveryState::receiving);
    }

    {
        reset_state();
        begin_transfer();
        append_chunk();
        finish_transfer();
        char payload_ref[96] = {};
        snprintf(payload_ref, sizeof(payload_ref), "%s", response_payload_ref());
        g_current_tick = 99;
        char request[256] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_abort_expired\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"%s\"}",
            payload_ref);
        JsonDocument doc = parse(request);
        signing::handle_usb_payload_transfer_abort_request(
            "req_abort_expired",
            doc,
            make_writer(),
            make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle);
    }

    {
        reset_state();
        append_oversized_decoded_chunk_wipes_matching_transfer();
    }

    {
        reset_state();
        append_oversized_decoded_chunk_preserves_wrong_session_transfer();
    }

    {
        reset_state();
        begin_transfer();
        char request[512] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_begin_2\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
            "\"totalBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
            kPayloadSize,
            kDigest);
        JsonDocument doc = parse(request);
        signing::handle_usb_payload_transfer_begin_request("req_begin_2", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(signing::payload_delivery_advance_and_snapshot(0).state ==
               signing::PayloadDeliveryState::receiving);
    }

    {
        reset_state();
        begin_transfer();
        char request[512] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_begin_2\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
            "\"totalBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
            kPayloadSize,
            kDigest);
        JsonDocument doc = parse(request);
        signing::handle_usb_payload_transfer_begin_request("req_begin_2_busy", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(signing::payload_delivery_advance_and_snapshot(0).state ==
               signing::PayloadDeliveryState::receiving);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_begin\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
            "\"totalBytes\":\"not-decimal\",\"payloadDigest\":\"not-digest\"}");
        signing::handle_usb_payload_transfer_begin_request("req_begin", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_begin_extra\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
            "\"totalBytes\":\"37\",\"payloadDigest\":\"sha256:c1280277d943fff9680e04557dacee6b39f6b22e5b381430576269feb22b679e\","
            "\"extra\":\"not-allowed\"}");
        signing::handle_usb_payload_transfer_begin_request("req_begin_extra", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_request") == 0);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_chunk_extra\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\","
            "\"offsetBytes\":\"0\",\"chunk\":\"E1yl7jeAyRJbpO02f8gRWqPsNX7HEFmi6zR9xg9YoeozfMUOVw==\","
            "\"extra\":\"not-allowed\"}");
        signing::handle_usb_payload_transfer_chunk_request("req_chunk_extra", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_request") == 0);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_finish_extra\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"finish\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\","
            "\"extra\":\"not-allowed\"}");
        signing::handle_usb_payload_transfer_finish_request("req_finish_extra", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_request") == 0);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_abort_extra\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\","
            "\"extra\":\"not-allowed\"}");
        signing::handle_usb_payload_transfer_abort_request("req_abort_extra", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_request") == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        char request[512] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_begin\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\","
            "\"sessionId\":\"session_aaaaaaaaaaaaaaaa\","
            "\"totalBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
            kPayloadSize,
            kDigest);
        JsonDocument doc = parse(request);
        signing::handle_usb_payload_transfer_begin_request("req_begin", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_session_calls == 1);
        assert(strcmp(g_last_session, "session_aaaaaaaaaaaaaaaa") == 0);
        assert(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle);
    }

    printf("USB payload transfer handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${COMMON_ROOT}/protocol/usb_active_session_request_guard.cpp" \
  -o "${TMP_DIR}/active_session_request_guard.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${COMMON_TRANSPORT_DIR}/usb_payload_transfer_handlers.cpp" \
  -o "${TMP_DIR}/usb_payload_transfer_handlers.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${COMMON_ROOT}/transport/payload_delivery_primitives.cpp" \
  -o "${TMP_DIR}/payload_delivery_primitives.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${COMMON_ROOT}/transport/payload_delivery_store.cpp" \
  -o "${TMP_DIR}/payload_delivery_store.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${COMMON_ROOT}/transport/payload_delivery_admission.cpp" \
  -o "${TMP_DIR}/payload_delivery_admission.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${COMMON_ROOT}/protocol/session_state.cpp" \
  -o "${TMP_DIR}/session.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -c "${COMMON_ROOT}/protocol/base64.cpp" \
  -o "${TMP_DIR}/base64.o"

cc -std=c99 -Wall -Wextra -Werror \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"

cc -std=c99 -Wall -Wextra -Werror \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${TMP_DIR}/stubs.cpp" \
  "${TMP_DIR}/active_session_request_guard.o" \
  "${TMP_DIR}/usb_payload_transfer_handlers.o" \
  "${TMP_DIR}/payload_delivery_primitives.o" \
  "${TMP_DIR}/payload_delivery_store.o" \
  "${TMP_DIR}/payload_delivery_admission.o" \
  "${TMP_DIR}/session.o" \
  "${TMP_DIR}/base64.o" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
