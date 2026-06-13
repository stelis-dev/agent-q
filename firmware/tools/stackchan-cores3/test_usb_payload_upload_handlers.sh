#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_payload_upload_handlers.sh

ESP-IDF must already be active in the shell so IDF_PATH points to the ESP-IDF
checkout. This host test compiles the USB payload upload handlers with the real
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
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_AGENT_Q_DIR="${REPO_ROOT}/firmware/src/common/agent_q"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

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
  "${AGENT_Q_DIR}/agent_q_usb_payload_upload_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_payload_upload_handlers.h" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_admission.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_admission.h" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_primitives.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_primitives.h" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_store.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_store.h" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${COMMON_AGENT_Q_DIR}/agent_q_sign_route.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-payload-upload-handlers.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/freertos"
ln -s "${COMMON_AGENT_Q_DIR}/policy" "${TMP_DIR}/agent_q_common/policy"

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

#include "agent_q_approval_history.h"

namespace {

char g_response_type[48] = {};
char g_response_upload_id[96] = {};
char g_response_payload_ref[96] = {};
char g_response_chain[32] = {};
char g_response_method[80] = {};
char g_response_payload_kind[24] = {};
char g_response_size_bytes[24] = {};
char g_response_payload_digest[96] = {};
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

namespace agent_q {

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
        output_size != kAgentQApprovalHistoryDigestSize ||
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
    snprintf(g_response_type, sizeof(g_response_type), "%s", response["type"] | "");
    snprintf(g_response_upload_id, sizeof(g_response_upload_id), "%s", response["uploadId"] | "");
    snprintf(g_response_payload_ref, sizeof(g_response_payload_ref), "%s", response["payloadRef"] | "");
    snprintf(g_response_chain, sizeof(g_response_chain), "%s", response["chain"] | "");
    snprintf(g_response_method, sizeof(g_response_method), "%s", response["method"] | "");
    snprintf(g_response_payload_kind, sizeof(g_response_payload_kind), "%s", response["payloadKind"] | "");
    snprintf(g_response_size_bytes, sizeof(g_response_size_bytes), "%s", response["sizeBytes"] | "");
    snprintf(g_response_payload_digest, sizeof(g_response_payload_digest), "%s", response["payloadDigest"] | "");
    snprintf(g_response_received_bytes, sizeof(g_response_received_bytes), "%s", response["receivedBytes"] | "");
    snprintf(g_response_chunk_max_bytes, sizeof(g_response_chunk_max_bytes), "%s", response["chunkMaxBytes"] | "");
    snprintf(g_response_status, sizeof(g_response_status), "%s", response["status"] | "");
    return true;
}

}  // namespace agent_q

const char* response_type() { return g_response_type; }
const char* response_upload_id() { return g_response_upload_id; }
const char* response_payload_ref() { return g_response_payload_ref; }
const char* response_chain() { return g_response_chain; }
const char* response_method() { return g_response_method; }
const char* response_payload_kind() { return g_response_payload_kind; }
const char* response_size_bytes() { return g_response_size_bytes; }
const char* response_payload_digest() { return g_response_payload_digest; }
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

#include "agent_q_payload_delivery_store.h"
#include "agent_q_usb_payload_upload_handlers.h"

extern const char* response_type();
extern const char* response_upload_id();
extern const char* response_payload_ref();
extern const char* response_chain();
extern const char* response_method();
extern const char* response_payload_kind();
extern const char* response_size_bytes();
extern const char* response_payload_digest();
extern const char* response_received_bytes();
extern const char* response_chunk_max_bytes();
extern const char* response_status();
extern const char* response_json();
extern void set_decode_should_fail_after_write(bool value);
extern bool last_decode_output_wiped();

namespace {

int g_error_calls = 0;
int g_log_calls = 0;
int g_material_calls = 0;
int g_busy_calls = 0;
int g_session_calls = 0;
size_t g_last_deadline_size = 0;
agent_q::AgentQTimeoutTick g_current_tick = 0;
bool g_material_ready = true;
bool g_busy = false;
bool g_session_valid = true;
const char* g_last_error_code = nullptr;
const char* g_last_error_message = nullptr;
const char* g_last_session = nullptr;

constexpr const char* kDigest =
    "sha256:c1280277d943fff9680e04557dacee6b39f6b22e5b381430576269feb22b679e";
constexpr const char* kPayloadChunk =
    "E1yl7jeAyRJbpO02f8gRWqPsNX7HEFmi6zR9xg9YoeozfMUOVw==";
constexpr const char* kPayloadSize = "37";
constexpr const char* kPayloadMaxSize = "131072";
constexpr const char* kPayloadMaxPlusOneSize = "131073";

std::string oversized_chunk_base64()
{
    const size_t decoded_size = agent_q::kAgentQPayloadDeliveryDefaultChunkMaxBytes + 1;
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
    g_last_error_message = nullptr;
    g_last_session = nullptr;
    set_decode_should_fail_after_write(false);
    agent_q::payload_delivery_store_reset();
}

bool write_error(const char*, const char* code, const char* message)
{
    ++g_error_calls;
    g_last_error_code = code;
    g_last_error_message = message;
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

bool write_busy(const char*)
{
    ++g_busy_calls;
    return g_busy;
}

bool require_session(const char*, const char* session_id)
{
    ++g_session_calls;
    g_last_session = session_id;
    if (!g_session_valid) {
        ++g_error_calls;
        g_last_error_code = "invalid_session";
        g_last_error_message = "Session is unknown or already ended.";
        return false;
    }
    return g_session_valid;
}

agent_q::AgentQTimeoutWindow timeout_window_for_size(size_t size_bytes)
{
    g_last_deadline_size = size_bytes;
    return agent_q::timeout_window_from_deadline(0, 99);
}

agent_q::AgentQTimeoutTick current_tick()
{
    return g_current_tick;
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{write_error, log_write_failure};
}

agent_q::AgentQUsbPayloadUploadHandlerOps make_ops()
{
    return agent_q::AgentQUsbPayloadUploadHandlerOps{
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

void begin_upload()
{
    char request[512] = {};
    snprintf(
        request,
        sizeof(request),
        "{\"id\":\"req_begin\",\"version\":1,\"type\":\"payload_upload_begin\","
        "\"sessionId\":\"session_abcdef\",\"chain\":\"sui\",\"method\":\"sign_transaction\","
        "\"payloadKind\":\"transaction\",\"sizeBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
        kPayloadSize,
        kDigest);
    JsonDocument doc = parse(request);
    agent_q::handle_usb_payload_upload_begin_request("req_begin", doc, make_writer(), make_ops());
    assert(g_error_calls == 0);
    assert(strcmp(response_type(), "payload_upload_begin_result") == 0);
    assert(strncmp(response_upload_id(), "upload_", 7) == 0);
    assert(strcmp(response_received_bytes(), "0") == 0);
    assert(strcmp(response_chunk_max_bytes(), "2700") == 0);
    assert(strstr(response_json(), "\"receivedBytes\":\"0\"") != nullptr);
    assert(strstr(response_json(), "\"chunkMaxBytes\":\"2700\"") != nullptr);
    assert(g_last_deadline_size == 37);
}

void begin_max_payload_upload()
{
    char request[512] = {};
    snprintf(
        request,
        sizeof(request),
        "{\"id\":\"req_begin_max\",\"version\":1,\"type\":\"payload_upload_begin\","
        "\"sessionId\":\"session_abcdef\",\"chain\":\"sui\",\"method\":\"sign_transaction\","
        "\"payloadKind\":\"transaction\",\"sizeBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
        kPayloadMaxSize,
        kDigest);
    JsonDocument doc = parse(request);
    agent_q::handle_usb_payload_upload_begin_request(
        "req_begin_max",
        doc,
        make_writer(),
        make_ops());
    assert(g_error_calls == 0);
    assert(strcmp(response_type(), "payload_upload_begin_result") == 0);
    assert(strncmp(response_upload_id(), "upload_", 7) == 0);
    assert(strcmp(response_received_bytes(), "0") == 0);
    assert(strcmp(response_chunk_max_bytes(), "2700") == 0);
    assert(g_last_deadline_size == 131072);
}

void begin_max_plus_one_payload_upload_fails_closed()
{
    char request[512] = {};
    snprintf(
        request,
        sizeof(request),
        "{\"id\":\"req_begin_oversize\",\"version\":1,\"type\":\"payload_upload_begin\","
        "\"sessionId\":\"session_abcdef\",\"chain\":\"sui\",\"method\":\"sign_transaction\","
        "\"payloadKind\":\"transaction\",\"sizeBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
        kPayloadMaxPlusOneSize,
        kDigest);
    JsonDocument doc = parse(request);
    agent_q::handle_usb_payload_upload_begin_request(
        "req_begin_oversize",
        doc,
        make_writer(),
        make_ops());
    assert(g_error_calls == 1);
    assert(strcmp(g_last_error_code, "unsupported_payload_size") == 0);
    assert(g_last_deadline_size == 131073);
    assert(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle);
}

void append_chunk()
{
    char request[256] = {};
    snprintf(
        request,
        sizeof(request),
        "{\"id\":\"req_chunk\",\"version\":1,\"type\":\"payload_upload_chunk\","
        "\"sessionId\":\"session_abcdef\",\"uploadId\":\"%s\",\"offsetBytes\":\"0\","
        "\"chunk\":\"%s\"}",
        response_upload_id(),
        kPayloadChunk);
    JsonDocument doc = parse(request);
    agent_q::handle_usb_payload_upload_chunk_request("req_chunk", doc, make_writer(), make_ops());
    assert(g_error_calls == 0);
    assert(strcmp(response_type(), "payload_upload_chunk_result") == 0);
    assert(strcmp(response_received_bytes(), kPayloadSize) == 0);
    assert(strstr(response_json(), "\"receivedBytes\":\"37\"") != nullptr);
}

void append_oversized_decoded_chunk_wipes_matching_upload()
{
    begin_upload();
    char upload_id[96] = {};
    snprintf(upload_id, sizeof(upload_id), "%s", response_upload_id());
    const std::string chunk = oversized_chunk_base64();
    const std::string request =
        std::string("{\"id\":\"req_chunk_oversize\",\"version\":1,\"type\":\"payload_upload_chunk\",") +
        "\"sessionId\":\"session_abcdef\",\"uploadId\":\"" + upload_id +
        "\",\"offsetBytes\":\"0\",\"chunk\":\"" + chunk + "\"}";
    JsonDocument doc = parse(request.c_str());
    agent_q::handle_usb_payload_upload_chunk_request(
        "req_chunk_oversize",
        doc,
        make_writer(),
        make_ops());
    assert(g_error_calls == 1);
    assert(strcmp(g_last_error_code, "invalid_params") == 0);
    assert(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle);
}

void append_oversized_decoded_chunk_preserves_wrong_session_upload()
{
    begin_upload();
    char upload_id[96] = {};
    snprintf(upload_id, sizeof(upload_id), "%s", response_upload_id());
    const std::string chunk = oversized_chunk_base64();
    const std::string request =
        std::string("{\"id\":\"req_chunk_oversize_wrong_session\",\"version\":1,") +
        "\"type\":\"payload_upload_chunk\",\"sessionId\":\"session_other\",\"uploadId\":\"" +
        upload_id + "\",\"offsetBytes\":\"0\",\"chunk\":\"" + chunk + "\"}";
    JsonDocument doc = parse(request.c_str());
    agent_q::handle_usb_payload_upload_chunk_request(
        "req_chunk_oversize_wrong_session",
        doc,
        make_writer(),
        make_ops());
    assert(g_error_calls == 1);
    assert(strcmp(g_last_error_code, "invalid_session") == 0);
    assert(agent_q::payload_delivery_advance_and_snapshot(0).state ==
           agent_q::AgentQPayloadDeliveryState::receiving);
}

void finish_upload()
{
    char request[256] = {};
    agent_q::AgentQPayloadDeliverySnapshot snapshot = agent_q::payload_delivery_advance_and_snapshot(0);
    snprintf(
        request,
        sizeof(request),
        "{\"id\":\"req_finish\",\"version\":1,\"type\":\"payload_upload_finish\","
        "\"sessionId\":\"session_abcdef\",\"uploadId\":\"%s\"}",
        snapshot.upload_id);
    JsonDocument doc = parse(request);
    agent_q::handle_usb_payload_upload_finish_request("req_finish", doc, make_writer(), make_ops());
    assert(g_error_calls == 0);
    assert(strcmp(response_type(), "payload_upload_finish_result") == 0);
    assert(strncmp(response_payload_ref(), "payload_", 8) == 0);
    assert(strcmp(response_chain(), "sui") == 0);
    assert(strcmp(response_method(), "sign_transaction") == 0);
    assert(strcmp(response_payload_kind(), "transaction") == 0);
    assert(strcmp(response_size_bytes(), kPayloadSize) == 0);
    assert(strcmp(response_payload_digest(), kDigest) == 0);
    assert(strstr(response_json(), "\"sizeBytes\":\"37\"") != nullptr);
}

}  // namespace

int main()
{
    {
        reset_state();
        begin_max_payload_upload();
        agent_q::payload_delivery_store_reset();
    }

    {
        reset_state();
        begin_max_plus_one_payload_upload_fails_closed();
    }

    {
        reset_state();
        begin_upload();
        append_chunk();
        finish_upload();
        char request[256] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_abort\",\"version\":1,\"type\":\"payload_upload_abort\","
            "\"sessionId\":\"session_abcdef\",\"payloadRef\":\"%s\"}",
            response_payload_ref());
        JsonDocument doc = parse(request);
        agent_q::handle_usb_payload_upload_abort_request("req_abort", doc, make_writer(), make_ops());
        assert(g_error_calls == 0);
        assert(strcmp(response_type(), "payload_upload_abort_result") == 0);
        assert(strcmp(response_status(), "aborted") == 0);
    }

    {
        reset_state();
        g_material_ready = false;
        JsonDocument doc = parse("{\"id\":\"req\",\"version\":1,\"type\":\"payload_upload_begin\",\"sessionId\":\"session_abcdef\"}");
        agent_q::handle_usb_payload_upload_begin_request("req", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_busy_calls == 0);
        assert(g_session_calls == 0);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_chunk\",\"version\":1,\"type\":\"payload_upload_chunk\","
            "\"sessionId\":\"session_abcdef\",\"uploadId\":\"upload_0000000000000001\","
            "\"offsetBytes\":\"0\",\"chunk\":\"E1yl7jeAyRJbpO02f8gRWqPsNX7HEFmi6zR9xg9YoeozfMUOVw==\"}");
        agent_q::handle_usb_payload_upload_chunk_request("req_chunk", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(g_busy_calls == 1);
        assert(g_session_calls == 1);
        assert(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle);
    }

    {
        reset_state();
        begin_upload();
        char upload_id[96] = {};
        snprintf(upload_id, sizeof(upload_id), "%s", response_upload_id());
        g_current_tick = 99;
        char request[256] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_chunk_expired\",\"version\":1,\"type\":\"payload_upload_chunk\","
            "\"sessionId\":\"session_abcdef\",\"uploadId\":\"%s\","
            "\"offsetBytes\":\"0\",\"chunk\":\"%s\"}",
            upload_id,
            kPayloadChunk);
        JsonDocument doc = parse(request);
        agent_q::handle_usb_payload_upload_chunk_request(
            "req_chunk_expired",
            doc,
            make_writer(),
            make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_chunk\",\"version\":1,\"type\":\"payload_upload_chunk\","
            "\"sessionId\":\"session_abcdef\",\"uploadId\":\"upload_0000000000000001\","
            "\"offsetBytes\":\"0\",\"chunk\":\"E1yl7jeAyRJbpO02f8gRWqPsNX7HEFmi6zR9xg9YoeozfMUOVw==\","
            "\"extra\":\"ignored-by-state\"}");
        agent_q::handle_usb_payload_upload_chunk_request("req_chunk_extra", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(g_busy_calls == 1);
        assert(g_session_calls == 1);
        assert(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_finish\",\"version\":1,\"type\":\"payload_upload_finish\","
            "\"sessionId\":\"session_abcdef\",\"uploadId\":\"upload_0000000000000001\"}");
        agent_q::handle_usb_payload_upload_finish_request("req_finish", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(g_busy_calls == 1);
        assert(g_session_calls == 1);
        assert(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle);
    }

    {
        reset_state();
        begin_upload();
        char upload_id[96] = {};
        snprintf(upload_id, sizeof(upload_id), "%s", response_upload_id());
        append_chunk();
        g_current_tick = 99;
        char request[256] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_finish_expired\",\"version\":1,\"type\":\"payload_upload_finish\","
            "\"sessionId\":\"session_abcdef\",\"uploadId\":\"%s\"}",
            upload_id);
        JsonDocument doc = parse(request);
        agent_q::handle_usb_payload_upload_finish_request(
            "req_finish_expired",
            doc,
            make_writer(),
            make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_finish\",\"version\":1,\"type\":\"payload_upload_finish\","
            "\"sessionId\":\"session_abcdef\",\"uploadId\":\"upload_0000000000000001\","
            "\"extra\":\"ignored-by-state\"}");
        agent_q::handle_usb_payload_upload_finish_request("req_finish_extra", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(g_busy_calls == 1);
        assert(g_session_calls == 1);
        assert(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle);
    }

    {
        reset_state();
        begin_upload();
        set_decode_should_fail_after_write(true);
        JsonDocument doc = parse(
            "{\"id\":\"req_chunk\",\"version\":1,\"type\":\"payload_upload_chunk\","
            "\"sessionId\":\"session_abcdef\",\"uploadId\":\"upload_0000000000000001\","
            "\"offsetBytes\":\"0\",\"chunk\":\"E1yl7jeAyRJbpO02f8gRWqPsNX7HEFmi6zR9xg9YoeozfMUOVw==\"}");
        agent_q::handle_usb_payload_upload_chunk_request("req_chunk", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(last_decode_output_wiped());
        assert(agent_q::payload_delivery_advance_and_snapshot(0).state ==
               agent_q::AgentQPayloadDeliveryState::receiving);
    }

    {
        reset_state();
        begin_upload();
        append_chunk();
        finish_upload();
        char payload_ref[96] = {};
        snprintf(payload_ref, sizeof(payload_ref), "%s", response_payload_ref());
        g_current_tick = 99;
        char request[256] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_abort_expired\",\"version\":1,\"type\":\"payload_upload_abort\","
            "\"sessionId\":\"session_abcdef\",\"payloadRef\":\"%s\"}",
            payload_ref);
        JsonDocument doc = parse(request);
        agent_q::handle_usb_payload_upload_abort_request(
            "req_abort_expired",
            doc,
            make_writer(),
            make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unknown_request") == 0);
        assert(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle);
    }

    {
        reset_state();
        append_oversized_decoded_chunk_wipes_matching_upload();
    }

    {
        reset_state();
        append_oversized_decoded_chunk_preserves_wrong_session_upload();
    }

    {
        reset_state();
        begin_upload();
        char request[512] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_begin_2\",\"version\":1,\"type\":\"payload_upload_begin\","
            "\"sessionId\":\"session_abcdef\",\"chain\":\"sui\",\"method\":\"sign_transaction\","
            "\"payloadKind\":\"transaction\",\"sizeBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
            kPayloadSize,
            kDigest);
        JsonDocument doc = parse(request);
        agent_q::handle_usb_payload_upload_begin_request("req_begin_2", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(agent_q::payload_delivery_advance_and_snapshot(0).state ==
               agent_q::AgentQPayloadDeliveryState::receiving);
    }

    {
        reset_state();
        begin_upload();
        char request[512] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_begin_2\",\"version\":1,\"type\":\"payload_upload_begin\","
            "\"sessionId\":\"session_abcdef\",\"chain\":\"sui\",\"method\":\"sign_transaction\","
            "\"payloadKind\":\"transaction\",\"sizeBytes\":\"%s\",\"payloadDigest\":\"%s\","
            "\"extra\":\"ignored-by-state\"}",
            kPayloadSize,
            kDigest);
        JsonDocument doc = parse(request);
        agent_q::handle_usb_payload_upload_begin_request("req_begin_2_extra", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(agent_q::payload_delivery_advance_and_snapshot(0).state ==
               agent_q::AgentQPayloadDeliveryState::receiving);
    }

    {
        reset_state();
        char request[512] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_begin\",\"version\":1,\"type\":\"payload_upload_begin\","
            "\"sessionId\":\"session_abcdef\",\"chain\":\"notchain\",\"method\":\"sign_transaction\","
            "\"payloadKind\":\"transaction\",\"sizeBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
            kPayloadSize,
            kDigest);
        JsonDocument doc = parse(request);
        agent_q::handle_usb_payload_upload_begin_request("req_begin", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unsupported_chain") == 0);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_begin\",\"version\":1,\"type\":\"payload_upload_begin\","
            "\"sessionId\":\"session_abcdef\",\"chain\":\"notchain\",\"method\":\"sign_transaction\","
            "\"payloadKind\":\"transaction\",\"sizeBytes\":\"not-decimal\",\"payloadDigest\":\"not-digest\"}");
        agent_q::handle_usb_payload_upload_begin_request("req_begin", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unsupported_chain") == 0);
    }

    {
        reset_state();
        char request[512] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_begin\",\"version\":1,\"type\":\"payload_upload_begin\","
            "\"sessionId\":\"session_abcdef\",\"chain\":\"sui\",\"method\":\"sign_personal_message\","
            "\"payloadKind\":\"transaction\",\"sizeBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
            kPayloadSize,
            kDigest);
        JsonDocument doc = parse(request);
        agent_q::handle_usb_payload_upload_begin_request("req_begin", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unsupported_method") == 0);
    }

    {
        reset_state();
        JsonDocument doc = parse(
            "{\"id\":\"req_begin\",\"version\":1,\"type\":\"payload_upload_begin\","
            "\"sessionId\":\"session_abcdef\",\"chain\":\"sui\",\"method\":\"future_method\","
            "\"payloadKind\":\"message\",\"sizeBytes\":\"not-decimal\",\"payloadDigest\":\"not-digest\"}");
        agent_q::handle_usb_payload_upload_begin_request("req_begin", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "unsupported_method") == 0);
    }

    {
        reset_state();
        char request[512] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_begin\",\"version\":1,\"type\":\"payload_upload_begin\","
            "\"sessionId\":\"session_abcdef\",\"chain\":\"SUI\",\"method\":\"sign_transaction\","
            "\"payloadKind\":\"transaction\",\"sizeBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
            kPayloadSize,
            kDigest);
        JsonDocument doc = parse(request);
        agent_q::handle_usb_payload_upload_begin_request("req_begin", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
    }

    {
        reset_state();
        char request[512] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_begin\",\"version\":1,\"type\":\"payload_upload_begin\","
            "\"sessionId\":\"session_abcdef\",\"chain\":\"sui\",\"method\":\"sign_transaction\","
            "\"payloadKind\":\"message\",\"sizeBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
            kPayloadSize,
            kDigest);
        JsonDocument doc = parse(request);
        agent_q::handle_usb_payload_upload_begin_request("req_begin", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        char request[512] = {};
        snprintf(
            request,
            sizeof(request),
            "{\"id\":\"req_begin\",\"version\":1,\"type\":\"payload_upload_begin\","
            "\"sessionId\":\"session_abcdef\",\"chain\":\"notchain\",\"method\":\"sign_transaction\","
            "\"payloadKind\":\"transaction\",\"sizeBytes\":\"%s\",\"payloadDigest\":\"%s\"}",
            kPayloadSize,
            kDigest);
        JsonDocument doc = parse(request);
        agent_q::handle_usb_payload_upload_begin_request("req_begin", doc, make_writer(), make_ops());
        assert(g_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_session_calls == 1);
        assert(strcmp(g_last_session, "session_abcdef") == 0);
        assert(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle);
    }

    printf("USB payload upload handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_AGENT_Q_DIR}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${AGENT_Q_DIR}/agent_q_usb_payload_upload_handlers.cpp" \
  -o "${TMP_DIR}/usb_payload_upload_handlers.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_AGENT_Q_DIR}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${AGENT_Q_DIR}/agent_q_payload_delivery_primitives.cpp" \
  -o "${TMP_DIR}/payload_delivery_primitives.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_AGENT_Q_DIR}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${AGENT_Q_DIR}/agent_q_payload_delivery_store.cpp" \
  -o "${TMP_DIR}/payload_delivery_store.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_AGENT_Q_DIR}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${AGENT_Q_DIR}/agent_q_payload_delivery_admission.cpp" \
  -o "${TMP_DIR}/payload_delivery_admission.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_AGENT_Q_DIR}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${AGENT_Q_DIR}/agent_q_session.cpp" \
  -o "${TMP_DIR}/session.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${AGENT_Q_DIR}" \
  -c "${AGENT_Q_DIR}/agent_q_base64.cpp" \
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
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_AGENT_Q_DIR}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${TMP_DIR}/stubs.cpp" \
  "${TMP_DIR}/usb_payload_upload_handlers.o" \
  "${TMP_DIR}/payload_delivery_primitives.o" \
  "${TMP_DIR}/payload_delivery_store.o" \
  "${TMP_DIR}/payload_delivery_admission.o" \
  "${TMP_DIR}/session.o" \
  "${TMP_DIR}/base64.o" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
