#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.h" \
  "${COMMON_ROOT}/protocol/device_response.h" \
  "${COMMON_ROOT}/protocol/usb_json_response.cpp" \
  "${COMMON_ROOT}/protocol/signing_response_store.cpp" \
  "${COMMON_ROOT}/protocol/signing_response_store.h" \
  "${COMMON_ROOT}/protocol/sign_route.h" \
  "${COMMON_ROOT}/signing/usb_signing_outcome_writer.cpp" \
  "${COMMON_ROOT}/signing/usb_signing_outcome_writer.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-signing-outcome-writer.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/firmware_common"
mkdir -p "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/firmware_common/sui"

cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/byte_conversions.h" <<'H'
#pragma once

#include <stddef.h>
#include <stdint.h>

static inline int bytes_to_base64(
    const uint8_t* input,
    size_t input_size,
    char* output,
    size_t output_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (input == nullptr || output == nullptr || output_size == 0) {
        return -1;
    }
    const size_t encoded_size = ((input_size + 2) / 3) * 4;
    if (encoded_size + 1 > output_size) {
        return -1;
    }
    size_t out = 0;
    for (size_t index = 0; index < input_size; index += 3) {
        const uint32_t b0 = input[index];
        const uint32_t b1 = index + 1 < input_size ? input[index + 1] : 0;
        const uint32_t b2 = index + 2 < input_size ? input[index + 2] : 0;
        const uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
        output[out++] = alphabet[(triple >> 18) & 0x3F];
        output[out++] = alphabet[(triple >> 12) & 0x3F];
        output[out++] = index + 1 < input_size ? alphabet[(triple >> 6) & 0x3F] : '=';
        output[out++] = index + 2 < input_size ? alphabet[triple & 0x3F] : '=';
    }
    output[out] = '\0';
    return 0;
}
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include "signing/usb_signing_outcome_writer.h"
#include "protocol/device_contract.h"
#include "protocol/device_response.h"
#include "protocol/protocol_constants.h"
#include "protocol/signing_response_store.h"
#include "sui/signature_scheme.h"
#include "sui/zklogin_signature.h"

namespace {

std::string g_last_json;
int g_json_writes = 0;
int g_error_writes = 0;
const char* g_last_error_id = nullptr;
const char* g_last_error_code = nullptr;

void reset_capture()
{
    g_last_json.clear();
    g_json_writes = 0;
    g_error_writes = 0;
    g_last_error_id = nullptr;
    g_last_error_code = nullptr;
}

JsonDocument parse_json(const std::string& json)
{
    JsonDocument document;
    assert(!deserializeJson(document, json));
    return document;
}

JsonDocument stored_json(const char* session_id, const char* request_id)
{
    char stored[signing::kResponseMaxSize] = {};
    size_t stored_len = 0;
    assert(signing::signing_response_find(session_id, request_id, stored, sizeof(stored), &stored_len));
    JsonDocument document;
    assert(!deserializeJson(document, stored, stored_len));
    return document;
}

bool capture_response_bytes(const char* data, size_t length, void*)
{
    if (data == nullptr || length == 0) {
        return false;
    }
    if (!(length == 1 && data[0] == '\n')) {
        g_json_writes += 1;
    }
    g_last_json.append(data, length);
    return true;
}

bool write_method_error_for_test(
    const char* id,
    const char* method,
    const char* code,
    void*)
{
    JsonDocument response;
    if (!signing::device_response_prepare_method_error(response, id, method, code)) {
        return false;
    }
    g_json_writes += 1;
    g_last_json.clear();
    serializeJson(response, g_last_json);
    return true;
}

const signing::UsbSigningOutcomeWriterOps& outcome_writer_ops()
{
    static const signing::UsbSigningOutcomeWriterOps ops{
        signing::UsbJsonResponseWriteOps{
            capture_response_bytes,
            nullptr,
            nullptr,
        },
        write_method_error_for_test,
        nullptr,
    };
    return ops;
}

void fill_native_signature(uint8_t* signature, size_t signature_size)
{
    assert(signature_size >= signing::kSuiEd25519SignatureBytes);
    memset(signature, 0, signature_size);
    signature[0] = signing::kSuiSignatureSchemeFlagEd25519;
    for (size_t index = 1; index < signing::kSuiEd25519SignatureBytes; ++index) {
        signature[index] = static_cast<uint8_t>(index + 1);
    }
}

void fill_zklogin_signature(uint8_t* signature, size_t signature_size)
{
    assert(signature_size > signing::kSuiEd25519SignatureBytes);
    memset(signature, 0, signature_size);
    signature[0] = signing::kSuiSignatureSchemeFlagZkLogin;
    for (size_t index = 0; index < signature_size; ++index) {
        if (index != 0) {
            signature[index] = static_cast<uint8_t>(index + 1);
        }
    }
}

}  // namespace

namespace signing {

bool usb_response_write_json(JsonDocument& response)
{
    g_json_writes += 1;
    g_last_json.clear();
    serializeJson(response, g_last_json);
    return true;
}

bool device_response_prepare_success_result(
    JsonDocument& response,
    const char* id,
    const char* method,
    JsonObjectConst result)
{
    if (method == nullptr || method[0] == '\0' || result.isNull()) {
        return false;
    }
    response.clear();
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["success"] = true;
    response["method"] = method;
    response["result"].set(result);
    return true;
}

bool device_response_prepare_method_error(
    JsonDocument& response,
    const char* id,
    const char* method,
    const char* code)
{
    const DeviceErrorRow* error = device_error_row(code);
    if (error == nullptr) {
        error = device_error_row("unknown_error");
    }
    if (error == nullptr) {
        return false;
    }
    response.clear();
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["success"] = false;
    if (method != nullptr && method[0] != '\0') {
        response["method"] = method;
    }
    response["error"]["code"] = error->code;
    response["error"]["message"] = error->message;
    response["error"]["retryable"] = error->retryable;
    return true;
}

bool usb_response_write_method_error(
    const char* id,
    const char* method,
    const char* code)
{
    JsonDocument response;
    if (!device_response_prepare_method_error(response, id, method, code)) {
        return false;
    }
    return usb_response_write_json(response);
}

bool usb_response_write_error(const char* id, const char* code)
{
    g_error_writes += 1;
    g_last_error_id = id;
    g_last_error_code = code;
    return true;
}

const char* user_signing_flow_terminal_status(UserSigningTerminalResult result)
{
    switch (result) {
        case UserSigningTerminalResult::rejected:
            return "user_rejected";
        case UserSigningTerminalResult::timed_out:
            return "user_timed_out";
        case UserSigningTerminalResult::signing_failed:
            return "signing_failed";
        case UserSigningTerminalResult::signed_success:
            return "signed";
        case UserSigningTerminalResult::canceled:
        case UserSigningTerminalResult::history_error:
        case UserSigningTerminalResult::none:
        default:
            return "";
    }
}

const char* user_signing_flow_terminal_reason(UserSigningTerminalResult result)
{
    switch (result) {
        case UserSigningTerminalResult::rejected:
            return "user_rejected";
        case UserSigningTerminalResult::timed_out:
            return "user_timed_out";
        case UserSigningTerminalResult::signing_failed:
            return "signing_failed";
        case UserSigningTerminalResult::signed_success:
            return "device_confirmed";
        case UserSigningTerminalResult::canceled:
        case UserSigningTerminalResult::history_error:
        case UserSigningTerminalResult::none:
        default:
            return "";
    }
}

}  // namespace signing

int main()
{
    signing::signing_response_clear_all();

    uint8_t identity[signing::kSignRequestIdentitySize] = {};
    identity[0] = 0xA1;

    {
        reset_capture();
        signing::PolicySigningExecutionResult result = {};
        result.status = signing::PolicySigningExecutionStatus::signed_success;
        result.signing_route = signing::Route::sui_sign_transaction;
        fill_native_signature(result.signature, sizeof(result.signature));
        result.signature_size = signing::kSuiEd25519SignatureBytes;
        assert(signing::usb_signing_outcome_write_policy_execution(
            "req-policy-signed",
            "session-a",
            identity,
            result,
            outcome_writer_ops()));
        assert(g_json_writes == 1);
        JsonDocument response = parse_json(g_last_json);
        assert(response["success"] == true);
        assert(strcmp(response["method"], "sign_transaction") == 0);
        assert(strcmp(response["result"]["authorization"], "policy") == 0);
        assert(strcmp(response["result"]["chain"], "sui") == 0);
        assert(strcmp(response["result"]["method"], "sign_transaction") == 0);
        assert(strlen(response["result"]["signature"]) > 0);
        JsonDocument stored = stored_json("session-a", "req-policy-signed");
        assert(stored["success"] == true);
        assert(strcmp(stored["method"], "sign_transaction") == 0);
        assert(strcmp(stored["result"]["authorization"], "policy") == 0);
    }

    {
        reset_capture();
        signing::PolicySigningExecutionResult result = {};
        result.status = signing::PolicySigningExecutionStatus::signed_success;
        result.signing_route = signing::Route::sui_sign_transaction;
        fill_zklogin_signature(result.signature, sizeof(result.signature));
        result.signature_size = signing::kSuiEd25519SignatureBytes + 48;
        assert(signing::usb_signing_outcome_write_policy_execution(
            "req-policy-zklogin-signed",
            "session-a",
            identity,
            result,
            outcome_writer_ops()));
        JsonDocument response = parse_json(g_last_json);
        assert(strcmp(response["method"], "sign_transaction") == 0);
        assert(strcmp(response["result"]["authorization"], "policy") == 0);
        assert(strcmp(response["result"]["method"], "sign_transaction") == 0);
        JsonDocument stored = stored_json("session-a", "req-policy-zklogin-signed");
        assert(stored["success"] == true);
        assert(strcmp(stored["result"]["authorization"], "policy") == 0);
    }

    {
        reset_capture();
        signing::UserSigningFlowSnapshot snapshot = {};
        snapshot.signing_route = signing::Route::sui_sign_personal_message;
        memcpy(snapshot.request_identity, identity, sizeof(identity));
        signing::UserSigningOutput output = {};
        output.signing_route = signing::Route::sui_sign_personal_message;
        fill_native_signature(output.signature, sizeof(output.signature));
        output.signature_size = signing::kSuiEd25519SignatureBytes;
        output.message_bytes[0] = 'h';
        output.message_bytes[1] = 'i';
        output.message_bytes_size = 2;
        assert(signing::usb_signing_outcome_user_signed_response_fits(
            "req-user-signed",
            "user",
            snapshot,
            output));
        assert(signing::usb_signing_outcome_write_user_signed(
            "req-user-signed",
            "session-a",
            "user",
            snapshot,
            output,
            outcome_writer_ops()));
        JsonDocument response = parse_json(g_last_json);
        assert(response["success"] == true);
        assert(strcmp(response["method"], "sign_personal_message") == 0);
        assert(strcmp(response["result"]["authorization"], "user") == 0);
        assert(strcmp(response["result"]["method"], "sign_personal_message") == 0);
        assert(strcmp(response["result"]["messageBytes"], "aGk=") == 0);
        JsonDocument stored = stored_json("session-a", "req-user-signed");
        assert(stored["success"] == true);
        assert(strcmp(stored["result"]["messageBytes"], "aGk=") == 0);
    }

    {
        reset_capture();
        signing::UserSigningFlowSnapshot snapshot = {};
        snapshot.signing_route = signing::Route::sui_sign_personal_message;
        memcpy(snapshot.request_identity, identity, sizeof(identity));
        signing::UserSigningOutput output = {};
        output.signing_route = signing::Route::sui_sign_personal_message;
        fill_zklogin_signature(output.signature, sizeof(output.signature));
        output.signature_size = signing::kSuiEd25519SignatureBytes + 48;
        output.message_bytes[0] = 'h';
        output.message_bytes[1] = 'i';
        output.message_bytes_size = 2;
        assert(signing::usb_signing_outcome_write_user_signed(
            "req-user-zklogin-personal-message",
            "session-a",
            "user",
            snapshot,
            output,
            outcome_writer_ops()));
        JsonDocument response = parse_json(g_last_json);
        assert(strcmp(response["method"], "sign_personal_message") == 0);
        assert(strcmp(response["result"]["authorization"], "user") == 0);
        assert(strcmp(response["result"]["method"], "sign_personal_message") == 0);
        assert(strcmp(response["result"]["messageBytes"], "aGk=") == 0);
        JsonDocument stored = stored_json("session-a", "req-user-zklogin-personal-message");
        assert(stored["success"] == true);
        assert(strcmp(stored["result"]["messageBytes"], "aGk=") == 0);
    }

    {
        reset_capture();
        signing::UserSigningFlowSnapshot snapshot = {};
        snapshot.signing_route = signing::Route::sui_sign_personal_message;
        memcpy(snapshot.request_identity, identity, sizeof(identity));
        signing::UserSigningOutput output = {};
        output.signing_route = signing::Route::sui_sign_personal_message;
        fill_zklogin_signature(output.signature, sizeof(output.signature));
        output.signature_size = sizeof(output.signature);
        for (size_t index = 0; index < signing::kSuiSignPersonalMessageMaxBytes; ++index) {
            output.message_bytes[index] = static_cast<uint8_t>('A' + (index % 26));
        }
        output.message_bytes_size = signing::kSuiSignPersonalMessageMaxBytes;
        assert(signing::usb_signing_outcome_user_signed_response_fits(
            "req-user-max-personal-message",
            "user",
            snapshot,
            output));
        assert(signing::usb_signing_outcome_write_user_signed(
            "req-user-max-personal-message",
            "session-a",
            "user",
            snapshot,
            output,
            outcome_writer_ops()));
        assert(g_json_writes == 1);
        assert(g_last_json.size() < signing::kResponseMaxSize);
        JsonDocument response = parse_json(g_last_json);
        assert(response["success"] == true);
        assert(strcmp(response["method"], "sign_personal_message") == 0);
        const char* message_bytes = response["result"]["messageBytes"];
        assert(message_bytes != nullptr);
        assert(strlen(message_bytes) == signing::kSuiSignPersonalMessageMaxBase64Size);
        JsonDocument stored = stored_json("session-a", "req-user-max-personal-message");
        assert(stored["success"] == true);
        assert(strcmp(stored["method"], "sign_personal_message") == 0);
        assert(strcmp(stored["result"]["messageBytes"], message_bytes) == 0);
    }

    {
        reset_capture();
        signing::UserSigningFlowSnapshot snapshot = {};
        snapshot.signing_route = signing::Route::sui_sign_personal_message;
        memcpy(snapshot.request_identity, identity, sizeof(identity));
        signing::UserSigningOutput output = {};
        output.signing_route = signing::Route::sui_sign_personal_message;
        fill_native_signature(output.signature, sizeof(output.signature));
        output.signature_size = signing::kSuiEd25519SignatureBytes;
        output.message_bytes[0] = 'h';
        output.message_bytes[1] = 'i';
        output.message_bytes_size = 2;
        std::string oversized_id(signing::kResponseMaxSize, 'r');
        assert(!signing::usb_signing_outcome_user_signed_response_fits(
            oversized_id.c_str(),
            "user",
            snapshot,
            output));
        assert(!signing::usb_signing_outcome_write_user_signed(
            oversized_id.c_str(),
            "session-too-large",
            "user",
            snapshot,
            output,
            outcome_writer_ops()));
        assert(g_json_writes == 0);
    }

    {
        uint8_t conflicting_identity[signing::kSignRequestIdentitySize] = {};
        conflicting_identity[0] = 0xB2;
        const char existing_response[] =
            "{\"id\":\"req-conflict\",\"version\":1,\"success\":true,"
            "\"method\":\"sign_personal_message\",\"result\":{}}";
        assert(signing::signing_response_store(
            "session-conflict",
            "req-conflict",
            conflicting_identity,
            sizeof(conflicting_identity),
            existing_response,
            strlen(existing_response)) ==
            signing::ResponseStoreOutcome::stored);
        reset_capture();
        signing::UserSigningFlowSnapshot snapshot = {};
        snapshot.signing_route = signing::Route::sui_sign_personal_message;
        memcpy(snapshot.request_identity, identity, sizeof(identity));
        signing::UserSigningOutput output = {};
        output.signing_route = signing::Route::sui_sign_personal_message;
        fill_native_signature(output.signature, sizeof(output.signature));
        output.signature_size = signing::kSuiEd25519SignatureBytes;
        output.message_bytes[0] = 'h';
        output.message_bytes[1] = 'i';
        output.message_bytes_size = 2;
        assert(!signing::usb_signing_outcome_write_user_signed(
            "req-conflict",
            "session-conflict",
            "user",
            snapshot,
            output,
            outcome_writer_ops()));
        assert(g_json_writes == 0);
    }

    {
        reset_capture();
        assert(signing::usb_signing_outcome_write_user_terminal(
            "req-user-rejected",
            "session-b",
            identity,
            "sign_personal_message",
            signing::UserSigningTerminalResult::rejected,
            outcome_writer_ops()));
        JsonDocument response = parse_json(g_last_json);
        assert(response["success"] == false);
        assert(strcmp(response["method"], "sign_personal_message") == 0);
        assert(strcmp(response["error"]["code"], "user_rejected") == 0);
        assert(response["error"]["retryable"] == false);
        JsonDocument stored = stored_json("session-b", "req-user-rejected");
        assert(stored["success"] == false);
        assert(strcmp(stored["method"], "sign_personal_message") == 0);
        assert(strcmp(stored["error"]["code"], "user_rejected") == 0);
    }

    {
        reset_capture();
        signing::PolicySigningExecutionResult result = {};
        result.status = signing::PolicySigningExecutionStatus::account_error;
        result.code = "account_unavailable";
        result.message = "Signing account is unavailable.";
        assert(signing::usb_signing_outcome_write_policy_execution(
            "req-policy-error",
            "session-c",
            identity,
            result,
            outcome_writer_ops()));
        assert(g_json_writes == 1);
        assert(g_error_writes == 0);
        JsonDocument response = parse_json(g_last_json);
        assert(response["success"] == false);
        assert(strcmp(response["method"], "sign_transaction") == 0);
        assert(strcmp(response["error"]["code"], "account_unavailable") == 0);
    }

    printf("USB signing outcome writer tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/usb_json_response.cpp" \
  "${COMMON_ROOT}/protocol/signing_response_store.cpp" \
  "${COMMON_ROOT}/signing/usb_signing_outcome_writer.cpp" \
  -o "${TMP_DIR}/test_usb_signing_outcome_writer"

"${TMP_DIR}/test_usb_signing_outcome_writer"
