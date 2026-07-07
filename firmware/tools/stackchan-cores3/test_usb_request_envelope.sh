#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_request_envelope.sh

Compiles the USB request envelope parser and verifies public line-envelope
classification before operation dispatch. It does not require hardware.
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
  "${COMMON_ROOT}/protocol/device_contract.cpp" \
  "${COMMON_ROOT}/protocol/device_contract.h" \
  "${RUNTIME_DIR}/usb_request_envelope.cpp" \
  "${RUNTIME_DIR}/usb_request_envelope.h" \
  "${COMMON_ROOT}/protocol/usb_operation_type.cpp" \
  "${COMMON_ROOT}/protocol/usb_operation_type.h" \
  "${COMMON_ROOT}/protocol/request_id.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-request-envelope.XXXXXX")"
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

#include "usb_request_envelope.h"

namespace signing {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

}  // namespace signing

namespace {

const char* status_name(signing::UsbRequestEnvelopeParseStatus status)
{
    switch (status) {
        case signing::UsbRequestEnvelopeParseStatus::ok:
            return "ok";
        case signing::UsbRequestEnvelopeParseStatus::invalid_json:
            return "invalid_json";
        case signing::UsbRequestEnvelopeParseStatus::invalid_id:
            return "invalid_id";
        case signing::UsbRequestEnvelopeParseStatus::invalid_request:
            return "invalid_request";
        case signing::UsbRequestEnvelopeParseStatus::invalid_params:
            return "invalid_params";
        case signing::UsbRequestEnvelopeParseStatus::invalid_session:
            return "invalid_session";
        case signing::UsbRequestEnvelopeParseStatus::unsupported_version:
            return "unsupported_version";
        case signing::UsbRequestEnvelopeParseStatus::unsupported_method:
            return "unsupported_method";
    }
    return "unknown";
}

void expect_status(
    const char* line,
    signing::UsbRequestEnvelopeParseStatus expected_status,
    const char* expected_id,
    signing::UsbOperationType expected_type)
{
    JsonDocument request;
    signing::UsbRequestEnvelope envelope = {};
    const auto status = signing::parse_usb_request_envelope(line, request, &envelope);
    if (status != expected_status) {
        fprintf(stderr, "status mismatch for %s: actual=%s expected=%s\n",
                line,
                status_name(status),
                status_name(expected_status));
    }
    assert(status == expected_status);
    if (expected_id == nullptr) {
        assert(envelope.id == nullptr);
    } else {
        assert(envelope.id != nullptr);
        assert(strcmp(envelope.id, expected_id) == 0);
    }
    assert(envelope.operation_type == expected_type);
}

}  // namespace

int main()
{
    using Status = signing::UsbRequestEnvelopeParseStatus;
    using Type = signing::UsbOperationType;

    expect_status(
        "{\"id\":\"req_1\",\"version\":1,\"method\":\"get_status\"}",
        Status::ok,
        "req_1",
        Type::get_status);
    expect_status(
        "{\"id\":\"req_sign\",\"version\":1,\"method\":\"sign_transaction\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"payload\":{\"chain\":\"sui\",\"network\":\"devnet\",\"txBytes\":\"AA==\"}}",
        Status::ok,
        "req_sign",
        Type::sign_transaction);
    expect_status(
        "{\"id\":\"req_transfer\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        Status::ok,
        "req_transfer",
        Type::payload_transfer_begin);
    expect_status(
        "{\"id\":\"req_transfer_type_bad\",\"version\":1,\"type\":\"other\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        Status::unsupported_method,
        "req_transfer_type_bad",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_transfer_type_non_string\",\"version\":1,\"type\":7,\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        Status::invalid_request,
        "req_transfer_type_non_string",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_transfer_extra\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"extra\":\"not-allowed\"}",
        Status::invalid_request,
        "req_transfer_extra",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_transfer_chunk_extra\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\",\"offsetBytes\":\"0\",\"chunk\":\"AA==\",\"extra\":\"not-allowed\"}",
        Status::invalid_request,
        "req_transfer_chunk_extra",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_transfer_finish_extra\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"finish\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\",\"extra\":\"not-allowed\"}",
        Status::invalid_request,
        "req_transfer_finish_extra",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_transfer_abort_extra\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\",\"extra\":\"not-allowed\"}",
        Status::invalid_request,
        "req_transfer_abort_extra",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_transfer_abort_payload\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"payloadRef\":\"payload_0000000000000001\"}",
        Status::ok,
        "req_transfer_abort_payload",
        Type::payload_transfer_abort);
    expect_status(
        "{\"id\":\"req_transfer_abort_missing_target\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\"}",
        Status::invalid_request,
        "req_transfer_abort_missing_target",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_transfer_abort_both\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\",\"payloadRef\":\"payload_0000000000000001\"}",
        Status::invalid_request,
        "req_transfer_abort_both",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_missing_method\",\"version\":1}",
        Status::invalid_request,
        "req_missing_method",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_bad_method_type\",\"version\":1,\"method\":7}",
        Status::invalid_request,
        "req_bad_method_type",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_unknown\",\"version\":1,\"method\":\"unknown\"}",
        Status::unsupported_method,
        "req_unknown",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_unknown_transfer\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"unknown\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\"}",
        Status::unsupported_method,
        "req_unknown_transfer",
        Type::unsupported);
    expect_status(
        "{not-json",
        Status::invalid_json,
        nullptr,
        Type::unsupported);
    expect_status(
        "[]",
        Status::invalid_json,
        nullptr,
        Type::unsupported);
    expect_status(
        "{\"version\":1,\"method\":\"get_status\"}",
        Status::invalid_id,
        nullptr,
        Type::unsupported);
    expect_status(
        "{\"id\":\"bad id\",\"version\":1,\"method\":\"get_status\"}",
        Status::invalid_id,
        nullptr,
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_version\",\"version\":2,\"method\":\"get_status\"}",
        Status::unsupported_version,
        "req_version",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_missing_version\",\"method\":\"get_status\"}",
        Status::invalid_request,
        "req_missing_version",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_string_version\",\"version\":\"1\",\"method\":\"get_status\"}",
        Status::invalid_request,
        "req_string_version",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_float_version\",\"version\":1.5,\"method\":\"get_status\"}",
        Status::invalid_request,
        "req_float_version",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_bool_version\",\"version\":true,\"method\":\"get_status\"}",
        Status::invalid_request,
        "req_bool_version",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_bad_type\",\"version\":1,\"type\":7}",
        Status::invalid_request,
        "req_bad_type",
        Type::unsupported);

    assert(strcmp(signing::usb_request_envelope_error_code(Status::invalid_json), "invalid_request") == 0);
    assert(signing::usb_request_envelope_error_code(Status::ok) == nullptr);

    printf("USB request envelope tests passed\n");
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
  "${COMMON_ROOT}/protocol/session_state.cpp" \
  "${RUNTIME_DIR}/usb_request_envelope.cpp" \
  "${COMMON_ROOT}/protocol/usb_operation_type.cpp" \
  "${COMMON_ROOT}/protocol/request_id.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
