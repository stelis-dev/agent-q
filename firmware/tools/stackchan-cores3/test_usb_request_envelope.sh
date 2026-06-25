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
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${AGENT_Q_DIR}/agent_q_usb_request_envelope.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_request_envelope.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_type.h" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-request-envelope.XXXXXX")"
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

#include "agent_q_usb_request_envelope.h"

namespace agent_q {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

}  // namespace agent_q

namespace {

const char* status_name(agent_q::AgentQUsbRequestEnvelopeParseStatus status)
{
    switch (status) {
        case agent_q::AgentQUsbRequestEnvelopeParseStatus::ok:
            return "ok";
        case agent_q::AgentQUsbRequestEnvelopeParseStatus::invalid_json:
            return "invalid_json";
        case agent_q::AgentQUsbRequestEnvelopeParseStatus::invalid_id:
            return "invalid_id";
        case agent_q::AgentQUsbRequestEnvelopeParseStatus::invalid_request:
            return "invalid_request";
        case agent_q::AgentQUsbRequestEnvelopeParseStatus::invalid_params:
            return "invalid_params";
        case agent_q::AgentQUsbRequestEnvelopeParseStatus::invalid_session:
            return "invalid_session";
        case agent_q::AgentQUsbRequestEnvelopeParseStatus::unsupported_version:
            return "unsupported_version";
        case agent_q::AgentQUsbRequestEnvelopeParseStatus::unsupported_method:
            return "unsupported_method";
    }
    return "unknown";
}

void expect_status(
    const char* line,
    agent_q::AgentQUsbRequestEnvelopeParseStatus expected_status,
    const char* expected_id,
    agent_q::AgentQUsbOperationType expected_type)
{
    JsonDocument request;
    agent_q::AgentQUsbRequestEnvelope envelope = {};
    const auto status = agent_q::parse_usb_request_envelope(line, request, &envelope);
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
    using Status = agent_q::AgentQUsbRequestEnvelopeParseStatus;
    using Type = agent_q::AgentQUsbOperationType;

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
        "{\"id\":\"req_missing_method\",\"version\":1}",
        Status::unsupported_method,
        "req_missing_method",
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
        "{\"id\":\"req_bad_type\",\"version\":1,\"type\":7}",
        Status::invalid_request,
        "req_bad_type",
        Type::unsupported);

    assert(strcmp(agent_q::usb_request_envelope_error_code(Status::invalid_json), "invalid_request") == 0);
    assert(agent_q::usb_request_envelope_error_code(Status::ok) == nullptr);

    printf("USB request envelope tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_device_contract.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_request_envelope.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
