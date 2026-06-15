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

namespace {

void expect_status(
    const char* line,
    agent_q::AgentQUsbRequestEnvelopeParseStatus expected_status,
    const char* expected_id,
    agent_q::AgentQUsbOperationType expected_type)
{
    JsonDocument request;
    agent_q::AgentQUsbRequestEnvelope envelope = {};
    const auto status = agent_q::parse_usb_request_envelope(line, request, &envelope);
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
        "{\"id\":\"req_1\",\"version\":1,\"type\":\"get_status\"}",
        Status::ok,
        "req_1",
        Type::get_status);
    expect_status(
        "{\"id\":\"req_sign\",\"version\":1,\"type\":\"sign_transaction\"}",
        Status::ok,
        "req_sign",
        Type::sign_transaction);
    expect_status(
        "{\"id\":\"req_missing_type\",\"version\":1}",
        Status::ok,
        "req_missing_type",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_unknown\",\"version\":1,\"type\":\"unknown\"}",
        Status::ok,
        "req_unknown",
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
        "{\"version\":1,\"type\":\"get_status\"}",
        Status::invalid_id,
        nullptr,
        Type::unsupported);
    expect_status(
        "{\"id\":\"bad id\",\"version\":1,\"type\":\"get_status\"}",
        Status::invalid_id,
        nullptr,
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_version\",\"version\":2,\"type\":\"get_status\"}",
        Status::unsupported_version,
        "req_version",
        Type::unsupported);
    expect_status(
        "{\"id\":\"req_bad_type\",\"version\":1,\"type\":7}",
        Status::unsupported_type,
        "req_bad_type",
        Type::unsupported);

    assert(strcmp(agent_q::usb_request_envelope_error_code(Status::invalid_json), "invalid_json") == 0);
    assert(strcmp(agent_q::usb_request_envelope_error_message(Status::invalid_id), "Invalid request id.") == 0);
    assert(agent_q::usb_request_envelope_error_code(Status::ok) == nullptr);
    assert(agent_q::usb_request_envelope_error_message(Status::ok) == nullptr);

    printf("USB request envelope tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_request_envelope.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
