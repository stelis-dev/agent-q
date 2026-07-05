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
  "${RUNTIME_DIR}/payload_transfer_request.cpp" \
  "${RUNTIME_DIR}/payload_transfer_request.h" \
  "${RUNTIME_DIR}/session_state.cpp" \
  "${COMMON_ROOT}/protocol/request_id.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stopwatch-esp32s3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stopwatch-payload-transfer-request.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/payload_transfer_request_test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "payload_transfer_request.h"

using namespace stopwatch_target;

namespace {

JsonDocument parse(const char* line)
{
    JsonDocument doc;
    const DeserializationError error = deserializeJson(doc, line);
    assert(!error);
    return doc;
}

void expect_parse(
    const char* line,
    PayloadTransferRequestParseStatus expected,
    const char* expected_id,
    const char* expected_session,
    PayloadTransferRequestAction expected_action)
{
    JsonDocument doc = parse(line);
    PayloadTransferRequestEnvelope envelope = {};
    const PayloadTransferRequestParseStatus actual =
        payload_transfer_request_parse(doc, &envelope);
    if (actual != expected) {
        fprintf(stderr, "status mismatch for %s\n", line);
    }
    assert(actual == expected);
    assert(strcmp(payload_transfer_request_error_code(PayloadTransferRequestParseStatus::invalid_envelope),
                  "invalid_request") == 0);
    assert(strcmp(payload_transfer_request_error_code(PayloadTransferRequestParseStatus::invalid_request),
                  "invalid_request") == 0);
    assert(strcmp(payload_transfer_request_error_code(PayloadTransferRequestParseStatus::unsupported_version),
                  "unsupported_version") == 0);
    assert(strcmp(payload_transfer_request_error_code(PayloadTransferRequestParseStatus::unsupported_method),
                  "unsupported_method") == 0);
    assert(strcmp(payload_transfer_request_error_code(PayloadTransferRequestParseStatus::invalid_session),
                  "invalid_session") == 0);
    assert(payload_transfer_request_error_code(PayloadTransferRequestParseStatus::ok) == nullptr);
    if (expected_id == nullptr) {
        assert(envelope.id == nullptr);
    } else {
        assert(envelope.id != nullptr);
        assert(strcmp(envelope.id, expected_id) == 0);
    }
    if (expected_session == nullptr) {
        assert(envelope.session_id == nullptr);
    } else {
        assert(envelope.session_id != nullptr);
        assert(strcmp(envelope.session_id, expected_session) == 0);
    }
    if (expected == PayloadTransferRequestParseStatus::ok) {
        assert(envelope.action == expected_action);
    }
}

}  // namespace

int main()
{
    expect_parse(
        "{\"id\":\"req_begin\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::ok,
        "req_begin",
        "session_aaaaaaaaaaaaaaaa",
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_chunk\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\",\"offsetBytes\":\"0\",\"chunk\":\"AA==\"}",
        PayloadTransferRequestParseStatus::ok,
        "req_chunk",
        "session_aaaaaaaaaaaaaaaa",
        PayloadTransferRequestAction::chunk);
    expect_parse(
        "{\"id\":\"req_finish\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"finish\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\"}",
        PayloadTransferRequestParseStatus::ok,
        "req_finish",
        "session_aaaaaaaaaaaaaaaa",
        PayloadTransferRequestAction::finish);
    expect_parse(
        "{\"id\":\"req_abort\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\"}",
        PayloadTransferRequestParseStatus::ok,
        "req_abort",
        "session_aaaaaaaaaaaaaaaa",
        PayloadTransferRequestAction::abort);
    expect_parse(
        "{\"id\":\"req_abort_payload\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"payloadRef\":\"payload_0000000000000001\"}",
        PayloadTransferRequestParseStatus::ok,
        "req_abort_payload",
        "session_aaaaaaaaaaaaaaaa",
        PayloadTransferRequestAction::abort);

    expect_parse(
        "{\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::invalid_envelope,
        nullptr,
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"bad id\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::invalid_envelope,
        nullptr,
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_missing_version\",\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::invalid_envelope,
        "req_missing_version",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_string_version\",\"version\":\"1\",\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::invalid_envelope,
        "req_string_version",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_float_version\",\"version\":1.5,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::invalid_envelope,
        "req_float_version",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_bool_version\",\"version\":true,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::invalid_envelope,
        "req_bool_version",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_version\",\"version\":2,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::unsupported_version,
        "req_version",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_type_bad\",\"version\":1,\"type\":\"other\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::unsupported_method,
        "req_type_bad",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_type_non_string\",\"version\":1,\"type\":7,\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::invalid_request,
        "req_type_non_string",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_action_missing\",\"version\":1,\"type\":\"payload_transfer\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::unsupported_method,
        "req_action_missing",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_action_unknown\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"unknown\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::unsupported_method,
        "req_action_unknown",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_begin_extra\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"begin\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"totalBytes\":\"1\",\"payloadDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"extra\":\"not-allowed\"}",
        PayloadTransferRequestParseStatus::invalid_request,
        "req_begin_extra",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_chunk_extra\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"chunk\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\",\"offsetBytes\":\"0\",\"chunk\":\"AA==\",\"extra\":\"not-allowed\"}",
        PayloadTransferRequestParseStatus::invalid_request,
        "req_chunk_extra",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_finish_extra\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"finish\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\",\"extra\":\"not-allowed\"}",
        PayloadTransferRequestParseStatus::invalid_request,
        "req_finish_extra",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_abort_extra\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\",\"extra\":\"not-allowed\"}",
        PayloadTransferRequestParseStatus::invalid_request,
        "req_abort_extra",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_abort_missing_target\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\"}",
        PayloadTransferRequestParseStatus::invalid_request,
        "req_abort_missing_target",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_abort_both\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"session_aaaaaaaaaaaaaaaa\",\"transferId\":\"transfer_0000000000000001\",\"payloadRef\":\"payload_0000000000000001\"}",
        PayloadTransferRequestParseStatus::invalid_request,
        "req_abort_both",
        nullptr,
        PayloadTransferRequestAction::begin);
    expect_parse(
        "{\"id\":\"req_bad_session\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":\"session_badg\",\"transferId\":\"transfer_0000000000000001\"}",
        PayloadTransferRequestParseStatus::invalid_session,
        "req_bad_session",
        nullptr,
        PayloadTransferRequestAction::abort);
    expect_parse(
        "{\"id\":\"req_missing_session\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"transferId\":\"transfer_0000000000000001\"}",
        PayloadTransferRequestParseStatus::invalid_session,
        "req_missing_session",
        nullptr,
        PayloadTransferRequestAction::abort);
    expect_parse(
        "{\"id\":\"req_non_string_session\",\"version\":1,\"type\":\"payload_transfer\",\"action\":\"abort\",\"sessionId\":7,\"transferId\":\"transfer_0000000000000001\"}",
        PayloadTransferRequestParseStatus::invalid_session,
        "req_non_string_session",
        nullptr,
        PayloadTransferRequestAction::abort);

    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/payload_transfer_request_test.cpp" \
  "${RUNTIME_DIR}/payload_transfer_request.cpp" \
  "${RUNTIME_DIR}/session_state.cpp" \
  "${RUNTIME_DIR}/sensitive_memory.cpp" \
  "${COMMON_ROOT}/protocol/request_id.cpp" \
  -o "${TMP_DIR}/payload_transfer_request_test"

"${TMP_DIR}/payload_transfer_request_test"
echo "StopWatch payload transfer request tests passed"
