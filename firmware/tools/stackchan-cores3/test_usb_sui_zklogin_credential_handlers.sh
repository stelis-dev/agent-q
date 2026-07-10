#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_sui_zklogin_credential_handlers.sh

Compiles the Sui zkLogin credential USB handlers and verifies preparation and
proposal admission, active-identity guards, and local PIN handoff behavior. It
does not require hardware.
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
  "${COMMON_ROOT}/sui/zklogin_credential_outcome.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_outcome.h" \
  "${COMMON_ROOT}/sui/zklogin_credential_payload.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_payload.h" \
  "${COMMON_ROOT}/protocol/json_input.h" \
  "${COMMON_ROOT}/protocol/request_id.h" \
  "${COMMON_ROOT}/protocol/active_session_request_guard.cpp" \
  "${COMMON_ROOT}/protocol/active_session_request_guard.h" \
  "${COMMON_ROOT}/protocol/sui_zklogin_credential_handlers.cpp" \
  "${COMMON_ROOT}/protocol/sui_zklogin_credential_handlers.h" \
  "${COMMON_ROOT}/sui/zklogin_proof_record.h" \
  "${COMMON_ROOT}/protocol/response_writer.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-sui-zklogin-credential-handlers.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos" "${TMP_DIR}/stubs"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/stubs/byte_conversions.h" <<'H'
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

inline int bytes_to_base64(
    const uint8_t* input,
    size_t input_size,
    char* output,
    size_t output_size)
{
    (void)input;
    (void)input_size;
    if (output == nullptr || output_size < 18) {
        return -1;
    }
    snprintf(output, output_size, "scheme-key-base64");
    return 0;
}
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/session_id.h"
#include "protocol/sui_zklogin_credential_handlers.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_write_json_calls = 0;
int g_material_calls = 0;
int g_prepare_admission_calls = 0;
int g_propose_admission_calls = 0;
int g_safe_read_admission_calls = 0;
int g_require_session_calls = 0;
int g_prepare_credential_calls = 0;
int g_current_tick_calls = 0;
int g_make_window_calls = 0;
int g_begin_proposal_calls = 0;
int g_show_review_calls = 0;
bool g_material_ready = true;
bool g_prepare_admission_blocks = false;
bool g_propose_admission_blocks = false;
bool g_safe_read_admission_blocks = false;
bool g_session_valid = true;
signing::SuiZkLoginCredentialPrepareResult g_prepare_result =
    signing::SuiZkLoginCredentialPrepareResult::ok;
signing::SuiZkLoginCredentialProposalBeginResult g_begin_result =
    signing::SuiZkLoginCredentialProposalBeginResult::ok;
bool g_show_review_result = true;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;
char g_last_json_type[40] = {};
char g_last_json_status[40] = {};
char g_last_json_reason[40] = {};
char g_last_json_public_key[48] = {};
char g_last_json_address[80] = {};
bool g_last_json_session_ended = false;
signing::OperationType g_last_safe_read_operation =
    signing::OperationType::unsupported;

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_write_json_calls = 0;
    g_material_calls = 0;
    g_prepare_admission_calls = 0;
    g_propose_admission_calls = 0;
    g_safe_read_admission_calls = 0;
    g_require_session_calls = 0;
    g_prepare_credential_calls = 0;
    g_current_tick_calls = 0;
    g_make_window_calls = 0;
    g_begin_proposal_calls = 0;
    g_show_review_calls = 0;
    g_material_ready = true;
    g_prepare_admission_blocks = false;
    g_propose_admission_blocks = false;
    g_safe_read_admission_blocks = false;
    g_session_valid = true;
    g_prepare_result = signing::SuiZkLoginCredentialPrepareResult::ok;
    g_begin_result = signing::SuiZkLoginCredentialProposalBeginResult::ok;
    g_show_review_result = true;
    g_last_id = nullptr;
    g_last_session = nullptr;
    g_last_error_code = nullptr;
    g_last_json_type[0] = '\0';
    g_last_json_status[0] = '\0';
    g_last_json_reason[0] = '\0';
    g_last_json_public_key[0] = '\0';
    g_last_json_address[0] = '\0';
    g_last_json_session_ended = false;
    g_last_safe_read_operation = signing::OperationType::unsupported;
}

bool write_error(const char* id, const char* code)
{
    g_write_error_calls += 1;
    g_last_id = id;
    g_last_error_code = code;
    return true;
}

void log_write_failure(const char* response_type, const char* id)
{
    (void)response_type;
    g_log_write_failure_calls += 1;
    g_last_id = id;
}

bool material_ready()
{
    g_material_calls += 1;
    return g_material_ready;
}

bool write_prepare_admission(const char* id, const signing::ResponseWriter& writer)
{
    g_prepare_admission_calls += 1;
    g_last_id = id;
    if (g_prepare_admission_blocks) {
        writer.write_error(id, "busy");
        return true;
    }
    return false;
}

bool write_propose_admission(const char* id, const signing::ResponseWriter& writer)
{
    g_propose_admission_calls += 1;
    g_last_id = id;
    if (g_propose_admission_blocks) {
        writer.write_error(id, "busy");
        return true;
    }
    return false;
}

bool write_safe_read_admission(
    const char* id,
    signing::OperationType operation,
    const signing::ResponseWriter& writer)
{
    g_safe_read_admission_calls += 1;
    g_last_id = id;
    g_last_safe_read_operation = operation;
    if (g_safe_read_admission_blocks) {
        writer.write_error(id, "busy");
        return true;
    }
    return false;
}

bool write_propose_state_error(const char* id, const signing::ResponseWriter& writer)
{
    if (g_prepare_result == signing::SuiZkLoginCredentialPrepareResult::ok) {
        return false;
    }
    writer.write_error(id, "invalid_state");
    return true;
}

bool require_session(
    const char* id,
    const char* session_id,
    const signing::ResponseWriter& writer)
{
    g_require_session_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    if (!signing::session_id_format_valid(session_id) || !g_session_valid) {
        writer.write_error(id, "invalid_session");
        return false;
    }
    return g_session_valid;
}

signing::SuiZkLoginCredentialPrepareResult prepare_credential(
    const char* session_id,
    signing::SuiZkLoginCredentialPreparation* output)
{
    g_prepare_credential_calls += 1;
    assert(strcmp(session_id, "session_0001020304050607") == 0);
    if (output == nullptr ||
        g_prepare_result != signing::SuiZkLoginCredentialPrepareResult::ok) {
        return g_prepare_result;
    }
    snprintf(output->address, sizeof(output->address), "%s",
             "0x1111111111111111111111111111111111111111111111111111111111111111");
    output->public_key[0] = 0x00;
    for (size_t index = 1; index < 33; ++index) {
        output->public_key[index] = static_cast<uint8_t>(index);
    }
    output->public_key_size = 33;
    return signing::SuiZkLoginCredentialPrepareResult::ok;
}

signing::TimeoutTick current_tick()
{
    g_current_tick_calls += 1;
    return 10;
}

signing::TimeoutWindow make_window(signing::TimeoutTick now)
{
    g_make_window_calls += 1;
    return signing::timeout_window_from_deadline(now, now + 100);
}

signing::SuiZkLoginCredentialProposalBeginResult begin_proposal(
    JsonVariantConst params,
    const char* request_id,
    const char* session_id,
    signing::TimeoutTick now,
    signing::TimeoutWindow request_window)
{
    (void)params;
    g_begin_proposal_calls += 1;
    assert(strcmp(request_id, "req") == 0);
    assert(strcmp(session_id, "session_0001020304050607") == 0);
    assert(now == 10);
    assert(request_window.deadline == 110);
    return g_begin_result;
}

bool show_review(const char* request_id)
{
    g_show_review_calls += 1;
    assert(strcmp(request_id, "req") == 0);
    return g_show_review_result;
}

bool write_success_result(const char* id, const char* method, JsonObjectConst result)
{
    g_write_json_calls += 1;
    snprintf(g_last_json_type, sizeof(g_last_json_type), "%s", method != nullptr ? method : "");
    snprintf(g_last_json_status, sizeof(g_last_json_status), "%s", result["status"] | "");
    snprintf(g_last_json_reason, sizeof(g_last_json_reason), "%s", result["reasonCode"] | "");
    snprintf(g_last_json_public_key, sizeof(g_last_json_public_key), "%s",
             result["preparation"]["publicKey"] | "");
    snprintf(g_last_json_address, sizeof(g_last_json_address), "%s",
             result["preparation"]["address"] | "");
    g_last_json_session_ended = result["sessionEnded"] | false;
    g_last_id = id;
    return true;
}

signing::ResponseWriter make_writer()
{
    return signing::ResponseWriter{
        write_error,
        write_success_result,
        log_write_failure,
    };
}

signing::SuiZkLoginCredentialHandlerOps make_ops()
{
    const signing::ActiveSessionRequestGuardOps prepare_guard{
        material_ready,
        nullptr,
        write_safe_read_admission,
        require_session,
    };
    const signing::ActiveSessionRequestGuardOps propose_guard{
        material_ready,
        nullptr,
        nullptr,
        require_session,
    };
    return signing::SuiZkLoginCredentialHandlerOps{
        write_prepare_admission,
        write_propose_admission,
        nullptr,
        write_propose_state_error,
        prepare_guard,
        propose_guard,
        signing::SessionIdMode::required,
        signing::SessionIdMode::required,
        prepare_credential,
        current_tick,
        make_window,
        begin_proposal,
        nullptr,
        show_review,
    };
}

JsonDocument parse_request(const char* json)
{
    JsonDocument request;
    const DeserializationError error = deserializeJson(request, json);
    assert(!error);
    return request;
}

}  // namespace

namespace signing {

bool usb_response_write_json(JsonDocument& response)
{
    g_write_json_calls += 1;
    JsonObjectConst result = response["result"].as<JsonObjectConst>();
    snprintf(g_last_json_type, sizeof(g_last_json_type), "%s", response["method"] | "");
    snprintf(g_last_json_status, sizeof(g_last_json_status), "%s", result["status"] | "");
    snprintf(g_last_json_reason, sizeof(g_last_json_reason), "%s", result["reasonCode"] | "");
    snprintf(g_last_json_public_key, sizeof(g_last_json_public_key), "%s",
             result["preparation"]["publicKey"] | "");
    snprintf(g_last_json_address, sizeof(g_last_json_address), "%s",
             result["preparation"]["address"] | "");
    g_last_json_session_ended = result["sessionEnded"] | false;
    return true;
}

bool usb_response_write_success_result(const char* id, const char* method, JsonObjectConst result)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = 1;
    response["success"] = true;
    response["method"] = method;
    response["result"].set(result);
    return usb_response_write_json(response);
}

}  // namespace signing

int main()
{
    {
        reset_state();
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
        signing::handle_protocol_credential_prepare_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_prepare_admission_calls == 1);
        assert(g_safe_read_admission_calls == 1);
        assert(g_last_safe_read_operation == signing::OperationType::credential_prepare);
        assert(g_require_session_calls == 1);
        assert(g_prepare_credential_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_type, "credential_prepare") == 0);
        assert(strcmp(g_last_json_status, "") == 0);
        assert(strcmp(g_last_json_public_key, "scheme-key-base64") == 0);
        assert(strcmp(g_last_json_address,
                      "0x1111111111111111111111111111111111111111111111111111111111111111") == 0);
    }

    {
        reset_state();
        g_prepare_result = signing::SuiZkLoginCredentialPrepareResult::invalid_state;
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
        signing::handle_protocol_credential_prepare_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"chain\":\"sui\",\"credential\":\"passkey\"}}");
        signing::handle_protocol_credential_prepare_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_prepare_credential_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_prepare\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
        signing::handle_protocol_credential_prepare_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_prepare_credential_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"session_badg\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
        signing::handle_protocol_credential_prepare_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_prepare_credential_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
        signing::handle_protocol_credential_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_propose_admission_calls == 1);
        assert(g_require_session_calls == 1);
        assert(g_begin_proposal_calls == 0);
        assert(g_show_review_calls == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\",\"network\":\"testnet\",\"address\":\"0x1\",\"publicKey\":\"bad\",\"maxEpoch\":\"1\",\"inputs\":{}}}");
        signing::handle_protocol_credential_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_propose_admission_calls == 1);
        assert(g_safe_read_admission_calls == 0);
        assert(g_require_session_calls == 1);
        assert(g_current_tick_calls == 1);
        assert(g_make_window_calls == 1);
        assert(g_begin_proposal_calls == 1);
        assert(g_show_review_calls == 1);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        g_begin_result = signing::SuiZkLoginCredentialProposalBeginResult::invalid_proof;
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\",\"network\":\"testnet\",\"address\":\"0x1\",\"publicKey\":\"bad\",\"maxEpoch\":\"1\",\"inputs\":{}}}");
        signing::handle_protocol_credential_propose_request("req", request, make_writer(), make_ops());
        assert(g_begin_proposal_calls == 1);
        assert(g_show_review_calls == 0);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_type, "credential_propose") == 0);
        assert(strcmp(g_last_json_status, "invalid_proof") == 0);
        assert(strcmp(g_last_json_reason, "invalid_proof") == 0);
        assert(!g_last_json_session_ended);
    }

    {
        reset_state();
        g_prepare_result = signing::SuiZkLoginCredentialPrepareResult::invalid_state;
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session_0001020304050607\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\",\"network\":\"testnet\",\"address\":\"0x1\",\"publicKey\":\"bad\",\"maxEpoch\":\"1\",\"inputs\":{}}}");
        signing::handle_protocol_credential_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_begin_proposal_calls == 0);
        assert(g_show_review_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_propose\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
        signing::handle_protocol_credential_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_begin_proposal_calls == 0);
        assert(g_show_review_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session_badg\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
        signing::handle_protocol_credential_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_begin_proposal_calls == 0);
        assert(g_show_review_calls == 0);
    }

    printf("USB Sui zkLogin credential handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${COMMON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_ROOT}/protocol/active_session_request_guard.cpp" \
  "${COMMON_ROOT}/protocol/sui_zklogin_credential_handlers.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_outcome.cpp" \
  "${COMMON_ROOT}/sui/zklogin_credential_payload.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
