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
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${AGENT_Q_DIR}/agent_q_usb_sui_zklogin_credential_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_sui_zklogin_credential_handlers.h" \
  "${AGENT_Q_DIR}/agent_q_usb_sui_zklogin_credential_outcome_writer.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_sui_zklogin_credential_outcome_writer.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-sui-zklogin-credential-handlers.XXXXXX")"
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

#include "agent_q_usb_sui_zklogin_credential_handlers.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_write_json_calls = 0;
int g_material_calls = 0;
int g_prepare_admission_calls = 0;
int g_propose_admission_calls = 0;
int g_safe_read_admission_calls = 0;
int g_require_session_calls = 0;
int g_resolve_identity_calls = 0;
int g_current_tick_calls = 0;
int g_make_window_calls = 0;
int g_begin_proposal_calls = 0;
int g_show_review_calls = 0;
bool g_material_ready = true;
bool g_prepare_admission_blocks = false;
bool g_propose_admission_blocks = false;
bool g_safe_read_admission_blocks = false;
bool g_session_valid = true;
agent_q::AgentQSuiActiveIdentity g_identity = {};
agent_q::AgentQSuiZkLoginProposalBeginResult g_begin_result =
    agent_q::AgentQSuiZkLoginProposalBeginResult::ok;
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
agent_q::AgentQUsbOperationType g_last_safe_read_operation =
    agent_q::AgentQUsbOperationType::unsupported;

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
    g_resolve_identity_calls = 0;
    g_current_tick_calls = 0;
    g_make_window_calls = 0;
    g_begin_proposal_calls = 0;
    g_show_review_calls = 0;
    g_material_ready = true;
    g_prepare_admission_blocks = false;
    g_propose_admission_blocks = false;
    g_safe_read_admission_blocks = false;
    g_session_valid = true;
    g_identity = {};
    g_identity.kind = agent_q::AgentQSuiActiveIdentityKind::native;
    g_identity.error = agent_q::AgentQSuiActiveIdentityError::none;
    snprintf(g_identity.address, sizeof(g_identity.address), "%s",
             "0x1111111111111111111111111111111111111111111111111111111111111111");
    g_identity.public_key[0] = agent_q::kAgentQSuiSignatureSchemeFlagEd25519;
    for (size_t index = 1; index < agent_q::kAgentQSuiSchemePrefixedEd25519PublicKeyBytes; ++index) {
        g_identity.public_key[index] = static_cast<uint8_t>(index);
    }
    g_identity.public_key_size = agent_q::kAgentQSuiSchemePrefixedEd25519PublicKeyBytes;
    g_begin_result = agent_q::AgentQSuiZkLoginProposalBeginResult::ok;
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
    g_last_safe_read_operation = agent_q::AgentQUsbOperationType::unsupported;
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

bool write_prepare_admission(const char* id, const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    g_prepare_admission_calls += 1;
    g_last_id = id;
    if (g_prepare_admission_blocks) {
        writer.write_error(id, "busy");
        return true;
    }
    return false;
}

bool write_propose_admission(const char* id, const agent_q::AgentQUsbOperationResponseWriter& writer)
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
    agent_q::AgentQUsbOperationType operation,
    const agent_q::AgentQUsbOperationResponseWriter& writer)
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

bool require_session(
    const char* id,
    const char* session_id,
    const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    g_require_session_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    if (!g_session_valid) {
        writer.write_error(id, "invalid_session");
    }
    return g_session_valid;
}

agent_q::AgentQSuiActiveIdentity resolve_identity()
{
    g_resolve_identity_calls += 1;
    return g_identity;
}

agent_q::AgentQTimeoutTick current_tick()
{
    g_current_tick_calls += 1;
    return 10;
}

agent_q::AgentQTimeoutWindow make_window(agent_q::AgentQTimeoutTick now)
{
    g_make_window_calls += 1;
    return agent_q::timeout_window_from_deadline(now, now + 100);
}

agent_q::AgentQSuiZkLoginProposalBeginResult begin_proposal(
    JsonVariantConst params,
    const char* request_id,
    const char* session_id,
    TickType_t now,
    agent_q::AgentQTimeoutWindow request_window)
{
    (void)params;
    g_begin_proposal_calls += 1;
    assert(strcmp(request_id, "req") == 0);
    assert(strcmp(session_id, "session") == 0);
    assert(now == 10);
    assert(request_window.deadline == 110);
    return g_begin_result;
}

const char* begin_result_reason(agent_q::AgentQSuiZkLoginProposalBeginResult result)
{
    return result == agent_q::AgentQSuiZkLoginProposalBeginResult::ok
               ? ""
               : "invalid_proof";
}

bool show_review(const char* request_id)
{
    g_show_review_calls += 1;
    assert(strcmp(request_id, "req") == 0);
    return g_show_review_result;
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

agent_q::AgentQUsbSuiZkLoginCredentialHandlerOps make_ops()
{
    return agent_q::AgentQUsbSuiZkLoginCredentialHandlerOps{
        material_ready,
        write_prepare_admission,
        write_propose_admission,
        write_safe_read_admission,
        require_session,
        resolve_identity,
        current_tick,
        make_window,
        begin_proposal,
        begin_result_reason,
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

namespace agent_q {

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

const char* sui_zklogin_proposal_terminal_status(
    AgentQSuiZkLoginProposalTerminalResult result)
{
    switch (result) {
        case AgentQSuiZkLoginProposalTerminalResult::invalid_proof:
            return "invalid_proof";
        case AgentQSuiZkLoginProposalTerminalResult::activated:
            return "activated";
        default:
            return "";
    }
}

const char* sui_zklogin_proposal_terminal_reason(
    AgentQSuiZkLoginProposalTerminalResult result)
{
    switch (result) {
        case AgentQSuiZkLoginProposalTerminalResult::invalid_proof:
            return "invalid_proof";
        case AgentQSuiZkLoginProposalTerminalResult::activated:
            return "device_confirmed";
        default:
            return "invalid_state";
    }
}

}  // namespace agent_q

int main()
{
    {
        reset_state();
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"session\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
        agent_q::handle_usb_credential_prepare_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_prepare_admission_calls == 1);
        assert(g_safe_read_admission_calls == 1);
        assert(g_last_safe_read_operation == agent_q::AgentQUsbOperationType::credential_prepare);
        assert(g_require_session_calls == 1);
        assert(g_resolve_identity_calls == 1);
        assert(g_write_json_calls == 1);
        assert(strcmp(g_last_json_type, "credential_prepare") == 0);
        assert(strcmp(g_last_json_status, "") == 0);
        assert(strcmp(g_last_json_public_key, "scheme-key-base64") == 0);
        assert(strcmp(g_last_json_address, g_identity.address) == 0);
    }

    {
        reset_state();
        g_identity.kind = agent_q::AgentQSuiActiveIdentityKind::zklogin;
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"session\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
        agent_q::handle_usb_credential_prepare_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_write_json_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_prepare\",\"sessionId\":\"session\",\"payload\":{\"chain\":\"sui\",\"credential\":\"passkey\"}}");
        agent_q::handle_usb_credential_prepare_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_resolve_identity_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
        agent_q::handle_usb_credential_propose_request("req", request, make_writer(), make_ops());
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
        g_begin_result = agent_q::AgentQSuiZkLoginProposalBeginResult::invalid_proof;
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
        agent_q::handle_usb_credential_propose_request("req", request, make_writer(), make_ops());
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
        g_identity.kind = agent_q::AgentQSuiActiveIdentityKind::zklogin;
        JsonDocument request = parse_request(
            "{\"id\":\"req\",\"version\":1,\"method\":\"credential_propose\",\"sessionId\":\"session\",\"payload\":{\"chain\":\"sui\",\"credential\":\"zklogin\"}}");
        agent_q::handle_usb_credential_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
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
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_sui_zklogin_credential_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_sui_zklogin_credential_outcome_writer.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
