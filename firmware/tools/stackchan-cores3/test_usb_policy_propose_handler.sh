#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_policy_propose_handler.sh

Compiles the extracted USB policy_propose handler and verifies state/session,
payload-delivery admission, field, policy-begin, UI-entry, and terminal-error
behavior. It does not require hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

if [[ -z "${IDF_PATH:-}" ]]; then
  echo "IDF_PATH is not set. Source ESP-IDF v5.5.4 export.sh before running this test." >&2
  exit 1
fi

MBEDTLS_ROOT="${IDF_PATH}/components/mbedtls/mbedtls"
MBEDTLS_INCLUDE_DIR="${MBEDTLS_ROOT}/include"
MBEDTLS_LIBRARY_DIR="${MBEDTLS_ROOT}/library"
if [[ ! -f "${MBEDTLS_INCLUDE_DIR}/mbedtls/sha256.h" || ! -f "${MBEDTLS_LIBRARY_DIR}/sha256.c" || ! -f "${MBEDTLS_LIBRARY_DIR}/platform_util.c" ]]; then
  echo "IDF_PATH does not expose the expected ESP-IDF mbedTLS sources: ${IDF_PATH}" >&2
  exit 1
fi

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_admission.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_admission.h" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_primitives.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_primitives.h" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_store.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_store.h" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_policy_propose_handler.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_policy_propose_handler.h" \
  "${AGENT_Q_DIR}/agent_q_usb_policy_propose_result_writer.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_policy_propose_result_writer.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_response_writer.h" \
  "${AGENT_Q_DIR}/agent_q_usb_response_writer.h" \
  "${AGENT_Q_DIR}/agent_q_policy_update_flow.h" \
  "${AGENT_Q_DIR}/agent_q_timeout_window.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_document.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
CC_BIN="${CC:-cc}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-policy-propose-handler.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/agent_q_common"
mkdir -p "${TMP_DIR}/freertos"
ln -s "${COMMON_POLICY_DIR}" "${TMP_DIR}/agent_q_common/policy"

cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_payload_delivery_admission.h"
#include "agent_q_payload_delivery_store.h"
#include "agent_q_usb_policy_propose_handler.h"
#include "agent_q_usb_policy_propose_result_writer.h"
#include "mbedtls/sha256.h"

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_material_calls = 0;
int g_busy_calls = 0;
int g_require_session_calls = 0;
int g_make_window_calls = 0;
int g_begin_calls = 0;
int g_reason_calls = 0;
int g_json_write_calls = 0;
int g_show_review_calls = 0;
int g_record_ui_error_calls = 0;
int g_finish_terminal_calls = 0;
int g_record_waiting_calls = 0;
bool g_material_ready = true;
bool g_busy = false;
bool g_session_valid = true;
bool g_json_write_ok = true;
bool g_show_review_ok = true;
agent_q::AgentQPolicyUpdateFlowBeginResult g_begin_result =
    agent_q::AgentQPolicyUpdateFlowBeginResult::ok;
agent_q::AgentQPolicyUpdateFlowTerminalResult g_ui_error_result =
    agent_q::AgentQPolicyUpdateFlowTerminalResult::ui_error;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;
char g_last_response_id[32] = {};
char g_last_response_type[40] = {};
char g_last_policy_status[40] = {};
char g_last_policy_reason[40] = {};
bool g_last_policy_included = false;
char g_last_policy_hash[80] = {};
size_t g_last_policy_count = 0;
size_t g_last_policy_condition_count = 0;
char g_last_policy_highest_action[16] = {};
agent_q::AgentQTimeoutWindow g_last_window = {};

void reset_state()
{
    agent_q::payload_delivery_store_reset();
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_material_calls = 0;
    g_busy_calls = 0;
    g_require_session_calls = 0;
    g_make_window_calls = 0;
    g_begin_calls = 0;
    g_reason_calls = 0;
    g_json_write_calls = 0;
    g_show_review_calls = 0;
    g_record_ui_error_calls = 0;
    g_finish_terminal_calls = 0;
    g_record_waiting_calls = 0;
    g_material_ready = true;
    g_busy = false;
    g_session_valid = true;
    g_json_write_ok = true;
    g_show_review_ok = true;
    g_begin_result = agent_q::AgentQPolicyUpdateFlowBeginResult::ok;
    g_ui_error_result = agent_q::AgentQPolicyUpdateFlowTerminalResult::ui_error;
    g_last_id = nullptr;
    g_last_session = nullptr;
    g_last_error_code = nullptr;
    g_last_response_id[0] = '\0';
    g_last_response_type[0] = '\0';
    g_last_policy_status[0] = '\0';
    g_last_policy_reason[0] = '\0';
    g_last_policy_included = false;
    g_last_policy_hash[0] = '\0';
    g_last_policy_count = 0;
    g_last_policy_condition_count = 0;
    g_last_policy_highest_action[0] = '\0';
    g_last_window = agent_q::AgentQTimeoutWindow{0, 0};
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
    assert(strcmp(response_type, "policy_propose_result") == 0);
    g_log_write_failure_calls += 1;
    g_last_id = id;
}

bool material_ready()
{
    g_material_calls += 1;
    return g_material_ready;
}

bool write_busy(const char* id, const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    g_busy_calls += 1;
    g_last_id = id;
    if (g_busy) {
        writer.write_error(id, "busy");
    }
    return g_busy;
}

bool write_busy_from_payload_delivery(
    const char* id,
    const agent_q::AgentQUsbOperationResponseWriter& writer)
{
    g_busy_calls += 1;
    if (agent_q::payload_delivery_admit_operation(
            agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                agent_q::AgentQPayloadDeliveryOperationKind::policy_propose,
                nullptr,
            }) !=
        agent_q::AgentQPayloadDeliveryAdmissionResult::busy) {
        return false;
    }
    return writer.write_error(id, "busy");
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

agent_q::AgentQTimeoutTick current_tick()
{
    return 10;
}

agent_q::AgentQTimeoutWindow make_review_window(agent_q::AgentQTimeoutTick now)
{
    g_make_window_calls += 1;
    return agent_q::AgentQTimeoutWindow{now, static_cast<agent_q::AgentQTimeoutTick>(now + 10)};
}

agent_q::AgentQPolicyUpdateFlowBeginResult begin_policy_update(
    JsonVariantConst policy,
    const char* request_id,
    const char* session_id,
    TickType_t now,
    agent_q::AgentQTimeoutWindow review_window)
{
    g_begin_calls += 1;
    assert(now == 10);
    assert(!policy.isNull());
    g_last_id = request_id;
    g_last_session = session_id;
    g_last_window = review_window;
    return g_begin_result;
}

const char* begin_result_reason(agent_q::AgentQPolicyUpdateFlowBeginResult result)
{
    g_reason_calls += 1;
    switch (result) {
        case agent_q::AgentQPolicyUpdateFlowBeginResult::too_large:
            return "too_large";
        case agent_q::AgentQPolicyUpdateFlowBeginResult::ok:
            return "ok";
        default:
            return "invalid_policy";
    }
}

bool show_policy_update_review()
{
    g_show_review_calls += 1;
    return g_show_review_ok;
}

agent_q::AgentQPolicyUpdateFlowTerminalResult record_ui_error()
{
    g_record_ui_error_calls += 1;
    return g_ui_error_result;
}

void finish_policy_update_terminal(
    const char* id,
    agent_q::AgentQPolicyUpdateFlowTerminalResult result)
{
    g_finish_terminal_calls += 1;
    g_last_id = id;
    assert(result == g_ui_error_result);
}

void record_waiting(const char* id)
{
    g_record_waiting_calls += 1;
    g_last_id = id;
}

agent_q::AgentQUsbOperationResponseWriter make_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

agent_q::AgentQUsbPolicyProposeHandlerOps make_ops()
{
    return agent_q::AgentQUsbPolicyProposeHandlerOps{
        material_ready,
        write_busy,
        require_session,
        current_tick,
        make_review_window,
        begin_policy_update,
        begin_result_reason,
        show_policy_update_review,
        record_ui_error,
        finish_policy_update_terminal,
        record_waiting,
    };
}

agent_q::AgentQUsbPolicyProposeHandlerOps make_payload_admission_ops()
{
    return agent_q::AgentQUsbPolicyProposeHandlerOps{
        material_ready,
        write_busy_from_payload_delivery,
        require_session,
        current_tick,
        make_review_window,
        begin_policy_update,
        begin_result_reason,
        show_policy_update_review,
        record_ui_error,
        finish_policy_update_terminal,
        record_waiting,
    };
}

void stage_finalized_payload()
{
    const uint8_t payload[] = {0x31, 0x41, 0x59, 0x26};
    char digest[agent_q::kAgentQApprovalHistoryDigestSize] = {};
    assert(agent_q::approval_history_digest_payload(
        payload,
        sizeof(payload),
        digest,
        sizeof(digest)));
    agent_q::AgentQPayloadDeliveryBeginOutput begin = {};
    assert(agent_q::payload_delivery_begin(0,
        agent_q::AgentQPayloadDeliveryBeginInput{
            "session_abcdef",
            sizeof(payload),
            digest,
            agent_q::AgentQPayloadDeliveryLimits{16, 128},
            agent_q::timeout_window_from_deadline(0, 1000),
        },
        &begin) == agent_q::AgentQPayloadDeliveryResult::ok);
    size_t received = 0;
    assert(agent_q::payload_delivery_append_chunk(0,
        agent_q::AgentQPayloadDeliveryChunkInput{
            "session_abcdef",
            begin.transfer_id,
            0,
            payload,
            sizeof(payload),
        },
        &received) == agent_q::AgentQPayloadDeliveryResult::ok);
    assert(received == sizeof(payload));
    agent_q::AgentQPayloadDeliveryFinishOutput finish = {};
    assert(agent_q::payload_delivery_finish(0,
        agent_q::AgentQPayloadDeliveryFinishInput{
            "session_abcdef",
            begin.transfer_id,
        },
        &finish) == agent_q::AgentQPayloadDeliveryResult::ok);
}

JsonDocument parse_request(const char* json)
{
    JsonDocument request;
    const DeserializationError error = deserializeJson(request, json);
    assert(!error);
    return request;
}

const char* valid_request()
{
    return "{\"id\":\"req\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session\",\"payload\":{\"policy\":{\"version\":1}}}";
}

}  // namespace

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
    if (payload == nullptr || payload_size == 0 || output == nullptr ||
        output_size != kAgentQApprovalHistoryDigestSize) {
        return false;
    }
    uint8_t digest[32] = {};
    if (mbedtls_sha256(payload, payload_size, digest, 0) != 0) {
        return false;
    }
    int written = snprintf(output, output_size,
                           "sha256:%02x%02x%02x%02x%02x%02x%02x%02x"
                           "%02x%02x%02x%02x%02x%02x%02x%02x"
                           "%02x%02x%02x%02x%02x%02x%02x%02x"
                           "%02x%02x%02x%02x%02x%02x%02x%02x",
                           digest[0], digest[1], digest[2], digest[3],
                           digest[4], digest[5], digest[6], digest[7],
                           digest[8], digest[9], digest[10], digest[11],
                           digest[12], digest[13], digest[14], digest[15],
                           digest[16], digest[17], digest[18], digest[19],
                           digest[20], digest[21], digest[22], digest[23],
                           digest[24], digest[25], digest[26], digest[27],
                           digest[28], digest[29], digest[30], digest[31]);
    return written == 71;
}

bool usb_response_write_json(JsonDocument& response)
{
    g_json_write_calls += 1;
    JsonObjectConst result =
        response["result"].is<JsonObjectConst>()
            ? response["result"].as<JsonObjectConst>()
            : response.as<JsonObjectConst>();
    snprintf(g_last_response_id, sizeof(g_last_response_id), "%s", response["id"].as<const char*>());
    snprintf(g_last_response_type, sizeof(g_last_response_type), "%s", response["method"] | response["type"] | "");
    snprintf(g_last_policy_status, sizeof(g_last_policy_status), "%s", result["status"].as<const char*>());
    snprintf(g_last_policy_reason, sizeof(g_last_policy_reason), "%s", result["reasonCode"].as<const char*>());
    g_last_policy_included = !result["policy"].isNull();
    if (g_last_policy_included) {
        JsonObjectConst policy = result["policy"].as<JsonObjectConst>();
        snprintf(g_last_policy_hash, sizeof(g_last_policy_hash), "%s", policy["policyHash"].as<const char*>());
        g_last_policy_count = policy["policyCount"].as<size_t>();
        g_last_policy_condition_count = policy["conditionCount"].as<size_t>();
        snprintf(g_last_policy_highest_action, sizeof(g_last_policy_highest_action), "%s", policy["highestAction"].as<const char*>());
    }
    return g_json_write_ok;
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

}  // namespace agent_q

int main()
{
    {
        reset_state();
        g_material_ready = false;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_busy_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_busy = true;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_busy_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(g_require_session_calls == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        stage_finalized_payload();
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request(
            "req",
            request,
            make_writer(),
            make_payload_admission_ops());
        assert(g_busy_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(g_require_session_calls == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":7,\"payload\":{\"policy\":{}}}");
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_require_session_calls == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_require_session_calls == 1);
        assert(strcmp(g_last_session, "session") == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session\",\"payload\":{\"policy\":{}},\"extra\":true}");
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_require_session_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session\",\"payload\":7}");
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session\",\"payload\":{\"policy\":{},\"extra\":true}}");
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session\",\"payload\":{}}");
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_begin_result = agent_q::AgentQPolicyUpdateFlowBeginResult::too_large;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_make_window_calls == 1);
        assert(g_begin_calls == 1);
        assert(g_reason_calls == 1);
        assert(g_json_write_calls == 1);
        assert(strcmp(g_last_response_id, "req") == 0);
        assert(strcmp(g_last_response_type, "policy_propose") == 0);
        assert(strcmp(g_last_policy_status, "invalid_policy") == 0);
        assert(strcmp(g_last_policy_reason, "too_large") == 0);
        assert(!g_last_policy_included);
        assert(g_show_review_calls == 0);
        assert(g_finish_terminal_calls == 0);
    }

    {
        reset_state();
        g_begin_result = agent_q::AgentQPolicyUpdateFlowBeginResult::invalid_policy;
        g_json_write_ok = false;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_json_write_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(g_show_review_calls == 0);
    }

    {
        reset_state();
        const agent_q::AgentQPolicyUpdateFlowSnapshot snapshot{
            true,
            agent_q::AgentQPolicyUpdateFlowStage::committing,
            "req",
            "session",
            agent_q::AgentQTimeoutWindow{10, 20},
            "sha256:policy",
            1,
            1,
            3,
            7,
            "reject",
            "reject",
            "scopes=1/1 policies=3 conditions=7",
            "Update policy",
        };
        assert(agent_q::usb_policy_propose_result_write("req", "applied", "applied", &snapshot));
        assert(g_json_write_calls == 1);
        assert(strcmp(g_last_response_id, "req") == 0);
        assert(strcmp(g_last_response_type, "policy_propose") == 0);
        assert(strcmp(g_last_policy_status, "applied") == 0);
        assert(strcmp(g_last_policy_reason, "applied") == 0);
        assert(g_last_policy_included);
        assert(strcmp(g_last_policy_hash, "sha256:policy") == 0);
        assert(g_last_policy_count == 3);
        assert(g_last_policy_condition_count == 7);
        assert(strcmp(g_last_policy_highest_action, "reject") == 0);
    }

    {
        reset_state();
        g_show_review_ok = false;
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_begin_calls == 1);
        assert(g_show_review_calls == 1);
        assert(g_record_ui_error_calls == 1);
        assert(g_finish_terminal_calls == 1);
        assert(g_record_waiting_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(valid_request());
        agent_q::handle_usb_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_begin_calls == 1);
        assert(g_last_window.started_at == 10);
        assert(g_last_window.deadline == 20);
        assert(g_show_review_calls == 1);
        assert(g_record_waiting_calls == 1);
        assert(g_write_error_calls == 0);
        assert(g_json_write_calls == 0);
        assert(g_finish_terminal_calls == 0);
    }

    printf("usb_policy_propose_handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -c "${AGENT_Q_DIR}/agent_q_payload_delivery_admission.cpp" \
  -o "${TMP_DIR}/payload_delivery_admission.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -c "${AGENT_Q_DIR}/agent_q_payload_delivery_primitives.cpp" \
  -o "${TMP_DIR}/payload_delivery_primitives.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -c "${AGENT_Q_DIR}/agent_q_payload_delivery_store.cpp" \
  -o "${TMP_DIR}/payload_delivery_store.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -c "${AGENT_Q_DIR}/agent_q_session.cpp" \
  -o "${TMP_DIR}/session.o"

"${CC_BIN}" -std=c99 -Wall -Wextra -Werror \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"

"${CC_BIN}" -std=c99 -Wall -Wextra -Werror \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${TMP_DIR}/payload_delivery_admission.o" \
  "${TMP_DIR}/payload_delivery_primitives.o" \
  "${TMP_DIR}/payload_delivery_store.o" \
  "${TMP_DIR}/session.o" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  "${AGENT_Q_DIR}/agent_q_usb_policy_propose_handler.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_policy_propose_result_writer.cpp" \
  -o "${TMP_DIR}/test_usb_policy_propose_handler"

"${TMP_DIR}/test_usb_policy_propose_handler"
