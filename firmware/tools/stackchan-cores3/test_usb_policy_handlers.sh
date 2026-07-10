#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_policy_handlers.sh

Compiles the extracted USB policy handlers and verifies policy_get plus
policy_propose state/session, payload-delivery admission, field, policy-begin,
UI-entry, and terminal-error behavior. It does not require hardware.
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
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

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
  "${COMMON_ROOT}/transport/payload_delivery_admission.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_admission.h" \
  "${COMMON_ROOT}/transport/payload_delivery_operation_kind.h" \
  "${COMMON_ROOT}/transport/payload_delivery_primitives.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_primitives.h" \
  "${COMMON_ROOT}/transport/payload_delivery_store.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_store.h" \
  "${REPO_ROOT}/firmware/src/common/protocol/approval_history.h" \
  "${COMMON_ROOT}/protocol/session_state.cpp" \
  "${COMMON_ROOT}/protocol/active_session_request_guard.cpp" \
  "${COMMON_ROOT}/protocol/active_session_request_guard.h" \
  "${COMMON_ROOT}/policy/policy_handlers.cpp" \
  "${COMMON_ROOT}/policy/policy_handlers.h" \
  "${COMMON_POLICY_DIR}/policy_json_writer.cpp" \
  "${COMMON_POLICY_DIR}/policy_json_writer.h" \
  "${COMMON_ROOT}/protocol/response_writer.h" \
  "${RUNTIME_DIR}/usb_response_writer.h" \
  "${COMMON_POLICY_DIR}/policy_store.h" \
  "${REPO_ROOT}/firmware/src/common/policy/policy_update_flow.h" \
  "${COMMON_ROOT}/transport/timeout_window.h" \
  "${COMMON_POLICY_DIR}/document.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
CC_BIN="${CC:-cc}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-policy-handlers.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/firmware_common"
mkdir -p "${TMP_DIR}/freertos"
ln -s "${COMMON_POLICY_DIR}" "${TMP_DIR}/firmware_common/policy"

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

#include "protocol/approval_history.h"
#include "transport/payload_delivery_admission.h"
#include "transport/payload_delivery_store.h"
#include "policy/policy_json_writer.h"
#include "policy/policy_store.h"
#include "policy/policy_handlers.h"
#include "mbedtls/sha256.h"

namespace signing {

bool usb_response_write_success_result(const char* id, const char* method, JsonObjectConst result);

}  // namespace signing

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_material_calls = 0;
int g_busy_calls = 0;
int g_policy_get_admission_calls = 0;
int g_require_session_calls = 0;
int g_read_policy_calls = 0;
int g_record_policy_unavailable_calls = 0;
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
bool g_policy_get_admission_error = false;
bool g_session_valid = true;
bool g_read_policy_ok = true;
bool g_policy_has_document = true;
bool g_policy_json_write_ok = true;
bool g_json_write_ok = true;
bool g_show_review_ok = true;
signing::PolicyUpdateFlowBeginResult g_begin_result =
    signing::PolicyUpdateFlowBeginResult::ok;
signing::PolicyUpdateFlowTerminalResult g_ui_error_result =
    signing::PolicyUpdateFlowTerminalResult::ui_error;
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
char g_last_policy_id[80] = {};
char g_last_policy_default_action[16] = {};
char g_last_policy_where_type[256] = {};
signing::TimeoutWindow g_last_window = {};
signing::CurrentPolicyDocument g_policy_document = {};

void reset_state()
{
    signing::payload_delivery_store_reset();
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_material_calls = 0;
    g_busy_calls = 0;
    g_policy_get_admission_calls = 0;
    g_require_session_calls = 0;
    g_read_policy_calls = 0;
    g_record_policy_unavailable_calls = 0;
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
    g_policy_get_admission_error = false;
    g_session_valid = true;
    g_read_policy_ok = true;
    g_policy_has_document = true;
    g_policy_json_write_ok = true;
    g_json_write_ok = true;
    g_show_review_ok = true;
    g_begin_result = signing::PolicyUpdateFlowBeginResult::ok;
    g_ui_error_result = signing::PolicyUpdateFlowTerminalResult::ui_error;
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
    g_last_policy_id[0] = '\0';
    g_last_policy_default_action[0] = '\0';
    g_last_policy_where_type[0] = '\0';
    g_last_window = signing::TimeoutWindow{0, 0};
    g_policy_document = signing::CurrentPolicyDocument{
        signing::kCurrentPolicySchema,
        signing::CurrentPolicyAction::reject,
        nullptr,
        0,
    };
}

void count_policy_document(
    const signing::CurrentPolicyDocument& document,
    size_t* network_count,
    size_t* policy_count,
    size_t* condition_count)
{
    *network_count = 0;
    *policy_count = 0;
    *condition_count = 0;
    for (size_t blockchain_index = 0; blockchain_index < document.blockchain_count; ++blockchain_index) {
        const signing::CurrentPolicyBlockchainScope& blockchain =
            document.blockchains[blockchain_index];
        *network_count += blockchain.network_count;
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            const signing::CurrentPolicyNetworkScope& network = blockchain.networks[network_index];
            *policy_count += network.policy_count;
            for (size_t policy_index = 0; policy_index < network.policy_count; ++policy_index) {
                *condition_count += network.policies[policy_index].condition_count;
            }
        }
    }
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
    assert(strcmp(response_type, "policy_get") == 0 ||
           strcmp(response_type, "policy_propose") == 0);
    g_log_write_failure_calls += 1;
    g_last_id = id;
}

bool material_ready()
{
    g_material_calls += 1;
    return g_material_ready;
}

bool write_busy(const char* id, const signing::ResponseWriter& writer)
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
    const signing::ResponseWriter& writer)
{
    g_busy_calls += 1;
    if (signing::payload_delivery_admit_operation(
            signing::PayloadDeliveryOperationAdmissionInput{0,
                signing::PayloadDeliveryOperationKind::policy_propose,
            }) !=
        signing::PayloadDeliveryAdmissionResult::busy) {
        return false;
    }
    return writer.write_error(id, "busy");
}

bool write_policy_get_admission_error(
    const char* id,
    signing::OperationType operation,
    const signing::ResponseWriter& writer)
{
    assert(operation == signing::OperationType::policy_get);
    g_policy_get_admission_calls += 1;
    g_last_id = id;
    if (!g_policy_get_admission_error) {
        return false;
    }
    return writer.write_error(id, "busy");
}

bool require_session(
    const char* id,
    const char* session_id,
    const signing::ResponseWriter& writer)
{
    g_require_session_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    if (!g_session_valid) {
        writer.write_error(id, "invalid_session");
    }
    return g_session_valid;
}

signing::TimeoutTick current_tick()
{
    return 10;
}

signing::TimeoutWindow make_review_window(signing::TimeoutTick now)
{
    g_make_window_calls += 1;
    return signing::TimeoutWindow{now, static_cast<signing::TimeoutTick>(now + 10)};
}

signing::PolicyUpdateFlowBeginResult begin_policy_update(
    JsonVariantConst policy,
    const char* request_id,
    const char* session_id,
    TickType_t now,
    signing::TimeoutWindow review_window)
{
    g_begin_calls += 1;
    assert(now == 10);
    assert(!policy.isNull());
    g_last_id = request_id;
    g_last_session = session_id;
    g_last_window = review_window;
    return g_begin_result;
}

const char* begin_result_reason(signing::PolicyUpdateFlowBeginResult result)
{
    g_reason_calls += 1;
    switch (result) {
        case signing::PolicyUpdateFlowBeginResult::too_large:
            return "too_large";
        case signing::PolicyUpdateFlowBeginResult::ok:
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

signing::PolicyUpdateFlowTerminalResult record_ui_error()
{
    g_record_ui_error_calls += 1;
    return g_ui_error_result;
}

void finish_policy_update_terminal(
    const char* id,
    signing::PolicyUpdateFlowTerminalResult result)
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

void record_policy_unavailable()
{
    g_record_policy_unavailable_calls += 1;
}

signing::ResponseWriter make_writer()
{
    return signing::ResponseWriter{
        write_error,
        signing::usb_response_write_success_result,
        log_write_failure,
    };
}

signing::PolicyHandlerOps make_ops()
{
    return signing::PolicyHandlerOps{
        material_ready,
        write_busy,
        write_policy_get_admission_error,
        write_busy,
        require_session,
        record_policy_unavailable,
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

signing::PolicyHandlerOps make_payload_admission_ops()
{
    return signing::PolicyHandlerOps{
        material_ready,
        write_busy_from_payload_delivery,
        write_policy_get_admission_error,
        write_busy_from_payload_delivery,
        require_session,
        record_policy_unavailable,
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
    char digest[signing::kApprovalHistoryDigestSize] = {};
    assert(signing::approval_history_digest_payload(
        payload,
        sizeof(payload),
        digest,
        sizeof(digest)));
    signing::PayloadDeliveryBeginOutput begin = {};
    assert(signing::payload_delivery_begin(0,
        signing::PayloadDeliveryBeginInput{
            "session_abcdef",
            sizeof(payload),
            digest,
            signing::PayloadDeliveryLimits{16, 128},
            signing::timeout_window_from_deadline(0, 1000),
        },
        &begin) == signing::PayloadDeliveryResult::ok);
    size_t received = 0;
    assert(signing::payload_delivery_append_chunk(0,
        signing::PayloadDeliveryChunkInput{
            "session_abcdef",
            begin.transfer_id,
            0,
            payload,
            sizeof(payload),
        },
        &received) == signing::PayloadDeliveryResult::ok);
    assert(received == sizeof(payload));
    signing::PayloadDeliveryFinishOutput finish = {};
    assert(signing::payload_delivery_finish(0,
        signing::PayloadDeliveryFinishInput{
            "session_abcdef",
            begin.transfer_id,
            signing::approval_history_digest_payload,
        },
        &finish) == signing::PayloadDeliveryResult::ok);
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
    if (payload == nullptr || payload_size == 0 || output == nullptr ||
        output_size != kApprovalHistoryDigestSize) {
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
    JsonObjectConst result = response["result"].as<JsonObjectConst>();
    snprintf(g_last_response_id, sizeof(g_last_response_id), "%s", response["id"].as<const char*>());
    snprintf(g_last_response_type, sizeof(g_last_response_type), "%s", response["method"] | "");
    snprintf(g_last_policy_status, sizeof(g_last_policy_status), "%s", result["status"] | "");
    snprintf(g_last_policy_reason, sizeof(g_last_policy_reason), "%s", result["reasonCode"] | "");
    g_last_policy_included = !result["policy"].isNull();
    if (g_last_policy_included) {
        JsonObjectConst policy = result["policy"].as<JsonObjectConst>();
        snprintf(g_last_policy_hash, sizeof(g_last_policy_hash), "%s", policy["policyHash"] | "");
        snprintf(g_last_policy_id, sizeof(g_last_policy_id), "%s", policy["policyId"] | "");
        snprintf(g_last_policy_default_action, sizeof(g_last_policy_default_action), "%s", policy["defaultAction"] | "");
        g_last_policy_count = policy["policyCount"] | 0;
        g_last_policy_condition_count = policy["conditionCount"] | 0;
        snprintf(g_last_policy_highest_action, sizeof(g_last_policy_highest_action), "%s", policy["highestAction"] | "");
        const char* where_type =
            policy["blockchains"][0]["networks"][0]["policies"][0]["conditions"][0]["where"]["type"] | "";
        snprintf(g_last_policy_where_type, sizeof(g_last_policy_where_type), "%s", where_type);
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

bool read_active_policy_document(StoredPolicyDocument* out)
{
    g_read_policy_calls += 1;
    if (!g_read_policy_ok || out == nullptr) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (!g_policy_has_document) {
        return true;
    }
    size_t network_count = 0;
    size_t policy_count = 0;
    size_t condition_count = 0;
    count_policy_document(
        g_policy_document,
        &network_count,
        &policy_count,
        &condition_count);
    out->schema = kStoredPolicySchema;
    snprintf(out->policy_id, sizeof(out->policy_id), "sha256:test");
    out->default_action = current_policy_action_name(g_policy_document.default_action);
    out->blockchain_count = g_policy_document.blockchain_count;
    out->network_count = network_count;
    out->policy_count = policy_count;
    out->condition_count = condition_count;
    out->document = &g_policy_document;
    return true;
}

bool policy_store_write_policy_json(JsonObject policy_json, const StoredPolicyDocument& policy)
{
    if (!g_policy_json_write_ok) {
        return false;
    }
    return write_current_policy_json(
        policy_json,
        policy.schema,
        policy.policy_id,
        policy.default_action,
        policy.blockchain_count,
        policy.network_count,
        policy.policy_count,
        policy.condition_count,
        policy.document);
}

}  // namespace signing

int main()
{
    {
        reset_state();
        g_material_ready = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":\"session\"}");
        signing::handle_protocol_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_busy_calls == 0);
        assert(g_policy_get_admission_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_policy_calls == 0);
    }

    {
        reset_state();
        g_busy = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":\"session\"}");
        signing::handle_protocol_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_busy_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(g_policy_get_admission_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_policy_calls == 0);
    }

    {
        reset_state();
        g_policy_get_admission_error = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":\"session\"}");
        signing::handle_protocol_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_busy_calls == 1);
        assert(g_policy_get_admission_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_policy_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":7}");
        signing::handle_protocol_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_policy_get_admission_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_policy_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":\"session\"}");
        signing::handle_protocol_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_policy_get_admission_calls == 1);
        assert(g_require_session_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_read_policy_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":\"session\",\"extra\":1}");
        signing::handle_protocol_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_policy_get_admission_calls == 1);
        assert(g_require_session_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_request") == 0);
        assert(g_read_policy_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":\"session\"}");
        signing::handle_protocol_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_busy_calls == 1);
        assert(g_policy_get_admission_calls == 1);
        assert(g_require_session_calls == 1);
        assert(g_read_policy_calls == 1);
        assert(g_json_write_calls == 1);
        assert(strcmp(g_last_response_type, "policy_get") == 0);
        assert(g_last_policy_included);
        assert(strcmp(g_last_policy_id, "sha256:test") == 0);
        assert(strcmp(g_last_policy_default_action, "reject") == 0);
        assert(g_last_policy_count == 0);
        assert(g_last_policy_condition_count == 0);
        assert(g_record_policy_unavailable_calls == 0);
    }

    {
        reset_state();
        constexpr const char* kSuiTypeTag =
            "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";
        const char* amount_values[] = {"1000000000"};
        const signing::CurrentPolicyCondition conditions[] = {
            {
                "sui.token_totals_by_type.amount_raw",
                signing::CurrentPolicyOperator::lte,
                amount_values,
                sizeof(amount_values) / sizeof(amount_values[0]),
                kSuiTypeTag,
            },
        };
        const signing::CurrentPolicy policies[] = {
            {
                "sui-testnet-max-one-sui",
                signing::CurrentPolicyAction::sign,
                conditions,
                sizeof(conditions) / sizeof(conditions[0]),
            },
        };
        const signing::CurrentPolicyNetworkScope networks[] = {
            {
                "testnet",
                policies,
                sizeof(policies) / sizeof(policies[0]),
            },
        };
        const signing::CurrentPolicyBlockchainScope blockchains[] = {
            {
                "sui",
                networks,
                sizeof(networks) / sizeof(networks[0]),
            },
        };
        g_policy_document = signing::CurrentPolicyDocument{
            signing::kCurrentPolicySchema,
            signing::CurrentPolicyAction::reject,
            blockchains,
            sizeof(blockchains) / sizeof(blockchains[0]),
        };
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":\"session\"}");
        signing::handle_protocol_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_read_policy_calls == 1);
        assert(g_json_write_calls == 1);
        assert(g_last_policy_count == 1);
        assert(g_last_policy_condition_count == 1);
        assert(strcmp(g_last_policy_where_type, kSuiTypeTag) == 0);
    }

    {
        reset_state();
        g_read_policy_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":\"session\"}");
        signing::handle_protocol_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_read_policy_calls == 1);
        assert(g_record_policy_unavailable_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "policy_unavailable") == 0);
    }

    {
        reset_state();
        g_policy_has_document = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":\"session\"}");
        signing::handle_protocol_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_read_policy_calls == 1);
        assert(g_record_policy_unavailable_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "policy_unavailable") == 0);
    }

    {
        reset_state();
        g_policy_json_write_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":\"session\"}");
        signing::handle_protocol_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_read_policy_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(g_write_error_calls == 0);
    }

    {
        reset_state();
        g_json_write_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_get\",\"sessionId\":\"session\"}");
        signing::handle_protocol_policy_get_request("req", request, make_writer(), make_ops());
        assert(g_read_policy_calls == 1);
        assert(g_json_write_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(g_write_error_calls == 0);
    }

    {
        reset_state();
        g_material_ready = false;
        JsonDocument request = parse_request(valid_request());
        signing::handle_protocol_policy_propose_request("req", request, make_writer(), make_ops());
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
        signing::handle_protocol_policy_propose_request("req", request, make_writer(), make_ops());
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
        signing::handle_protocol_policy_propose_request(
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
        signing::handle_protocol_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_require_session_calls == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request(valid_request());
        signing::handle_protocol_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_require_session_calls == 1);
        assert(strcmp(g_last_session, "session") == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session\",\"payload\":{\"policy\":{}},\"extra\":true}");
        signing::handle_protocol_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_require_session_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_request") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session\",\"payload\":7}");
        signing::handle_protocol_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session\",\"payload\":{\"policy\":{},\"extra\":true}}");
        signing::handle_protocol_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"policy_propose\",\"sessionId\":\"session\",\"payload\":{}}");
        signing::handle_protocol_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_begin_calls == 0);
    }

    {
        reset_state();
        g_begin_result = signing::PolicyUpdateFlowBeginResult::too_large;
        JsonDocument request = parse_request(valid_request());
        signing::handle_protocol_policy_propose_request("req", request, make_writer(), make_ops());
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
        g_begin_result = signing::PolicyUpdateFlowBeginResult::invalid_policy;
        g_json_write_ok = false;
        JsonDocument request = parse_request(valid_request());
        signing::handle_protocol_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_json_write_calls == 1);
        assert(g_log_write_failure_calls == 1);
        assert(g_show_review_calls == 0);
    }

    {
        reset_state();
        const signing::PolicyUpdateFlowSnapshot snapshot{
            true,
            signing::PolicyUpdateFlowStage::committing,
            "req",
            "session",
            signing::TimeoutWindow{10, 20},
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
        assert(signing::policy_propose_outcome_write(
            "req",
            "applied",
            "applied",
            &snapshot,
            make_writer()));
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
        signing::handle_protocol_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_begin_calls == 1);
        assert(g_show_review_calls == 1);
        assert(g_record_ui_error_calls == 1);
        assert(g_finish_terminal_calls == 1);
        assert(g_record_waiting_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request(valid_request());
        signing::handle_protocol_policy_propose_request("req", request, make_writer(), make_ops());
        assert(g_begin_calls == 1);
        assert(g_last_window.started_at == 10);
        assert(g_last_window.deadline == 20);
        assert(g_show_review_calls == 1);
        assert(g_record_waiting_calls == 1);
        assert(g_write_error_calls == 0);
        assert(g_json_write_calls == 0);
        assert(g_finish_terminal_calls == 0);
    }

    printf("usb_policy_handlers tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -c "${COMMON_POLICY_DIR}/document.cpp" \
  -o "${TMP_DIR}/policy_document.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -c "${COMMON_POLICY_DIR}/policy_json_writer.cpp" \
  -o "${TMP_DIR}/policy_json_writer.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -c "${COMMON_ROOT}/transport/payload_delivery_admission.cpp" \
  -o "${TMP_DIR}/payload_delivery_admission.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -c "${COMMON_ROOT}/transport/payload_delivery_primitives.cpp" \
  -o "${TMP_DIR}/payload_delivery_primitives.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -c "${COMMON_ROOT}/transport/payload_delivery_store.cpp" \
  -o "${TMP_DIR}/payload_delivery_store.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -c "${COMMON_ROOT}/protocol/session_state.cpp" \
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
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${TMP_DIR}/payload_delivery_admission.o" \
  "${TMP_DIR}/payload_delivery_primitives.o" \
  "${TMP_DIR}/payload_delivery_store.o" \
  "${TMP_DIR}/policy_document.o" \
  "${TMP_DIR}/policy_json_writer.o" \
  "${TMP_DIR}/session.o" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  "${COMMON_ROOT}/protocol/active_session_request_guard.cpp" \
  "${COMMON_ROOT}/policy/policy_handlers.cpp" \
  -o "${TMP_DIR}/test_usb_policy_handlers"

"${TMP_DIR}/test_usb_policy_handlers"
