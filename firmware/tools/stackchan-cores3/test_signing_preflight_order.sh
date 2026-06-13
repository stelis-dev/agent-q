#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_signing_preflight_order.sh

ESP-IDF must already be active in the shell so IDF_PATH points to the ESP-IDF
checkout. This host test composes the production route classifier, signing
ingress, request identity, result store, and Sui preparation helpers to verify
the critical signing preflight order by behavior:

  route -> state/session -> shallow params -> identity/replay -> preparation

It does not require hardware.
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
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${AGENT_Q_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"
DEFAULT_SIGNING_DIR="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib"
SIGNING_ROOT="${AGENT_Q_SIGNING_CRYPTO_ROOT:-${DEFAULT_SIGNING_DIR}}"
SIGNING_CORE="${SIGNING_ROOT}/src/microsui_core"

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
  "${SIGNING_CORE}/byte_conversions.c" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_request_identity.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_admission.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_primitives.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_store.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_payload_upload_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_payload_upload_handlers.h" \
  "${AGENT_Q_DIR}/agent_q_usb_signing_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_signing_handlers.h" \
  "${AGENT_Q_DIR}/agent_q_usb_signing_result_writer.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_preflight.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_retry_response.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_ingress.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_retry_delivery.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_ingress.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_result_store.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_signing_preparation.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_sign_transaction_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
CC_BIN="${CC:-cc}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-signing-preflight-order.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/agent_q_common"
mkdir -p "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"

cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

#include "agent_q_sign_route.h"
#include "agent_q_sign_transaction_user_ingress.h"
#include "agent_q_signing_preflight.h"
#include "agent_q_sign_request_identity.h"
#include "agent_q_signing_retry_response.h"
#include "agent_q_signing_result_store.h"
#include "agent_q_usb_signing_result_writer.h"
#include "agent_q_sui_account_store.h"
#include "agent_q_sui_signing_authority.h"
#include "agent_q_sui_signing_preparation.h"
#include "agent_q_usb_payload_upload_handlers.h"
#include "agent_q_usb_signing_handlers.h"

extern "C" {
#include "byte_conversions.h"
}

namespace {

int g_failures = 0;
int g_session_calls = 0;
int g_digest_calls = 0;
int g_binding_calls = 0;
int g_upload_error_calls = 0;
int g_handler_preflight_calls = 0;
int g_handler_begin_transaction_calls = 0;
int g_handler_clear_prepared_calls = 0;
int g_handler_waiting_calls = 0;
int g_handler_policy_evaluation_calls = 0;
int g_handler_policy_execution_calls = 0;
int g_handler_policy_response_calls = 0;
int g_handler_notice_calls = 0;
int g_handler_event_sequence = 0;
int g_handler_policy_evaluation_event = 0;
int g_handler_policy_execution_event = 0;
int g_handler_policy_response_event = 0;
int g_handler_last_clear_prepared_event = 0;
char g_upload_response_type[64] = {};
char g_upload_response_upload_id[agent_q::kAgentQPayloadDeliveryUploadIdSize] = {};
char g_upload_response_payload_ref[agent_q::kAgentQPayloadDeliveryPayloadRefSize] = {};
char g_upload_response_received_bytes[32] = {};
char g_upload_response_payload_digest[96] = {};
char g_upload_response_size_bytes[32] = {};
char g_upload_response_error_code[48] = {};
char g_handler_last_waiting_id[64] = {};

agent_q::AgentQSessionValidationResult g_session_result =
    agent_q::AgentQSessionValidationResult::ok;
agent_q::AgentQSuiSigningAccountBindingResult g_binding_result =
    agent_q::AgentQSuiSigningAccountBindingResult::ok;
agent_q::AgentQSigningAuthorizationMode g_signing_mode =
    agent_q::AgentQSigningAuthorizationMode::user;
agent_q::AgentQSigningRetryDeliveryStatus g_retry_status =
    agent_q::AgentQSigningRetryDeliveryStatus::not_found;
int g_retry_response_write_calls = 0;
std::string g_retry_response_json;
char g_handler_retry_stored_result[agent_q::kSigningResultMaxSize] = {};

enum class PreflightOutcome {
    ok_prepared,
    route_invalid_params,
    route_unsupported_chain,
    route_unsupported_method,
    ingress_invalid_state,
    ingress_busy,
    ingress_invalid_session,
    ingress_invalid_tx_bytes,
    identity_error,
    replay_match,
    replay_conflict,
    preparation_error,
    preparation_unsupported_payload_size,
};

int hex_value(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return 10 + value - 'a';
    }
    if (value >= 'A' && value <= 'F') {
        return 10 + value - 'A';
    }
    return -1;
}

std::vector<uint8_t> read_hex(const char* path)
{
    FILE* file = fopen(path, "rb");
    assert(file != nullptr);
    std::string hex;
    int ch = 0;
    while ((ch = fgetc(file)) != EOF) {
        if (!isspace(ch)) {
            hex.push_back(static_cast<char>(ch));
        }
    }
    fclose(file);
    assert((hex.size() % 2) == 0);
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t index = 0; index < bytes.size(); ++index) {
        const int high = hex_value(hex[index * 2]);
        const int low = hex_value(hex[index * 2 + 1]);
        assert(high >= 0 && low >= 0);
        bytes[index] = static_cast<uint8_t>((high << 4) | low);
    }
    return bytes;
}

std::string base64(const std::vector<uint8_t>& bytes)
{
    std::string out(((bytes.size() + 2) / 3) * 4 + 1, '\0');
    assert(bytes_to_base64(bytes.data(), bytes.size(), out.data(), out.size()) == 0);
    out.resize(strlen(out.c_str()));
    return out;
}

JsonDocument parse_json(const std::string& json)
{
    JsonDocument document;
    const DeserializationError error = deserializeJson(document, json.c_str());
    assert(!error);
    assert(!document.overflowed());
    return document;
}

std::string payload_upload_begin_json(
    const char* request_id,
    const char* session_id,
    size_t size_bytes,
    const char* payload_digest)
{
    return std::string("{\"id\":\"") + request_id +
           "\",\"version\":1,\"type\":\"payload_upload_begin\"," +
           "\"sessionId\":\"" + session_id + "\"," +
           "\"chain\":\"sui\",\"method\":\"sign_transaction\"," +
           "\"payloadKind\":\"transaction\"," +
           "\"sizeBytes\":\"" + std::to_string(size_bytes) +
           "\",\"payloadDigest\":\"" + payload_digest + "\"}";
}

std::string payload_upload_chunk_json(
    const char* request_id,
    const char* session_id,
    const char* upload_id,
    size_t offset_bytes,
    const char* chunk_base64)
{
    return std::string("{\"id\":\"") + request_id +
           "\",\"version\":1,\"type\":\"payload_upload_chunk\"," +
           "\"sessionId\":\"" + session_id + "\"," +
           "\"uploadId\":\"" + upload_id + "\"," +
           "\"offsetBytes\":\"" + std::to_string(offset_bytes) +
           "\",\"chunk\":\"" + chunk_base64 + "\"}";
}

std::string payload_upload_finish_json(
    const char* request_id,
    const char* session_id,
    const char* upload_id)
{
    return std::string("{\"id\":\"") + request_id +
           "\",\"version\":1,\"type\":\"payload_upload_finish\"," +
           "\"sessionId\":\"" + session_id + "\"," +
           "\"uploadId\":\"" + upload_id + "\"}";
}

std::string request_json(
    const char* request_id,
    const char* session_id,
    const char* chain,
    const char* method,
    const char* network,
    const char* tx_bytes)
{
    return std::string("{\"id\":\"") + request_id +
           "\",\"version\":1,\"type\":\"sign_transaction\"," +
           "\"sessionId\":\"" + session_id + "\"," +
           "\"chain\":\"" + chain + "\"," +
           "\"method\":\"" + method + "\"," +
           "\"params\":{\"network\":\"" + network + "\",\"txBytes\":\"" + tx_bytes + "\"}}";
}

std::string staged_request_json(
    const char* request_id,
    const char* session_id,
    const char* chain,
    const char* method,
    const char* network,
    const char* payload_ref,
    size_t size_bytes,
    const char* payload_digest)
{
    return std::string("{\"id\":\"") + request_id +
           "\",\"version\":1,\"type\":\"sign_transaction\"," +
           "\"sessionId\":\"" + session_id + "\"," +
           "\"chain\":\"" + chain + "\"," +
           "\"method\":\"" + method + "\"," +
           "\"params\":{\"network\":\"" + network +
           "\",\"payloadRef\":\"" + payload_ref +
           "\",\"payloadKind\":\"transaction\"," +
           "\"sizeBytes\":\"" + std::to_string(size_bytes) +
           "\",\"payloadDigest\":\"" + payload_digest + "\"}}";
}

agent_q::AgentQSessionValidationResult validate_session(
    const char* session_id,
    void*)
{
    ++g_session_calls;
    if (strcmp(session_id, "session_aaaaaaaaaaaaaaaa") != 0) {
        return agent_q::AgentQSessionValidationResult::mismatch;
    }
    return g_session_result;
}

bool upload_material_ready()
{
    return true;
}

bool upload_not_busy(const char*)
{
    return false;
}

bool upload_require_active_matching_session(const char*, const char* session_id)
{
    return session_id != nullptr && strcmp(session_id, "session_aaaaaaaaaaaaaaaa") == 0;
}

agent_q::AgentQTimeoutWindow upload_timeout_window_for_size(size_t)
{
    return agent_q::timeout_window_from_deadline(0, 100000);
}

agent_q::AgentQTimeoutTick current_tick()
{
    return 0;
}

bool upload_write_error(const char*, const char* code, const char*)
{
    ++g_upload_error_calls;
    snprintf(g_upload_response_error_code, sizeof(g_upload_response_error_code), "%s", code);
    return true;
}

void upload_log_write_failure(const char*, const char*)
{
    ++g_upload_error_calls;
    snprintf(g_upload_response_error_code, sizeof(g_upload_response_error_code), "%s", "write_failed");
}

agent_q::AgentQUsbOperationResponseWriter upload_writer()
{
    return agent_q::AgentQUsbOperationResponseWriter{
        upload_write_error,
        upload_log_write_failure,
    };
}

agent_q::AgentQUsbPayloadUploadHandlerOps upload_ops()
{
    return agent_q::AgentQUsbPayloadUploadHandlerOps{
        upload_material_ready,
        upload_not_busy,
        upload_require_active_matching_session,
        current_tick,
        upload_timeout_window_for_size,
    };
}

agent_q::AgentQPayloadDeliveryAdmissionDecision admit_payload_delivery(
    const agent_q::AgentQPayloadDeliverySignTransactionAdmissionInput& input,
    void* context)
{
    return agent_q::payload_delivery_admit_sign_transaction(input, context);
}

agent_q::AgentQSignTransactionUserIngressState state(bool material_ready, bool busy)
{
    return agent_q::AgentQSignTransactionUserIngressState{
        0,
        material_ready,
        busy,
        validate_session,
        nullptr,
        admit_payload_delivery,
        nullptr,
    };
}

PreflightOutcome preflight_result_outcome(
    agent_q::AgentQSigningPreflightResult result,
    const agent_q::AgentQSignTransactionPreflightOutput& output)
{
    switch (result) {
        case agent_q::AgentQSigningPreflightResult::ok:
            return PreflightOutcome::ok_prepared;
        case agent_q::AgentQSigningPreflightResult::route_invalid_params:
            return PreflightOutcome::route_invalid_params;
        case agent_q::AgentQSigningPreflightResult::route_unsupported_chain:
            return PreflightOutcome::route_unsupported_chain;
        case agent_q::AgentQSigningPreflightResult::route_unsupported_method:
            return PreflightOutcome::route_unsupported_method;
        case agent_q::AgentQSigningPreflightResult::transaction_ingress_error:
            switch (output.ingress_result) {
                case agent_q::AgentQSignTransactionUserIngressResult::invalid_state:
                    return PreflightOutcome::ingress_invalid_state;
                case agent_q::AgentQSignTransactionUserIngressResult::busy:
                    return PreflightOutcome::ingress_busy;
                case agent_q::AgentQSignTransactionUserIngressResult::invalid_session:
                    return PreflightOutcome::ingress_invalid_session;
                case agent_q::AgentQSignTransactionUserIngressResult::invalid_tx_bytes:
                    return PreflightOutcome::ingress_invalid_tx_bytes;
                default:
                    return PreflightOutcome::identity_error;
            }
        case agent_q::AgentQSigningPreflightResult::retry_consumed:
            if (g_retry_status == agent_q::AgentQSigningRetryDeliveryStatus::match) {
                return PreflightOutcome::replay_match;
            }
            if (g_retry_status ==
                agent_q::AgentQSigningRetryDeliveryStatus::request_id_conflict) {
                return PreflightOutcome::replay_conflict;
            }
            return PreflightOutcome::identity_error;
        case agent_q::AgentQSigningPreflightResult::transaction_preparation_error:
            if (output.preparation_result ==
                agent_q::AgentQSuiSigningPreparationResult::unsupported_payload_size) {
                return PreflightOutcome::preparation_unsupported_payload_size;
            }
            return PreflightOutcome::preparation_error;
        default:
            return PreflightOutcome::identity_error;
    }
}

bool read_signing_mode(
    agent_q::AgentQSigningAuthorizationMode* mode,
    void*)
{
    assert(mode != nullptr);
    *mode = g_signing_mode;
    return true;
}

bool capture_retry_response(JsonDocument& response, void*)
{
    ++g_retry_response_write_calls;
    g_retry_response_json.clear();
    serializeJson(response, g_retry_response_json);
    return true;
}

agent_q::AgentQSigningPreflightRetryDisposition respond_to_retry(
    const char* request_id,
    const agent_q::AgentQSigningRetryDeliveryResult& retry,
    const char* stored_result,
    void*)
{
    g_retry_status = retry.status;
    const agent_q::AgentQSigningRetryResponseResult response_result =
        agent_q::deliver_signing_retry_response(
            request_id,
            retry,
            stored_result,
            capture_retry_response,
            nullptr);
    switch (response_result) {
        case agent_q::AgentQSigningRetryResponseResult::not_found:
        case agent_q::AgentQSigningRetryResponseResult::invalid_stored_result:
        case agent_q::AgentQSigningRetryResponseResult::replay_write_failed:
            return agent_q::AgentQSigningPreflightRetryDisposition::continue_preflight;
        case agent_q::AgentQSigningRetryResponseResult::replayed_result:
        case agent_q::AgentQSigningRetryResponseResult::error_response:
        case agent_q::AgentQSigningRetryResponseResult::error_write_failed:
            return agent_q::AgentQSigningPreflightRetryDisposition::consumed;
    }
    return agent_q::AgentQSigningPreflightRetryDisposition::consumed;
}

PreflightOutcome run_transaction_preflight(
    const std::string& json,
    bool material_ready,
    bool busy)
{
    JsonDocument document = parse_json(json);
    agent_q::AgentQSignTransactionPreflightOutput output = {};
    char retry_stored_result[agent_q::kSigningResultMaxSize] = {};
    const agent_q::AgentQSigningPreflightResult result =
        agent_q::evaluate_sign_transaction_preflight(
            document,
            state(material_ready, busy),
            agent_q::AgentQSigningPreflightRuntime{
                0,
                read_signing_mode,
                nullptr,
                respond_to_retry,
                nullptr,
                retry_stored_result,
                sizeof(retry_stored_result),
            },
            &output);
    const PreflightOutcome outcome = preflight_result_outcome(result, output);
    agent_q::clear_prepared_sui_sign_transaction(&output.prepared);
    return outcome;
}

agent_q::AgentQSigningPreflightResult evaluate_transaction_preflight_for_handler(
    JsonDocument& request,
    const agent_q::AgentQSignTransactionUserIngressState& state,
    const agent_q::AgentQSigningPreflightRuntime& runtime,
    agent_q::AgentQSignTransactionPreflightOutput* output)
{
    ++g_handler_preflight_calls;
    return agent_q::evaluate_sign_transaction_preflight(request, state, runtime, output);
}

bool handler_material_ready()
{
    return true;
}

bool handler_not_busy()
{
    return false;
}

agent_q::AgentQSignTransactionPolicyRuntimeResult handler_evaluate_policy(
    const agent_q::AgentQSuiPreparedSignTransaction& prepared)
{
    ++g_handler_policy_evaluation_calls;
    g_handler_policy_evaluation_event = ++g_handler_event_sequence;
    assert(prepared.route == agent_q::AgentQSupportedSignRoute::sui_sign_transaction);
    assert(prepared.tx_bytes != nullptr);
    assert(prepared.tx_bytes_size > 0);
    assert(prepared.payload_digest[0] != '\0');
    agent_q::AgentQSignTransactionPolicyRuntimeResult result = {};
    result.status = agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_authorized;
    result.code = "policy_signed";
    result.message = "Policy authorized signing.";
    snprintf(result.chain, sizeof(result.chain), "%s", "sui");
    snprintf(result.method, sizeof(result.method), "%s", "sign_transaction");
    result.tx_bytes = prepared.tx_bytes;
    result.tx_bytes_size = prepared.tx_bytes_size;
    return result;
}

agent_q::AgentQPolicySigningExecutionResult handler_execute_policy(
    const agent_q::AgentQSignTransactionPolicyRuntimeResult& policy_result)
{
    ++g_handler_policy_execution_calls;
    g_handler_policy_execution_event = ++g_handler_event_sequence;
    assert(policy_result.tx_bytes != nullptr);
    assert(policy_result.tx_bytes_size > 0);
    agent_q::AgentQPolicySigningExecutionResult result = {};
    result.status = agent_q::AgentQPolicySigningExecutionStatus::signed_success;
    result.signing_route = agent_q::AgentQSigningRoute::sui_sign_transaction;
    result.code = "policy_signed";
    result.message = "Policy authorized signing.";
    for (size_t index = 0; index < sizeof(result.signature); ++index) {
        result.signature[index] = static_cast<uint8_t>(index + 1U);
    }
    result.signature_size = sizeof(result.signature);
    return result;
}

bool handler_write_policy_response(
    const char* id,
    const uint8_t* request_identity,
    const agent_q::AgentQPolicySigningExecutionResult& result)
{
    ++g_handler_policy_response_calls;
    g_handler_policy_response_event = ++g_handler_event_sequence;
    return agent_q::usb_signing_result_write_policy_execution(
        id,
        "session_aaaaaaaaaaaaaaaa",
        request_identity,
        result);
}

void handler_clear_policy_execution(agent_q::AgentQPolicySigningExecutionResult* result)
{
    if (result != nullptr) {
        memset(result, 0, sizeof(*result));
    }
}

void handler_clear_policy_runtime(agent_q::AgentQSignTransactionPolicyRuntimeResult* result)
{
    if (result != nullptr) {
        memset(result, 0, sizeof(*result));
    }
}

agent_q::AgentQTimeoutWindow handler_user_signing_window()
{
    return agent_q::AgentQTimeoutWindow{1, 1000};
}

agent_q::AgentQUserSigningFlowBeginResult handler_begin_transaction_user_signing(
    const agent_q::AgentQUserSigningTransactionBeginInput& input)
{
    ++g_handler_begin_transaction_calls;
    assert(input.request_id != nullptr);
    assert(strcmp(input.request_id, "req_usb_full_staged_1") == 0);
    assert(input.request_identity != nullptr);
    assert(input.session_id != nullptr);
    assert(strcmp(input.session_id, "session_aaaaaaaaaaaaaaaa") == 0);
    assert(input.route == agent_q::AgentQSigningRoute::sui_sign_transaction);
    assert(input.prepared != nullptr);
    assert(input.prepared->tx_bytes != nullptr);
    assert(input.prepared->tx_bytes_size > 0);
    assert(agent_q::timeout_window_valid(input.request_window));
    return agent_q::AgentQUserSigningFlowBeginResult::ok;
}

agent_q::AgentQUserSigningFlowBeginResult handler_begin_personal_message_user_signing(
    const agent_q::AgentQUserSigningPersonalMessageBeginInput&)
{
    return agent_q::AgentQUserSigningFlowBeginResult::ok;
}

void handler_clear_prepared_transaction(agent_q::AgentQSuiPreparedSignTransaction* prepared)
{
    ++g_handler_clear_prepared_calls;
    g_handler_last_clear_prepared_event = ++g_handler_event_sequence;
    agent_q::clear_prepared_sui_sign_transaction(prepared);
}

void handler_clear_prepared_personal_message(agent_q::AgentQSuiPreparedPersonalMessage* prepared)
{
    agent_q::clear_prepared_sui_sign_personal_message(prepared);
}

bool handler_show_review()
{
    return true;
}

void handler_noop()
{
}

void handler_record_waiting(const char* id, agent_q::AgentQSigningRoute route)
{
    ++g_handler_waiting_calls;
    snprintf(g_handler_last_waiting_id, sizeof(g_handler_last_waiting_id), "%s", id);
    assert(route == agent_q::AgentQSigningRoute::sui_sign_transaction);
}

void handler_show_notice(const char*, agent_q::AgentQUsbSigningNoticeKind)
{
    ++g_handler_notice_calls;
}

void handler_log_policy_rejected(const char*, const char*, const char*, const char*)
{
}

void handler_log_policy_failed(const char*, const char*, const char*)
{
}

void handler_log_policy_signed(const char*, const char*, const char*, const char*)
{
}

void handler_log_write_failure(const char*, const char*)
{
}

agent_q::AgentQUsbSigningHandlerOps signing_handler_ops()
{
    return agent_q::AgentQUsbSigningHandlerOps{
        handler_material_ready,
        handler_not_busy,
        handler_not_busy,
        current_tick,
        validate_session,
        nullptr,
        admit_payload_delivery,
        nullptr,
        read_signing_mode,
        nullptr,
        respond_to_retry,
        nullptr,
        g_handler_retry_stored_result,
        sizeof(g_handler_retry_stored_result),
        evaluate_transaction_preflight_for_handler,
        nullptr,
        handler_noop,
        handler_evaluate_policy,
        handler_execute_policy,
        handler_write_policy_response,
        handler_clear_policy_execution,
        handler_clear_policy_runtime,
        handler_user_signing_window,
        handler_begin_transaction_user_signing,
        handler_begin_personal_message_user_signing,
        handler_clear_prepared_transaction,
        handler_clear_prepared_personal_message,
        handler_show_review,
        handler_noop,
        handler_noop,
        handler_record_waiting,
        handler_show_notice,
        handler_log_policy_rejected,
        handler_log_policy_failed,
        handler_log_policy_signed,
        handler_log_write_failure,
    };
}

void reset_counters()
{
    g_session_calls = 0;
    g_digest_calls = 0;
    g_binding_calls = 0;
    g_session_result = agent_q::AgentQSessionValidationResult::ok;
    g_binding_result = agent_q::AgentQSuiSigningAccountBindingResult::ok;
    g_signing_mode = agent_q::AgentQSigningAuthorizationMode::user;
    g_retry_status = agent_q::AgentQSigningRetryDeliveryStatus::not_found;
    g_retry_response_write_calls = 0;
    g_retry_response_json.clear();
    g_upload_error_calls = 0;
    g_upload_response_type[0] = '\0';
    g_upload_response_upload_id[0] = '\0';
    g_upload_response_payload_ref[0] = '\0';
    g_upload_response_received_bytes[0] = '\0';
    g_upload_response_payload_digest[0] = '\0';
    g_upload_response_size_bytes[0] = '\0';
    g_upload_response_error_code[0] = '\0';
    g_handler_preflight_calls = 0;
    g_handler_begin_transaction_calls = 0;
    g_handler_clear_prepared_calls = 0;
    g_handler_waiting_calls = 0;
    g_handler_policy_evaluation_calls = 0;
    g_handler_policy_execution_calls = 0;
    g_handler_policy_response_calls = 0;
    g_handler_notice_calls = 0;
    g_handler_event_sequence = 0;
    g_handler_policy_evaluation_event = 0;
    g_handler_policy_execution_event = 0;
    g_handler_policy_response_event = 0;
    g_handler_last_clear_prepared_event = 0;
    g_handler_last_waiting_id[0] = '\0';
    memset(g_handler_retry_stored_result, 0, sizeof(g_handler_retry_stored_result));
    agent_q::signing_result_clear_all();
}

void expect_case(
    const char* label,
    PreflightOutcome actual,
    PreflightOutcome expected,
    int expected_session_calls,
    int expected_digest_calls,
    int expected_binding_calls)
{
    if (actual != expected ||
        g_session_calls != expected_session_calls ||
        g_digest_calls != expected_digest_calls ||
        g_binding_calls != expected_binding_calls) {
        fprintf(stderr,
                "%s: outcome/session/digest/binding = %d/%d/%d/%d, expected %d/%d/%d/%d\n",
                label,
                static_cast<int>(actual),
                g_session_calls,
                g_digest_calls,
                g_binding_calls,
                static_cast<int>(expected),
                expected_session_calls,
                expected_digest_calls,
                expected_binding_calls);
        ++g_failures;
    }
}

void expect_contains(const char* label, const std::string& value, const char* expected)
{
    if (value.find(expected) == std::string::npos) {
        fprintf(stderr, "%s: expected JSON to contain %s, got %s\n",
                label,
                expected,
                value.c_str());
        ++g_failures;
    }
}

void expect_no_stored_result(const char* label, const char* session_id, const char* request_id)
{
    char stored[agent_q::kSigningResultMaxSize] = {};
    size_t stored_len = 0;
    if (agent_q::signing_result_find(
            session_id,
            request_id,
            stored,
            sizeof(stored),
            &stored_len)) {
        fprintf(stderr, "%s: unexpected stored signing result\n", label);
        ++g_failures;
    }
}

void store_identity_for(
    const std::string& json,
    const char* stored_result)
{
    JsonDocument document = parse_json(json);
    const agent_q::AgentQSignRouteClassification classification =
        agent_q::classify_sign_route(
            agent_q::AgentQSignOperation::sign_transaction,
            document["chain"].as<const char*>(),
            document["method"].as<const char*>());
    assert(classification.result == agent_q::AgentQSignRouteResult::ok);
    agent_q::AgentQSignTransactionUserIngressOutput ingress = {};
    assert(agent_q::evaluate_sign_transaction_user_ingress(
               document,
               classification.route,
               state(true, false),
               &ingress) == agent_q::AgentQSignTransactionUserIngressResult::ok);
    uint8_t identity[agent_q::kAgentQSignRequestIdentitySize] = {};
    assert(agent_q::sign_request_identity(
        classification.route,
        ingress.params.network,
        ingress.params.tx_bytes_base64,
        identity,
        sizeof(identity)));
    assert(agent_q::signing_result_store(
               ingress.session.session_id,
               ingress.envelope.request_id,
               identity,
               sizeof(identity),
               stored_result,
               strlen(stored_result)) == agent_q::SigningResultStoreOutcome::stored);
    g_session_calls = 0;
}

void store_staged_identity_for(
    const std::string& json,
    const char* stored_result)
{
    JsonDocument document = parse_json(json);
    const agent_q::AgentQSignRouteClassification classification =
        agent_q::classify_sign_route(
            agent_q::AgentQSignOperation::sign_transaction,
            document["chain"].as<const char*>(),
            document["method"].as<const char*>());
    assert(classification.result == agent_q::AgentQSignRouteResult::ok);
    agent_q::AgentQSignTransactionUserIngressOutput ingress = {};
    assert(agent_q::evaluate_sign_transaction_user_ingress(
               document,
               classification.route,
               state(true, false),
               &ingress) == agent_q::AgentQSignTransactionUserIngressResult::ok);
    assert(ingress.params.payload_form == agent_q::AgentQSignTransactionPayloadForm::staged_payload_ref);
    uint8_t identity[agent_q::kAgentQSignRequestIdentitySize] = {};
    assert(agent_q::sign_request_identity_for_payload_descriptor(
        classification.route,
        ingress.params.network,
        ingress.params.payload_kind,
        ingress.params.payload_size_bytes,
        ingress.params.payload_digest,
        identity,
        sizeof(identity)));
    assert(agent_q::signing_result_store(
               ingress.session.session_id,
               ingress.envelope.request_id,
               identity,
               sizeof(identity),
               stored_result,
               strlen(stored_result)) == agent_q::SigningResultStoreOutcome::stored);
    g_session_calls = 0;
}

std::string stage_payload(const std::vector<uint8_t>& payload, const char* payload_digest)
{
    agent_q::payload_delivery_store_reset();
    agent_q::AgentQPayloadDeliveryBeginOutput begin = {};
    const agent_q::AgentQPayloadDeliveryResult begin_result =
        agent_q::payload_delivery_begin(0,
            agent_q::AgentQPayloadDeliveryBeginInput{
                "session_aaaaaaaaaaaaaaaa",
                agent_q::AgentQSupportedSignRoute::sui_sign_transaction,
                "transaction",
                payload.size(),
                payload_digest,
                agent_q::AgentQPayloadDeliveryLimits{4096, 128 * 1024},
                agent_q::timeout_window_from_deadline(0, 100000),
            },
            &begin);
    assert(begin_result == agent_q::AgentQPayloadDeliveryResult::ok);
    size_t received = 0;
    const agent_q::AgentQPayloadDeliveryResult chunk_result =
        agent_q::payload_delivery_append_chunk(0,
            agent_q::AgentQPayloadDeliveryChunkInput{
                "session_aaaaaaaaaaaaaaaa",
                begin.upload_id,
                0,
                payload.data(),
                payload.size(),
            },
            &received);
    assert(chunk_result == agent_q::AgentQPayloadDeliveryResult::ok);
    assert(received == payload.size());
    agent_q::AgentQPayloadDeliveryFinishOutput finish = {};
    const agent_q::AgentQPayloadDeliveryResult finish_result =
        agent_q::payload_delivery_finish(0,
            agent_q::AgentQPayloadDeliveryFinishInput{
                "session_aaaaaaaaaaaaaaaa",
                begin.upload_id,
            },
            &finish);
    assert(finish_result == agent_q::AgentQPayloadDeliveryResult::ok);
    return finish.descriptor.payload_ref;
}

std::string stage_payload_through_usb_handlers(
    const std::vector<uint8_t>& payload,
    const std::string& payload_base64,
    const char* payload_digest)
{
    (void)payload_base64;
    agent_q::payload_delivery_store_reset();
    JsonDocument begin_doc = parse_json(
        payload_upload_begin_json(
            "req_upload_begin",
            "session_aaaaaaaaaaaaaaaa",
            payload.size(),
            payload_digest));
    agent_q::handle_usb_payload_upload_begin_request(
        "req_upload_begin",
        begin_doc,
        upload_writer(),
        upload_ops());
    assert(g_upload_error_calls == 0);
    assert(strcmp(g_upload_response_type, "payload_upload_begin_result") == 0);
    assert(g_upload_response_upload_id[0] != '\0');
    const std::string upload_id = g_upload_response_upload_id;

    size_t offset = 0;
    while (offset < payload.size()) {
        const size_t next_size = std::min(
            agent_q::kAgentQPayloadDeliveryDefaultChunkMaxBytes,
            payload.size() - offset);
        const std::vector<uint8_t> chunk(
            payload.begin() + static_cast<std::ptrdiff_t>(offset),
            payload.begin() + static_cast<std::ptrdiff_t>(offset + next_size));
        const size_t next_offset = offset + next_size;
        JsonDocument chunk_doc = parse_json(
            payload_upload_chunk_json(
                "req_upload_chunk",
                "session_aaaaaaaaaaaaaaaa",
                upload_id.c_str(),
                offset,
                base64(chunk).c_str()));
        agent_q::handle_usb_payload_upload_chunk_request(
            "req_upload_chunk",
            chunk_doc,
            upload_writer(),
            upload_ops());
        assert(g_upload_error_calls == 0);
        assert(strcmp(g_upload_response_type, "payload_upload_chunk_result") == 0);
        assert(strcmp(
                   g_upload_response_received_bytes,
                   std::to_string(next_offset).c_str()) == 0);
        offset = next_offset;
    }

    JsonDocument finish_doc = parse_json(
        payload_upload_finish_json(
            "req_upload_finish",
            "session_aaaaaaaaaaaaaaaa",
            upload_id.c_str()));
    agent_q::handle_usb_payload_upload_finish_request(
        "req_upload_finish",
        finish_doc,
        upload_writer(),
        upload_ops());
    assert(g_upload_error_calls == 0);
    assert(strcmp(g_upload_response_type, "payload_upload_finish_result") == 0);
    assert(strcmp(g_upload_response_size_bytes, std::to_string(payload.size()).c_str()) == 0);
    assert(strcmp(g_upload_response_payload_digest, payload_digest) == 0);
    assert(g_upload_response_payload_ref[0] != '\0');
    return g_upload_response_payload_ref;
}

}  // namespace

namespace agent_q {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool approval_history_digest_payload(
    const uint8_t* payload,
    size_t payload_size,
    char* digest_out,
    size_t digest_out_size)
{
    ++g_digest_calls;
    if (payload == nullptr || payload_size == 0 || digest_out_size < 72) {
        return false;
    }
    snprintf(digest_out, digest_out_size,
             "%s", "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    return true;
}

const char* user_signing_flow_terminal_status(AgentQUserSigningTerminalResult)
{
    return "failed";
}

const char* user_signing_flow_terminal_reason(AgentQUserSigningTerminalResult)
{
    return "signing_failed";
}

bool usb_response_write_json(JsonDocument& response)
{
    snprintf(g_upload_response_type, sizeof(g_upload_response_type), "%s", response["type"] | "");
    snprintf(g_upload_response_upload_id, sizeof(g_upload_response_upload_id), "%s", response["uploadId"] | "");
    snprintf(g_upload_response_payload_ref, sizeof(g_upload_response_payload_ref), "%s", response["payloadRef"] | "");
    snprintf(g_upload_response_received_bytes, sizeof(g_upload_response_received_bytes), "%s", response["receivedBytes"] | "");
    snprintf(g_upload_response_payload_digest, sizeof(g_upload_response_payload_digest), "%s", response["payloadDigest"] | "");
    snprintf(g_upload_response_size_bytes, sizeof(g_upload_response_size_bytes), "%s", response["sizeBytes"] | "");
    return true;
}

bool usb_response_write_error(const char* id, const char* code, const char* message)
{
    (void)id;
    (void)message;
    snprintf(g_upload_response_error_code, sizeof(g_upload_response_error_code), "%s", code);
    return true;
}

AgentQSuiSigningAccountBindingResult verify_sui_signing_stored_account_binding(
    const SuiTransactionPolicyFacts&)
{
    ++g_binding_calls;
    return g_binding_result;
}

SuiAccountDerivationResult derive_sui_ed25519_account_from_stored_root(
    uint8_t* public_key,
    char* address,
    size_t address_size)
{
    memset(public_key, 0xA5, kSuiEd25519PublicKeyBytes);
    snprintf(address, address_size,
             "%s", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    return SuiAccountDerivationResult::ok;
}

}  // namespace agent_q

int main(int argc, char** argv)
{
    assert(argc == 2);
    const std::vector<uint8_t> valid = read_hex(argv[1]);
    const std::string valid_b64 = base64(valid);
    const std::string valid_request =
        request_json(
            "req_sign_1",
            "session_aaaaaaaaaaaaaaaa",
            "sui",
            "sign_transaction",
            "devnet",
            valid_b64.c_str());
    const char* staged_digest =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    reset_counters();
    expect_case(
        "unsupported chain stops before state/session",
        run_transaction_preflight(
            request_json(
                "req_sign_1",
                "session_aaaaaaaaaaaaaaaa",
                "evm",
                "sign_transaction",
                "devnet",
                valid_b64.c_str()),
            false,
            false),
        PreflightOutcome::route_unsupported_chain,
        0,
        0,
        0);

    reset_counters();
    expect_case(
        "wrong state stops before session, params, replay, and preparation",
        run_transaction_preflight(
            request_json(
                "req_sign_1",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                "%%%"),
            false,
            false),
        PreflightOutcome::ingress_invalid_state,
        0,
        0,
        0);

    reset_counters();
    expect_case(
        "invalid base64 runs after session but before replay/preparation",
        run_transaction_preflight(
            request_json(
                "req_sign_1",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                "%%%"),
            true,
            false),
        PreflightOutcome::ingress_invalid_tx_bytes,
        1,
        0,
        0);

    reset_counters();
    store_identity_for(valid_request, "{\"type\":\"sign_result\",\"status\":\"signed\"}");
    expect_case(
        "matching retry replays before preparation",
        run_transaction_preflight(valid_request, true, false),
        PreflightOutcome::replay_match,
        1,
        0,
        0);
    if (g_retry_response_write_calls != 1) {
        fprintf(stderr, "matching retry: expected one public JSON response, got %d\n",
                g_retry_response_write_calls);
        ++g_failures;
    }
    expect_contains("matching retry response", g_retry_response_json, "\"type\":\"sign_result\"");
    expect_contains("matching retry response", g_retry_response_json, "\"status\":\"signed\"");

    reset_counters();
    store_identity_for(
        valid_request,
        "{\"type\":\"sign_result\",\"status\":\"signing_failed\","
        "\"error\":{\"code\":\"signing_failed\","
        "\"message\":\"The device could not produce a signature.\"}}");
    expect_case(
        "matching signing_failed retry replays terminal failure without preparation",
        run_transaction_preflight(valid_request, true, false),
        PreflightOutcome::replay_match,
        1,
        0,
        0);
    if (g_retry_response_write_calls != 1) {
        fprintf(stderr,
                "matching signing_failed retry: expected one public JSON response, got %d\n",
                g_retry_response_write_calls);
        ++g_failures;
    }
    expect_contains(
        "matching signing_failed retry response",
        g_retry_response_json,
        "\"type\":\"sign_result\"");
    expect_contains(
        "matching signing_failed retry response",
        g_retry_response_json,
        "\"status\":\"signing_failed\"");
    expect_contains(
        "matching signing_failed retry response",
        g_retry_response_json,
        "\"code\":\"signing_failed\"");

    reset_counters();
    store_identity_for(valid_request, "{\"type\":\"sign_result\",\"status\":\"signed\"}");
    expect_case(
        "conflicting retry stops before preparation",
        run_transaction_preflight(
            request_json(
                "req_sign_1",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                "AQID"),
            true,
            false),
        PreflightOutcome::replay_conflict,
        1,
        0,
        0);
    if (g_retry_response_write_calls != 1) {
        fprintf(stderr, "conflicting retry: expected one public JSON response, got %d\n",
                g_retry_response_write_calls);
        ++g_failures;
    }
    expect_contains("conflicting retry response", g_retry_response_json, "\"type\":\"error\"");
    expect_contains("conflicting retry response", g_retry_response_json, "request_id_conflict");

    reset_counters();
    store_identity_for(valid_request, "{\"type\":\"sign_result\",\"status\":\"signed\"}");
    expect_case(
        "invalid current request shape cannot replay a stored result",
        run_transaction_preflight(
            request_json(
                "req_sign_1",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                "%%%"),
            true,
            false),
        PreflightOutcome::ingress_invalid_tx_bytes,
        1,
        0,
        0);
    if (g_retry_response_write_calls != 0) {
        fprintf(stderr,
                "invalid current request shape: unexpected retry response count %d\n",
                g_retry_response_write_calls);
        ++g_failures;
    }

    reset_counters();
    expect_case(
        "fresh valid request reaches preparation",
        run_transaction_preflight(valid_request, true, false),
        PreflightOutcome::ok_prepared,
        1,
        1,
        1);

    const std::vector<uint8_t> above_inline_payload(
        agent_q::kAgentQSuiSignTransactionInlineTxBytesMaxBytes + 1,
        0xA5);
    reset_counters();
    expect_case(
        "fresh inline payload above inline cap fails at preparation capacity",
        run_transaction_preflight(
            request_json(
                "req_above_inline_cap",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                base64(above_inline_payload).c_str()),
            true,
            false),
        PreflightOutcome::preparation_unsupported_payload_size,
        1,
        0,
        0);

    const std::string staged_ref = stage_payload(valid, staged_digest);
    const std::string staged_request =
        staged_request_json(
            "req_staged_1",
            "session_aaaaaaaaaaaaaaaa",
            "sui",
            "sign_transaction",
            "devnet",
            staged_ref.c_str(),
            valid.size(),
            staged_digest);
    reset_counters();
    expect_case(
        "finalized payload blocks unrelated inline signing",
        run_transaction_preflight(valid_request, true, false),
        PreflightOutcome::ingress_busy,
        1,
        0,
        0);

    reset_counters();
    expect_case(
        "fresh staged request reaches preparation with descriptor identity",
        run_transaction_preflight(staged_request, true, false),
        PreflightOutcome::ok_prepared,
        1,
        0,
        1);

    reset_counters();
    store_staged_identity_for(staged_request, "{\"type\":\"sign_result\",\"status\":\"signed\"}");
    expect_case(
        "staged matching retry replays after live payload cleanup",
        run_transaction_preflight(staged_request, true, false),
        PreflightOutcome::replay_match,
        1,
        0,
        0);
    expect_contains("staged matching retry response", g_retry_response_json, "\"type\":\"sign_result\"");
    expect_contains("staged matching retry response", g_retry_response_json, "\"status\":\"signed\"");

    reset_counters();
    const std::string ref_independent_original =
        staged_request_json(
            "req_staged_ref_independent",
            "session_aaaaaaaaaaaaaaaa",
            "sui",
            "sign_transaction",
            "devnet",
            "payload_original_descriptor",
            valid.size(),
            staged_digest);
    const std::string ref_independent_retry =
        staged_request_json(
            "req_staged_ref_independent",
            "session_aaaaaaaaaaaaaaaa",
            "sui",
            "sign_transaction",
            "devnet",
            "payload_different_handle",
            valid.size(),
            staged_digest);
    store_staged_identity_for(
        ref_independent_original,
        "{\"type\":\"sign_result\",\"status\":\"signed\"}");
    expect_case(
        "staged retained identity ignores payloadRef handle after cleanup",
        run_transaction_preflight(ref_independent_retry, true, false),
        PreflightOutcome::replay_match,
        1,
        0,
        0);
    expect_contains(
        "staged payloadRef-independent retry response",
        g_retry_response_json,
        "\"type\":\"sign_result\"");

    reset_counters();
    store_staged_identity_for(staged_request, "{\"type\":\"sign_result\",\"status\":\"signed\"}");
    expect_case(
        "staged descriptor conflict stops before live payload resolution",
        run_transaction_preflight(
            staged_request_json(
                "req_staged_1",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                staged_ref.c_str(),
                valid.size(),
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
            true,
            false),
        PreflightOutcome::replay_conflict,
        1,
        0,
        0);
    expect_contains("staged descriptor conflict response", g_retry_response_json, "request_id_conflict");

    const std::string mismatch_ref = stage_payload(valid, staged_digest);
    reset_counters();
    expect_case(
        "fresh staged descriptor mismatch fails before taking finalized payload",
        run_transaction_preflight(
            staged_request_json(
                "req_staged_mismatch",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                mismatch_ref.c_str(),
                valid.size(),
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
            true,
            false),
        PreflightOutcome::preparation_error,
        1,
        0,
        0);
    reset_counters();
    expect_case(
        "matching staged request still consumes after mismatch rejection",
        run_transaction_preflight(
            staged_request_json(
                "req_staged_after_mismatch",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                mismatch_ref.c_str(),
                valid.size(),
                staged_digest),
            true,
            false),
        PreflightOutcome::ok_prepared,
        1,
        0,
        1);

    const std::string usb_staged_ref =
        stage_payload_through_usb_handlers(valid, valid_b64, staged_digest);
    const std::string usb_staged_request =
        staged_request_json(
            "req_usb_staged_1",
            "session_aaaaaaaaaaaaaaaa",
            "sui",
            "sign_transaction",
            "devnet",
            usb_staged_ref.c_str(),
            valid.size(),
            staged_digest);
    reset_counters();
    expect_case(
        "USB upload handlers produce finalized payload consumed by production preflight",
        run_transaction_preflight(usb_staged_request, true, false),
        PreflightOutcome::ok_prepared,
        1,
        0,
        1);

    const std::string full_handler_staged_ref =
        stage_payload_through_usb_handlers(valid, valid_b64, staged_digest);
    const std::string full_handler_staged_request =
        staged_request_json(
            "req_usb_full_staged_1",
            "session_aaaaaaaaaaaaaaaa",
            "sui",
            "sign_transaction",
            "devnet",
            full_handler_staged_ref.c_str(),
            valid.size(),
            staged_digest);
    reset_counters();
    {
        JsonDocument full_handler_doc = parse_json(full_handler_staged_request);
        agent_q::handle_usb_sign_transaction_request(
            "req_usb_full_staged_1",
            full_handler_doc,
            upload_writer(),
            signing_handler_ops());
    }
    if (g_upload_error_calls != 0 ||
        g_handler_preflight_calls != 1 ||
        g_handler_begin_transaction_calls != 1 ||
        g_handler_clear_prepared_calls != 2 ||
        g_handler_waiting_calls != 1 ||
        strcmp(g_handler_last_waiting_id, "req_usb_full_staged_1") != 0 ||
        g_handler_policy_evaluation_calls != 0 ||
        g_handler_policy_execution_calls != 0 ||
        g_handler_policy_response_calls != 0) {
        fprintf(stderr,
                "USB staged signing handler path failed: errors/preflight/begin/clear/waiting/policy = "
                "%d/%d/%d/%d/%d/%d/%d/%d\n",
                g_upload_error_calls,
                g_handler_preflight_calls,
                g_handler_begin_transaction_calls,
                g_handler_clear_prepared_calls,
                g_handler_waiting_calls,
                g_handler_policy_evaluation_calls,
                g_handler_policy_execution_calls,
                g_handler_policy_response_calls);
        ++g_failures;
    }
    if (agent_q::payload_delivery_advance_and_snapshot(0).state !=
        agent_q::AgentQPayloadDeliveryState::idle) {
        fprintf(stderr, "USB staged signing handler path left payload delivery non-idle\n");
        ++g_failures;
    }

    const std::string full_handler_policy_staged_ref =
        stage_payload_through_usb_handlers(valid, valid_b64, staged_digest);
    const std::string full_handler_policy_staged_request =
        staged_request_json(
            "req_usb_full_staged_policy_1",
            "session_aaaaaaaaaaaaaaaa",
            "sui",
            "sign_transaction",
            "devnet",
            full_handler_policy_staged_ref.c_str(),
            valid.size(),
            staged_digest);
    reset_counters();
    g_signing_mode = agent_q::AgentQSigningAuthorizationMode::policy;
    {
        JsonDocument full_handler_doc = parse_json(full_handler_policy_staged_request);
        agent_q::handle_usb_sign_transaction_request(
            "req_usb_full_staged_policy_1",
            full_handler_doc,
            upload_writer(),
            signing_handler_ops());
    }
    if (g_upload_error_calls != 0 ||
        g_handler_preflight_calls != 1 ||
        g_handler_begin_transaction_calls != 0 ||
        g_handler_waiting_calls != 0 ||
        g_handler_policy_evaluation_calls != 1 ||
        g_handler_policy_execution_calls != 1 ||
        g_handler_policy_response_calls != 1 ||
        g_handler_clear_prepared_calls != 2 ||
        !(g_handler_policy_evaluation_event > 0 &&
          g_handler_policy_evaluation_event < g_handler_policy_execution_event &&
          g_handler_policy_execution_event < g_handler_policy_response_event &&
          g_handler_policy_response_event < g_handler_last_clear_prepared_event)) {
        fprintf(stderr,
                "USB staged policy signing handler path failed: errors/preflight/begin/waiting/policy/clear/events = "
                "%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d\n",
                g_upload_error_calls,
                g_handler_preflight_calls,
                g_handler_begin_transaction_calls,
                g_handler_waiting_calls,
                g_handler_policy_evaluation_calls,
                g_handler_policy_execution_calls,
                g_handler_policy_response_calls,
                g_handler_clear_prepared_calls,
                g_handler_policy_evaluation_event,
                g_handler_policy_execution_event,
                g_handler_policy_response_event,
                g_handler_last_clear_prepared_event);
        ++g_failures;
    }
    if (agent_q::payload_delivery_advance_and_snapshot(0).state !=
        agent_q::AgentQPayloadDeliveryState::idle) {
        fprintf(stderr, "USB staged policy signing handler path left payload delivery non-idle\n");
        ++g_failures;
    }
    {
        char stored[agent_q::kSigningResultMaxSize] = {};
        size_t stored_len = 0;
        if (!agent_q::signing_result_find(
                "session_aaaaaaaaaaaaaaaa",
                "req_usb_full_staged_policy_1",
                stored,
                sizeof(stored),
                &stored_len)) {
            fprintf(stderr, "USB staged policy signing handler path did not buffer terminal result\n");
            ++g_failures;
        } else {
            const std::string stored_json(stored, stored_len);
            expect_contains("USB staged policy buffered result", stored_json, "\"type\":\"sign_result\"");
            expect_contains("USB staged policy buffered result", stored_json, "\"authorization\":\"policy\"");
            expect_contains("USB staged policy buffered result", stored_json, "\"status\":\"signed\"");
        }
    }

    std::vector<uint8_t> max_synthetic_payload(
        agent_q::kAgentQPayloadDeliveryDefaultMaxBytes);
    for (size_t index = 0; index < max_synthetic_payload.size(); ++index) {
        max_synthetic_payload[index] = static_cast<uint8_t>((index * 37U + 11U) & 0xffU);
    }
    const std::string max_staged_ref =
        stage_payload_through_usb_handlers(max_synthetic_payload, "", staged_digest);
    const std::string max_staged_request =
        staged_request_json(
            "req_usb_max_staged_1",
            "session_aaaaaaaaaaaaaaaa",
            "sui",
            "sign_transaction",
            "devnet",
            max_staged_ref.c_str(),
            max_synthetic_payload.size(),
            staged_digest);
    reset_counters();
    {
        JsonDocument max_handler_doc = parse_json(max_staged_request);
        agent_q::handle_usb_sign_transaction_request(
            "req_usb_max_staged_1",
            max_handler_doc,
            upload_writer(),
            signing_handler_ops());
    }
    if (g_upload_error_calls != 1 ||
        g_handler_preflight_calls != 1 ||
        g_handler_begin_transaction_calls != 0 ||
        g_handler_policy_evaluation_calls != 0 ||
        g_handler_policy_execution_calls != 0 ||
        g_handler_policy_response_calls != 0 ||
        (strcmp(g_upload_response_error_code, "malformed_transaction") != 0 &&
         strcmp(g_upload_response_error_code, "unsupported_transaction") != 0)) {
        fprintf(stderr,
                "USB max staged payload fail-closed path failed: errors/code/preflight/begin/policy = "
                "%d/%s/%d/%d/%d/%d/%d\n",
                g_upload_error_calls,
                g_upload_response_error_code,
                g_handler_preflight_calls,
                g_handler_begin_transaction_calls,
                g_handler_policy_evaluation_calls,
                g_handler_policy_execution_calls,
                g_handler_policy_response_calls);
        ++g_failures;
    }
    if (agent_q::payload_delivery_advance_and_snapshot(0).state !=
        agent_q::AgentQPayloadDeliveryState::idle) {
        fprintf(stderr, "USB max staged payload fail-closed path left payload delivery non-idle\n");
        ++g_failures;
    }
    expect_no_stored_result(
        "USB max staged payload fail-closed path",
        "session_aaaaaaaaaaaaaaaa",
        "req_usb_max_staged_1");

    reset_counters();
    const std::vector<uint8_t> malformed_tx(
        agent_q::kAgentQSuiSignTransactionInlineTxBytesMaxBytes,
        0x42);
    const std::string malformed_b64 = base64(malformed_tx);
    expect_case(
        "malformed prepared payload fails without buffering a result",
        run_transaction_preflight(
            request_json(
                "req_sign_malformed",
                "session_aaaaaaaaaaaaaaaa",
                "sui",
                "sign_transaction",
                "devnet",
                malformed_b64.c_str()),
            true,
            false),
        PreflightOutcome::preparation_error,
        1,
        1,
        0);
    expect_no_stored_result(
        "malformed prepared payload",
        "session_aaaaaaaaaaaaaaaa",
        "req_sign_malformed");

    if (g_failures != 0) {
        fprintf(stderr, "signing preflight order tests failed: %d\n", g_failures);
        return 1;
    }
    printf("Signing preflight order tests passed\n");
    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${SIGNING_CORE}" \
  -c "${SIGNING_CORE}/byte_conversions.c" \
  -o "${TMP_DIR}/byte_conversions.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${AGENT_Q_DIR}" \
  -I"${TMP_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_SUI_DIR}" \
  -I"${SIGNING_CORE}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${AGENT_Q_DIR}/agent_q_request_id.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_request_identity.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_admission.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_primitives.cpp" \
  "${AGENT_Q_DIR}/agent_q_payload_delivery_store.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_payload_upload_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_signing_handlers.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_signing_result_writer.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_preflight.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_retry_response.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_ingress.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_personal_message_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_retry_delivery.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_ingress.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_user_validation.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_result_store.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_signing_preparation.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_sign_transaction_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${TMP_DIR}/byte_conversions.o" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test" "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex"
