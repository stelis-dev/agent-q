#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_payload_delivery_store.sh

ESP-IDF must already be active in the shell so IDF_PATH points to the ESP-IDF
checkout. This host test compiles the volatile payload delivery store and checks
sequential chunk assembly, digest finalization, same-session guards, cleanup,
and small descriptor/view ownership. It does NOT require hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET_ROOT="${REPO_ROOT}/firmware/src/stackchan-cores3"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
USB_REQUEST_SERVER_SOURCE="${TARGET_ROOT}/agent_q/agent_q_usb_request_server.cpp"
USB_CONNECT_HANDLER_HEADER="${TARGET_ROOT}/agent_q/agent_q_usb_connect_handler.h"
USB_DEVICE_HANDLER_HEADER="${TARGET_ROOT}/agent_q/agent_q_usb_device_handlers.h"
USB_POLICY_PROPOSE_HANDLER_HEADER="${TARGET_ROOT}/agent_q/agent_q_usb_policy_propose_handler.h"

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
  "${TARGET_ROOT}/agent_q/agent_q_payload_delivery_primitives.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_payload_delivery_primitives.h" \
  "${TARGET_ROOT}/agent_q/agent_q_payload_delivery_store.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_payload_delivery_store.h" \
  "${TARGET_ROOT}/agent_q/agent_q_payload_delivery_admission.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_payload_delivery_admission.h" \
  "${USB_REQUEST_SERVER_SOURCE}" \
  "${TARGET_ROOT}/agent_q/agent_q_session.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_approval_history.h" \
  "${COMMON_ROOT}/agent_q_sign_route.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

expect_request_server_wiring() {
  local pattern="$1"
  local label="$2"

  if ! grep -Eq "${pattern}" "${USB_REQUEST_SERVER_SOURCE}"; then
    echo "FAILED: ${label}" >&2
    exit 1
  fi
}

expect_request_server_block_wiring() {
  local start_pattern="$1"
  local pattern="$2"
  local label="$3"

  if ! awk -v start_pattern="${start_pattern}" -v pattern="${pattern}" '
    $0 ~ start_pattern { inside = 1 }
    inside && $0 ~ pattern { found = 1 }
    inside && /^}/ { exit(found ? 0 : 1) }
    END { if (!inside || !found) exit 1 }
  ' "${USB_REQUEST_SERVER_SOURCE}"; then
    echo "FAILED: ${label}" >&2
    exit 1
  fi
}

expect_request_server_wiring \
  'write_busy_if_pending_or_local_flow_active_for_operation' \
  "USB request server must expose operation-aware busy gating"
expect_request_server_wiring \
  'write_busy_if_pending_or_local_flow_active\(id, false, true\)' \
  "operation-aware busy gate must preserve local-flow busy checks while delegating payload delivery admission"
expect_request_server_wiring \
  'write_payload_delivery_operation_busy\(id, operation\)' \
  "operation-aware busy gate must consume payload delivery admission"
expect_request_server_wiring \
  'payload_delivery_advance_and_snapshot\(now\)' \
  "device activity projection must use a timeout-aware payload delivery snapshot"
expect_request_server_wiring \
  'current_timeout_tick\(\)' \
  "payload delivery admission must use the request-server timeout tick source"
expect_request_server_wiring \
  'payload_delivery_admission_blocks_sensitive_flow' \
  "sensitive USB gates must consume the payload delivery sensitive-flow predicate"
expect_request_server_wiring \
  'write_payload_delivery_identify_device_busy' \
  "identify_device production ops must use payload delivery admission"
expect_request_server_wiring \
  'AgentQPayloadDeliveryOperationKind::identify_device' \
  "identify_device admission must use its named operation kind"
expect_request_server_wiring \
  'write_payload_delivery_connect_busy' \
  "connect production ops must use payload delivery admission"
expect_request_server_wiring \
  'AgentQPayloadDeliveryOperationKind::connect' \
  "connect admission must use its named operation kind"
expect_request_server_wiring \
  'write_payload_delivery_policy_propose_busy' \
  "policy_propose production ops must use payload delivery admission"
expect_request_server_wiring \
  'AgentQPayloadDeliveryOperationKind::policy_propose' \
  "policy_propose admission must use its named operation kind"
expect_request_server_wiring \
  'write_payload_delivery_safe_read_admission_error' \
  "session read production ops must use payload delivery safe-read admission"
expect_request_server_wiring \
  'payload_delivery_admission_allows_safe_read' \
  "session read production ops must consume the payload delivery safe-read predicate"
expect_request_server_block_wiring \
  'usb_get_status_handler_ops' \
  'write_payload_delivery_safe_read_admission_error' \
  "get_status production ops must use payload delivery safe-read admission"
expect_request_server_block_wiring \
  'approval_history_handler_ops' \
  'write_payload_delivery_safe_read_admission_error' \
  "approval history production ops must use payload delivery safe-read admission"
expect_request_server_wiring \
  'AgentQPayloadDeliveryOperationKind::safe_read' \
  "session read admission must use the safe_read operation kind"
expect_request_server_wiring \
  'write_payload_delivery_retained_result_admission_error' \
  "retained result production ops must use payload delivery retained-result admission"
expect_request_server_wiring \
  'payload_delivery_admission_allows_retained_result_cleanup' \
  "retained result production ops must consume the payload delivery retained-result predicate"
expect_request_server_wiring \
  'AgentQPayloadDeliveryOperationKind::retained_result_read_cleanup' \
  "retained result admission must use the retained_result_read_cleanup operation kind"
expect_request_server_wiring \
  'payload_delivery_admission_allows_disconnect_cleanup' \
  "disconnect production ops must consume the payload delivery disconnect predicate"
expect_request_server_wiring \
  'AgentQPayloadDeliveryOperationKind::sign_personal_message' \
  "sign_personal_message admission must use its named operation kind"

if grep -Eq 'write_busy_if_pending_or_local_flow_active' \
    "${USB_CONNECT_HANDLER_HEADER}" \
    "${USB_DEVICE_HANDLER_HEADER}" \
    "${USB_POLICY_PROPOSE_HANDLER_HEADER}"; then
  echo "FAILED: sensitive USB handlers must expose operation-specific admission callbacks" >&2
  exit 1
fi

grep -q 'write_connect_admission_error' "${USB_CONNECT_HANDLER_HEADER}" || {
  echo "FAILED: connect handler must expose connect admission callback" >&2
  exit 1
}
grep -q 'write_identify_device_admission_error' "${USB_DEVICE_HANDLER_HEADER}" || {
  echo "FAILED: identify_device handler must expose identify admission callback" >&2
  exit 1
}
grep -q 'write_policy_propose_admission_error' "${USB_POLICY_PROPOSE_HANDLER_HEADER}" || {
  echo "FAILED: policy_propose handler must expose policy admission callback" >&2
  exit 1
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-payload-delivery-store.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"

cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
typedef uint32_t TickType_t;
H

cat >"${TMP_DIR}/payload_delivery_store_test.cpp" <<'CPP'
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#include "agent_q_payload_delivery_admission.h"
#include "agent_q_payload_delivery_store.h"
#include "mbedtls/sha256.h"

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
    constexpr char kPrefix[] = "sha256:";
    memcpy(output, kPrefix, sizeof(kPrefix) - 1);
    char* cursor = output + sizeof(kPrefix) - 1;
    constexpr char kHex[] = "0123456789abcdef";
    for (size_t index = 0; index < sizeof(digest); ++index) {
        *cursor++ = kHex[(digest[index] >> 4) & 0x0f];
        *cursor++ = kHex[digest[index] & 0x0f];
    }
    *cursor = '\0';
    return true;
}

}  // namespace agent_q

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void expect_admission(
    agent_q::AgentQPayloadDeliveryOperationKind operation,
    agent_q::AgentQPayloadDeliveryAdmissionResult expected,
    const char* label)
{
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   operation,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == expected,
           label);
}

void expect_admission_decision(
    agent_q::AgentQPayloadDeliveryOperationKind operation,
    bool staged_payload_ref,
    const char* payload_ref,
    agent_q::AgentQPayloadDeliveryAdmissionResult expected_result,
    agent_q::AgentQPayloadDeliveryAdmissionReason expected_reason,
    const char* label)
{
    const agent_q::AgentQPayloadDeliveryAdmissionDecision decision =
        agent_q::payload_delivery_admit_operation(
            agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                operation,
                "session_abcdef",
                staged_payload_ref,
                payload_ref,
            });
    expect(decision.result == expected_result, label);
    if (decision.reason != expected_reason) {
        fprintf(stderr, "FAILED: %s reason expected %s got %s\n",
                label,
                agent_q::payload_delivery_admission_reason_name(expected_reason),
                agent_q::payload_delivery_admission_reason_name(decision.reason));
        ++failures;
    }
}

void expect_operation_blocked(
    agent_q::AgentQPayloadDeliveryOperationKind operation,
    const char* operation_name,
    const char* state_name)
{
    char label[128] = {};
    snprintf(label, sizeof(label), "%s blocks %s", state_name, operation_name);
    expect_admission(
        operation,
        agent_q::AgentQPayloadDeliveryAdmissionResult::busy,
        label);
}

void expect_sensitive_operations_blocked(const char* state_name)
{
    expect_operation_blocked(
        agent_q::AgentQPayloadDeliveryOperationKind::sign_personal_message,
        "sign_personal_message",
        state_name);
    expect_operation_blocked(
        agent_q::AgentQPayloadDeliveryOperationKind::policy_propose,
        "policy_propose",
        state_name);
    expect_operation_blocked(
        agent_q::AgentQPayloadDeliveryOperationKind::connect,
        "connect",
        state_name);
    expect_operation_blocked(
        agent_q::AgentQPayloadDeliveryOperationKind::identify_device,
        "identify_device",
        state_name);
}

std::vector<uint8_t> bytes(size_t size)
{
    std::vector<uint8_t> output(size);
    for (size_t index = 0; index < output.size(); ++index) {
        output[index] = static_cast<uint8_t>((index * 17 + 3) & 0xff);
    }
    return output;
}

std::string digest_for(const std::vector<uint8_t>& value)
{
    char digest[agent_q::kAgentQApprovalHistoryDigestSize] = {};
    expect(agent_q::approval_history_digest_payload(
               value.data(),
               value.size(),
               digest,
               sizeof(digest)),
           "digest helper succeeds");
    return digest;
}

agent_q::AgentQPayloadDeliveryBeginInput begin_input(
    const char* session_id,
    const std::vector<uint8_t>& payload,
    size_t chunk_max = 5,
    size_t payload_max = 32,
    uint64_t deadline = 1000,
    uint64_t started_at = 0)
{
    static std::string last_digest;
    last_digest = digest_for(payload);
    return agent_q::AgentQPayloadDeliveryBeginInput{
        session_id,
        agent_q::AgentQSupportedSignRoute::sui_sign_transaction,
        "transaction",
        payload.size(),
        last_digest.c_str(),
        agent_q::AgentQPayloadDeliveryLimits{chunk_max, payload_max},
        agent_q::timeout_window_from_deadline(
            static_cast<agent_q::AgentQTimeoutTick>(started_at),
            static_cast<agent_q::AgentQTimeoutTick>(deadline)),
    };
}

void append_all(
    const char* session_id,
    const char* upload_id,
    const std::vector<uint8_t>& payload,
    size_t chunk_size)
{
    size_t offset = 0;
    while (offset < payload.size()) {
        const size_t next_size = std::min(chunk_size, payload.size() - offset);
        size_t received = 0;
        const agent_q::AgentQPayloadDeliveryResult result =
            agent_q::payload_delivery_append_chunk(0,
                agent_q::AgentQPayloadDeliveryChunkInput{
                    session_id,
                    upload_id,
                    offset,
                    payload.data() + offset,
                    next_size,
                },
                &received);
        expect(result == agent_q::AgentQPayloadDeliveryResult::ok, "chunk append succeeds");
        offset += next_size;
        expect(received == offset, "received bytes advances monotonically");
    }
}

void test_successful_finalize_and_resolve()
{
    agent_q::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(12);
    agent_q::AgentQPayloadDeliveryBeginOutput begin = {};
    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin succeeds");
    expect(begin.received_bytes == 0, "begin starts at zero bytes");
    expect(begin.chunk_max_bytes == 5, "begin returns chunk limit");
    append_all("session_abcdef", begin.upload_id, payload, 5);

    agent_q::AgentQPayloadDeliveryFinishOutput finish = {};
    expect(agent_q::payload_delivery_finish(0,
               agent_q::AgentQPayloadDeliveryFinishInput{"session_abcdef", begin.upload_id},
               &finish) == agent_q::AgentQPayloadDeliveryResult::ok,
           "finish succeeds");
    expect(strcmp(finish.descriptor.chain, "sui") == 0, "descriptor chain projected from route");
    expect(strcmp(finish.descriptor.method, "sign_transaction") == 0,
           "descriptor method projected from route");
    expect(strcmp(finish.descriptor.payload_kind, "transaction") == 0,
           "descriptor payload kind preserved");
    expect(finish.descriptor.size_bytes == payload.size(), "descriptor stores payload size");
    expect(strcmp(finish.descriptor.payload_digest, digest_for(payload).c_str()) == 0,
           "descriptor stores digest");

    agent_q::AgentQPayloadDeliveryView view = {};
    expect(agent_q::payload_delivery_resolve_finalized(0,
               "session_abcdef",
               finish.descriptor.payload_ref,
               &view) == agent_q::AgentQPayloadDeliveryResult::ok,
           "finalized payload resolves");
    expect(view.bytes != nullptr, "resolved view borrows bytes");
    expect(view.size_bytes == payload.size(), "resolved view size");
    expect(memcmp(view.bytes, payload.data(), payload.size()) == 0, "resolved bytes match");
}

void test_default_max_payload_round_trip()
{
    agent_q::payload_delivery_store_reset();
    const std::vector<uint8_t> payload =
        bytes(agent_q::kAgentQPayloadDeliveryDefaultMaxBytes);
    agent_q::AgentQPayloadDeliveryBeginOutput begin = {};
    expect(agent_q::payload_delivery_begin(0,
               begin_input(
                   "session_abcdef",
                   payload,
                   agent_q::kAgentQPayloadDeliveryDefaultChunkMaxBytes,
                   agent_q::kAgentQPayloadDeliveryDefaultMaxBytes),
               &begin) == agent_q::AgentQPayloadDeliveryResult::ok,
           "default max payload begin succeeds");
    append_all(
        "session_abcdef",
        begin.upload_id,
        payload,
        agent_q::kAgentQPayloadDeliveryDefaultChunkMaxBytes);

    agent_q::AgentQPayloadDeliveryFinishOutput finish = {};
    expect(agent_q::payload_delivery_finish(0,
               agent_q::AgentQPayloadDeliveryFinishInput{"session_abcdef", begin.upload_id},
               &finish) == agent_q::AgentQPayloadDeliveryResult::ok,
           "default max payload finish succeeds");
    expect(finish.descriptor.size_bytes == payload.size(),
           "default max descriptor preserves size");
    expect(strcmp(finish.descriptor.payload_digest, digest_for(payload).c_str()) == 0,
           "default max descriptor preserves digest");

    agent_q::AgentQPayloadDeliveryView view = {};
    expect(agent_q::payload_delivery_resolve_finalized(0,
               "session_abcdef",
               finish.descriptor.payload_ref,
               &view) == agent_q::AgentQPayloadDeliveryResult::ok,
           "default max finalized payload resolves");
    expect(view.bytes != nullptr && view.size_bytes == payload.size(),
           "default max resolved payload size is preserved");
    expect(memcmp(view.bytes, payload.data(), payload.size()) == 0,
           "default max resolved payload bytes are preserved");
}

void test_take_finalized_transfers_ownership_and_clears_store()
{
    agent_q::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(16);
    agent_q::AgentQPayloadDeliveryBeginOutput begin = {};
    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin before take succeeds");
    append_all("session_abcdef", begin.upload_id, payload, 5);

    agent_q::AgentQPayloadDeliveryFinishOutput finish = {};
    expect(agent_q::payload_delivery_finish(0,
               agent_q::AgentQPayloadDeliveryFinishInput{"session_abcdef", begin.upload_id},
               &finish) == agent_q::AgentQPayloadDeliveryResult::ok,
           "finish before take succeeds");

    agent_q::AgentQPayloadDeliveryOwnedPayload owned = {};
    expect(agent_q::payload_delivery_take_finalized(0,
               "session_abcdef",
               finish.descriptor.payload_ref,
               &owned) == agent_q::AgentQPayloadDeliveryResult::ok,
           "take finalized succeeds");
    expect(owned.bytes != nullptr, "take returns owned bytes");
    expect(owned.size_bytes == payload.size(), "take returns owned byte size");
    expect(memcmp(owned.bytes, payload.data(), payload.size()) == 0,
           "taken bytes match finalized payload");
    expect(strcmp(owned.descriptor.payload_ref, finish.descriptor.payload_ref) == 0,
           "take preserves descriptor payloadRef");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "take clears store to idle");

    agent_q::AgentQPayloadDeliveryView view = {};
    expect(agent_q::payload_delivery_resolve_finalized(0,
               "session_abcdef",
               finish.descriptor.payload_ref,
               &view) == agent_q::AgentQPayloadDeliveryResult::not_found,
           "taken payload is no longer live in the store");
    agent_q::wipe_sensitive_buffer(owned.bytes, owned.size_bytes);
    free(owned.bytes);
}

void test_admission_matrix()
{
    agent_q::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(12);

    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::payload_upload_begin,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "idle allows upload begin");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::sign_transaction,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "idle allows inline sign transaction");
    expect_admission_decision(
        agent_q::AgentQPayloadDeliveryOperationKind::sign_transaction,
        false,
        nullptr,
        agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
        agent_q::AgentQPayloadDeliveryAdmissionReason::idle_passthrough,
        "idle inline sign transaction is passthrough");
    expect_admission_decision(
        agent_q::AgentQPayloadDeliveryOperationKind::sign_transaction,
        true,
        "payload_unknown",
        agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
        agent_q::AgentQPayloadDeliveryAdmissionReason::idle_passthrough,
        "idle staged sign transaction reaches retained lookup before live resolve");
    expect_admission_decision(
        agent_q::AgentQPayloadDeliveryOperationKind::payload_upload_chunk,
        false,
        nullptr,
        agent_q::AgentQPayloadDeliveryAdmissionResult::unknown_request,
        agent_q::AgentQPayloadDeliveryAdmissionReason::missing_active_payload,
        "idle rejects upload chunk before store lookup");
    expect_admission_decision(
        agent_q::AgentQPayloadDeliveryOperationKind::payload_upload_finish,
        false,
        nullptr,
        agent_q::AgentQPayloadDeliveryAdmissionResult::unknown_request,
        agent_q::AgentQPayloadDeliveryAdmissionReason::missing_active_payload,
        "idle rejects upload finish before store lookup");
    expect_admission_decision(
        agent_q::AgentQPayloadDeliveryOperationKind::payload_upload_abort,
        false,
        nullptr,
        agent_q::AgentQPayloadDeliveryAdmissionResult::unknown_request,
        agent_q::AgentQPayloadDeliveryAdmissionReason::missing_active_payload,
        "idle rejects upload abort before store lookup");

    agent_q::AgentQPayloadDeliveryBeginOutput begin = {};
    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for admission test succeeds");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::safe_read,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "receiving allows safe reads");
    expect_admission_decision(
        agent_q::AgentQPayloadDeliveryOperationKind::safe_read,
        false,
        nullptr,
        agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
        agent_q::AgentQPayloadDeliveryAdmissionReason::receiving_safe_read,
        "receiving safe read has explicit exception reason");
    expect(agent_q::payload_delivery_admission_allows_safe_read(
               agent_q::payload_delivery_admit_operation(
                   agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                       agent_q::AgentQPayloadDeliveryOperationKind::safe_read,
                       "session_abcdef",
                       false,
                       nullptr,
                   })),
           "receiving safe read is exposed through contract predicate");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::retained_result_read_cleanup,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "receiving allows retained result read/cleanup");
    expect(agent_q::payload_delivery_admission_allows_retained_result_cleanup(
               agent_q::payload_delivery_admit_operation(
                   agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                       agent_q::AgentQPayloadDeliveryOperationKind::retained_result_read_cleanup,
                       "session_abcdef",
                       false,
                       nullptr,
                   })),
           "receiving retained-result cleanup is exposed through contract predicate");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::disconnect,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "receiving allows disconnect cleanup");
    expect(agent_q::payload_delivery_admission_allows_disconnect_cleanup(
               agent_q::payload_delivery_admit_operation(
                   agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                       agent_q::AgentQPayloadDeliveryOperationKind::disconnect,
                       "session_abcdef",
                       false,
                       nullptr,
                   })),
           "receiving disconnect cleanup is exposed through contract predicate");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::payload_upload_begin,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::busy,
           "receiving blocks nested upload begin");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::payload_upload_chunk,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "receiving allows upload chunk");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::payload_upload_finish,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "receiving allows upload finish");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::payload_upload_abort,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "receiving allows upload abort");
    expect_sensitive_operations_blocked("receiving");
    expect(agent_q::payload_delivery_admit_sign_transaction(
               agent_q::AgentQPayloadDeliverySignTransactionAdmissionInput{0,
                   "session_abcdef",
                   false,
                   nullptr,
               },
               nullptr) == agent_q::AgentQPayloadDeliveryAdmissionResult::busy,
           "receiving blocks inline sign transaction");
    expect_admission_decision(
        agent_q::AgentQPayloadDeliveryOperationKind::sign_transaction,
        false,
        nullptr,
        agent_q::AgentQPayloadDeliveryAdmissionResult::busy,
        agent_q::AgentQPayloadDeliveryAdmissionReason::blocked_incomplete_upload,
        "receiving blocks signing because upload is incomplete");
    expect(agent_q::payload_delivery_admission_blocks_sensitive_flow(
               agent_q::payload_delivery_admit_operation(
                   agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                       agent_q::AgentQPayloadDeliveryOperationKind::sign_transaction,
                       "session_abcdef",
                       false,
                       nullptr,
                   })),
           "receiving signing block is exposed through sensitive-flow predicate");

    append_all("session_abcdef", begin.upload_id, payload, 5);
    agent_q::AgentQPayloadDeliveryFinishOutput finish = {};
    expect(agent_q::payload_delivery_finish(0,
               agent_q::AgentQPayloadDeliveryFinishInput{"session_abcdef", begin.upload_id},
               &finish) == agent_q::AgentQPayloadDeliveryResult::ok,
           "finish for admission test succeeds");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::safe_read,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "finalized allows safe reads");
    expect_admission_decision(
        agent_q::AgentQPayloadDeliveryOperationKind::sign_transaction,
        false,
        nullptr,
        agent_q::AgentQPayloadDeliveryAdmissionResult::busy,
        agent_q::AgentQPayloadDeliveryAdmissionReason::blocked_pending_finalized_payload,
        "finalized blocks inline signing because payload is pending");
    expect(agent_q::payload_delivery_admission_blocks_sensitive_flow(
               agent_q::payload_delivery_admit_operation(
                   agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                       agent_q::AgentQPayloadDeliveryOperationKind::sign_transaction,
                       "session_abcdef",
                       false,
                       nullptr,
                   })),
           "finalized inline signing block is exposed through sensitive-flow predicate");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::retained_result_read_cleanup,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "finalized allows retained result read/cleanup");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::disconnect,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "finalized allows disconnect cleanup");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::payload_upload_begin,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::busy,
           "finalized blocks nested upload begin");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::payload_upload_chunk,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::busy,
           "finalized blocks upload chunk");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::payload_upload_finish,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::busy,
           "finalized blocks upload finish");
    expect(agent_q::payload_delivery_admit_operation(
               agent_q::AgentQPayloadDeliveryOperationAdmissionInput{0,
                   agent_q::AgentQPayloadDeliveryOperationKind::payload_upload_abort,
                   "session_abcdef",
                   false,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "finalized allows upload abort");
    expect_sensitive_operations_blocked("finalized");
    expect(agent_q::payload_delivery_admit_sign_transaction(
               agent_q::AgentQPayloadDeliverySignTransactionAdmissionInput{0,
                   "session_abcdef",
                   false,
                   nullptr,
               },
               nullptr) == agent_q::AgentQPayloadDeliveryAdmissionResult::busy,
           "finalized blocks inline sign transaction");
    expect(agent_q::payload_delivery_admit_sign_transaction(
               agent_q::AgentQPayloadDeliverySignTransactionAdmissionInput{0,
                   "session_other",
                   true,
                   finish.descriptor.payload_ref,
               },
               nullptr) == agent_q::AgentQPayloadDeliveryAdmissionResult::invalid_session,
           "finalized rejects different session consumer");
    expect(agent_q::payload_delivery_admit_sign_transaction(
               agent_q::AgentQPayloadDeliverySignTransactionAdmissionInput{0,
                   "session_abcdef",
                   true,
                   "payload_unknown",
               },
               nullptr) == agent_q::AgentQPayloadDeliveryAdmissionResult::invalid_payload_ref,
           "finalized rejects mismatched payloadRef consumer");
    expect(agent_q::payload_delivery_admit_sign_transaction(
               agent_q::AgentQPayloadDeliverySignTransactionAdmissionInput{0,
                   "session_abcdef",
                   true,
                   finish.descriptor.payload_ref,
               },
               nullptr) == agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
           "finalized allows matching staged sign transaction");
    expect_admission_decision(
        agent_q::AgentQPayloadDeliveryOperationKind::sign_transaction,
        true,
        finish.descriptor.payload_ref,
        agent_q::AgentQPayloadDeliveryAdmissionResult::ok,
        agent_q::AgentQPayloadDeliveryAdmissionReason::finalized_matching_staged_consumer,
        "finalized matching staged consumer has explicit authority reason");
    expect(agent_q::payload_delivery_admission_allows_staged_consumer(
               agent_q::payload_delivery_admit_sign_transaction(
                   agent_q::AgentQPayloadDeliverySignTransactionAdmissionInput{0,
                       "session_abcdef",
                       true,
                       finish.descriptor.payload_ref,
                   },
                   nullptr)),
           "finalized matching staged consumer is exposed through contract predicate");
}

void test_guards_and_cleanup()
{
    agent_q::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(8);
    const uint8_t first_chunk[2] = {1, 2};

    expect(agent_q::payload_delivery_append_chunk(0,
               agent_q::AgentQPayloadDeliveryChunkInput{
                   "session_abcdef",
                   "upload_0000000000000001",
                   0,
                   first_chunk,
                   sizeof(first_chunk),
               },
               nullptr) == agent_q::AgentQPayloadDeliveryResult::not_found,
           "chunk without active upload is not found");
    agent_q::AgentQPayloadDeliveryFinishOutput idle_finish = {};
    expect(agent_q::payload_delivery_finish(0,
               agent_q::AgentQPayloadDeliveryFinishInput{
                   "session_abcdef",
                   "upload_0000000000000001",
               },
               &idle_finish) == agent_q::AgentQPayloadDeliveryResult::not_found,
           "finish without active upload is not found");

    agent_q::AgentQPayloadDeliveryBeginOutput begin = {};
    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8, 50), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for guard tests succeeds");

    const uint8_t too_large[5] = {1, 2, 3, 4, 5};
    expect(agent_q::payload_delivery_append_chunk(0,
               agent_q::AgentQPayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.upload_id,
                   0,
                   too_large,
                   sizeof(too_large),
               },
               nullptr) == agent_q::AgentQPayloadDeliveryResult::chunk_too_large,
           "chunk max+1 rejected");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "chunk too large wipes owned active upload");

    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8, 50), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for reported chunk oversize succeeds");
    expect(agent_q::payload_delivery_reject_chunk_too_large(0,
               "session_abcdef",
               begin.upload_id) == agent_q::AgentQPayloadDeliveryResult::chunk_too_large,
           "reported chunk oversize rejected by store owner");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "reported chunk oversize wipes owned active upload");

    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8, 50), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for offset mismatch succeeds");

    expect(agent_q::payload_delivery_append_chunk(0,
               agent_q::AgentQPayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.upload_id,
                   1,
                   payload.data(),
                   2,
               },
               nullptr) == agent_q::AgentQPayloadDeliveryResult::offset_mismatch,
           "offset mismatch rejected");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "offset mismatch wipes owned active upload");

    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8, 50), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for different session mismatch succeeds");

    expect(agent_q::payload_delivery_append_chunk(0,
               agent_q::AgentQPayloadDeliveryChunkInput{
                   "session_other",
                   begin.upload_id,
                   0,
                   payload.data(),
                   2,
               },
               nullptr) == agent_q::AgentQPayloadDeliveryResult::invalid_session,
           "different session cannot append");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state ==
               agent_q::AgentQPayloadDeliveryState::receiving,
           "different session failure does not wipe active upload");
    expect(agent_q::payload_delivery_reject_chunk_too_large(0,
               "session_other",
               begin.upload_id) == agent_q::AgentQPayloadDeliveryResult::invalid_session,
           "different session reported oversize cannot clear active upload");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state ==
               agent_q::AgentQPayloadDeliveryState::receiving,
           "different session reported oversize preserves active upload");

    expect(agent_q::payload_delivery_append_chunk(0,
               agent_q::AgentQPayloadDeliveryChunkInput{
                   "session_abcdef",
                   "bad-upload",
                   0,
                   payload.data(),
                   2,
               },
               nullptr) == agent_q::AgentQPayloadDeliveryResult::invalid_upload_id,
           "malformed upload id is separated from session mismatch");

    agent_q::payload_delivery_store_reset();
    agent_q::AgentQPayloadDeliveryBeginInput inactive_deadline =
        begin_input("session_abcdef", payload, 4, 8, 0, 0);
    expect(agent_q::payload_delivery_begin(0, inactive_deadline, &begin) ==
               agent_q::AgentQPayloadDeliveryResult::invalid_argument,
           "begin rejects inactive timeout window");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "inactive timeout rejection leaves store idle");

    agent_q::AgentQPayloadDeliveryBeginInput zero_wrapped_deadline =
        begin_input("session_abcdef", payload, 4, 8, 0, UINT32_MAX - 5);
    expect(agent_q::payload_delivery_begin(0, zero_wrapped_deadline, &begin) ==
               agent_q::AgentQPayloadDeliveryResult::invalid_argument,
           "begin rejects deadline that wraps to inactive zero");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "zero-wrapped timeout rejection leaves store idle");

    expect(agent_q::payload_delivery_begin(50,
               begin_input("session_abcdef", payload, 4, 8, 50),
               &begin) == agent_q::AgentQPayloadDeliveryResult::invalid_argument,
           "begin rejects timeout window closed at operation tick");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "closed timeout begin rejection leaves store idle");

    expect(agent_q::payload_delivery_begin(49,
               begin_input("session_abcdef", payload, 4, 8, 50),
               &begin) == agent_q::AgentQPayloadDeliveryResult::ok,
           "begin accepts timeout window open at operation tick");
    expect(agent_q::payload_delivery_advance_and_snapshot(49).state ==
               agent_q::AgentQPayloadDeliveryState::receiving,
           "open timeout begin enters receiving");
    agent_q::payload_delivery_store_reset();

    expect(agent_q::payload_delivery_begin(5,
               begin_input("session_abcdef", payload, 4, 8, 5, UINT32_MAX - 10),
               &begin) == agent_q::AgentQPayloadDeliveryResult::invalid_argument,
           "begin rejects wrapped timeout window closed at operation tick");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "closed wrapped timeout begin rejection leaves store idle");

    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8, 50), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for deadline cleanup succeeds");
    expect(!agent_q::payload_delivery_clear_expired(49), "deadline before expiry keeps upload");
    expect(agent_q::payload_delivery_clear_expired(50), "deadline expiry clears upload");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "expired upload returns to idle");

    agent_q::AgentQPayloadDeliveryBeginOutput wrap_begin = {};
    expect(agent_q::payload_delivery_begin(0,
               begin_input("session_abcdef", payload, 4, 8, 5, UINT32_MAX - 10),
               &wrap_begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for wrapped deadline succeeds");
    expect(!agent_q::payload_delivery_clear_expired(UINT32_MAX - 2),
           "wrapped deadline keeps upload before deadline");
    expect(agent_q::payload_delivery_clear_expired(5),
           "wrapped deadline clears upload at deadline");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "wrapped expired upload returns to idle");
}

void test_timeout_operation_boundaries()
{
    agent_q::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(6);
    agent_q::AgentQPayloadDeliveryBeginOutput begin = {};

    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8, 50), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for expired append boundary succeeds");
    size_t received = 0;
    expect(agent_q::payload_delivery_append_chunk(
               50,
               agent_q::AgentQPayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.upload_id,
                   0,
                   payload.data(),
                   payload.size(),
               },
               &received) == agent_q::AgentQPayloadDeliveryResult::not_found,
           "expired append clears store before accepting chunk");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "expired append boundary leaves store idle");

    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 8, 8, 50), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for expired finish boundary succeeds");
    append_all("session_abcdef", begin.upload_id, payload, 8);
    agent_q::AgentQPayloadDeliveryFinishOutput finish = {};
    expect(agent_q::payload_delivery_finish(
               50,
               agent_q::AgentQPayloadDeliveryFinishInput{"session_abcdef", begin.upload_id},
               &finish) == agent_q::AgentQPayloadDeliveryResult::not_found,
           "expired finish clears store before finalizing");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "expired finish boundary leaves store idle");

    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 8, 8, 50), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for expired finalized boundary succeeds");
    append_all("session_abcdef", begin.upload_id, payload, 8);
    expect(agent_q::payload_delivery_finish(
               0,
               agent_q::AgentQPayloadDeliveryFinishInput{"session_abcdef", begin.upload_id},
               &finish) == agent_q::AgentQPayloadDeliveryResult::ok,
           "finish before deadline succeeds");
    const std::string payload_ref = finish.descriptor.payload_ref;
    agent_q::AgentQPayloadDeliveryView view = {};
    expect(agent_q::payload_delivery_resolve_finalized(
               50,
               "session_abcdef",
               payload_ref.c_str(),
               &view) == agent_q::AgentQPayloadDeliveryResult::not_found,
           "expired resolve clears finalized payload before borrowing bytes");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "expired resolve boundary leaves store idle");

    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 8, 8, 50), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for expired take boundary succeeds");
    append_all("session_abcdef", begin.upload_id, payload, 8);
    expect(agent_q::payload_delivery_finish(
               0,
               agent_q::AgentQPayloadDeliveryFinishInput{"session_abcdef", begin.upload_id},
               &finish) == agent_q::AgentQPayloadDeliveryResult::ok,
           "finish before expired take succeeds");
    const std::string take_payload_ref = finish.descriptor.payload_ref;
    agent_q::AgentQPayloadDeliveryOwnedPayload owned = {};
    expect(agent_q::payload_delivery_take_finalized(
               50,
               "session_abcdef",
               take_payload_ref.c_str(),
               &owned) == agent_q::AgentQPayloadDeliveryResult::not_found,
           "expired take clears finalized payload before ownership transfer");
    expect(owned.bytes == nullptr, "expired take does not return owned bytes");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "expired take boundary leaves store idle");

    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 8, 8, 50), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for expired admission boundary succeeds");
    append_all("session_abcdef", begin.upload_id, payload, 8);
    expect(agent_q::payload_delivery_finish(
               0,
               agent_q::AgentQPayloadDeliveryFinishInput{"session_abcdef", begin.upload_id},
               &finish) == agent_q::AgentQPayloadDeliveryResult::ok,
           "finish before expired admission succeeds");
    const agent_q::AgentQPayloadDeliveryAdmissionDecision expired_consumer =
        agent_q::payload_delivery_admit_sign_transaction(
            agent_q::AgentQPayloadDeliverySignTransactionAdmissionInput{
                50,
                "session_abcdef",
                true,
                finish.descriptor.payload_ref,
            },
            nullptr);
    expect(!agent_q::payload_delivery_admission_allows_staged_consumer(expired_consumer),
           "expired finalized payload is not admitted as a staged consumer");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "expired admission boundary leaves store idle");
}

void test_oversize_and_digest_mismatch()
{
    agent_q::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(9);
    agent_q::AgentQPayloadDeliveryBeginOutput begin = {};
    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::unsupported_payload_size,
           "payload max+1 rejected at begin");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "begin max+1 leaves store idle");

    const std::vector<uint8_t> valid = bytes(4);
    std::string wrong_digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    agent_q::AgentQPayloadDeliveryBeginInput input =
        begin_input("session_abcdef", valid, 4, 8);
    input.payload_digest = wrong_digest.c_str();
    expect(agent_q::payload_delivery_begin(0, input, &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin with well-formed wrong digest succeeds");
    append_all("session_abcdef", begin.upload_id, valid, 4);
    agent_q::AgentQPayloadDeliveryFinishOutput finish = {};
    expect(agent_q::payload_delivery_finish(0,
               agent_q::AgentQPayloadDeliveryFinishInput{"session_abcdef", begin.upload_id},
               &finish) == agent_q::AgentQPayloadDeliveryResult::digest_mismatch,
           "digest mismatch rejected at finish");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "digest mismatch wipes upload");
}

void test_size_mismatch_and_payload_overflow()
{
    agent_q::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(8);
    agent_q::AgentQPayloadDeliveryBeginOutput begin = {};
    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for size mismatch succeeds");

    size_t received = 0;
    expect(agent_q::payload_delivery_append_chunk(0,
               agent_q::AgentQPayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.upload_id,
                   0,
                   payload.data(),
                   4,
               },
               &received) == agent_q::AgentQPayloadDeliveryResult::ok,
           "partial chunk append succeeds");
    expect(received == 4, "partial append reports received bytes");

    agent_q::AgentQPayloadDeliveryFinishOutput finish = {};
    expect(agent_q::payload_delivery_finish(0,
               agent_q::AgentQPayloadDeliveryFinishInput{"session_abcdef", begin.upload_id},
               &finish) == agent_q::AgentQPayloadDeliveryResult::size_mismatch,
           "early finish returns size mismatch");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "size mismatch wipes owned active upload");
    expect(agent_q::payload_delivery_append_chunk(0,
               agent_q::AgentQPayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.upload_id,
                   4,
                   payload.data() + 4,
                   4,
               },
               &received) == agent_q::AgentQPayloadDeliveryResult::not_found,
           "stale upload cannot continue after size mismatch");

    agent_q::payload_delivery_store_reset();
    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload, 6, 8), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin for payload overflow succeeds");
    expect(agent_q::payload_delivery_append_chunk(0,
               agent_q::AgentQPayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.upload_id,
                   0,
                   payload.data(),
                   6,
               },
               &received) == agent_q::AgentQPayloadDeliveryResult::ok,
           "first overflow setup chunk succeeds");
    const uint8_t overflow_chunk[3] = {1, 2, 3};
    expect(agent_q::payload_delivery_append_chunk(0,
               agent_q::AgentQPayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.upload_id,
                   6,
                   overflow_chunk,
                   sizeof(overflow_chunk),
               },
               nullptr) == agent_q::AgentQPayloadDeliveryResult::payload_overflow,
           "declared-size overflow is rejected");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "declared-size overflow wipes upload");
}

void test_abort_active_and_finalized()
{
    agent_q::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(6);
    agent_q::AgentQPayloadDeliveryBeginOutput begin = {};
    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin active abort succeeds");
    expect(agent_q::payload_delivery_abort(0,
               agent_q::AgentQPayloadDeliveryAbortInput{
                   "session_abcdef",
                   begin.upload_id,
                   nullptr,
               }) == agent_q::AgentQPayloadDeliveryResult::ok,
           "active upload abort succeeds");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state == agent_q::AgentQPayloadDeliveryState::idle,
           "active abort clears store");

    expect(agent_q::payload_delivery_begin(0, begin_input("session_abcdef", payload), &begin) ==
               agent_q::AgentQPayloadDeliveryResult::ok,
           "begin finalized abort succeeds");
    append_all("session_abcdef", begin.upload_id, payload, 5);
    agent_q::AgentQPayloadDeliveryFinishOutput finish = {};
    expect(agent_q::payload_delivery_finish(0,
               agent_q::AgentQPayloadDeliveryFinishInput{"session_abcdef", begin.upload_id},
               &finish) == agent_q::AgentQPayloadDeliveryResult::ok,
           "finish for abort succeeds");
    expect(agent_q::payload_delivery_abort(0,
               agent_q::AgentQPayloadDeliveryAbortInput{
                   "session_other",
                   nullptr,
                   finish.descriptor.payload_ref,
               }) == agent_q::AgentQPayloadDeliveryResult::invalid_session,
           "different session cannot abort finalized payload");
    expect(agent_q::payload_delivery_advance_and_snapshot(0).state ==
               agent_q::AgentQPayloadDeliveryState::finalized,
           "different session finalized abort does not wipe");
    agent_q::AgentQPayloadDeliveryView view = {};
    expect(agent_q::payload_delivery_resolve_finalized(0,
               "session_abcdef",
               "bad-payload",
               &view) == agent_q::AgentQPayloadDeliveryResult::invalid_payload_ref,
           "malformed payload ref is separated from session mismatch");
    expect(agent_q::payload_delivery_abort(0,
               agent_q::AgentQPayloadDeliveryAbortInput{
                   "session_abcdef",
                   nullptr,
                   finish.descriptor.payload_ref,
               }) == agent_q::AgentQPayloadDeliveryResult::ok,
           "same session finalized abort succeeds");
}

void test_descriptor_and_view_are_small()
{
    static_assert(sizeof(agent_q::AgentQPayloadDeliveryDescriptor) < 512,
                  "payload descriptor must not carry payload bytes");
    static_assert(sizeof(agent_q::AgentQPayloadDeliveryView) < 576,
                  "payload view must not copy payload bytes");
    static_assert(sizeof(agent_q::AgentQPayloadDeliverySnapshot) < 320,
                  "payload snapshot must not copy payload bytes");
}

}  // namespace

int main()
{
    test_descriptor_and_view_are_small();
    test_successful_finalize_and_resolve();
    test_default_max_payload_round_trip();
    test_take_finalized_transfers_ownership_and_clears_store();
    test_admission_matrix();
    test_guards_and_cleanup();
    test_timeout_operation_boundaries();
    test_oversize_and_digest_mismatch();
    test_size_mismatch_and_payload_overflow();
    test_abort_active_and_finalized();
    agent_q::payload_delivery_store_reset();

    if (failures != 0) {
        fprintf(stderr, "%d payload delivery store test(s) failed\n", failures);
        return 1;
    }
    printf("payload delivery store tests passed\n");
    return 0;
}
CPP

c++ -std=c++17 -Wall -Wextra -Werror \
  -I"${TARGET_ROOT}/agent_q" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${TARGET_ROOT}/agent_q/agent_q_payload_delivery_primitives.cpp" \
  -o "${TMP_DIR}/payload_delivery_primitives.o"

c++ -std=c++17 -Wall -Wextra -Werror \
  -I"${TARGET_ROOT}/agent_q" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${TARGET_ROOT}/agent_q/agent_q_payload_delivery_store.cpp" \
  -o "${TMP_DIR}/payload_delivery_store.o"

c++ -std=c++17 -Wall -Wextra -Werror \
  -I"${TARGET_ROOT}/agent_q" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${TARGET_ROOT}/agent_q/agent_q_payload_delivery_admission.cpp" \
  -o "${TMP_DIR}/payload_delivery_admission.o"

c++ -std=c++17 -Wall -Wextra -Werror \
  -I"${TARGET_ROOT}/agent_q" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${TARGET_ROOT}/agent_q/agent_q_session.cpp" \
  -o "${TMP_DIR}/session.o"

cc -std=c99 -Wall -Wextra -Werror \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"

cc -std=c99 -Wall -Wextra -Werror \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

c++ -std=c++17 -Wall -Wextra -Werror \
  -I"${TARGET_ROOT}/agent_q" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/payload_delivery_store_test.cpp" \
  "${TMP_DIR}/payload_delivery_primitives.o" \
  "${TMP_DIR}/payload_delivery_store.o" \
  "${TMP_DIR}/payload_delivery_admission.o" \
  "${TMP_DIR}/session.o" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/payload_delivery_store_test"

"${TMP_DIR}/payload_delivery_store_test"
