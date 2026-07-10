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
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
USB_REQUEST_SERVER_SOURCE="${TARGET_ROOT}/runtime/protocol_request_server.cpp"
USB_OPERATION_MANIFEST_SOURCE="${REPO_ROOT}/firmware/src/common/protocol/operation_manifest.cpp"
USB_DEVICE_HANDLER_SOURCE="${COMMON_ROOT}/protocol/device_handlers.cpp"
USB_SESSION_READ_HANDLER_SOURCE="${COMMON_ROOT}/protocol/session_read_handlers.cpp"
USB_POLICY_HANDLER_SOURCE="${COMMON_ROOT}/policy/policy_handlers.cpp"
USB_APPROVAL_HISTORY_HANDLER_SOURCE="${COMMON_ROOT}/protocol/approval_history_handler.cpp"
USB_RETAINED_RESPONSE_HANDLER_SOURCE="${COMMON_ROOT}/transport/retained_response_handlers.cpp"
USB_DISCONNECT_HANDLER_SOURCE="${COMMON_ROOT}/transport/disconnect_handler.cpp"
USB_CONNECT_HANDLER_HEADER="${COMMON_ROOT}/transport/connect_handler.h"
USB_DEVICE_HANDLER_HEADER="${COMMON_ROOT}/protocol/device_handlers.h"
USB_POLICY_HANDLER_HEADER="${COMMON_ROOT}/policy/policy_handlers.h"
USB_SUI_ZKLOGIN_CREDENTIAL_HANDLER_HEADER="${COMMON_ROOT}/protocol/sui_zklogin_credential_handlers.h"

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
  "${COMMON_ROOT}/transport/payload_delivery_admission.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_admission.h" \
  "${COMMON_ROOT}/transport/payload_delivery_operation_kind.h" \
  "${COMMON_ROOT}/transport/payload_delivery_primitives.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_primitives.h" \
  "${COMMON_ROOT}/transport/payload_delivery_store.cpp" \
  "${COMMON_ROOT}/transport/payload_delivery_store.h" \
  "${REPO_ROOT}/firmware/src/common/protocol/operation_manifest.cpp" \
  "${REPO_ROOT}/firmware/src/common/protocol/operation_manifest.h" \
  "${USB_DEVICE_HANDLER_SOURCE}" \
  "${USB_SESSION_READ_HANDLER_SOURCE}" \
  "${USB_APPROVAL_HISTORY_HANDLER_SOURCE}" \
  "${USB_RETAINED_RESPONSE_HANDLER_SOURCE}" \
  "${USB_DISCONNECT_HANDLER_SOURCE}" \
  "${USB_REQUEST_SERVER_SOURCE}" \
  "${COMMON_ROOT}/protocol/session_state.cpp" \
  "${REPO_ROOT}/firmware/src/common/protocol/approval_history.h" \
  "${USB_SUI_ZKLOGIN_CREDENTIAL_HANDLER_HEADER}" \
  "${COMMON_ROOT}/protocol/sign_route.h"; do
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

expect_source_wiring() {
  local source_path="$1"
  local pattern="$2"
  local label="$3"

  if ! grep -Eq "${pattern}" "${source_path}"; then
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

expect_manifest_operation_wiring() {
  local start_pattern="$1"
  local handler_pattern="$2"
  local payload_pattern="$3"
  local label="$4"

  if ! awk \
      -v start_pattern="${start_pattern}" \
      -v handler_pattern="${handler_pattern}" \
      -v payload_pattern="${payload_pattern}" '
    $0 ~ start_pattern { inside = 1 }
    inside && $0 ~ handler_pattern { found_handler = 1 }
    inside && $0 ~ payload_pattern { found_payload = 1 }
    inside && /^    },/ { exit((found_handler && found_payload) ? 0 : 1) }
    END { if (!inside || !found_handler || !found_payload) exit 1 }
  ' "${USB_OPERATION_MANIFEST_SOURCE}"; then
    echo "FAILED: ${label}" >&2
    exit 1
  fi
}

expect_request_server_wiring \
  'write_busy_if_pending_or_local_flow_active_for_operation' \
  "USB request server must expose operation-aware busy gating"
expect_request_server_wiring \
  'write_busy_if_pending_or_local_flow_active\(id, writer, false, true\)' \
  "operation-aware busy gate must preserve local-flow busy checks while delegating payload delivery admission"
expect_request_server_wiring \
  'write_payload_delivery_operation_busy\(id, writer, operation\)' \
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
  'OperationType::identify_device' \
  "identify_device admission must use its named USB operation"
expect_request_server_wiring \
  'operation_manifest_entry\(operation\)' \
  "operation-aware busy gate must consume the USB operation manifest"
expect_manifest_operation_wiring \
  'OperationType::identify_device' \
  'OperationHandlerSlot::identify_device' \
  'PayloadDeliveryOperationKind::identify_device' \
  "identify_device manifest entry must bind USB operation to payload admission kind"
expect_request_server_wiring \
  'write_connect_admission_error' \
  "connect production ops must use connect admission wrapper"
expect_request_server_wiring \
  'signing::session_active\(\)' \
  "connect admission must detect a live session before payload-delivery busy admission"
expect_request_server_wiring \
  'write_existing_session_connect_response' \
  "connect admission must recover an existing live session on the originating transport"
expect_request_server_wiring \
  'write_payload_delivery_connect_busy\(id, writer\)' \
  "connect admission wrapper must still use payload delivery admission"
expect_request_server_wiring \
  'OperationType::connect' \
  "connect admission must use its named USB operation"
expect_manifest_operation_wiring \
  'OperationType::connect' \
  'OperationHandlerSlot::connect' \
  'PayloadDeliveryOperationKind::connect' \
  "connect manifest entry must bind USB operation to payload admission kind"
expect_request_server_wiring \
  'write_payload_delivery_policy_propose_busy' \
  "policy_propose production ops must use payload delivery admission"
expect_request_server_wiring \
  'OperationType::policy_propose' \
  "policy_propose admission must use its named USB operation"
expect_manifest_operation_wiring \
  'OperationType::policy_propose' \
  'OperationHandlerSlot::policy_propose' \
  'PayloadDeliveryOperationKind::policy_propose' \
  "policy_propose manifest entry must bind USB operation to payload admission kind"
expect_request_server_wiring \
  'write_payload_delivery_credential_propose_busy' \
  "credential_propose production ops must use payload delivery admission"
expect_request_server_wiring \
  'OperationType::credential_propose' \
  "credential_propose admission must use its named USB operation"
expect_manifest_operation_wiring \
  'OperationType::credential_prepare' \
  'OperationHandlerSlot::credential_prepare' \
  'PayloadDeliveryOperationKind::safe_read' \
  "credential_prepare manifest entry must bind USB operation to safe-read payload admission"
expect_manifest_operation_wiring \
  'OperationType::credential_propose' \
  'OperationHandlerSlot::credential_propose' \
  'PayloadDeliveryOperationKind::credential_propose' \
  "credential_propose manifest entry must bind USB operation to payload admission kind"
expect_request_server_wiring \
  'write_payload_delivery_safe_read_admission_error' \
  "session read production ops must use payload delivery safe-read admission"
expect_request_server_wiring \
  'payload_delivery_admission_allows_safe_read' \
  "session read production ops must consume the payload delivery safe-read predicate"
expect_request_server_block_wiring \
  'get_status_handler_ops' \
  'write_payload_delivery_safe_read_admission_error' \
  "get_status production ops must use payload delivery safe-read admission"
expect_request_server_block_wiring \
  'approval_history_handler_ops' \
  'write_payload_delivery_safe_read_admission_error' \
  "approval history production ops must use payload delivery safe-read admission"
expect_source_wiring \
  "${USB_DEVICE_HANDLER_SOURCE}" \
  'OperationType::get_status' \
  "get_status handler must pass its own USB operation to safe-read admission"
expect_source_wiring \
  "${USB_SESSION_READ_HANDLER_SOURCE}" \
  'OperationType::get_capabilities' \
  "get_capabilities handler must pass its own USB operation to safe-read admission"
expect_source_wiring \
  "${USB_SESSION_READ_HANDLER_SOURCE}" \
  'OperationType::get_accounts' \
  "get_accounts handler must pass its own USB operation to safe-read admission"
expect_source_wiring \
  "${USB_POLICY_HANDLER_SOURCE}" \
  'OperationType::policy_get' \
  "policy_get handler must pass its own USB operation to safe-read admission"
expect_source_wiring \
  "${USB_APPROVAL_HISTORY_HANDLER_SOURCE}" \
  'OperationType::get_approval_history' \
  "get_approval_history handler must pass its own USB operation to safe-read admission"
expect_manifest_operation_wiring \
  'OperationType::get_status' \
  'OperationHandlerSlot::get_status' \
  'PayloadDeliveryOperationKind::safe_read' \
  "get_status manifest entry must bind USB operation to safe-read payload admission"
expect_manifest_operation_wiring \
  'OperationType::get_capabilities' \
  'OperationHandlerSlot::get_capabilities' \
  'PayloadDeliveryOperationKind::safe_read' \
  "get_capabilities manifest entry must bind USB operation to safe-read payload admission"
expect_manifest_operation_wiring \
  'OperationType::get_accounts' \
  'OperationHandlerSlot::get_accounts' \
  'PayloadDeliveryOperationKind::safe_read' \
  "get_accounts manifest entry must bind USB operation to safe-read payload admission"
expect_manifest_operation_wiring \
  'OperationType::policy_get' \
  'OperationHandlerSlot::policy_get' \
  'PayloadDeliveryOperationKind::safe_read' \
  "policy_get manifest entry must bind USB operation to safe-read payload admission"
expect_manifest_operation_wiring \
  'OperationType::get_approval_history' \
  'OperationHandlerSlot::get_approval_history' \
  'PayloadDeliveryOperationKind::safe_read' \
  "get_approval_history manifest entry must bind USB operation to safe-read payload admission"
expect_request_server_wiring \
  'write_payload_delivery_retained_response_admission_error' \
  "retained response production ops must use payload delivery retained-response admission"
expect_request_server_wiring \
  'payload_delivery_admission_allows_retained_response_cleanup' \
  "retained response production ops must consume the payload delivery retained-response predicate"
expect_source_wiring \
  "${USB_RETAINED_RESPONSE_HANDLER_SOURCE}" \
  'OperationType::get_result' \
  "get_result handler must pass its own USB operation to retained-response admission"
expect_source_wiring \
  "${USB_RETAINED_RESPONSE_HANDLER_SOURCE}" \
  'OperationType::ack_result' \
  "ack_result handler must pass its own USB operation to retained-response admission"
expect_manifest_operation_wiring \
  'OperationType::get_result' \
  'OperationHandlerSlot::get_result' \
  'PayloadDeliveryOperationKind::retained_response_read_cleanup' \
  "get_result manifest entry must bind USB operation to retained-response payload admission"
expect_manifest_operation_wiring \
  'OperationType::ack_result' \
  'OperationHandlerSlot::ack_result' \
  'PayloadDeliveryOperationKind::retained_response_read_cleanup' \
  "ack_result manifest entry must bind USB operation to retained-response payload admission"
expect_request_server_wiring \
  'payload_delivery_admission_allows_disconnect_cleanup' \
  "disconnect production ops must consume the payload delivery disconnect predicate"
expect_source_wiring \
  "${USB_DISCONNECT_HANDLER_SOURCE}" \
  'OperationType::disconnect' \
  "disconnect handler must pass its own USB operation to disconnect admission"
expect_request_server_wiring \
  'OperationType::sign_personal_message' \
  "sign_personal_message admission must use its named USB operation"
expect_manifest_operation_wiring \
  'OperationType::sign_personal_message' \
  'OperationHandlerSlot::sign_personal_message' \
  'PayloadDeliveryOperationKind::sign_personal_message' \
  "sign_personal_message manifest entry must bind USB operation to payload admission kind"

 if grep -Eq 'write_busy_if_pending_or_local_flow_active' \
    "${USB_CONNECT_HANDLER_HEADER}" \
    "${USB_DEVICE_HANDLER_HEADER}" \
    "${USB_POLICY_HANDLER_HEADER}" \
    "${USB_SUI_ZKLOGIN_CREDENTIAL_HANDLER_HEADER}"; then
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
grep -q 'write_policy_propose_busy' "${USB_POLICY_HANDLER_HEADER}" || {
  echo "FAILED: policy_propose handler must expose payload delivery busy callback" >&2
  exit 1
}
grep -q 'write_credential_propose_admission_error' "${USB_SUI_ZKLOGIN_CREDENTIAL_HANDLER_HEADER}" || {
  echo "FAILED: credential_propose handler must expose credential admission callback" >&2
  exit 1
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-payload-delivery-store.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/firmware_common" "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"

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

#include "transport/payload_delivery_admission.h"
#include "transport/payload_delivery_store.h"
#include "mbedtls/sha256.h"

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
        output_size != kPayloadDeliveryDigestSize) {
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

}  // namespace signing

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
    signing::PayloadDeliveryOperationKind operation,
    signing::PayloadDeliveryAdmissionResult expected,
    const char* label)
{
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   operation,
               }) == expected,
           label);
}

void expect_admission_decision(
    signing::PayloadDeliveryOperationKind operation,
    signing::PayloadDeliveryAdmissionResult expected_result,
    signing::PayloadDeliveryAdmissionReason expected_reason,
    const char* label)
{
    const signing::PayloadDeliveryAdmissionDecision decision =
        signing::payload_delivery_admit_operation(
            signing::PayloadDeliveryOperationAdmissionInput{0,
                operation,
            });
    expect(decision.result == expected_result, label);
    if (decision.reason != expected_reason) {
        fprintf(stderr, "FAILED: %s reason expected %s got %s\n",
                label,
                signing::payload_delivery_admission_reason_name(expected_reason),
                signing::payload_delivery_admission_reason_name(decision.reason));
        ++failures;
    }
}

void expect_operation_blocked(
    signing::PayloadDeliveryOperationKind operation,
    const char* operation_name,
    const char* state_name)
{
    char label[128] = {};
    snprintf(label, sizeof(label), "%s blocks %s", state_name, operation_name);
    expect_admission(
        operation,
        signing::PayloadDeliveryAdmissionResult::busy,
        label);
}

void expect_sensitive_operations_blocked(const char* state_name)
{
    expect_operation_blocked(
        signing::PayloadDeliveryOperationKind::sign_personal_message,
        "sign_personal_message",
        state_name);
    expect_operation_blocked(
        signing::PayloadDeliveryOperationKind::policy_propose,
        "policy_propose",
        state_name);
    expect_operation_blocked(
        signing::PayloadDeliveryOperationKind::credential_propose,
        "credential_propose",
        state_name);
    expect_operation_blocked(
        signing::PayloadDeliveryOperationKind::connect,
        "connect",
        state_name);
    expect_operation_blocked(
        signing::PayloadDeliveryOperationKind::identify_device,
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
    char digest[signing::kPayloadDeliveryDigestSize] = {};
    expect(signing::approval_history_digest_payload(
               value.data(),
               value.size(),
               digest,
               sizeof(digest)),
           "digest helper succeeds");
    return digest;
}

signing::PayloadDeliveryBeginInput begin_input(
    const char* session_id,
    const std::vector<uint8_t>& payload,
    size_t chunk_max = 5,
    size_t payload_max = 32,
    uint64_t deadline = 1000,
    uint64_t started_at = 0)
{
    static std::string last_digest;
    last_digest = digest_for(payload);
    return signing::PayloadDeliveryBeginInput{
        session_id,
        payload.size(),
        last_digest.c_str(),
        signing::PayloadDeliveryLimits{chunk_max, payload_max},
        signing::timeout_window_from_deadline(
            static_cast<signing::TimeoutTick>(started_at),
            static_cast<signing::TimeoutTick>(deadline)),
    };
}

void append_all(
    const char* session_id,
    const char* transfer_id,
    const std::vector<uint8_t>& payload,
    size_t chunk_size)
{
    size_t offset = 0;
    while (offset < payload.size()) {
        const size_t next_size = std::min(chunk_size, payload.size() - offset);
        size_t received = 0;
        const signing::PayloadDeliveryResult result =
            signing::payload_delivery_append_chunk(0,
                signing::PayloadDeliveryChunkInput{
                    session_id,
                    transfer_id,
                    offset,
                    payload.data() + offset,
                    next_size,
                },
                &received);
        expect(result == signing::PayloadDeliveryResult::ok, "chunk append succeeds");
        offset += next_size;
        expect(received == offset, "received bytes advances monotonically");
    }
}

void test_successful_finalize_and_resolve()
{
    signing::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(12);
    signing::PayloadDeliveryBeginOutput begin = {};
    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin succeeds");
    expect(begin.received_bytes == 0, "begin starts at zero bytes");
    expect(begin.chunk_max_bytes == 5, "begin returns chunk limit");
    append_all("session_abcdef", begin.transfer_id, payload, 5);

    signing::PayloadDeliveryFinishOutput finish = {};
    expect(signing::payload_delivery_finish(0,
               signing::PayloadDeliveryFinishInput{"session_abcdef", begin.transfer_id, signing::approval_history_digest_payload},
               &finish) == signing::PayloadDeliveryResult::ok,
           "finish succeeds");
    expect(finish.descriptor.size_bytes == payload.size(), "descriptor stores payload size");
    expect(strcmp(finish.descriptor.payload_digest, digest_for(payload).c_str()) == 0,
           "descriptor stores digest");

    signing::PayloadDeliveryView view = {};
    expect(signing::payload_delivery_resolve_finalized(0,
               "session_abcdef",
               finish.descriptor.payload_ref,
               &view) == signing::PayloadDeliveryResult::ok,
           "finalized payload resolves");
    expect(view.bytes != nullptr, "resolved view borrows bytes");
    expect(view.size_bytes == payload.size(), "resolved view size");
    expect(memcmp(view.bytes, payload.data(), payload.size()) == 0, "resolved bytes match");
}

void test_default_max_payload_round_trip()
{
    signing::payload_delivery_store_reset();
    const std::vector<uint8_t> payload =
        bytes(signing::kPayloadDeliveryDefaultMaxBytes);
    signing::PayloadDeliveryBeginOutput begin = {};
    expect(signing::payload_delivery_begin(0,
               begin_input(
                   "session_abcdef",
                   payload,
                   signing::kPayloadDeliveryDefaultChunkMaxBytes,
                   signing::kPayloadDeliveryDefaultMaxBytes),
               &begin) == signing::PayloadDeliveryResult::ok,
           "default max payload begin succeeds");
    append_all(
        "session_abcdef",
        begin.transfer_id,
        payload,
        signing::kPayloadDeliveryDefaultChunkMaxBytes);

    signing::PayloadDeliveryFinishOutput finish = {};
    expect(signing::payload_delivery_finish(0,
               signing::PayloadDeliveryFinishInput{"session_abcdef", begin.transfer_id, signing::approval_history_digest_payload},
               &finish) == signing::PayloadDeliveryResult::ok,
           "default max payload finish succeeds");
    expect(finish.descriptor.size_bytes == payload.size(),
           "default max descriptor preserves size");
    expect(strcmp(finish.descriptor.payload_digest, digest_for(payload).c_str()) == 0,
           "default max descriptor preserves digest");

    signing::PayloadDeliveryView view = {};
    expect(signing::payload_delivery_resolve_finalized(0,
               "session_abcdef",
               finish.descriptor.payload_ref,
               &view) == signing::PayloadDeliveryResult::ok,
           "default max finalized payload resolves");
    expect(view.bytes != nullptr && view.size_bytes == payload.size(),
           "default max resolved payload size is preserved");
    expect(memcmp(view.bytes, payload.data(), payload.size()) == 0,
           "default max resolved payload bytes are preserved");
}

void test_take_finalized_transfers_ownership_and_clears_store()
{
    signing::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(16);
    signing::PayloadDeliveryBeginOutput begin = {};
    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin before take succeeds");
    append_all("session_abcdef", begin.transfer_id, payload, 5);

    signing::PayloadDeliveryFinishOutput finish = {};
    expect(signing::payload_delivery_finish(0,
               signing::PayloadDeliveryFinishInput{"session_abcdef", begin.transfer_id, signing::approval_history_digest_payload},
               &finish) == signing::PayloadDeliveryResult::ok,
           "finish before take succeeds");

    signing::PayloadDeliveryOwnedPayload owned = {};
    expect(signing::payload_delivery_take_finalized(0,
               "session_abcdef",
               finish.descriptor.payload_ref,
               &owned) == signing::PayloadDeliveryResult::ok,
           "take finalized succeeds");
    expect(owned.bytes != nullptr, "take returns owned bytes");
    expect(owned.size_bytes == payload.size(), "take returns owned byte size");
    expect(memcmp(owned.bytes, payload.data(), payload.size()) == 0,
           "taken bytes match finalized payload");
    expect(strcmp(owned.descriptor.payload_ref, finish.descriptor.payload_ref) == 0,
           "take preserves descriptor payloadRef");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "take clears store to idle");

    signing::PayloadDeliveryView view = {};
    expect(signing::payload_delivery_resolve_finalized(0,
               "session_abcdef",
               finish.descriptor.payload_ref,
               &view) == signing::PayloadDeliveryResult::not_found,
           "taken payload is no longer live in the store");
    signing::wipe_sensitive_buffer(owned.bytes, owned.size_bytes);
    free(owned.bytes);
}

void test_admission_matrix()
{
    signing::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(12);

    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::payload_transfer_begin,
               }) == signing::PayloadDeliveryAdmissionResult::ok,
           "idle allows transfer begin");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::sign_transaction,
               }) == signing::PayloadDeliveryAdmissionResult::ok,
           "idle allows inline sign transaction");
    expect_admission_decision(
        signing::PayloadDeliveryOperationKind::sign_transaction,
        signing::PayloadDeliveryAdmissionResult::ok,
        signing::PayloadDeliveryAdmissionReason::idle_passthrough,
        "idle inline sign transaction is passthrough");
    expect_admission_decision(
        signing::PayloadDeliveryOperationKind::payload_transfer_chunk,
        signing::PayloadDeliveryAdmissionResult::unknown_request,
        signing::PayloadDeliveryAdmissionReason::missing_active_payload,
        "idle rejects transfer chunk before store lookup");
    expect_admission_decision(
        signing::PayloadDeliveryOperationKind::payload_transfer_finish,
        signing::PayloadDeliveryAdmissionResult::unknown_request,
        signing::PayloadDeliveryAdmissionReason::missing_active_payload,
        "idle rejects transfer finish before store lookup");
    expect_admission_decision(
        signing::PayloadDeliveryOperationKind::payload_transfer_abort,
        signing::PayloadDeliveryAdmissionResult::unknown_request,
        signing::PayloadDeliveryAdmissionReason::missing_active_payload,
        "idle rejects transfer abort before store lookup");

    signing::PayloadDeliveryBeginOutput begin = {};
    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for admission test succeeds");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::safe_read,
               }) == signing::PayloadDeliveryAdmissionResult::ok,
           "receiving allows safe reads");
    expect_admission_decision(
        signing::PayloadDeliveryOperationKind::safe_read,
        signing::PayloadDeliveryAdmissionResult::ok,
        signing::PayloadDeliveryAdmissionReason::receiving_safe_read,
        "receiving safe read has explicit exception reason");
    expect(signing::payload_delivery_admission_allows_safe_read(
               signing::payload_delivery_admit_operation(
                   signing::PayloadDeliveryOperationAdmissionInput{0,
                       signing::PayloadDeliveryOperationKind::safe_read,
                   })),
           "receiving safe read is exposed through contract predicate");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::retained_response_read_cleanup,
               }) == signing::PayloadDeliveryAdmissionResult::ok,
           "receiving allows retained response read/cleanup");
    expect(signing::payload_delivery_admission_allows_retained_response_cleanup(
               signing::payload_delivery_admit_operation(
                   signing::PayloadDeliveryOperationAdmissionInput{0,
                       signing::PayloadDeliveryOperationKind::retained_response_read_cleanup,
                   })),
           "receiving retained-response cleanup is exposed through contract predicate");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::disconnect,
               }) == signing::PayloadDeliveryAdmissionResult::ok,
           "receiving allows disconnect cleanup");
    expect(signing::payload_delivery_admission_allows_disconnect_cleanup(
               signing::payload_delivery_admit_operation(
                   signing::PayloadDeliveryOperationAdmissionInput{0,
                       signing::PayloadDeliveryOperationKind::disconnect,
                   })),
           "receiving disconnect cleanup is exposed through contract predicate");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::payload_transfer_begin,
               }) == signing::PayloadDeliveryAdmissionResult::busy,
           "receiving blocks nested transfer begin");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::payload_transfer_chunk,
               }) == signing::PayloadDeliveryAdmissionResult::ok,
           "receiving allows transfer chunk");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::payload_transfer_finish,
               }) == signing::PayloadDeliveryAdmissionResult::ok,
           "receiving allows transfer finish");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::payload_transfer_abort,
               }) == signing::PayloadDeliveryAdmissionResult::ok,
           "receiving allows transfer abort");
    expect_sensitive_operations_blocked("receiving");
    expect_admission_decision(
        signing::PayloadDeliveryOperationKind::sign_transaction,
        signing::PayloadDeliveryAdmissionResult::busy,
        signing::PayloadDeliveryAdmissionReason::blocked_incomplete_transfer,
        "receiving blocks signing because transfer is incomplete");
    expect(signing::payload_delivery_admission_blocks_sensitive_flow(
               signing::payload_delivery_admit_operation(
                   signing::PayloadDeliveryOperationAdmissionInput{0,
                       signing::PayloadDeliveryOperationKind::sign_transaction,
                   })),
           "receiving signing block is exposed through sensitive-flow predicate");

    append_all("session_abcdef", begin.transfer_id, payload, 5);
    signing::PayloadDeliveryFinishOutput finish = {};
    expect(signing::payload_delivery_finish(0,
               signing::PayloadDeliveryFinishInput{"session_abcdef", begin.transfer_id, signing::approval_history_digest_payload},
               &finish) == signing::PayloadDeliveryResult::ok,
           "finish for admission test succeeds");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::safe_read,
               }) == signing::PayloadDeliveryAdmissionResult::ok,
           "finalized allows safe reads");
    expect_admission_decision(
        signing::PayloadDeliveryOperationKind::sign_transaction,
        signing::PayloadDeliveryAdmissionResult::busy,
        signing::PayloadDeliveryAdmissionReason::blocked_unrelated_sensitive_flow,
        "finalized blocks direct signing while payload is pending");
    expect(signing::payload_delivery_admission_blocks_sensitive_flow(
               signing::payload_delivery_admit_operation(
                   signing::PayloadDeliveryOperationAdmissionInput{0,
                       signing::PayloadDeliveryOperationKind::sign_transaction,
                   })),
           "finalized inline signing block is exposed through sensitive-flow predicate");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::retained_response_read_cleanup,
               }) == signing::PayloadDeliveryAdmissionResult::ok,
           "finalized allows retained response read/cleanup");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::disconnect,
               }) == signing::PayloadDeliveryAdmissionResult::ok,
           "finalized allows disconnect cleanup");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::payload_transfer_begin,
               }) == signing::PayloadDeliveryAdmissionResult::busy,
           "finalized blocks nested transfer begin");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::payload_transfer_chunk,
               }) == signing::PayloadDeliveryAdmissionResult::busy,
           "finalized blocks transfer chunk");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::payload_transfer_finish,
               }) == signing::PayloadDeliveryAdmissionResult::busy,
           "finalized blocks transfer finish");
    expect(signing::payload_delivery_admit_operation(
               signing::PayloadDeliveryOperationAdmissionInput{0,
                   signing::PayloadDeliveryOperationKind::payload_transfer_abort,
               }) == signing::PayloadDeliveryAdmissionResult::ok,
           "finalized allows transfer abort");
    expect_sensitive_operations_blocked("finalized");
}

void test_guards_and_cleanup()
{
    signing::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(8);
    const uint8_t first_chunk[2] = {1, 2};

    expect(signing::payload_delivery_append_chunk(0,
               signing::PayloadDeliveryChunkInput{
                   "session_abcdef",
                   "transfer_0000000000000001",
                   0,
                   first_chunk,
                   sizeof(first_chunk),
               },
               nullptr) == signing::PayloadDeliveryResult::not_found,
           "chunk without active transfer is not found");
    signing::PayloadDeliveryFinishOutput idle_finish = {};
    expect(signing::payload_delivery_finish(0,
               signing::PayloadDeliveryFinishInput{
                   "session_abcdef",
                   "transfer_0000000000000001",
                   signing::approval_history_digest_payload,
               },
               &idle_finish) == signing::PayloadDeliveryResult::not_found,
           "finish without active transfer is not found");

    signing::PayloadDeliveryBeginOutput begin = {};
    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8, 50), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for guard tests succeeds");

    const uint8_t too_large[5] = {1, 2, 3, 4, 5};
    expect(signing::payload_delivery_append_chunk(0,
               signing::PayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.transfer_id,
                   0,
                   too_large,
                   sizeof(too_large),
               },
               nullptr) == signing::PayloadDeliveryResult::chunk_too_large,
           "chunk max+1 rejected");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "chunk too large wipes owned active transfer");

    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8, 50), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for reported chunk oversize succeeds");
    expect(signing::payload_delivery_reject_chunk_too_large(0,
               "session_abcdef",
               begin.transfer_id) == signing::PayloadDeliveryResult::chunk_too_large,
           "reported chunk oversize rejected by store owner");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "reported chunk oversize wipes owned active transfer");

    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8, 50), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for offset mismatch succeeds");

    expect(signing::payload_delivery_append_chunk(0,
               signing::PayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.transfer_id,
                   1,
                   payload.data(),
                   2,
               },
               nullptr) == signing::PayloadDeliveryResult::offset_mismatch,
           "offset mismatch rejected");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "offset mismatch wipes owned active transfer");

    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8, 50), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for different session mismatch succeeds");

    expect(signing::payload_delivery_append_chunk(0,
               signing::PayloadDeliveryChunkInput{
                   "session_other",
                   begin.transfer_id,
                   0,
                   payload.data(),
                   2,
               },
               nullptr) == signing::PayloadDeliveryResult::invalid_session,
           "different session cannot append");
    expect(signing::payload_delivery_advance_and_snapshot(0).state ==
               signing::PayloadDeliveryState::receiving,
           "different session failure does not wipe active transfer");
    expect(signing::payload_delivery_reject_chunk_too_large(0,
               "session_other",
               begin.transfer_id) == signing::PayloadDeliveryResult::invalid_session,
           "different session reported oversize cannot clear active transfer");
    expect(signing::payload_delivery_advance_and_snapshot(0).state ==
               signing::PayloadDeliveryState::receiving,
           "different session reported oversize preserves active transfer");

    expect(signing::payload_delivery_append_chunk(0,
               signing::PayloadDeliveryChunkInput{
                   "session_abcdef",
                   "bad-transfer",
                   0,
                   payload.data(),
                   2,
               },
               nullptr) == signing::PayloadDeliveryResult::invalid_transfer_id,
           "malformed transfer id is separated from session mismatch");

    signing::payload_delivery_store_reset();
    signing::PayloadDeliveryBeginInput inactive_deadline =
        begin_input("session_abcdef", payload, 4, 8, 0, 0);
    expect(signing::payload_delivery_begin(0, inactive_deadline, &begin) ==
               signing::PayloadDeliveryResult::invalid_argument,
           "begin rejects inactive timeout window");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "inactive timeout rejection leaves store idle");

    signing::PayloadDeliveryBeginInput zero_wrapped_deadline =
        begin_input("session_abcdef", payload, 4, 8, 0, UINT32_MAX - 5);
    expect(signing::payload_delivery_begin(0, zero_wrapped_deadline, &begin) ==
               signing::PayloadDeliveryResult::invalid_argument,
           "begin rejects deadline that wraps to inactive zero");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "zero-wrapped timeout rejection leaves store idle");

    expect(signing::payload_delivery_begin(50,
               begin_input("session_abcdef", payload, 4, 8, 50),
               &begin) == signing::PayloadDeliveryResult::invalid_argument,
           "begin rejects timeout window closed at operation tick");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "closed timeout begin rejection leaves store idle");

    expect(signing::payload_delivery_begin(49,
               begin_input("session_abcdef", payload, 4, 8, 50),
               &begin) == signing::PayloadDeliveryResult::ok,
           "begin accepts timeout window open at operation tick");
    expect(signing::payload_delivery_advance_and_snapshot(49).state ==
               signing::PayloadDeliveryState::receiving,
           "open timeout begin enters receiving");
    signing::payload_delivery_store_reset();

    expect(signing::payload_delivery_begin(5,
               begin_input("session_abcdef", payload, 4, 8, 5, UINT32_MAX - 10),
               &begin) == signing::PayloadDeliveryResult::invalid_argument,
           "begin rejects wrapped timeout window closed at operation tick");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "closed wrapped timeout begin rejection leaves store idle");

    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8, 50), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for deadline cleanup succeeds");
    expect(!signing::payload_delivery_clear_expired(49), "deadline before expiry keeps transfer");
    expect(signing::payload_delivery_clear_expired(50), "deadline expiry clears transfer");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "expired transfer returns to idle");

    signing::PayloadDeliveryBeginOutput wrap_begin = {};
    expect(signing::payload_delivery_begin(0,
               begin_input("session_abcdef", payload, 4, 8, 5, UINT32_MAX - 10),
               &wrap_begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for wrapped deadline succeeds");
    expect(!signing::payload_delivery_clear_expired(UINT32_MAX - 2),
           "wrapped deadline keeps transfer before deadline");
    expect(signing::payload_delivery_clear_expired(5),
           "wrapped deadline clears transfer at deadline");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "wrapped expired transfer returns to idle");
}

void test_timeout_operation_boundaries()
{
    signing::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(6);
    signing::PayloadDeliveryBeginOutput begin = {};

    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8, 50), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for expired append boundary succeeds");
    size_t received = 0;
    expect(signing::payload_delivery_append_chunk(
               50,
               signing::PayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.transfer_id,
                   0,
                   payload.data(),
                   payload.size(),
               },
               &received) == signing::PayloadDeliveryResult::not_found,
           "expired append clears store before accepting chunk");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "expired append boundary leaves store idle");

    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 8, 8, 50), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for expired finish boundary succeeds");
    append_all("session_abcdef", begin.transfer_id, payload, 8);
    signing::PayloadDeliveryFinishOutput finish = {};
    expect(signing::payload_delivery_finish(
               50,
               signing::PayloadDeliveryFinishInput{"session_abcdef", begin.transfer_id, signing::approval_history_digest_payload},
               &finish) == signing::PayloadDeliveryResult::not_found,
           "expired finish clears store before finalizing");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "expired finish boundary leaves store idle");

    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 8, 8, 50), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for expired finalized boundary succeeds");
    append_all("session_abcdef", begin.transfer_id, payload, 8);
    expect(signing::payload_delivery_finish(
               0,
               signing::PayloadDeliveryFinishInput{"session_abcdef", begin.transfer_id, signing::approval_history_digest_payload},
               &finish) == signing::PayloadDeliveryResult::ok,
           "finish before deadline succeeds");
    const std::string payload_ref = finish.descriptor.payload_ref;
    signing::PayloadDeliveryView view = {};
    expect(signing::payload_delivery_resolve_finalized(
               50,
               "session_abcdef",
               payload_ref.c_str(),
               &view) == signing::PayloadDeliveryResult::not_found,
           "expired resolve clears finalized payload before borrowing bytes");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "expired resolve boundary leaves store idle");

    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 8, 8, 50), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for expired take boundary succeeds");
    append_all("session_abcdef", begin.transfer_id, payload, 8);
    expect(signing::payload_delivery_finish(
               0,
               signing::PayloadDeliveryFinishInput{"session_abcdef", begin.transfer_id, signing::approval_history_digest_payload},
               &finish) == signing::PayloadDeliveryResult::ok,
           "finish before expired take succeeds");
    const std::string take_payload_ref = finish.descriptor.payload_ref;
    signing::PayloadDeliveryOwnedPayload owned = {};
    expect(signing::payload_delivery_take_finalized(
               50,
               "session_abcdef",
               take_payload_ref.c_str(),
               &owned) == signing::PayloadDeliveryResult::not_found,
           "expired take clears finalized payload before ownership transfer");
    expect(owned.bytes == nullptr, "expired take does not return owned bytes");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "expired take boundary leaves store idle");

    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 8, 8, 50), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for expired admission boundary succeeds");
    append_all("session_abcdef", begin.transfer_id, payload, 8);
    expect(signing::payload_delivery_finish(
               0,
               signing::PayloadDeliveryFinishInput{"session_abcdef", begin.transfer_id, signing::approval_history_digest_payload},
               &finish) == signing::PayloadDeliveryResult::ok,
           "finish before expired admission succeeds");
    const signing::PayloadDeliveryAdmissionDecision expired_admission =
        signing::payload_delivery_admit_operation(
            signing::PayloadDeliveryOperationAdmissionInput{
                50,
                signing::PayloadDeliveryOperationKind::sign_transaction,
            });
    expect(expired_admission.result == signing::PayloadDeliveryAdmissionResult::ok,
           "expired finalized payload is cleared before sign transaction admission");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "expired admission boundary leaves store idle");
}

void test_oversize_and_digest_mismatch()
{
    signing::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(9);
    signing::PayloadDeliveryBeginOutput begin = {};
    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8), &begin) ==
               signing::PayloadDeliveryResult::payload_too_large,
           "payload max+1 rejected at begin");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "begin max+1 leaves store idle");

    const std::vector<uint8_t> valid = bytes(4);
    std::string wrong_digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    signing::PayloadDeliveryBeginInput input =
        begin_input("session_abcdef", valid, 4, 8);
    input.payload_digest = wrong_digest.c_str();
    expect(signing::payload_delivery_begin(0, input, &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin with well-formed wrong digest succeeds");
    append_all("session_abcdef", begin.transfer_id, valid, 4);
    signing::PayloadDeliveryFinishOutput finish = {};
    expect(signing::payload_delivery_finish(0,
               signing::PayloadDeliveryFinishInput{"session_abcdef", begin.transfer_id, signing::approval_history_digest_payload},
               &finish) == signing::PayloadDeliveryResult::digest_mismatch,
           "digest mismatch rejected at finish");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "digest mismatch wipes transfer");
}

void test_size_mismatch_and_payload_overflow()
{
    signing::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(8);
    signing::PayloadDeliveryBeginOutput begin = {};
    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 4, 8), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for size mismatch succeeds");

    size_t received = 0;
    expect(signing::payload_delivery_append_chunk(0,
               signing::PayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.transfer_id,
                   0,
                   payload.data(),
                   4,
               },
               &received) == signing::PayloadDeliveryResult::ok,
           "partial chunk append succeeds");
    expect(received == 4, "partial append reports received bytes");

    signing::PayloadDeliveryFinishOutput finish = {};
    expect(signing::payload_delivery_finish(0,
               signing::PayloadDeliveryFinishInput{"session_abcdef", begin.transfer_id, signing::approval_history_digest_payload},
               &finish) == signing::PayloadDeliveryResult::size_mismatch,
           "early finish returns size mismatch");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "size mismatch wipes owned active transfer");
    expect(signing::payload_delivery_append_chunk(0,
               signing::PayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.transfer_id,
                   4,
                   payload.data() + 4,
                   4,
               },
               &received) == signing::PayloadDeliveryResult::not_found,
           "stale transfer cannot continue after size mismatch");

    signing::payload_delivery_store_reset();
    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload, 6, 8), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin for payload overflow succeeds");
    expect(signing::payload_delivery_append_chunk(0,
               signing::PayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.transfer_id,
                   0,
                   payload.data(),
                   6,
               },
               &received) == signing::PayloadDeliveryResult::ok,
           "first overflow setup chunk succeeds");
    const uint8_t overflow_chunk[3] = {1, 2, 3};
    expect(signing::payload_delivery_append_chunk(0,
               signing::PayloadDeliveryChunkInput{
                   "session_abcdef",
                   begin.transfer_id,
                   6,
                   overflow_chunk,
                   sizeof(overflow_chunk),
               },
               nullptr) == signing::PayloadDeliveryResult::payload_overflow,
           "declared-size overflow is rejected");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "declared-size overflow wipes transfer");
}

void test_abort_active_and_finalized()
{
    signing::payload_delivery_store_reset();
    const std::vector<uint8_t> payload = bytes(6);
    signing::PayloadDeliveryBeginOutput begin = {};
    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin active abort succeeds");
    expect(signing::payload_delivery_abort(0,
               signing::PayloadDeliveryAbortInput{
                   "session_abcdef",
                   begin.transfer_id,
                   nullptr,
               }) == signing::PayloadDeliveryResult::ok,
           "active transfer abort succeeds");
    expect(signing::payload_delivery_advance_and_snapshot(0).state == signing::PayloadDeliveryState::idle,
           "active abort clears store");

    expect(signing::payload_delivery_begin(0, begin_input("session_abcdef", payload), &begin) ==
               signing::PayloadDeliveryResult::ok,
           "begin finalized abort succeeds");
    append_all("session_abcdef", begin.transfer_id, payload, 5);
    signing::PayloadDeliveryFinishOutput finish = {};
    expect(signing::payload_delivery_finish(0,
               signing::PayloadDeliveryFinishInput{"session_abcdef", begin.transfer_id, signing::approval_history_digest_payload},
               &finish) == signing::PayloadDeliveryResult::ok,
           "finish for abort succeeds");
    expect(signing::payload_delivery_abort(0,
               signing::PayloadDeliveryAbortInput{
                   "session_other",
                   nullptr,
                   finish.descriptor.payload_ref,
               }) == signing::PayloadDeliveryResult::invalid_session,
           "different session cannot abort finalized payload");
    expect(signing::payload_delivery_advance_and_snapshot(0).state ==
               signing::PayloadDeliveryState::finalized,
           "different session finalized abort does not wipe");
    signing::PayloadDeliveryView view = {};
    expect(signing::payload_delivery_resolve_finalized(0,
               "session_abcdef",
               "bad-payload",
               &view) == signing::PayloadDeliveryResult::invalid_payload_ref,
           "malformed payload ref is separated from session mismatch");
    expect(signing::payload_delivery_abort(0,
               signing::PayloadDeliveryAbortInput{
                   "session_abcdef",
                   nullptr,
                   finish.descriptor.payload_ref,
               }) == signing::PayloadDeliveryResult::ok,
           "same session finalized abort succeeds");
}

void test_descriptor_and_view_are_small()
{
    static_assert(sizeof(signing::PayloadDeliveryDescriptor) < 512,
                  "payload descriptor must not carry payload bytes");
    static_assert(sizeof(signing::PayloadDeliveryView) < 576,
                  "payload view must not copy payload bytes");
    static_assert(sizeof(signing::PayloadDeliverySnapshot) < 320,
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
    signing::payload_delivery_store_reset();

    if (failures != 0) {
        fprintf(stderr, "%d payload delivery store test(s) failed\n", failures);
        return 1;
    }
    printf("payload delivery store tests passed\n");
    return 0;
}
CPP

c++ -std=c++17 -Wall -Wextra -Werror \
  -I"${TARGET_ROOT}/runtime" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${COMMON_ROOT}/transport/payload_delivery_primitives.cpp" \
  -o "${TMP_DIR}/payload_delivery_primitives.o"

c++ -std=c++17 -Wall -Wextra -Werror \
  -I"${TARGET_ROOT}/runtime" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${COMMON_ROOT}/transport/payload_delivery_store.cpp" \
  -o "${TMP_DIR}/payload_delivery_store.o"

c++ -std=c++17 -Wall -Wextra -Werror \
  -I"${TARGET_ROOT}/runtime" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${COMMON_ROOT}/transport/payload_delivery_admission.cpp" \
  -o "${TMP_DIR}/payload_delivery_admission.o"

c++ -std=c++17 -Wall -Wextra -Werror \
  -I"${TARGET_ROOT}/runtime" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${COMMON_ROOT}/protocol/session_state.cpp" \
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
  -I"${TARGET_ROOT}/runtime" \
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
