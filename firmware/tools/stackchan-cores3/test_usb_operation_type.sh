#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_operation_type.sh

Compiles the USB operation type classifier and verifies the current public
request type strings map to the expected operation enum. It does not require
hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"

for required in \
  "${RUNTIME_DIR}/usb_operation_type.h" \
  "${RUNTIME_DIR}/usb_operation_manifest.h" \
  "${RUNTIME_DIR}/usb_operation_manifest.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-operation-type.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "usb_operation_manifest.h"
#include "usb_operation_type.h"

namespace {

void expect_type(const char* value, signing::UsbOperationType expected)
{
    assert(signing::classify_usb_operation_type(value) == expected);
    if (expected != signing::UsbOperationType::unsupported) {
        assert(strcmp(signing::usb_operation_type_wire_name(expected), value) == 0);
    }
}

void expect_payload_kind(
    signing::UsbOperationType type,
    signing::PayloadDeliveryOperationKind expected)
{
    const signing::UsbOperationManifestEntry* entry =
        signing::usb_operation_manifest_entry(type);
    assert(entry != nullptr);
    assert(entry->payload_delivery_operation == expected);
}

void expect_terminal_policy(
    signing::UsbOperationType type,
    signing::UsbOperationCompletionPolicy expected)
{
    const signing::UsbOperationManifestEntry* entry =
        signing::usb_operation_manifest_entry(type);
    assert(entry != nullptr);
    assert(entry->completion_policy == expected);
}

}  // namespace

int main()
{
    using Type = signing::UsbOperationType;

    expect_type("get_status", Type::get_status);
    expect_type("identify_device", Type::identify_device);
    expect_type("connect", Type::connect);
    expect_type("sign_transaction", Type::sign_transaction);
    expect_type("sign_personal_message", Type::sign_personal_message);
    expect_type("get_result", Type::get_result);
    expect_type("ack_result", Type::ack_result);
    expect_type("disconnect", Type::disconnect);
    expect_type("get_capabilities", Type::get_capabilities);
    expect_type("get_accounts", Type::get_accounts);
    expect_type("policy_get", Type::policy_get);
    expect_type("get_approval_history", Type::get_approval_history);
    expect_type("policy_propose", Type::policy_propose);
    expect_type("credential_prepare", Type::credential_prepare);
    expect_type("credential_propose", Type::credential_propose);
    expect_type("payload_transfer_begin", Type::payload_transfer_begin);
    expect_type("payload_transfer_chunk", Type::payload_transfer_chunk);
    expect_type("payload_transfer_finish", Type::payload_transfer_finish);
    expect_type("payload_transfer_abort", Type::payload_transfer_abort);
    expect_type("", Type::unsupported);
    expect_type("sign_transaction_user", Type::unsupported);
    expect_type("sign_transaction_policy", Type::unsupported);
    expect_type("unknown", Type::unsupported);
    expect_type(nullptr, Type::unsupported);
    assert(signing::usb_operation_type_wire_name(Type::unsupported) == nullptr);

    expect_payload_kind(Type::get_status, signing::PayloadDeliveryOperationKind::safe_read);
    expect_payload_kind(Type::get_capabilities, signing::PayloadDeliveryOperationKind::safe_read);
    expect_payload_kind(Type::get_result, signing::PayloadDeliveryOperationKind::retained_response_read_cleanup);
    expect_payload_kind(Type::ack_result, signing::PayloadDeliveryOperationKind::retained_response_read_cleanup);
    expect_payload_kind(Type::connect, signing::PayloadDeliveryOperationKind::connect);
    expect_payload_kind(Type::policy_propose, signing::PayloadDeliveryOperationKind::policy_propose);
    expect_payload_kind(Type::credential_prepare, signing::PayloadDeliveryOperationKind::safe_read);
    expect_payload_kind(Type::credential_propose, signing::PayloadDeliveryOperationKind::credential_propose);

    expect_terminal_policy(
        Type::get_result,
        signing::UsbOperationCompletionPolicy::signing_retained_response_read);
    expect_terminal_policy(
        Type::ack_result,
        signing::UsbOperationCompletionPolicy::signing_retained_response_ack);
    expect_terminal_policy(
        Type::policy_propose,
        signing::UsbOperationCompletionPolicy::policy_update_history_marker);
    expect_terminal_policy(
        Type::credential_prepare,
        signing::UsbOperationCompletionPolicy::immediate_response);
    expect_terminal_policy(
        Type::credential_propose,
        signing::UsbOperationCompletionPolicy::credential_proposal_outcome);
    expect_terminal_policy(
        Type::sign_transaction,
        signing::UsbOperationCompletionPolicy::signing_retained_response);

    const signing::UsbOperationManifestEntry* status_entry =
        signing::usb_operation_manifest_entry(Type::get_status);
    assert(status_entry != nullptr);
    assert(status_entry->read_side_effect_policy ==
           signing::UsbOperationReadSideEffectPolicy::persistent_material_consistency_refresh);

    assert(signing::usb_operation_is_retained_response_read_cleanup(Type::get_result));
    assert(signing::usb_operation_is_retained_response_read_cleanup(Type::ack_result));
    assert(!signing::usb_operation_is_retained_response_read_cleanup(Type::policy_propose));
    assert(!signing::usb_operation_is_retained_response_read_cleanup(Type::credential_propose));

    printf("USB operation type tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/usb_operation_manifest.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
