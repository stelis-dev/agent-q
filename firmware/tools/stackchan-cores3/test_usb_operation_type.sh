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
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"

for required in \
  "${AGENT_Q_DIR}/agent_q_usb_operation_type.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-operation-type.XXXXXX")"
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

#include "agent_q_usb_operation_manifest.h"
#include "agent_q_usb_operation_type.h"

namespace {

void expect_type(const char* value, agent_q::AgentQUsbOperationType expected)
{
    assert(agent_q::classify_usb_operation_type(value) == expected);
    if (expected != agent_q::AgentQUsbOperationType::unsupported) {
        assert(strcmp(agent_q::usb_operation_type_wire_name(expected), value) == 0);
    }
}

void expect_payload_kind(
    agent_q::AgentQUsbOperationType type,
    agent_q::AgentQPayloadDeliveryOperationKind expected)
{
    const agent_q::AgentQUsbOperationManifestEntry* entry =
        agent_q::usb_operation_manifest_entry(type);
    assert(entry != nullptr);
    assert(entry->payload_delivery_operation == expected);
}

void expect_terminal_policy(
    agent_q::AgentQUsbOperationType type,
    agent_q::AgentQUsbOperationTerminalResultPolicy expected)
{
    const agent_q::AgentQUsbOperationManifestEntry* entry =
        agent_q::usb_operation_manifest_entry(type);
    assert(entry != nullptr);
    assert(entry->terminal_result_policy == expected);
}

}  // namespace

int main()
{
    using Type = agent_q::AgentQUsbOperationType;

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
    assert(agent_q::usb_operation_type_wire_name(Type::unsupported) == nullptr);

    expect_payload_kind(Type::get_status, agent_q::AgentQPayloadDeliveryOperationKind::safe_read);
    expect_payload_kind(Type::get_capabilities, agent_q::AgentQPayloadDeliveryOperationKind::safe_read);
    expect_payload_kind(Type::get_result, agent_q::AgentQPayloadDeliveryOperationKind::retained_result_read_cleanup);
    expect_payload_kind(Type::ack_result, agent_q::AgentQPayloadDeliveryOperationKind::retained_result_read_cleanup);
    expect_payload_kind(Type::connect, agent_q::AgentQPayloadDeliveryOperationKind::connect);
    expect_payload_kind(Type::policy_propose, agent_q::AgentQPayloadDeliveryOperationKind::policy_propose);
    expect_payload_kind(Type::credential_prepare, agent_q::AgentQPayloadDeliveryOperationKind::safe_read);
    expect_payload_kind(Type::credential_propose, agent_q::AgentQPayloadDeliveryOperationKind::credential_propose);

    expect_terminal_policy(
        Type::get_result,
        agent_q::AgentQUsbOperationTerminalResultPolicy::signing_retained_result_read);
    expect_terminal_policy(
        Type::ack_result,
        agent_q::AgentQUsbOperationTerminalResultPolicy::signing_retained_result_ack);
    expect_terminal_policy(
        Type::policy_propose,
        agent_q::AgentQUsbOperationTerminalResultPolicy::policy_update_result_history_marker);
    expect_terminal_policy(
        Type::credential_prepare,
        agent_q::AgentQUsbOperationTerminalResultPolicy::immediate_response);
    expect_terminal_policy(
        Type::credential_propose,
        agent_q::AgentQUsbOperationTerminalResultPolicy::credential_propose_result);
    expect_terminal_policy(
        Type::sign_transaction,
        agent_q::AgentQUsbOperationTerminalResultPolicy::signing_retained_result);

    const agent_q::AgentQUsbOperationManifestEntry* status_entry =
        agent_q::usb_operation_manifest_entry(Type::get_status);
    assert(status_entry != nullptr);
    assert(status_entry->read_side_effect_policy ==
           agent_q::AgentQUsbOperationReadSideEffectPolicy::persistent_material_consistency_refresh);

    assert(agent_q::usb_operation_is_retained_result_read_cleanup(Type::get_result));
    assert(agent_q::usb_operation_is_retained_result_read_cleanup(Type::ack_result));
    assert(!agent_q::usb_operation_is_retained_result_read_cleanup(Type::policy_propose));
    assert(!agent_q::usb_operation_is_retained_result_read_cleanup(Type::credential_propose));

    printf("USB operation type tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
