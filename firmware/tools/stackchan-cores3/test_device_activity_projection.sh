#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_device_activity_projection.sh

Compiles the StackChan CoreS3 device-activity projection module against host
headers and verifies active-flow state projection and operation-specific gates.
This test uses only a host C++ compiler and does NOT require ESP-IDF.
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
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"
CXX_BIN="${CXX:-c++}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${AGENT_Q_DIR}/agent_q_device_activity_projection.cpp" \
  "${AGENT_Q_DIR}/agent_q_device_activity_projection.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.h" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_type.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-device-activity.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/device_activity_projection_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_device_activity_projection.h"
#include "agent_q_usb_operation_type.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

agent_q::AgentQPolicyUpdateFlowSnapshot policy_update(
    bool active,
    agent_q::AgentQPolicyUpdateFlowStage stage)
{
    agent_q::AgentQPolicyUpdateFlowSnapshot snapshot{};
    snapshot.active = active;
    snapshot.stage = stage;
    return snapshot;
}

agent_q::AgentQSuiZkLoginProposalSnapshot sui_zklogin_proposal(
    bool active,
    agent_q::AgentQSuiZkLoginProposalStage stage)
{
    agent_q::AgentQSuiZkLoginProposalSnapshot snapshot{};
    snapshot.active = active;
    snapshot.stage = stage;
    return snapshot;
}

agent_q::AgentQLocalResetSnapshot local_reset(
    bool active,
    agent_q::AgentQLocalResetStage stage)
{
    agent_q::AgentQLocalResetSnapshot snapshot{};
    snapshot.flow_active = active;
    snapshot.stage = stage;
    return snapshot;
}

agent_q::AgentQUserSigningFlowCoreSnapshot user_signing(
    bool active,
    agent_q::AgentQUserSigningStage stage)
{
    agent_q::AgentQUserSigningFlowCoreSnapshot snapshot{};
    snapshot.active = active;
    snapshot.stage = stage;
    return snapshot;
}

agent_q::AgentQDeviceActivityFacts idle_facts()
{
    return {
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        policy_update(false, agent_q::AgentQPolicyUpdateFlowStage::idle),
        sui_zklogin_proposal(false, agent_q::AgentQSuiZkLoginProposalStage::idle),
        local_reset(false, agent_q::AgentQLocalResetStage::none),
        user_signing(false, agent_q::AgentQUserSigningStage::none),
    };
}

agent_q::AgentQDeviceActivityProjection project(
    const agent_q::AgentQDeviceActivityFacts& facts)
{
    return agent_q::project_device_activity(facts);
}

void expect_usb_block(
    const agent_q::AgentQDeviceActivityProjection& activity,
    bool allow_settings_menu,
    bool allow_payload_delivery,
    bool blocked,
    const char* message)
{
    const agent_q::AgentQDeviceActivityUsbRequestBlock block =
        agent_q::device_activity_usb_request_block(
            activity,
            { allow_settings_menu, allow_payload_delivery });
    expect(block.blocked == blocked, "USB block flag matches expectation");
    if (message != nullptr) {
        expect(block.message != nullptr, "USB block has a message");
        expect(block.message != nullptr && strcmp(block.message, message) == 0,
               "USB block message matches expectation");
    }
}

}  // namespace

int main()
{
    agent_q::AgentQDeviceActivityFacts facts = idle_facts();
    agent_q::AgentQDeviceActivityProjection activity = project(facts);
    expect(activity.device_state == agent_q::AgentQProjectedDeviceState::idle,
           "idle facts project to idle");
    expect(agent_q::device_activity_allows_local_settings_touch_entry(activity),
           "idle provisioned activity allows touch settings entry");
    expect(!agent_q::device_activity_blocks_user_signing_ingress(activity),
           "idle activity allows user signing ingress");
    expect_usb_block(activity, false, false, false, nullptr);
    expect(agent_q::usb_operation_is_retained_result_read_cleanup(
               agent_q::AgentQUsbOperationType::get_result),
           "get_result is a retained-result read route");
    expect(agent_q::usb_operation_is_retained_result_read_cleanup(
               agent_q::AgentQUsbOperationType::ack_result),
           "ack_result is a retained-result cleanup route");
    expect(!agent_q::usb_operation_is_retained_result_read_cleanup(
               agent_q::AgentQUsbOperationType::sign_transaction),
           "sign_transaction is not a retained-result route");
    expect(!agent_q::usb_operation_is_retained_result_read_cleanup(
               agent_q::AgentQUsbOperationType::policy_propose),
           "policy_propose is not a retained-result route");
    expect(!agent_q::usb_operation_is_retained_result_read_cleanup(
               agent_q::AgentQUsbOperationType::credential_propose),
           "credential_propose is not a retained-result route");

    for (agent_q::AgentQPolicyUpdateFlowStage stage : {
             agent_q::AgentQPolicyUpdateFlowStage::reviewing,
             agent_q::AgentQPolicyUpdateFlowStage::pin_entry,
         }) {
        facts = idle_facts();
        facts.policy_update = policy_update(true, stage);
        activity = project(facts);
        expect(activity.device_state == agent_q::AgentQProjectedDeviceState::awaiting_approval,
               "policy update review/PIN stages project to awaiting_approval");
        expect(!agent_q::device_activity_allows_local_settings_start(activity),
               "policy update blocks local settings start");
        expect(agent_q::device_activity_blocks_user_signing_ingress(activity),
               "policy update blocks signing ingress");
        expect_usb_block(activity, false, false, true, "Device has a pending policy update.");
    }

    for (agent_q::AgentQPolicyUpdateFlowStage stage : {
             agent_q::AgentQPolicyUpdateFlowStage::pin_verifying,
             agent_q::AgentQPolicyUpdateFlowStage::committing,
             agent_q::AgentQPolicyUpdateFlowStage::idle,
         }) {
        facts = idle_facts();
        facts.policy_update = policy_update(true, stage);
        activity = project(facts);
        expect(activity.device_state == agent_q::AgentQProjectedDeviceState::busy,
               "policy update non-review active stages project to busy");
        expect(!agent_q::device_activity_allows_local_settings_start(activity),
               "busy policy update blocks local settings start");
        expect(agent_q::device_activity_blocks_user_signing_ingress(activity),
               "busy policy update blocks signing ingress");
        expect_usb_block(activity, false, false, true, "Device has a pending policy update.");
    }

    for (agent_q::AgentQSuiZkLoginProposalStage stage : {
             agent_q::AgentQSuiZkLoginProposalStage::reviewing,
             agent_q::AgentQSuiZkLoginProposalStage::pin_entry,
         }) {
        facts = idle_facts();
        facts.sui_zklogin_proposal = sui_zklogin_proposal(true, stage);
        activity = project(facts);
        expect(activity.device_state == agent_q::AgentQProjectedDeviceState::awaiting_approval,
               "Sui zkLogin review/PIN stages project to awaiting_approval");
        expect(!agent_q::device_activity_allows_local_settings_start(activity),
               "Sui zkLogin proposal blocks local settings start");
        expect(agent_q::device_activity_blocks_user_signing_ingress(activity),
               "Sui zkLogin proposal blocks signing ingress");
        expect_usb_block(activity, false, false, true, "Device has a pending Sui zkLogin proposal.");
    }

    for (agent_q::AgentQSuiZkLoginProposalStage stage : {
             agent_q::AgentQSuiZkLoginProposalStage::pin_verifying,
             agent_q::AgentQSuiZkLoginProposalStage::committing,
             agent_q::AgentQSuiZkLoginProposalStage::idle,
         }) {
        facts = idle_facts();
        facts.sui_zklogin_proposal = sui_zklogin_proposal(true, stage);
        activity = project(facts);
        expect(activity.device_state == agent_q::AgentQProjectedDeviceState::busy,
               "Sui zkLogin non-PIN active stages project to busy");
        expect(!agent_q::device_activity_allows_local_settings_start(activity),
               "busy Sui zkLogin proposal blocks local settings start");
        expect(agent_q::device_activity_blocks_user_signing_ingress(activity),
               "busy Sui zkLogin proposal blocks signing ingress");
        expect_usb_block(activity, false, false, true, "Device has a pending Sui zkLogin proposal.");
    }

    facts = idle_facts();
    facts.local_reset = local_reset(true, agent_q::AgentQLocalResetStage::settings_menu);
    activity = project(facts);
    expect(activity.device_state == agent_q::AgentQProjectedDeviceState::idle,
           "idle settings menu remains idle for device.state");
    expect(!agent_q::device_activity_allows_local_settings_start(activity),
           "active settings menu blocks starting another settings flow");
    expect_usb_block(activity, false, false, true, "Device is showing local settings UI.");
    expect_usb_block(activity, true, false, false, nullptr);

    facts = idle_facts();
    facts.local_reset = local_reset(true, agent_q::AgentQLocalResetStage::pin_entry);
    activity = project(facts);
    expect(activity.device_state == agent_q::AgentQProjectedDeviceState::busy,
           "local reset PIN entry projects to busy");
    expect(agent_q::device_activity_blocks_user_signing_ingress(activity),
           "local reset blocks signing ingress");
    expect_usb_block(activity, true, false, true, "Device is showing local reset UI.");

    facts = idle_facts();
    facts.payload_delivery_receiving = true;
    activity = project(facts);
    expect(activity.device_state == agent_q::AgentQProjectedDeviceState::busy,
           "payload delivery receiving projects to busy");
    expect(!agent_q::device_activity_allows_local_settings_start(activity),
           "payload delivery receiving blocks local settings start");
    expect(agent_q::device_activity_blocks_user_signing_ingress(activity),
           "payload delivery receiving blocks signing ingress");
    expect_usb_block(activity, false, false, true, "Device has a pending payload transfer.");
    expect_usb_block(activity, false, true, false, nullptr);

    facts = idle_facts();
    facts.payload_delivery_finalized = true;
    activity = project(facts);
    expect(activity.device_state == agent_q::AgentQProjectedDeviceState::busy,
           "payload delivery finalized projects to busy");
    expect(!agent_q::device_activity_allows_local_settings_start(activity),
           "payload delivery finalized blocks local settings start");
    expect(!agent_q::device_activity_blocks_user_signing_ingress(activity),
           "payload delivery finalized leaves signing admission request-aware");
    expect_usb_block(activity, false, false, true, "Device has a pending signable payload.");
    expect_usb_block(activity, false, true, false, nullptr);

    facts = idle_facts();
    facts.user_signing = user_signing(true, agent_q::AgentQUserSigningStage::reviewing);
    activity = project(facts);
    expect(activity.device_state == agent_q::AgentQProjectedDeviceState::awaiting_approval,
           "user signing review projects to awaiting_approval");
    expect(agent_q::device_activity_blocks_user_signing_ingress(activity),
           "active user signing blocks another signing ingress");

    if (failures != 0) {
        fprintf(stderr, "%d device activity projection test(s) failed\n", failures);
        return 1;
    }
    printf("Device activity projection tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${ARDUINOJSON_ROOT}" \
  "${TMP_DIR}/device_activity_projection_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_device_activity_projection.cpp" \
  "${AGENT_Q_DIR}/agent_q_usb_operation_manifest.cpp" \
  -o "${TMP_DIR}/device_activity_projection_test"

"${TMP_DIR}/device_activity_projection_test"
