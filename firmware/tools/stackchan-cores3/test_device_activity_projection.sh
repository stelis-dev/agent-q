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
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_PROTOCOL_DIR="${COMMON_ROOT}/protocol"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"
CXX_BIN="${CXX:-c++}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${RUNTIME_DIR}/device_activity_projection.cpp" \
  "${RUNTIME_DIR}/device_activity_projection.h" \
  "${COMMON_PROTOCOL_DIR}/operation_manifest.cpp" \
  "${COMMON_PROTOCOL_DIR}/operation_manifest.h" \
  "${COMMON_ROOT}/protocol/operation_type.cpp" \
  "${COMMON_ROOT}/protocol/operation_type.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-device-activity.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/firmware_common" "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/firmware_common/sui"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/device_activity_projection_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "device_activity_projection.h"
#include "protocol/operation_type.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

signing::PolicyUpdateFlowSnapshot policy_update(
    bool active,
    signing::PolicyUpdateFlowStage stage)
{
    signing::PolicyUpdateFlowSnapshot snapshot{};
    snapshot.active = active;
    snapshot.stage = stage;
    return snapshot;
}

signing::SuiZkLoginProposalSnapshot sui_zklogin_proposal(
    bool active,
    signing::SuiZkLoginProposalStage stage)
{
    signing::SuiZkLoginProposalSnapshot snapshot{};
    snapshot.active = active;
    snapshot.stage = stage;
    return snapshot;
}

signing::StorageMaintenanceSnapshot storage_maintenance(
    bool active,
    signing::StorageMaintenanceStage stage)
{
    signing::StorageMaintenanceSnapshot snapshot{};
    snapshot.flow_active = active;
    snapshot.stage = stage;
    return snapshot;
}

signing::UserSigningFlowCoreSnapshot user_signing(
    bool active,
    signing::UserSigningStage stage)
{
    signing::UserSigningFlowCoreSnapshot snapshot{};
    snapshot.active = active;
    snapshot.stage = stage;
    return snapshot;
}

signing::DeviceActivityFacts idle_facts()
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
        policy_update(false, signing::PolicyUpdateFlowStage::idle),
        sui_zklogin_proposal(false, signing::SuiZkLoginProposalStage::idle),
        storage_maintenance(false, signing::StorageMaintenanceStage::none),
        user_signing(false, signing::UserSigningStage::none),
    };
}

signing::DeviceActivityProjection project(
    const signing::DeviceActivityFacts& facts)
{
    return signing::project_device_activity(facts);
}

void expect_usb_block(
    const signing::DeviceActivityProjection& activity,
    bool allow_settings_menu,
    bool allow_payload_delivery,
    bool blocked,
    const char* message)
{
    const signing::DeviceActivityRequestBlock block =
        signing::device_activity_request_block(
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
    signing::DeviceActivityFacts facts = idle_facts();
    signing::DeviceActivityProjection activity = project(facts);
    expect(activity.device_state == signing::ProjectedDeviceState::idle,
           "idle facts project to idle");
    expect(signing::device_activity_allows_local_settings_touch_entry(activity),
           "idle provisioned activity allows touch settings entry");
    expect(!signing::device_activity_blocks_user_signing_ingress(activity),
           "idle activity allows user signing ingress");
    expect_usb_block(activity, false, false, false, nullptr);
    expect(signing::operation_is_retained_response_read_cleanup(
               signing::OperationType::get_result),
           "get_result is a retained-response read route");
    expect(signing::operation_is_retained_response_read_cleanup(
               signing::OperationType::ack_result),
           "ack_result is a retained-response cleanup route");
    expect(!signing::operation_is_retained_response_read_cleanup(
               signing::OperationType::sign_transaction),
           "sign_transaction is not a retained-response route");
    expect(!signing::operation_is_retained_response_read_cleanup(
               signing::OperationType::policy_propose),
           "policy_propose is not a retained-response route");
    expect(!signing::operation_is_retained_response_read_cleanup(
               signing::OperationType::credential_propose),
           "credential_propose is not a retained-response route");

    for (signing::PolicyUpdateFlowStage stage : {
             signing::PolicyUpdateFlowStage::reviewing,
             signing::PolicyUpdateFlowStage::pin_entry,
         }) {
        facts = idle_facts();
        facts.policy_update = policy_update(true, stage);
        activity = project(facts);
        expect(activity.device_state == signing::ProjectedDeviceState::awaiting_approval,
               "policy update review/PIN stages project to awaiting_approval");
        expect(!signing::device_activity_allows_local_settings_start(activity),
               "policy update blocks local settings start");
        expect(signing::device_activity_blocks_user_signing_ingress(activity),
               "policy update blocks signing ingress");
        expect_usb_block(activity, false, false, true, "Device has a pending policy update.");
    }

    for (signing::PolicyUpdateFlowStage stage : {
             signing::PolicyUpdateFlowStage::pin_verifying,
             signing::PolicyUpdateFlowStage::committing,
             signing::PolicyUpdateFlowStage::idle,
         }) {
        facts = idle_facts();
        facts.policy_update = policy_update(true, stage);
        activity = project(facts);
        expect(activity.device_state == signing::ProjectedDeviceState::busy,
               "policy update non-review active stages project to busy");
        expect(!signing::device_activity_allows_local_settings_start(activity),
               "busy policy update blocks local settings start");
        expect(signing::device_activity_blocks_user_signing_ingress(activity),
               "busy policy update blocks signing ingress");
        expect_usb_block(activity, false, false, true, "Device has a pending policy update.");
    }

    for (signing::SuiZkLoginProposalStage stage : {
             signing::SuiZkLoginProposalStage::reviewing,
             signing::SuiZkLoginProposalStage::pin_entry,
         }) {
        facts = idle_facts();
        facts.sui_zklogin_proposal = sui_zklogin_proposal(true, stage);
        activity = project(facts);
        expect(activity.device_state == signing::ProjectedDeviceState::awaiting_approval,
               "Sui zkLogin review/PIN stages project to awaiting_approval");
        expect(!signing::device_activity_allows_local_settings_start(activity),
               "Sui zkLogin proposal blocks local settings start");
        expect(signing::device_activity_blocks_user_signing_ingress(activity),
               "Sui zkLogin proposal blocks signing ingress");
        expect_usb_block(activity, false, false, true, "Device has a pending Sui zkLogin proposal.");
    }

    for (signing::SuiZkLoginProposalStage stage : {
             signing::SuiZkLoginProposalStage::pin_verifying,
             signing::SuiZkLoginProposalStage::committing,
             signing::SuiZkLoginProposalStage::idle,
         }) {
        facts = idle_facts();
        facts.sui_zklogin_proposal = sui_zklogin_proposal(true, stage);
        activity = project(facts);
        expect(activity.device_state == signing::ProjectedDeviceState::busy,
               "Sui zkLogin non-PIN active stages project to busy");
        expect(!signing::device_activity_allows_local_settings_start(activity),
               "busy Sui zkLogin proposal blocks local settings start");
        expect(signing::device_activity_blocks_user_signing_ingress(activity),
               "busy Sui zkLogin proposal blocks signing ingress");
        expect_usb_block(activity, false, false, true, "Device has a pending Sui zkLogin proposal.");
    }

    facts = idle_facts();
    facts.storage_maintenance = storage_maintenance(true, signing::StorageMaintenanceStage::settings_menu);
    activity = project(facts);
    expect(activity.device_state == signing::ProjectedDeviceState::idle,
           "idle settings menu remains idle for device.state");
    expect(!signing::device_activity_allows_local_settings_start(activity),
           "active settings menu blocks starting another settings flow");
    expect_usb_block(activity, false, false, true, "Device is showing local settings UI.");
    expect_usb_block(activity, true, false, false, nullptr);

    facts = idle_facts();
    facts.storage_maintenance = storage_maintenance(true, signing::StorageMaintenanceStage::pin_entry);
    activity = project(facts);
    expect(activity.device_state == signing::ProjectedDeviceState::busy,
           "local action PIN entry projects to busy");
    expect(signing::device_activity_blocks_user_signing_ingress(activity),
           "storage maintenance blocks signing ingress");
    expect_usb_block(activity, true, false, true, "Device is showing storage maintenance UI.");

    facts = idle_facts();
    facts.payload_delivery_receiving = true;
    activity = project(facts);
    expect(activity.device_state == signing::ProjectedDeviceState::busy,
           "payload delivery receiving projects to busy");
    expect(!signing::device_activity_allows_local_settings_start(activity),
           "payload delivery receiving blocks local settings start");
    expect(signing::device_activity_blocks_user_signing_ingress(activity),
           "payload delivery receiving blocks signing ingress");
    expect_usb_block(activity, false, false, true, "Device has a pending payload transfer.");
    expect_usb_block(activity, false, true, false, nullptr);

    facts = idle_facts();
    facts.payload_delivery_finalized = true;
    activity = project(facts);
    expect(activity.device_state == signing::ProjectedDeviceState::busy,
           "payload delivery finalized projects to busy");
    expect(!signing::device_activity_allows_local_settings_start(activity),
           "payload delivery finalized blocks local settings start");
    expect(signing::device_activity_blocks_user_signing_ingress(activity),
           "payload delivery finalized blocks signing ingress");
    expect_usb_block(activity, false, false, true, "Device has a pending signable payload.");
    expect_usb_block(activity, false, true, false, nullptr);

    facts = idle_facts();
    facts.user_signing = user_signing(true, signing::UserSigningStage::reviewing);
    activity = project(facts);
    expect(activity.device_state == signing::ProjectedDeviceState::awaiting_approval,
           "user signing review projects to awaiting_approval");
    expect(signing::device_activity_blocks_user_signing_ingress(activity),
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
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${ARDUINOJSON_ROOT}" \
  "${TMP_DIR}/device_activity_projection_test.cpp" \
  "${RUNTIME_DIR}/device_activity_projection.cpp" \
  "${COMMON_PROTOCOL_DIR}/operation_manifest.cpp" \
  "${COMMON_ROOT}/protocol/operation_type.cpp" \
  -o "${TMP_DIR}/device_activity_projection_test"

"${TMP_DIR}/device_activity_projection_test"
