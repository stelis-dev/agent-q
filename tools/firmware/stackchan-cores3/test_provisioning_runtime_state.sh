#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_provisioning_runtime_state.sh

Compiles the StackChan CoreS3 provisioning runtime-state owner against host
stubs and verifies boot load orchestration, reset-marker handling, persist
updates, material-ready gates, and error reporting. This test uses only a host
C++ compiler and does NOT require ESP-IDF.
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
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-provisioning-runtime-state.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/stubs/freertos"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once

#define ESP_LOGI(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGE(tag, format, ...) do { (void)(tag); } while (0)
H

cat >"${TMP_DIR}/stubs/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
H

cat >"${TMP_DIR}/provisioning_runtime_state_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_provisioning_runtime_state.h"
#include "agent_q_provisioning_state_store.h"

namespace {

using RuntimeState = agent_q::AgentQProvisioningRuntimeState;
using PersistedState = agent_q::AgentQProvisioningPersistedState;
using StorageStatus = agent_q::AgentQProvisioningStateStorageStatus;
using ConsistencyResult = agent_q::AgentQPersistentMaterialConsistencyResult;
using RuntimeFailure = agent_q::AgentQPersistentMaterialRuntimeFailure;
using ResetResult = agent_q::AgentQLocalResetCommitResult;

StorageStatus g_store_status = StorageStatus::missing;
char g_store_value[agent_q::kAgentQProvisioningStateStoreValueSize] = {};
bool g_store_load_transport_fails = false;
bool g_store_save_fails = false;
PersistedState g_saved_state = PersistedState::unprovisioned;
int g_store_load_count = 0;
int g_store_save_count = 0;
bool g_reset_marker_present = false;
ResetResult g_reset_result = ResetResult::ok;
int g_reset_resume_count = 0;
RuntimeState g_validate_loaded_effective = RuntimeState::unprovisioned;
ConsistencyResult g_validate_loaded_result = ConsistencyResult::ok;
int g_validate_loaded_count = 0;
bool g_runtime_validate_result = true;
int g_runtime_validate_count = 0;
RuntimeState g_last_runtime_validate_state = RuntimeState::unprovisioned;
bool g_error_active = false;
int g_begin_load_count = 0;
int g_record_failure_count = 0;
RuntimeFailure g_last_failure = RuntimeFailure::root_material_unreadable;
int g_persist_callback_count = 0;
int g_consistency_callback_count = 0;
int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void reset_stubs()
{
    g_store_status = StorageStatus::missing;
    g_store_value[0] = '\0';
    g_store_load_transport_fails = false;
    g_store_save_fails = false;
    g_saved_state = PersistedState::unprovisioned;
    g_store_load_count = 0;
    g_store_save_count = 0;
    g_reset_marker_present = false;
    g_reset_result = ResetResult::ok;
    g_reset_resume_count = 0;
    g_validate_loaded_effective = RuntimeState::unprovisioned;
    g_validate_loaded_result = ConsistencyResult::ok;
    g_validate_loaded_count = 0;
    g_runtime_validate_result = true;
    g_runtime_validate_count = 0;
    g_last_runtime_validate_state = RuntimeState::unprovisioned;
    g_error_active = false;
    g_begin_load_count = 0;
    g_record_failure_count = 0;
    g_last_failure = RuntimeFailure::root_material_unreadable;
    g_persist_callback_count = 0;
    g_consistency_callback_count = 0;
}

bool persist_callback(PersistedState state)
{
    ++g_persist_callback_count;
    if (state == PersistedState::provisioned) {
        return agent_q::provisioning_runtime_state_persist(RuntimeState::provisioned);
    }
    return agent_q::provisioning_runtime_state_persist(RuntimeState::unprovisioned);
}

void consistency_callback(const char*)
{
    ++g_consistency_callback_count;
}

agent_q::AgentQPersistentMaterialOps material_ops()
{
    return agent_q::AgentQPersistentMaterialOps{
        persist_callback,
        consistency_callback,
    };
}

void clear_session_callback() {}

bool persist_unprovisioned_callback()
{
    return agent_q::provisioning_runtime_state_persist(RuntimeState::unprovisioned);
}

void record_material_failure_callback(RuntimeFailure failure)
{
    agent_q::persistent_material_record_runtime_failure(failure, material_ops());
}

agent_q::AgentQLocalResetPersistenceOps reset_ops()
{
    return agent_q::AgentQLocalResetPersistenceOps{
        clear_session_callback,
        persist_unprovisioned_callback,
        record_material_failure_callback,
    };
}

}  // namespace

namespace agent_q {

const char* provisioning_runtime_state_to_string(AgentQProvisioningRuntimeState state)
{
    switch (state) {
        case AgentQProvisioningRuntimeState::provisioned:
            return "provisioned";
        case AgentQProvisioningRuntimeState::provisioning:
            return "provisioning";
        case AgentQProvisioningRuntimeState::unprovisioned:
        default:
            return "unprovisioned";
    }
}

bool provisioning_state_store_load(AgentQProvisioningStateStoreRecord* output)
{
    ++g_store_load_count;
    if (output == nullptr || g_store_load_transport_fails) {
        return false;
    }
    output->status = g_store_status;
    memcpy(output->value, g_store_value, sizeof(output->value));
    output->value[sizeof(output->value) - 1] = '\0';
    return true;
}

bool provisioning_state_store_save(AgentQProvisioningPersistedState state)
{
    ++g_store_save_count;
    if (g_store_save_fails) {
        return false;
    }
    g_saved_state = state;
    return true;
}

void persistent_material_begin_load()
{
    ++g_begin_load_count;
    g_error_active = false;
}

bool persistent_material_consistency_error_active()
{
    return g_error_active;
}

AgentQPersistentMaterialConsistencyResult persistent_material_record_runtime_failure(
    AgentQPersistentMaterialRuntimeFailure failure,
    const AgentQPersistentMaterialOps& ops)
{
    ++g_record_failure_count;
    g_last_failure = failure;
    g_error_active = true;
    if (ops.on_consistency_error != nullptr) {
        ops.on_consistency_error("failure");
    }
    return AgentQPersistentMaterialConsistencyResult::consistency_error;
}

AgentQPersistentMaterialConsistencyResult persistent_material_validate_loaded_storage_state(
    AgentQProvisioningStateStorageStatus storage_status,
    const char* stored_state,
    AgentQProvisioningRuntimeState* effective_state,
    const AgentQPersistentMaterialOps& ops)
{
    (void)ops;
    ++g_validate_loaded_count;
    expect(storage_status == g_store_status ||
               (g_store_load_transport_fails && storage_status == StorageStatus::unreadable),
           "loaded validator receives storage status");
    if (stored_state != nullptr && g_store_value[0] != '\0') {
        expect(strcmp(stored_state, g_store_value) == 0, "loaded validator receives stored value");
    }
    if (effective_state != nullptr) {
        *effective_state = g_validate_loaded_effective;
    }
    if (g_validate_loaded_result == AgentQPersistentMaterialConsistencyResult::consistency_error ||
        g_validate_loaded_result == AgentQPersistentMaterialConsistencyResult::state_storage_error) {
        g_error_active = true;
    }
    return g_validate_loaded_result;
}

bool persistent_material_validate_runtime_state(
    AgentQProvisioningRuntimeState current_state,
    const AgentQPersistentMaterialOps& ops)
{
    (void)ops;
    ++g_runtime_validate_count;
    g_last_runtime_validate_state = current_state;
    if (!g_runtime_validate_result) {
        g_error_active = true;
    }
    return g_runtime_validate_result;
}

AgentQLocalResetCommitResult local_reset_resume_pending_if_needed(
    const AgentQLocalResetPersistenceOps& ops,
    bool* marker_present)
{
    (void)ops;
    ++g_reset_resume_count;
    if (marker_present != nullptr) {
        *marker_present = g_reset_marker_present;
    }
    return g_reset_result;
}

}  // namespace agent_q

int main()
{
    reset_stubs();
    agent_q::provisioning_runtime_state_load(reset_ops(), material_ops());
    expect(g_begin_load_count == 1, "load begins a fresh material validation epoch");
    expect(g_reset_resume_count == 1, "load checks pending local reset marker first");
    expect(g_store_load_count == 1, "load reads provisioning state when no reset marker");
    expect(g_validate_loaded_count == 1, "load validates stored state against material");
    expect(agent_q::provisioning_runtime_state_is_unprovisioned(),
           "missing state loads as unprovisioned");
    expect(strcmp(agent_q::provisioning_runtime_state_reported(), "unprovisioned") == 0,
           "reported state is unprovisioned");

    reset_stubs();
    g_store_status = StorageStatus::present;
    snprintf(g_store_value, sizeof(g_store_value), "%s", "provisioned");
    g_validate_loaded_effective = RuntimeState::provisioned;
    agent_q::provisioning_runtime_state_load(reset_ops(), material_ops());
    expect(agent_q::provisioning_runtime_state_is_provisioned(), "provisioned load updates current state");
    expect(agent_q::provisioning_runtime_state_material_ready(material_ops()),
           "material ready validates provisioned runtime state");
    expect(g_runtime_validate_count == 1, "material ready calls runtime validator");
    expect(g_last_runtime_validate_state == RuntimeState::provisioned,
           "runtime validator receives current provisioned state");

    reset_stubs();
    g_store_status = StorageStatus::present;
    snprintf(g_store_value, sizeof(g_store_value), "%s", "provisioned");
    g_validate_loaded_effective = RuntimeState::provisioned;
    g_validate_loaded_result = ConsistencyResult::consistency_error;
    agent_q::provisioning_runtime_state_load(reset_ops(), material_ops());
    expect(strcmp(agent_q::provisioning_runtime_state_reported(), "error") == 0,
           "reported state is error when material latch is active");

    reset_stubs();
    g_store_status = StorageStatus::present;
    snprintf(g_store_value, sizeof(g_store_value), "%s", "unknown");
    g_validate_loaded_result = ConsistencyResult::consistency_error;
    agent_q::provisioning_runtime_state_load(reset_ops(), material_ops());
    expect(strcmp(agent_q::provisioning_runtime_state_reported(), "error") == 0,
           "unknown stored state is reported as error");
    expect(g_store_save_count == 0, "unknown stored state is not normalized by runtime owner");

    reset_stubs();
    g_reset_marker_present = true;
    g_reset_result = ResetResult::ok;
    agent_q::provisioning_runtime_state_load(reset_ops(), material_ops());
    expect(g_store_load_count == 0, "pending reset marker avoids normal provisioning load");
    expect(agent_q::provisioning_runtime_state_is_unprovisioned(),
           "successful pending reset leaves runtime state unprovisioned");
    expect(strcmp(agent_q::provisioning_runtime_state_reported(), "unprovisioned") == 0,
           "successful pending reset is not error");

    reset_stubs();
    g_reset_marker_present = true;
    g_reset_result = ResetResult::root_wipe_error;
    agent_q::provisioning_runtime_state_load(reset_ops(), material_ops());
    expect(g_record_failure_count == 1, "failed pending reset records material failure");
    expect(g_last_failure == RuntimeFailure::pending_reset_resume_failed,
           "pending reset failure is typed");
    expect(strcmp(agent_q::provisioning_runtime_state_reported(), "error") == 0,
           "failed pending reset enters error");

    reset_stubs();
    expect(agent_q::provisioning_runtime_state_persist(RuntimeState::provisioned),
           "persist provisioned succeeds");
    expect(g_store_save_count == 1, "persist writes state store");
    expect(g_saved_state == PersistedState::provisioned, "state store receives provisioned");
    expect(agent_q::provisioning_runtime_state_is_provisioned(),
           "persist success updates current state");

    reset_stubs();
    expect(agent_q::provisioning_runtime_state_persist(RuntimeState::provisioned),
           "set previous provisioned state before transient persist");
    g_store_save_count = 0;
    expect(!agent_q::provisioning_runtime_state_persist(RuntimeState::provisioning),
           "persist rejects transient provisioning runtime state");
    expect(g_store_save_count == 0, "transient runtime state is rejected before state store write");
    expect(agent_q::provisioning_runtime_state_is_provisioned(),
           "transient persist failure preserves current state");

    reset_stubs();
    expect(agent_q::provisioning_runtime_state_persist(RuntimeState::provisioned),
           "set previous provisioned state");
    g_store_save_fails = true;
    expect(!agent_q::provisioning_runtime_state_persist(RuntimeState::unprovisioned),
           "persist failure is reported");
    expect(agent_q::provisioning_runtime_state_is_provisioned(),
           "persist failure preserves current state");

    reset_stubs();
    expect(agent_q::provisioning_runtime_state_persist(RuntimeState::provisioned),
           "set provisioned before runtime refresh");
    g_runtime_validate_result = false;
    expect(!agent_q::provisioning_runtime_state_refresh(material_ops()),
           "runtime refresh propagates material failure");
    expect(strcmp(agent_q::provisioning_runtime_state_reported(), "error") == 0,
           "runtime refresh failure latches error");
    expect(!agent_q::provisioning_runtime_state_material_ready(material_ops()),
           "material ready is false after consistency error");

    if (failures != 0) {
        fprintf(stderr, "%d provisioning runtime-state test(s) failed\n", failures);
        return 1;
    }
    printf("Provisioning runtime-state tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/provisioning_runtime_state_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_provisioning_runtime_state.cpp" \
  -o "${TMP_DIR}/provisioning_runtime_state_test"

"${TMP_DIR}/provisioning_runtime_state_test"
