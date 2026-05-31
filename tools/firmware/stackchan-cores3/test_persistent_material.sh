#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_persistent_material.sh

Compiles the StackChan CoreS3 persistent material coordinator against host
stubs and verifies setup commit rollback, reset wipe coverage, loaded-state
consistency classification, and legacy missing-policy migration. This test uses
only a host C++ compiler and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/products/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/products/firmware/src/common/agent_q"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-persistent-material.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/stubs"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once

#define ESP_LOGI(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGE(tag, format, ...) do { (void)(tag); } while (0)
H

cat >"${TMP_DIR}/persistent_material_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_persistent_material.h"

namespace {

bool g_root_present = false;
bool g_policy_present = false;
bool g_auth_present = false;
bool g_connect_setting_present = false;
bool g_root_store_fails = false;
bool g_policy_store_fails = false;
bool g_auth_store_fails = false;
bool g_root_wipe_fails = false;
bool g_persist_state_fails = false;
agent_q::AgentQPolicyStoreStatus g_policy_status = agent_q::AgentQPolicyStoreStatus::missing;
agent_q::AgentQLocalAuthStatus g_auth_status = agent_q::AgentQLocalAuthStatus::missing;
agent_q::AgentQProvisioningRuntimeState g_persisted_state =
    agent_q::AgentQProvisioningRuntimeState::unprovisioned;
int g_consistency_error_count = 0;
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
    g_root_present = false;
    g_policy_present = false;
    g_auth_present = false;
    g_connect_setting_present = false;
    g_root_store_fails = false;
    g_policy_store_fails = false;
    g_auth_store_fails = false;
    g_root_wipe_fails = false;
    g_persist_state_fails = false;
    g_policy_status = agent_q::AgentQPolicyStoreStatus::missing;
    g_auth_status = agent_q::AgentQLocalAuthStatus::missing;
    g_persisted_state = agent_q::AgentQProvisioningRuntimeState::unprovisioned;
    g_consistency_error_count = 0;
}

bool persist_state(agent_q::AgentQProvisioningRuntimeState state)
{
    if (g_persist_state_fails) {
        return false;
    }
    g_persisted_state = state;
    return true;
}

void enter_consistency_error(const char*)
{
    ++g_consistency_error_count;
}

agent_q::AgentQPersistentMaterialOps ops()
{
    return agent_q::AgentQPersistentMaterialOps{
        persist_state,
        enter_consistency_error,
    };
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

bool has_root_material()
{
    return g_root_present;
}

bool store_root_material(const uint8_t*, size_t size)
{
    if (g_root_store_fails || size != kRootMaterialBytes) {
        return false;
    }
    g_root_present = true;
    return true;
}

bool wipe_root_material()
{
    if (g_root_wipe_fails) {
        return false;
    }
    g_root_present = false;
    return true;
}

bool read_root_material(uint8_t*, size_t)
{
    return false;
}

bool store_default_policy()
{
    if (g_policy_store_fails) {
        return false;
    }
    g_policy_present = true;
    g_policy_status = AgentQPolicyStoreStatus::active;
    return true;
}

bool wipe_policy()
{
    g_policy_present = false;
    g_policy_status = AgentQPolicyStoreStatus::missing;
    return true;
}

AgentQPolicyStoreStatus active_policy_status()
{
    return g_policy_status;
}

AgentQPolicyProvider active_policy_provider()
{
    return AgentQPolicyProvider{nullptr, nullptr};
}

bool read_active_policy_summary(AgentQStoredPolicySummary*)
{
    return false;
}

bool is_valid_local_pin(const char* pin)
{
    return pin != nullptr && strlen(pin) == kLocalPinDigits;
}

bool store_local_pin_verifier(const char* pin)
{
    if (g_auth_store_fails || !is_valid_local_pin(pin)) {
        return false;
    }
    g_auth_present = true;
    g_auth_status = AgentQLocalAuthStatus::active;
    return true;
}

bool verify_local_pin(const char*, bool*)
{
    return false;
}

bool wipe_local_auth()
{
    g_auth_present = false;
    g_auth_status = AgentQLocalAuthStatus::missing;
    return true;
}

AgentQLocalAuthStatus local_auth_status()
{
    return g_auth_status;
}

bool read_require_pin_on_connect(bool*)
{
    return false;
}

bool connect_requires_pin()
{
    return true;
}

bool store_require_pin_on_connect(bool)
{
    return false;
}

bool wipe_require_pin_on_connect()
{
    g_connect_setting_present = false;
    return true;
}

}  // namespace agent_q

int main()
{
    using State = agent_q::AgentQProvisioningRuntimeState;
    using Consistency = agent_q::AgentQPersistentMaterialConsistencyResult;
    using Commit = agent_q::AgentQPersistentMaterialCommitResult;
    using Wipe = agent_q::AgentQPersistentMaterialWipeResult;

    uint8_t root[agent_q::kRootMaterialBytes] = {};

    reset_stubs();
    expect(agent_q::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::ok,
           "setup commit succeeds");
    expect(g_root_present && g_policy_present && g_auth_present,
           "setup commit stores all required material");
    expect(g_persisted_state == State::provisioned,
           "setup commit persists provisioned after material");

    reset_stubs();
    g_policy_store_fails = true;
    expect(agent_q::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::policy_storage_error,
           "policy storage failure is reported");
    expect(!g_root_present && !g_policy_present && !g_auth_present,
           "policy failure rolls back partial setup material");
    expect(g_consistency_error_count == 0,
           "clean rollback does not enter consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = agent_q::AgentQPolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = agent_q::AgentQLocalAuthStatus::active;
    g_connect_setting_present = true;
    expect(agent_q::persistent_material_wipe_all() == Wipe::ok,
           "wipe all succeeds");
    expect(!g_root_present && !g_policy_present && !g_auth_present && !g_connect_setting_present,
           "wipe all removes required and reset-scoped settings material");

    reset_stubs();
    State effective = State::unprovisioned;
    expect(agent_q::persistent_material_validate_loaded_state(State::unprovisioned, &effective, ops()) ==
               Consistency::ok,
           "empty unprovisioned state is valid");
    expect(effective == State::unprovisioned,
           "empty unprovisioned effective state remains unprovisioned");

    reset_stubs();
    g_root_present = true;
    g_auth_present = true;
    g_auth_status = agent_q::AgentQLocalAuthStatus::active;
    expect(agent_q::persistent_material_validate_loaded_state(State::provisioned, &effective, ops()) ==
               Consistency::legacy_policy_initialized,
           "legacy provisioned root plus auth initializes default policy");
    expect(effective == State::provisioned && g_policy_status == agent_q::AgentQPolicyStoreStatus::active,
           "legacy policy migration yields provisioned material");

    reset_stubs();
    g_root_present = true;
    g_policy_status = agent_q::AgentQPolicyStoreStatus::invalid;
    g_auth_present = true;
    g_auth_status = agent_q::AgentQLocalAuthStatus::active;
    expect(agent_q::persistent_material_validate_loaded_state(State::provisioned, &effective, ops()) ==
               Consistency::consistency_error,
           "invalid policy under provisioned state fails closed");
    expect(g_consistency_error_count == 1,
           "invalid policy reports consistency error");

    reset_stubs();
    g_root_present = true;
    expect(agent_q::persistent_material_validate_loaded_state(State::unprovisioned, &effective, ops()) ==
               Consistency::consistency_error,
           "material outside provisioned state fails closed");

    reset_stubs();
    expect(agent_q::persistent_material_validate_loaded_state(State::provisioning, &effective, ops()) ==
               Consistency::legacy_provisioning_reset,
           "legacy provisioning state is reset");
    expect(g_persisted_state == State::unprovisioned,
           "legacy provisioning reset persists unprovisioned");

    if (failures != 0) {
        fprintf(stderr, "%d persistent material test(s) failed\n", failures);
        return 1;
    }
    printf("Persistent material tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/persistent_material_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_persistent_material.cpp" \
  -o "${TMP_DIR}/persistent_material_test"

"${TMP_DIR}/persistent_material_test"
