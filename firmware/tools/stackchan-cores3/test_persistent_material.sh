#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_persistent_material.sh

Compiles the StackChan CoreS3 persistent material coordinator against host
stubs and verifies setup commit rollback, reset wipe coverage,
provisioning-state storage envelope consistency classification, policy-update
marker coverage, typed runtime material failure handling, and
persistent-material consistency error latch ownership. This test uses only a
host C++ compiler and does NOT require ESP-IDF.
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

#include "agent_q_human_approval_settings.h"
#include "agent_q_local_auth_test.h"
#include "agent_q_persistent_material.h"

namespace {

bool g_root_present = false;
bool g_policy_present = false;
bool g_auth_present = false;
bool g_human_approval_setting_present = false;
bool g_approval_history_present = false;
bool g_policy_update_marker_present = false;
bool g_zklogin_proof_present = false;
bool g_signing_mode_present = false;
bool g_root_store_fails = false;
bool g_policy_store_fails = false;
bool g_auth_store_fails = false;
bool g_human_approval_setting_store_fails = false;
bool g_signing_mode_store_fails = false;
bool g_root_wipe_fails = false;
bool g_signing_mode_wipe_fails = false;
bool g_approval_history_wipe_fails = false;
bool g_policy_update_marker_wipe_fails = false;
bool g_zklogin_proof_wipe_fails = false;
bool g_persist_state_fails = false;
agent_q::AgentQPolicyStoreStatus g_policy_status = agent_q::AgentQPolicyStoreStatus::missing;
agent_q::AgentQLocalAuthStatus g_auth_status = agent_q::AgentQLocalAuthStatus::missing;
agent_q::AgentQSigningAuthorizationModeStatus g_signing_mode_status =
    agent_q::AgentQSigningAuthorizationModeStatus::missing;
agent_q::AgentQSigningAuthorizationMode g_signing_mode =
    agent_q::AgentQSigningAuthorizationMode::user;
agent_q::AgentQHumanApprovalInputMode g_human_approval_input_mode =
    agent_q::AgentQHumanApprovalInputMode::pin;
agent_q::AgentQPolicyUpdateMarkerStatus g_policy_update_marker_status =
    agent_q::AgentQPolicyUpdateMarkerStatus::clear;
agent_q::AgentQSuiZkLoginProofRecordStatus g_zklogin_proof_status =
    agent_q::AgentQSuiZkLoginProofRecordStatus::missing;
agent_q::AgentQProvisioningPersistedState g_persisted_state =
    agent_q::AgentQProvisioningPersistedState::unprovisioned;
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
    g_human_approval_setting_present = false;
    g_approval_history_present = false;
    g_policy_update_marker_present = false;
    g_zklogin_proof_present = false;
    g_signing_mode_present = false;
    g_root_store_fails = false;
    g_policy_store_fails = false;
    g_auth_store_fails = false;
    g_human_approval_setting_store_fails = false;
    g_signing_mode_store_fails = false;
    g_root_wipe_fails = false;
    g_signing_mode_wipe_fails = false;
    g_approval_history_wipe_fails = false;
    g_policy_update_marker_wipe_fails = false;
    g_zklogin_proof_wipe_fails = false;
    g_persist_state_fails = false;
    g_policy_status = agent_q::AgentQPolicyStoreStatus::missing;
    g_auth_status = agent_q::AgentQLocalAuthStatus::missing;
    g_signing_mode_status = agent_q::AgentQSigningAuthorizationModeStatus::missing;
    g_signing_mode = agent_q::AgentQSigningAuthorizationMode::user;
    g_human_approval_input_mode = agent_q::AgentQHumanApprovalInputMode::pin;
    g_policy_update_marker_status = agent_q::AgentQPolicyUpdateMarkerStatus::clear;
    g_zklogin_proof_status = agent_q::AgentQSuiZkLoginProofRecordStatus::missing;
    g_persisted_state = agent_q::AgentQProvisioningPersistedState::unprovisioned;
    g_consistency_error_count = 0;
    agent_q::persistent_material_begin_load();
}

bool persist_state(agent_q::AgentQProvisioningPersistedState state)
{
    if (g_persist_state_fails) {
        return false;
    }
    g_persisted_state = state;
    return true;
}

void on_consistency_error(const char*)
{
    ++g_consistency_error_count;
}

agent_q::AgentQPersistentMaterialOps ops()
{
    return agent_q::AgentQPersistentMaterialOps{
        persist_state,
        on_consistency_error,
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

bool prepare_local_pin_verifier_record(const char* pin, AgentQLocalAuthPreparedRecord* out)
{
    if (!is_valid_local_pin(pin) || out == nullptr) {
        return false;
    }
    memset(out->bytes, 0, sizeof(out->bytes));
    memcpy(out->bytes, pin, kLocalPinBufferSize);
    return true;
}

bool store_prepared_local_pin_verifier(const AgentQLocalAuthPreparedRecord* prepared)
{
    if (prepared == nullptr || g_auth_store_fails) {
        return false;
    }
    const char* pin = reinterpret_cast<const char*>(prepared->bytes);
    if (!is_valid_local_pin(pin)) {
        return false;
    }
    g_auth_present = true;
    g_auth_status = AgentQLocalAuthStatus::active;
    return true;
}

void wipe_local_pin_verifier_record(AgentQLocalAuthPreparedRecord* prepared)
{
    if (prepared != nullptr) {
        memset(prepared->bytes, 0, sizeof(prepared->bytes));
    }
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

bool read_signing_authorization_mode(AgentQSigningAuthorizationMode* mode)
{
    if (mode == nullptr || !g_signing_mode_present ||
        g_signing_mode_status != AgentQSigningAuthorizationModeStatus::active) {
        return false;
    }
    *mode = g_signing_mode;
    return true;
}

bool store_signing_authorization_mode(AgentQSigningAuthorizationMode mode)
{
    if (g_signing_mode_store_fails) {
        return false;
    }
    g_signing_mode_present = true;
    g_signing_mode_status = AgentQSigningAuthorizationModeStatus::active;
    g_signing_mode = mode;
    return true;
}

bool wipe_signing_authorization_mode()
{
    if (g_signing_mode_wipe_fails) {
        return false;
    }
    g_signing_mode_present = false;
    g_signing_mode_status = AgentQSigningAuthorizationModeStatus::missing;
    g_signing_mode = AgentQSigningAuthorizationMode::user;
    return true;
}

AgentQSigningAuthorizationModeStatus signing_authorization_mode_status()
{
    return g_signing_mode_status;
}

const char* signing_authorization_mode_name(AgentQSigningAuthorizationMode mode)
{
    return mode == AgentQSigningAuthorizationMode::policy ? "policy" : "user";
}

bool read_human_approval_input_mode(AgentQHumanApprovalInputMode* mode)
{
    if (mode == nullptr || !g_human_approval_setting_present) {
        return false;
    }
    *mode = g_human_approval_input_mode;
    return true;
}

bool human_approval_requires_pin()
{
    return true;
}

bool store_human_approval_input_mode(AgentQHumanApprovalInputMode mode)
{
    if (g_human_approval_setting_store_fails) {
        return false;
    }
    g_human_approval_setting_present = true;
    g_human_approval_input_mode = mode;
    return true;
}

bool wipe_human_approval_input_mode()
{
    g_human_approval_setting_present = false;
    g_human_approval_input_mode = AgentQHumanApprovalInputMode::pin;
    return true;
}

bool approval_history_wipe()
{
    if (g_approval_history_wipe_fails) {
        return false;
    }
    g_approval_history_present = false;
    return true;
}

AgentQPolicyUpdateMarkerStatus policy_update_marker_status()
{
    return g_policy_update_marker_status;
}

AgentQPolicyUpdateMarkerBeginResult policy_update_marker_begin(
    const uint8_t*,
    size_t policy_digest_size,
    size_t policy_count,
    AgentQPolicyUpdateHighestAction)
{
    if (policy_digest_size != kAgentQPolicyUpdateDigestBytes ||
        policy_count > kAgentQCurrentPolicyMaxTotalPolicies) {
        return AgentQPolicyUpdateMarkerBeginResult::invalid_input;
    }
    g_policy_update_marker_present = true;
    g_policy_update_marker_status = AgentQPolicyUpdateMarkerStatus::pending;
    return AgentQPolicyUpdateMarkerBeginResult::written;
}

bool policy_update_marker_clear()
{
    if (g_policy_update_marker_wipe_fails) {
        return false;
    }
    g_policy_update_marker_present = false;
    g_policy_update_marker_status = AgentQPolicyUpdateMarkerStatus::clear;
    return true;
}

agent_q::AgentQSuiZkLoginProofRecordStatus sui_zklogin_proof_record_status()
{
    return g_zklogin_proof_status;
}

bool wipe_sui_zklogin_proof_record()
{
    if (g_zklogin_proof_wipe_fails) {
        return false;
    }
    g_zklogin_proof_present = false;
    g_zklogin_proof_status = AgentQSuiZkLoginProofRecordStatus::missing;
    return true;
}

}  // namespace agent_q

int main()
{
    using State = agent_q::AgentQProvisioningRuntimeState;
    using PersistedState = agent_q::AgentQProvisioningPersistedState;
    using Storage = agent_q::AgentQProvisioningStateStorageStatus;
    using Consistency = agent_q::AgentQPersistentMaterialConsistencyResult;
    using Commit = agent_q::AgentQPersistentMaterialCommitResult;
    using Wipe = agent_q::AgentQPersistentMaterialWipeResult;

    uint8_t root[agent_q::kRootMaterialBytes] = {};
    State effective = State::unprovisioned;

    reset_stubs();
    expect(agent_q::persistent_material_record_runtime_failure(
               agent_q::AgentQPersistentMaterialRuntimeFailure::root_material_unreadable, ops()) ==
               Consistency::consistency_error,
           "runtime material failure is recorded as consistency error");
    expect(agent_q::persistent_material_consistency_error_active(),
           "runtime material failure latches consistency error");
    expect(agent_q::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::ok,
           "setup commit succeeds after runtime failure is resolved");
    expect(!agent_q::persistent_material_consistency_error_active(),
           "setup commit success clears consistency error latch");

    reset_stubs();
    expect(agent_q::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::ok,
           "setup commit succeeds");
    expect(g_root_present && g_policy_present && g_auth_present &&
               g_signing_mode_present && g_human_approval_setting_present,
           "setup commit stores all required material, signing mode, and human approval default");
    expect(g_signing_mode == agent_q::AgentQSigningAuthorizationMode::user,
           "setup commit initializes signing mode to user");
    expect(g_human_approval_input_mode == agent_q::AgentQHumanApprovalInputMode::pin,
           "setup commit initializes human approval input mode to PIN");
    expect(g_persisted_state == PersistedState::provisioned,
           "setup commit persists provisioned after material");

    reset_stubs();
    g_signing_mode_present = true;
    g_signing_mode_status = agent_q::AgentQSigningAuthorizationModeStatus::active;
    g_signing_mode = agent_q::AgentQSigningAuthorizationMode::policy;
    expect(agent_q::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::ok,
           "setup commit succeeds over stale signing mode material");
    expect(g_signing_mode_present && g_signing_mode == agent_q::AgentQSigningAuthorizationMode::user,
           "setup commit reinitializes stale signing mode to user");

    reset_stubs();
    g_human_approval_setting_present = true;
    g_human_approval_input_mode = agent_q::AgentQHumanApprovalInputMode::confirm;
    expect(agent_q::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::ok,
           "setup commit succeeds over stale human approval input mode material");
    expect(g_human_approval_setting_present &&
               g_human_approval_input_mode == agent_q::AgentQHumanApprovalInputMode::pin,
           "setup commit reinitializes stale human approval input mode to PIN");

    reset_stubs();
    g_policy_store_fails = true;
    expect(agent_q::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::policy_storage_error,
           "policy storage failure is reported");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_signing_mode_present && !g_human_approval_setting_present,
           "policy failure rolls back partial setup material");
    expect(g_consistency_error_count == 0,
           "clean rollback does not enter consistency error");

    reset_stubs();
    g_signing_mode_store_fails = true;
    expect(agent_q::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::signing_mode_storage_error,
           "signing mode storage failure is reported");
    expect(!g_root_present && !g_policy_present && !g_auth_present && !g_signing_mode_present,
           "signing mode failure rolls back partial setup material");
    expect(g_consistency_error_count == 0,
           "clean signing mode rollback does not enter consistency error");

    reset_stubs();
    g_human_approval_setting_store_fails = true;
    expect(agent_q::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::human_approval_setting_storage_error,
           "human approval input mode storage failure is reported");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_signing_mode_present && !g_human_approval_setting_present,
           "human approval input mode failure rolls back partial setup material");
    expect(g_consistency_error_count == 0,
           "clean human approval input mode rollback does not enter consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = agent_q::AgentQPolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = agent_q::AgentQLocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = agent_q::AgentQSigningAuthorizationModeStatus::active;
    g_human_approval_setting_present = true;
    g_approval_history_present = true;
    g_policy_update_marker_present = true;
    g_policy_update_marker_status = agent_q::AgentQPolicyUpdateMarkerStatus::pending;
    g_zklogin_proof_present = true;
    g_zklogin_proof_status = agent_q::AgentQSuiZkLoginProofRecordStatus::active;
    expect(agent_q::persistent_material_record_runtime_failure(
               agent_q::AgentQPersistentMaterialRuntimeFailure::local_reset_root_wipe_failed, ops()) ==
               Consistency::consistency_error,
           "local reset material failure latches consistency error before wipe");
    expect(agent_q::persistent_material_wipe_all() == Wipe::ok,
           "wipe all succeeds");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_signing_mode_present && !g_human_approval_setting_present && !g_approval_history_present &&
               !g_policy_update_marker_present && !g_zklogin_proof_present,
           "wipe all removes required, signing-mode, reset-scoped settings, approval-history, policy-update marker, and zkLogin proof material");
    expect(!agent_q::persistent_material_consistency_error_active(),
           "wipe all success clears consistency error latch");

    reset_stubs();
    g_policy_update_marker_status = agent_q::AgentQPolicyUpdateMarkerStatus::pending;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::missing, nullptr, &effective, ops()) ==
               Consistency::consistency_error,
           "missing state with policy-update marker fails closed");
    expect(g_consistency_error_count == 1,
           "missing state with policy-update marker reports consistency error");

    reset_stubs();
    g_zklogin_proof_present = true;
    g_zklogin_proof_status = agent_q::AgentQSuiZkLoginProofRecordStatus::active;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::missing, nullptr, &effective, ops()) ==
               Consistency::consistency_error,
           "missing state with zkLogin proof material fails closed");
    expect(g_consistency_error_count == 1,
           "missing state with zkLogin proof material reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = agent_q::AgentQPolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = agent_q::AgentQLocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = agent_q::AgentQSigningAuthorizationModeStatus::active;
    g_policy_update_marker_present = true;
    g_policy_update_marker_status = agent_q::AgentQPolicyUpdateMarkerStatus::pending;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "pending policy-update marker blocks provisioned material readiness");
    expect(g_consistency_error_count == 1,
           "pending policy-update marker reports consistency error");

    reset_stubs();
    g_policy_update_marker_present = true;
    g_policy_update_marker_status = agent_q::AgentQPolicyUpdateMarkerStatus::pending;
    g_policy_update_marker_wipe_fails = true;
    expect(agent_q::persistent_material_wipe_all() == Wipe::policy_update_marker_wipe_error,
           "policy-update marker wipe failure is reported");
    expect(g_policy_update_marker_present,
           "failed policy-update marker wipe leaves marker for caller-owned fail-closed handling");

    reset_stubs();
    g_zklogin_proof_present = true;
    g_zklogin_proof_status = agent_q::AgentQSuiZkLoginProofRecordStatus::active;
    g_zklogin_proof_wipe_fails = true;
    expect(agent_q::persistent_material_wipe_all() == Wipe::zklogin_proof_wipe_error,
           "zkLogin proof wipe failure is reported");
    expect(g_zklogin_proof_present,
           "failed zkLogin proof wipe leaves proof for caller-owned fail-closed handling");

    reset_stubs();
    g_signing_mode_present = true;
    g_signing_mode_status = agent_q::AgentQSigningAuthorizationModeStatus::active;
    g_signing_mode_wipe_fails = true;
    expect(agent_q::persistent_material_wipe_all() == Wipe::signing_mode_wipe_error,
           "signing mode wipe failure is reported");
    expect(g_signing_mode_present,
           "failed signing mode wipe leaves signing mode for caller-owned fail-closed handling");

    reset_stubs();
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::missing, nullptr, &effective, ops()) ==
               Consistency::ok,
           "missing state without material is valid unprovisioned");
    expect(effective == State::unprovisioned,
           "missing state effective state remains unprovisioned");

    reset_stubs();
    g_root_present = true;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::missing, nullptr, &effective, ops()) ==
               Consistency::consistency_error,
           "missing state with material fails closed");
    expect(g_consistency_error_count == 1,
           "missing state with material reports consistency error");
    expect(agent_q::persistent_material_consistency_error_active(),
           "missing state with material latches persistent material error");

    reset_stubs();
    g_signing_mode_present = true;
    g_signing_mode_status = agent_q::AgentQSigningAuthorizationModeStatus::active;
    g_signing_mode = agent_q::AgentQSigningAuthorizationMode::policy;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::missing, nullptr, &effective, ops()) ==
               Consistency::consistency_error,
           "missing state with signing mode material fails closed");
    expect(g_consistency_error_count == 1,
           "missing state with signing mode material reports consistency error");

    reset_stubs();
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::unreadable, nullptr, &effective, ops()) ==
               Consistency::state_storage_error,
           "unreadable state fails closed");
    expect(g_consistency_error_count == 1,
           "unreadable state reports consistency error");
    expect(agent_q::persistent_material_consistency_error_active(),
           "unreadable state latches persistent material error");

    reset_stubs();
    g_persisted_state = PersistedState::provisioned;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::present, "unknown", &effective, ops()) ==
               Consistency::consistency_error,
           "unknown state without material fails closed");
    expect(g_persisted_state == PersistedState::provisioned,
           "unknown state is not normalized to unprovisioned");
    expect(g_consistency_error_count == 1,
           "unknown state without material reports consistency error");
    expect(agent_q::persistent_material_consistency_error_active(),
           "unknown state without material latches persistent material error");

    reset_stubs();
    g_root_present = true;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::present, "unknown", &effective, ops()) ==
               Consistency::consistency_error,
           "unknown state with material fails closed");
    expect(g_consistency_error_count == 1,
           "unknown state with material reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = agent_q::AgentQPolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = agent_q::AgentQLocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = agent_q::AgentQSigningAuthorizationModeStatus::active;
    g_zklogin_proof_status = agent_q::AgentQSuiZkLoginProofRecordStatus::invalid;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "complete provisioned material with invalid zkLogin proof fails closed");
    expect(g_consistency_error_count == 1,
           "invalid zkLogin proof under provisioned state reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = agent_q::AgentQPolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = agent_q::AgentQLocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = agent_q::AgentQSigningAuthorizationModeStatus::active;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::ok,
           "complete native provisioned material is valid");
    expect(effective == State::provisioned,
           "complete native provisioned material loads provisioned state");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = agent_q::AgentQPolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = agent_q::AgentQLocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = agent_q::AgentQSigningAuthorizationModeStatus::active;
    g_zklogin_proof_present = true;
    g_zklogin_proof_status = agent_q::AgentQSuiZkLoginProofRecordStatus::active;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::ok,
           "complete zkLogin provisioned material is valid");
    expect(effective == State::provisioned,
           "complete zkLogin provisioned material loads provisioned state");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = agent_q::AgentQPolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = agent_q::AgentQLocalAuthStatus::active;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "provisioned material without signing mode fails closed");
    expect(g_consistency_error_count == 1,
           "missing signing mode reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = agent_q::AgentQPolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = agent_q::AgentQLocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = agent_q::AgentQSigningAuthorizationModeStatus::invalid;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "invalid signing mode under provisioned state fails closed");
    expect(g_consistency_error_count == 1,
           "invalid signing mode reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_auth_present = true;
    g_auth_status = agent_q::AgentQLocalAuthStatus::active;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "provisioned root plus auth without active policy fails closed");
    expect(g_consistency_error_count == 1,
           "missing active policy reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_status = agent_q::AgentQPolicyStoreStatus::invalid;
    g_auth_present = true;
    g_auth_status = agent_q::AgentQLocalAuthStatus::active;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "invalid policy under provisioned state fails closed");
    expect(g_consistency_error_count == 1,
           "invalid policy reports consistency error");

    reset_stubs();
    g_root_present = true;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::present, "unprovisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "material outside provisioned state fails closed");

    reset_stubs();
    g_persisted_state = PersistedState::provisioned;
    expect(agent_q::persistent_material_validate_loaded_storage_state(Storage::present, "provisioning", &effective, ops()) ==
               Consistency::consistency_error,
           "persisted provisioning state fails closed");
    expect(g_persisted_state == PersistedState::provisioned,
           "persisted provisioning state is not normalized to unprovisioned");
    expect(g_consistency_error_count == 1,
           "persisted provisioning state reports consistency error");

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
