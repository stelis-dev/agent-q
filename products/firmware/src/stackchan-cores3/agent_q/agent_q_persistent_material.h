#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_local_auth.h"
#include "agent_q_policy_store.h"
#include "agent_q_root_material.h"

namespace agent_q {

enum class AgentQProvisioningRuntimeState {
    unprovisioned,
    provisioning,
    provisioned,
};

enum class AgentQPersistentMaterialConsistencyResult {
    ok,
    legacy_policy_initialized,
    legacy_provisioning_reset,
    unknown_state_reset,
    consistency_error,
    state_storage_error,
};

enum class AgentQPersistentMaterialRuntimeFailure {
    root_material_unreadable,
    pending_reset_resume_failed,
    local_reset_root_wipe_failed,
    local_reset_policy_wipe_failed,
    local_reset_local_auth_wipe_failed,
    local_reset_connect_setting_wipe_failed,
    local_reset_approval_history_wipe_failed,
    local_reset_material_remaining,
    local_reset_state_storage_failed,
    local_reset_marker_clear_failed,
    local_reset_auth_unavailable,
    local_pin_auth_unavailable,
    pin_change_auth_unavailable,
};

enum class AgentQPersistentMaterialCommitResult {
    ok,
    missing_input,
    root_storage_error,
    policy_storage_error,
    local_auth_storage_error,
    state_storage_error,
};

enum class AgentQPersistentMaterialWipeResult {
    ok,
    root_wipe_error,
    policy_wipe_error,
    local_auth_wipe_error,
    connect_setting_wipe_error,
    approval_history_wipe_error,
    material_remaining_error,
};

struct AgentQPersistentMaterialStatus {
    bool root_present;
    AgentQPolicyStoreStatus policy_status;
    AgentQLocalAuthStatus local_auth_status;

    bool complete() const;
    bool any_material() const;
};

struct AgentQPersistentMaterialOps {
    bool (*persist_state)(AgentQProvisioningRuntimeState state);
    void (*on_consistency_error)(const char* message);
};

enum class AgentQProvisioningStateStorageStatus {
    present,
    missing,
    unreadable,
};

const char* provisioning_runtime_state_to_string(AgentQProvisioningRuntimeState state);

AgentQPersistentMaterialStatus persistent_material_status();
bool persistent_material_exists();
bool persistent_material_consistency_error_active();
void persistent_material_begin_load();
AgentQPersistentMaterialConsistencyResult persistent_material_record_runtime_failure(
    AgentQPersistentMaterialRuntimeFailure failure,
    const AgentQPersistentMaterialOps& ops);
AgentQPersistentMaterialConsistencyResult persistent_material_validate_loaded_storage_state(
    AgentQProvisioningStateStorageStatus storage_status,
    const char* stored_state,
    AgentQProvisioningRuntimeState* effective_state,
    const AgentQPersistentMaterialOps& ops);
bool persistent_material_validate_runtime_state(
    AgentQProvisioningRuntimeState current_state,
    const AgentQPersistentMaterialOps& ops);
AgentQPersistentMaterialCommitResult persistent_material_commit_setup(
    const uint8_t* root_material,
    size_t root_material_size,
    const char* setup_pin,
    const AgentQPersistentMaterialOps& ops);
AgentQPersistentMaterialCommitResult persistent_material_commit_setup_with_prepared_auth(
    const uint8_t* root_material,
    size_t root_material_size,
    const AgentQLocalAuthPreparedRecord* prepared_auth,
    const AgentQPersistentMaterialOps& ops);
AgentQPersistentMaterialWipeResult persistent_material_wipe_all();

}  // namespace agent_q
