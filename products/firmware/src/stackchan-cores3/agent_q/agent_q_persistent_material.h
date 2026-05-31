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
    consistency_error,
    state_storage_error,
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
    void (*enter_consistency_error)(const char* message);
};

const char* provisioning_runtime_state_to_string(AgentQProvisioningRuntimeState state);
bool parse_provisioning_runtime_state(const char* value, AgentQProvisioningRuntimeState* output);

AgentQPersistentMaterialStatus persistent_material_status();
bool persistent_material_exists();
AgentQPersistentMaterialConsistencyResult persistent_material_validate_loaded_state(
    AgentQProvisioningRuntimeState stored_state,
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
AgentQPersistentMaterialWipeResult persistent_material_wipe_all();

}  // namespace agent_q
