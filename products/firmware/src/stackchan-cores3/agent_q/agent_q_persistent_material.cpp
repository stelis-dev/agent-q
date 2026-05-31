#include "agent_q_persistent_material.h"

#include <string.h>

#include "agent_q_connect_settings.h"
#include "esp_log.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQMaterial";

void enter_consistency_error(
    const AgentQPersistentMaterialOps& ops,
    const char* message)
{
    if (ops.enter_consistency_error != nullptr) {
        ops.enter_consistency_error(message);
    }
}

bool persist_state(
    const AgentQPersistentMaterialOps& ops,
    AgentQProvisioningRuntimeState state)
{
    return ops.persist_state != nullptr && ops.persist_state(state);
}

void rollback_setup_material()
{
    wipe_local_auth();
    wipe_policy();
    wipe_root_material();
}

}  // namespace

bool AgentQPersistentMaterialStatus::complete() const
{
    return root_present &&
           policy_status == AgentQPolicyStoreStatus::active &&
           local_auth_status == AgentQLocalAuthStatus::active;
}

bool AgentQPersistentMaterialStatus::any_material() const
{
    return root_present ||
           policy_status != AgentQPolicyStoreStatus::missing ||
           local_auth_status != AgentQLocalAuthStatus::missing;
}

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

bool parse_provisioning_runtime_state(const char* value, AgentQProvisioningRuntimeState* output)
{
    if (value == nullptr || output == nullptr) {
        return false;
    }
    if (strcmp(value, "unprovisioned") == 0) {
        *output = AgentQProvisioningRuntimeState::unprovisioned;
        return true;
    }
    if (strcmp(value, "provisioning") == 0) {
        *output = AgentQProvisioningRuntimeState::provisioning;
        return true;
    }
    if (strcmp(value, "provisioned") == 0) {
        *output = AgentQProvisioningRuntimeState::provisioned;
        return true;
    }
    return false;
}

AgentQPersistentMaterialStatus persistent_material_status()
{
    return AgentQPersistentMaterialStatus{
        has_root_material(),
        active_policy_status(),
        local_auth_status(),
    };
}

bool persistent_material_exists()
{
    return persistent_material_status().any_material();
}

AgentQPersistentMaterialConsistencyResult persistent_material_validate_loaded_state(
    AgentQProvisioningRuntimeState stored_state,
    AgentQProvisioningRuntimeState* effective_state,
    const AgentQPersistentMaterialOps& ops)
{
    if (effective_state == nullptr) {
        enter_consistency_error(ops, "Persistent material state output unavailable; failing closed");
        return AgentQPersistentMaterialConsistencyResult::consistency_error;
    }

    *effective_state = AgentQProvisioningRuntimeState::unprovisioned;
    AgentQPersistentMaterialStatus status = persistent_material_status();
    if (stored_state == AgentQProvisioningRuntimeState::provisioned) {
        if (status.complete()) {
            *effective_state = AgentQProvisioningRuntimeState::provisioned;
            return AgentQPersistentMaterialConsistencyResult::ok;
        }
        if (status.root_present &&
            status.policy_status == AgentQPolicyStoreStatus::missing &&
            status.local_auth_status == AgentQLocalAuthStatus::active) {
            ESP_LOGW(kTag, "Provisioned state has root material but no active policy; installing default-reject policy");
            if (!store_default_policy()) {
                enter_consistency_error(
                    ops,
                    "Could not initialize active policy for existing provisioned material; failing closed");
                return AgentQPersistentMaterialConsistencyResult::consistency_error;
            }
            status = persistent_material_status();
            if (!status.complete()) {
                enter_consistency_error(
                    ops,
                    "Initialized active policy is unreadable for existing provisioned material; failing closed");
                return AgentQPersistentMaterialConsistencyResult::consistency_error;
            }
            *effective_state = AgentQProvisioningRuntimeState::provisioned;
            return AgentQPersistentMaterialConsistencyResult::legacy_policy_initialized;
        }

        enter_consistency_error(
            ops,
            "Stored provisioned state is missing root material, active policy, or local PIN verifier; failing closed");
        return AgentQPersistentMaterialConsistencyResult::consistency_error;
    }

    if (status.any_material()) {
        enter_consistency_error(
            ops,
            "Persistent setup material exists without provisioned state; failing closed");
        return AgentQPersistentMaterialConsistencyResult::consistency_error;
    }

    if (stored_state == AgentQProvisioningRuntimeState::provisioning) {
        if (!persist_state(ops, AgentQProvisioningRuntimeState::unprovisioned)) {
            enter_consistency_error(
                ops,
                "Legacy provisioning state could not be reset; failing closed");
            return AgentQPersistentMaterialConsistencyResult::state_storage_error;
        }
        return AgentQPersistentMaterialConsistencyResult::legacy_provisioning_reset;
    }

    *effective_state = stored_state;
    return AgentQPersistentMaterialConsistencyResult::ok;
}

bool persistent_material_validate_runtime_state(
    AgentQProvisioningRuntimeState current_state,
    const AgentQPersistentMaterialOps& ops)
{
    const AgentQPersistentMaterialStatus status = persistent_material_status();
    if (current_state == AgentQProvisioningRuntimeState::provisioned) {
        if (status.complete()) {
            return true;
        }
        enter_consistency_error(
            ops,
            "Provisioned state lost root material, active policy, or local PIN verifier; failing closed");
        return false;
    }

    if (status.any_material()) {
        enter_consistency_error(
            ops,
            "Persistent setup material exists outside provisioned state; failing closed");
        return false;
    }
    return true;
}

AgentQPersistentMaterialCommitResult persistent_material_commit_setup(
    const uint8_t* root_material,
    size_t root_material_size,
    const char* setup_pin,
    const AgentQPersistentMaterialOps& ops)
{
    if (root_material == nullptr || root_material_size != kRootMaterialBytes ||
        setup_pin == nullptr || setup_pin[0] == '\0') {
        return AgentQPersistentMaterialCommitResult::missing_input;
    }

    if (!store_root_material(root_material, root_material_size)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            enter_consistency_error(
                ops,
                "Root material storage left partial persistent setup material; failing closed");
        }
        return AgentQPersistentMaterialCommitResult::root_storage_error;
    }

    if (!store_default_policy()) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            enter_consistency_error(
                ops,
                "Policy storage failed with persistent setup material present; failing closed");
        }
        return AgentQPersistentMaterialCommitResult::policy_storage_error;
    }

    if (!store_local_pin_verifier(setup_pin)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            enter_consistency_error(
                ops,
                "Local PIN verifier storage failed with persistent setup material present; failing closed");
        }
        return AgentQPersistentMaterialCommitResult::local_auth_storage_error;
    }

    if (!persist_state(ops, AgentQProvisioningRuntimeState::provisioned)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            enter_consistency_error(
                ops,
                "Provisioning state storage failed with persistent setup material present; failing closed");
        }
        return AgentQPersistentMaterialCommitResult::state_storage_error;
    }

    return AgentQPersistentMaterialCommitResult::ok;
}

AgentQPersistentMaterialWipeResult persistent_material_wipe_all()
{
    const bool root_wiped = wipe_root_material();
    const bool policy_wiped = wipe_policy();
    const bool local_auth_wiped = wipe_local_auth();
    const bool connect_setting_wiped = wipe_require_pin_on_connect();

    if (!root_wiped) {
        return AgentQPersistentMaterialWipeResult::root_wipe_error;
    }
    if (!policy_wiped) {
        return AgentQPersistentMaterialWipeResult::policy_wipe_error;
    }
    if (!local_auth_wiped) {
        return AgentQPersistentMaterialWipeResult::local_auth_wipe_error;
    }
    if (!connect_setting_wiped) {
        return AgentQPersistentMaterialWipeResult::connect_setting_wipe_error;
    }
    if (persistent_material_exists()) {
        return AgentQPersistentMaterialWipeResult::material_remaining_error;
    }
    return AgentQPersistentMaterialWipeResult::ok;
}

}  // namespace agent_q
