#include "agent_q_persistent_material.h"

#include <string.h>

#include "agent_q_approval_history.h"
#include "agent_q_connect_settings.h"
#include "agent_q_policy_update_marker.h"
#include "agent_q_signing_mode.h"

namespace agent_q {
namespace {

bool g_consistency_error = false;

void latch_consistency_error(
    const AgentQPersistentMaterialOps& ops,
    const char* message)
{
    g_consistency_error = true;
    if (ops.on_consistency_error != nullptr) {
        ops.on_consistency_error(message);
    }
}

bool persist_state(
    const AgentQPersistentMaterialOps& ops,
    AgentQProvisioningPersistedState state)
{
    return ops.persist_state != nullptr && ops.persist_state(state);
}

bool parse_persisted_provisioning_state(const char* value, AgentQProvisioningPersistedState* output)
{
    if (value == nullptr || output == nullptr) {
        return false;
    }
    if (strcmp(value, "unprovisioned") == 0) {
        *output = AgentQProvisioningPersistedState::unprovisioned;
        return true;
    }
    if (strcmp(value, "provisioned") == 0) {
        *output = AgentQProvisioningPersistedState::provisioned;
        return true;
    }
    return false;
}

void rollback_setup_material()
{
    wipe_signing_authorization_mode();
    wipe_local_auth();
    wipe_policy();
    wipe_root_material();
}

const char* runtime_failure_message(AgentQPersistentMaterialRuntimeFailure failure)
{
    switch (failure) {
        case AgentQPersistentMaterialRuntimeFailure::root_material_unreadable:
            return "Root material unreadable while provisioned; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::active_policy_unavailable:
            return "Active policy unavailable while provisioned; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::pending_reset_resume_failed:
            return "Pending local reset could not be completed during boot; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::local_reset_root_wipe_failed:
            return "Local reset could not wipe root material; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::local_reset_policy_wipe_failed:
            return "Local reset could not wipe active policy; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::local_reset_local_auth_wipe_failed:
            return "Local reset could not wipe local PIN verifier; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::local_reset_connect_setting_wipe_failed:
            return "Local reset could not wipe connect PIN setting; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::local_reset_signing_mode_wipe_failed:
            return "Local reset could not wipe signing authorization mode; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::local_reset_approval_history_wipe_failed:
            return "Local reset could not wipe approval history; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::local_reset_policy_update_marker_wipe_failed:
            return "Local reset could not wipe policy update marker; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::local_reset_material_remaining:
            return "Local reset reported success but persistent material remains; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::local_reset_state_storage_failed:
            return "Local reset wiped material but could not persist unprovisioned state; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::local_reset_marker_clear_failed:
            return "Local reset completed but could not clear reset marker; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::local_reset_auth_unavailable:
            return "Local reset could not verify stored PIN; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::local_pin_auth_unavailable:
            return "Local PIN verifier unavailable during PIN authorization; failing closed";
        case AgentQPersistentMaterialRuntimeFailure::pin_change_auth_unavailable:
            return "Change PIN failed and local PIN verifier is unavailable; failing closed";
        default:
            return "Persistent material runtime failure; failing closed";
    }
}

AgentQPersistentMaterialConsistencyResult validate_loaded_runtime_state(
    AgentQProvisioningPersistedState stored_state,
    AgentQProvisioningRuntimeState* effective_state,
    const AgentQPersistentMaterialOps& ops)
{
    AgentQPersistentMaterialStatus status = persistent_material_status();
    if (stored_state == AgentQProvisioningPersistedState::provisioned) {
        if (status.complete()) {
            *effective_state = AgentQProvisioningRuntimeState::provisioned;
            return AgentQPersistentMaterialConsistencyResult::ok;
        }
        latch_consistency_error(
            ops,
            "Stored provisioned state is missing root material, active policy, local PIN verifier, signing mode, or has pending policy update material; failing closed");
        return AgentQPersistentMaterialConsistencyResult::consistency_error;
    }

    if (status.any_material()) {
        latch_consistency_error(
            ops,
            "Persistent setup material exists outside provisioned state; failing closed");
        return AgentQPersistentMaterialConsistencyResult::consistency_error;
    }

    *effective_state = AgentQProvisioningRuntimeState::unprovisioned;
    return AgentQPersistentMaterialConsistencyResult::ok;
}

}  // namespace

bool AgentQPersistentMaterialStatus::complete() const
{
    return root_present &&
           policy_status == AgentQPolicyStoreStatus::active &&
           local_auth_status == AgentQLocalAuthStatus::active &&
           signing_mode_status == AgentQSigningAuthorizationModeStatus::active &&
           policy_update_marker_status == AgentQPolicyUpdateMarkerStatus::clear;
}

bool AgentQPersistentMaterialStatus::any_material() const
{
    return root_present ||
           policy_status != AgentQPolicyStoreStatus::missing ||
           local_auth_status != AgentQLocalAuthStatus::missing ||
           signing_mode_status != AgentQSigningAuthorizationModeStatus::missing ||
           policy_update_marker_status != AgentQPolicyUpdateMarkerStatus::clear;
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

const char* provisioning_persisted_state_to_string(AgentQProvisioningPersistedState state)
{
    switch (state) {
        case AgentQProvisioningPersistedState::provisioned:
            return "provisioned";
        case AgentQProvisioningPersistedState::unprovisioned:
        default:
            return "unprovisioned";
    }
}

AgentQPersistentMaterialStatus persistent_material_status()
{
    return AgentQPersistentMaterialStatus{
        has_root_material(),
        active_policy_status(),
        local_auth_status(),
        signing_authorization_mode_status(),
        policy_update_marker_status(),
    };
}

bool persistent_material_exists()
{
    return persistent_material_status().any_material();
}

bool persistent_material_consistency_error_active()
{
    return g_consistency_error;
}

void persistent_material_begin_load()
{
    g_consistency_error = false;
}

AgentQPersistentMaterialConsistencyResult persistent_material_record_runtime_failure(
    AgentQPersistentMaterialRuntimeFailure failure,
    const AgentQPersistentMaterialOps& ops)
{
    latch_consistency_error(ops, runtime_failure_message(failure));
    return AgentQPersistentMaterialConsistencyResult::consistency_error;
}

AgentQPersistentMaterialConsistencyResult persistent_material_validate_loaded_storage_state(
    AgentQProvisioningStateStorageStatus storage_status,
    const char* stored_state,
    AgentQProvisioningRuntimeState* effective_state,
    const AgentQPersistentMaterialOps& ops)
{
    g_consistency_error = false;

    if (effective_state == nullptr) {
        latch_consistency_error(ops, "Persistent material state output unavailable; failing closed");
        return AgentQPersistentMaterialConsistencyResult::consistency_error;
    }

    *effective_state = AgentQProvisioningRuntimeState::unprovisioned;

    if (storage_status == AgentQProvisioningStateStorageStatus::missing) {
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Persistent setup material exists without provisioning state; failing closed");
            return AgentQPersistentMaterialConsistencyResult::consistency_error;
        }
        return AgentQPersistentMaterialConsistencyResult::ok;
    }

    if (storage_status == AgentQProvisioningStateStorageStatus::unreadable) {
        latch_consistency_error(
            ops,
            "Provisioning state could not be read; failing closed");
        return AgentQPersistentMaterialConsistencyResult::state_storage_error;
    }

    AgentQProvisioningPersistedState parsed_state = AgentQProvisioningPersistedState::unprovisioned;
    if (!parse_persisted_provisioning_state(stored_state, &parsed_state)) {
        latch_consistency_error(
            ops,
            "Unknown provisioning state; failing closed");
        return AgentQPersistentMaterialConsistencyResult::consistency_error;
    }

    return validate_loaded_runtime_state(parsed_state, effective_state, ops);
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
        latch_consistency_error(
            ops,
            "Provisioned state lost root material, active policy, local PIN verifier, signing mode, or has pending policy update material; failing closed");
        return false;
    }

    if (status.any_material()) {
        latch_consistency_error(
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

    AgentQLocalAuthPreparedRecord prepared_auth = {};
    if (!prepare_local_pin_verifier_record(setup_pin, &prepared_auth)) {
        return AgentQPersistentMaterialCommitResult::local_auth_storage_error;
    }
    const AgentQPersistentMaterialCommitResult result =
        persistent_material_commit_setup_with_prepared_auth(
            root_material,
            root_material_size,
            &prepared_auth,
            ops);
    wipe_local_pin_verifier_record(&prepared_auth);
    return result;
}

AgentQPersistentMaterialCommitResult persistent_material_commit_setup_with_prepared_auth(
    const uint8_t* root_material,
    size_t root_material_size,
    const AgentQLocalAuthPreparedRecord* prepared_auth,
    const AgentQPersistentMaterialOps& ops)
{
    if (root_material == nullptr || root_material_size != kRootMaterialBytes ||
        prepared_auth == nullptr) {
        return AgentQPersistentMaterialCommitResult::missing_input;
    }

    if (!store_root_material(root_material, root_material_size)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Root material storage left partial persistent setup material; failing closed");
        }
        return AgentQPersistentMaterialCommitResult::root_storage_error;
    }

    if (!store_default_policy()) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Policy storage failed with persistent setup material present; failing closed");
        }
        return AgentQPersistentMaterialCommitResult::policy_storage_error;
    }

    if (!store_prepared_local_pin_verifier(prepared_auth)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Local PIN verifier storage failed with persistent setup material present; failing closed");
        }
        return AgentQPersistentMaterialCommitResult::local_auth_storage_error;
    }

    if (!store_signing_authorization_mode(AgentQSigningAuthorizationMode::user)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Signing mode storage failed with persistent setup material present; failing closed");
        }
        return AgentQPersistentMaterialCommitResult::signing_mode_storage_error;
    }

    if (!persist_state(ops, AgentQProvisioningPersistedState::provisioned)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Provisioning state storage failed with persistent setup material present; failing closed");
        }
        return AgentQPersistentMaterialCommitResult::state_storage_error;
    }

    g_consistency_error = false;
    return AgentQPersistentMaterialCommitResult::ok;
}

AgentQPersistentMaterialWipeResult persistent_material_wipe_all()
{
    const bool root_wiped = wipe_root_material();
    const bool policy_wiped = wipe_policy();
    const bool local_auth_wiped = wipe_local_auth();
    const bool connect_setting_wiped = wipe_require_pin_on_connect();
    const bool signing_mode_wiped = wipe_signing_authorization_mode();
    const bool approval_history_wiped = approval_history_wipe();
    const bool policy_update_marker_wiped = policy_update_marker_clear();

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
    if (!signing_mode_wiped) {
        return AgentQPersistentMaterialWipeResult::signing_mode_wipe_error;
    }
    if (!approval_history_wiped) {
        return AgentQPersistentMaterialWipeResult::approval_history_wipe_error;
    }
    if (!policy_update_marker_wiped) {
        return AgentQPersistentMaterialWipeResult::policy_update_marker_wipe_error;
    }
    if (persistent_material_exists()) {
        return AgentQPersistentMaterialWipeResult::material_remaining_error;
    }
    g_consistency_error = false;
    return AgentQPersistentMaterialWipeResult::ok;
}

}  // namespace agent_q
