#pragma once

#include <stddef.h>
#include <stdint.h>

#include "local_auth.h"
#include "policy_store.h"
#include "policy_update_marker.h"
#include "root_material.h"
#include "signing_mode.h"
#include "sui_account_settings.h"
#include "sui_zklogin_proof_store.h"

namespace signing {

enum class ProvisioningRuntimeState {
    unprovisioned,
    provisioning,
    provisioned,
};

enum class ProvisioningPersistedState {
    unprovisioned,
    provisioned,
};

enum class PersistentMaterialConsistencyResult {
    ok,
    consistency_error,
    state_storage_error,
};

enum class PersistentMaterialRuntimeFailure {
    root_material_unreadable,
    active_policy_unavailable,
    pending_reset_resume_failed,
    local_reset_root_wipe_failed,
    local_reset_policy_wipe_failed,
    local_reset_local_auth_wipe_failed,
    local_reset_human_approval_setting_wipe_failed,
    local_reset_signing_mode_wipe_failed,
    local_reset_sui_account_settings_wipe_failed,
    local_reset_approval_history_wipe_failed,
    local_reset_policy_update_marker_wipe_failed,
    local_reset_zklogin_proof_wipe_failed,
    local_reset_material_remaining,
    local_reset_state_storage_failed,
    local_reset_marker_clear_failed,
    local_reset_auth_unavailable,
    local_pin_auth_unavailable,
    pin_change_auth_unavailable,
};

enum class PersistentMaterialCommitResult {
    ok,
    missing_input,
    root_storage_error,
    policy_storage_error,
    local_auth_storage_error,
    signing_mode_storage_error,
    human_approval_setting_storage_error,
    sui_account_settings_storage_error,
    state_storage_error,
};

enum class PersistentMaterialWipeResult {
    ok,
    root_wipe_error,
    policy_wipe_error,
    local_auth_wipe_error,
    human_approval_setting_wipe_error,
    signing_mode_wipe_error,
    sui_account_settings_wipe_error,
    approval_history_wipe_error,
    policy_update_marker_wipe_error,
    zklogin_proof_wipe_error,
    material_remaining_error,
};

struct PersistentMaterialStatus {
    bool root_present;
    PolicyStoreStatus policy_status;
    LocalAuthStatus local_auth_status;
    AuthorizationModeStatus signing_mode_status;
    SuiAccountSettingsStatus sui_account_settings_status;
    PolicyUpdateMarkerStatus policy_update_marker_status;
    SuiZkLoginProofRecordStatus zklogin_proof_status;

    bool complete() const;
    bool any_material() const;
};

struct PersistentMaterialOps {
    bool (*persist_state)(ProvisioningPersistedState state);
    void (*on_consistency_error)(const char* message);
};

enum class ProvisioningStateStorageStatus {
    present,
    missing,
    unreadable,
};

const char* provisioning_runtime_state_to_string(ProvisioningRuntimeState state);
const char* provisioning_persisted_state_to_string(ProvisioningPersistedState state);

PersistentMaterialStatus persistent_material_status();
bool persistent_material_exists();
bool persistent_material_consistency_error_active();
void persistent_material_begin_load();
PersistentMaterialConsistencyResult persistent_material_record_runtime_failure(
    PersistentMaterialRuntimeFailure failure,
    const PersistentMaterialOps& ops);
PersistentMaterialConsistencyResult persistent_material_validate_loaded_storage_state(
    ProvisioningStateStorageStatus storage_status,
    const char* stored_state,
    ProvisioningRuntimeState* effective_state,
    const PersistentMaterialOps& ops);
bool persistent_material_validate_runtime_state(
    ProvisioningRuntimeState current_state,
    const PersistentMaterialOps& ops);
PersistentMaterialCommitResult persistent_material_commit_setup(
    const uint8_t* root_material,
    size_t root_material_size,
    const char* setup_pin,
    const PersistentMaterialOps& ops);
PersistentMaterialCommitResult persistent_material_commit_setup_with_prepared_auth(
    const uint8_t* root_material,
    size_t root_material_size,
    const LocalAuthPreparedRecord* prepared_auth,
    const PersistentMaterialOps& ops);
PersistentMaterialWipeResult persistent_material_wipe_all();

}  // namespace signing
