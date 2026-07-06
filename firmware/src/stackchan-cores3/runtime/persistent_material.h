#pragma once

#include <stddef.h>
#include <stdint.h>

#include "protocol/approval_history.h"
#include "human_approval_settings.h"
#include "local_auth.h"
#include "policy/policy_store.h"
#include "policy/policy_update_marker.h"
#include "root_material.h"
#include "protocol/signing_mode.h"
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
    pending_storage_action_resume_failed,
    wallet_erase_root_wipe_failed,
    wallet_erase_policy_wipe_failed,
    wallet_erase_local_auth_wipe_failed,
    wallet_erase_human_approval_setting_wipe_failed,
    wallet_erase_signing_mode_wipe_failed,
    wallet_erase_sui_account_settings_wipe_failed,
    wallet_erase_approval_history_wipe_failed,
    wallet_erase_policy_update_marker_wipe_failed,
    wallet_erase_zklogin_proof_wipe_failed,
    wallet_erase_material_remaining,
    wallet_erase_state_storage_failed,
    wallet_erase_marker_clear_failed,
    wallet_erase_auth_unavailable,
    settings_reset_policy_store_failed,
    settings_reset_human_approval_setting_store_failed,
    settings_reset_signing_mode_store_failed,
    settings_reset_sui_account_settings_store_failed,
    settings_reset_approval_history_wipe_failed,
    settings_reset_policy_update_marker_wipe_failed,
    settings_reset_zklogin_proof_wipe_failed,
    settings_reset_material_incomplete,
    settings_reset_state_storage_failed,
    settings_reset_marker_clear_failed,
    settings_reset_auth_unavailable,
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

enum class PersistentMaterialWalletEraseResult {
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

enum class PersistentMaterialSettingsResetResult {
    ok,
    key_unavailable,
    auth_unavailable,
    policy_store_error,
    human_approval_setting_store_error,
    signing_mode_store_error,
    sui_account_settings_store_error,
    approval_history_wipe_error,
    policy_update_marker_wipe_error,
    zklogin_proof_wipe_error,
    material_incomplete_error,
};

struct PersistentMaterialStatus {
    bool root_present;
    PolicyStoreStatus policy_status;
    LocalAuthStatus local_auth_status;
    HumanApprovalInputModeStatus human_approval_setting_status;
    AuthorizationModeStatus signing_mode_status;
    SuiAccountSettingsStatus sui_account_settings_status;
    ApprovalHistoryStorageStatus approval_history_status;
    PolicyUpdateMarkerStatus policy_update_marker_status;
    SuiZkLoginProofRecordStatus zklogin_proof_status;

    bool complete() const;
    bool any_material() const;
    bool signing_key_material_present() const;
    bool authority_gate_active() const;
    bool recoverable_settings_complete() const;
    bool recoverable_settings_material_present() const;
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
bool persistent_material_can_reset_recoverable_settings();
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
PersistentMaterialWalletEraseResult persistent_material_wallet_erase();
PersistentMaterialSettingsResetResult persistent_material_reset_recoverable_settings();

}  // namespace signing
