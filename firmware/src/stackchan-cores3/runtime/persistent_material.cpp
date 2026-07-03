#include "persistent_material.h"

#include <string.h>

#include "approval_history.h"
#include "human_approval_settings.h"
#include "policy_update_marker.h"
#include "signing_mode.h"
#include "sui_account_settings.h"
#include "sui_zklogin_proof_store.h"

namespace signing {
namespace {

bool g_consistency_error = false;

void latch_consistency_error(
    const PersistentMaterialOps& ops,
    const char* message)
{
    g_consistency_error = true;
    if (ops.on_consistency_error != nullptr) {
        ops.on_consistency_error(message);
    }
}

bool persist_state(
    const PersistentMaterialOps& ops,
    ProvisioningPersistedState state)
{
    return ops.persist_state != nullptr && ops.persist_state(state);
}

bool parse_persisted_provisioning_state(const char* value, ProvisioningPersistedState* output)
{
    if (value == nullptr || output == nullptr) {
        return false;
    }
    if (strcmp(value, "unprovisioned") == 0) {
        *output = ProvisioningPersistedState::unprovisioned;
        return true;
    }
    if (strcmp(value, "provisioned") == 0) {
        *output = ProvisioningPersistedState::provisioned;
        return true;
    }
    return false;
}

void rollback_setup_material()
{
    wipe_sui_zklogin_proof_record();
    wipe_human_approval_input_mode();
    wipe_signing_authorization_mode();
    wipe_sui_account_settings();
    clear_local_auth();
    wipe_policy();
    wipe_root_material();
}

const char* runtime_failure_message(PersistentMaterialRuntimeFailure failure)
{
    switch (failure) {
        case PersistentMaterialRuntimeFailure::root_material_unreadable:
            return "Root material unreadable while provisioned; failing closed";
        case PersistentMaterialRuntimeFailure::active_policy_unavailable:
            return "Active policy unavailable while provisioned; failing closed";
        case PersistentMaterialRuntimeFailure::pending_storage_action_resume_failed:
            return "Pending storage action could not be completed during boot; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_root_wipe_failed:
            return "Device reset could not wipe root material; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_policy_wipe_failed:
            return "Device reset could not wipe active policy; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_local_auth_wipe_failed:
            return "Device reset could not wipe local PIN verifier; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_human_approval_setting_wipe_failed:
            return "Device reset could not wipe human approval input mode; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_signing_mode_wipe_failed:
            return "Device reset could not wipe signing authorization mode; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_sui_account_settings_wipe_failed:
            return "Device reset could not wipe Sui account settings; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_approval_history_wipe_failed:
            return "Device reset could not wipe approval history; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_policy_update_marker_wipe_failed:
            return "Device reset could not wipe policy update marker; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_zklogin_proof_wipe_failed:
            return "Device reset could not wipe Sui zkLogin proof record; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_material_remaining:
            return "Device reset reported success but persistent material remains; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_state_storage_failed:
            return "Device reset wiped material but could not persist unprovisioned state; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_marker_clear_failed:
            return "Device reset completed but could not clear pending marker; failing closed";
        case PersistentMaterialRuntimeFailure::wallet_erase_auth_unavailable:
            return "Device reset could not verify stored PIN; failing closed";
        case PersistentMaterialRuntimeFailure::settings_reset_policy_store_failed:
            return "Settings repair could not store default policy; failing closed";
        case PersistentMaterialRuntimeFailure::settings_reset_human_approval_setting_store_failed:
            return "Settings repair could not store human approval input mode; failing closed";
        case PersistentMaterialRuntimeFailure::settings_reset_signing_mode_store_failed:
            return "Settings repair could not store signing authorization mode; failing closed";
        case PersistentMaterialRuntimeFailure::settings_reset_sui_account_settings_store_failed:
            return "Settings repair could not store Sui account settings; failing closed";
        case PersistentMaterialRuntimeFailure::settings_reset_approval_history_wipe_failed:
            return "Settings repair could not wipe approval history; failing closed";
        case PersistentMaterialRuntimeFailure::settings_reset_policy_update_marker_wipe_failed:
            return "Settings repair could not clear policy update marker; failing closed";
        case PersistentMaterialRuntimeFailure::settings_reset_zklogin_proof_wipe_failed:
            return "Settings repair could not wipe Sui zkLogin proof record; failing closed";
        case PersistentMaterialRuntimeFailure::settings_reset_material_incomplete:
            return "Settings repair reported success but recoverable settings are incomplete; failing closed";
        case PersistentMaterialRuntimeFailure::settings_reset_state_storage_failed:
            return "Settings repair rebuilt settings but could not persist provisioned state; failing closed";
        case PersistentMaterialRuntimeFailure::settings_reset_marker_clear_failed:
            return "Settings repair completed but could not clear pending marker; failing closed";
        case PersistentMaterialRuntimeFailure::settings_reset_auth_unavailable:
            return "Settings repair could not verify stored PIN; failing closed";
        case PersistentMaterialRuntimeFailure::local_pin_auth_unavailable:
            return "Local PIN verifier unavailable during PIN authorization; failing closed";
        case PersistentMaterialRuntimeFailure::pin_change_auth_unavailable:
            return "Change PIN failed and local PIN verifier is unavailable; failing closed";
        default:
            return "Persistent material runtime failure; failing closed";
    }
}

PersistentMaterialConsistencyResult validate_loaded_runtime_state(
    ProvisioningPersistedState stored_state,
    ProvisioningRuntimeState* effective_state,
    const PersistentMaterialOps& ops)
{
    PersistentMaterialStatus status = persistent_material_status();
    if (stored_state == ProvisioningPersistedState::provisioned) {
        if (status.complete()) {
            *effective_state = ProvisioningRuntimeState::provisioned;
            return PersistentMaterialConsistencyResult::ok;
        }
        if (!status.signing_key_material_present()) {
            latch_consistency_error(
                ops,
                "Stored provisioned state is missing signing key material; failing closed");
            return PersistentMaterialConsistencyResult::consistency_error;
        }
        if (!status.authority_gate_active()) {
            latch_consistency_error(
                ops,
                "Stored signing key material exists without valid local authentication verifier; failing closed");
            return PersistentMaterialConsistencyResult::consistency_error;
        }
        latch_consistency_error(
            ops,
            "Stored signing key material and local authentication verifier exist without valid recoverable settings; failing closed");
        return PersistentMaterialConsistencyResult::consistency_error;
    }

    if (status.signing_key_material_present()) {
        latch_consistency_error(
            ops,
            "Signing key material exists outside provisioned state; failing closed");
        return PersistentMaterialConsistencyResult::consistency_error;
    }

    if (status.authority_gate_active() || status.recoverable_settings_material_present()) {
        latch_consistency_error(
            ops,
            "Persistent settings or authority-gate material exists without signing key material; failing closed");
        return PersistentMaterialConsistencyResult::consistency_error;
    }

    *effective_state = ProvisioningRuntimeState::unprovisioned;
    return PersistentMaterialConsistencyResult::ok;
}

}  // namespace

bool PersistentMaterialStatus::complete() const
{
    return signing_key_material_present() &&
           authority_gate_active() &&
           recoverable_settings_complete();
}

bool PersistentMaterialStatus::any_material() const
{
    return root_present ||
           policy_status != PolicyStoreStatus::missing ||
           local_auth_status != LocalAuthStatus::missing ||
           human_approval_setting_status != HumanApprovalInputModeStatus::missing ||
           signing_mode_status != AuthorizationModeStatus::missing ||
           sui_account_settings_status != SuiAccountSettingsStatus::missing ||
           approval_history_status != ApprovalHistoryStorageStatus::missing ||
           policy_update_marker_status != PolicyUpdateMarkerStatus::clear ||
           zklogin_proof_status != SuiZkLoginProofRecordStatus::missing;
}

bool PersistentMaterialStatus::signing_key_material_present() const
{
    return root_present;
}

bool PersistentMaterialStatus::authority_gate_active() const
{
    return local_auth_status == LocalAuthStatus::active;
}

bool PersistentMaterialStatus::recoverable_settings_complete() const
{
    return policy_status == PolicyStoreStatus::active &&
           human_approval_setting_status == HumanApprovalInputModeStatus::active &&
           signing_mode_status == AuthorizationModeStatus::active &&
           sui_account_settings_status == SuiAccountSettingsStatus::active &&
           (approval_history_status == ApprovalHistoryStorageStatus::missing ||
            approval_history_status == ApprovalHistoryStorageStatus::active) &&
           policy_update_marker_status == PolicyUpdateMarkerStatus::clear &&
           (zklogin_proof_status == SuiZkLoginProofRecordStatus::missing ||
            zklogin_proof_status == SuiZkLoginProofRecordStatus::active);
}

bool PersistentMaterialStatus::recoverable_settings_material_present() const
{
    return policy_status != PolicyStoreStatus::missing ||
           human_approval_setting_status != HumanApprovalInputModeStatus::missing ||
           signing_mode_status != AuthorizationModeStatus::missing ||
           sui_account_settings_status != SuiAccountSettingsStatus::missing ||
           approval_history_status != ApprovalHistoryStorageStatus::missing ||
           policy_update_marker_status != PolicyUpdateMarkerStatus::clear ||
           zklogin_proof_status != SuiZkLoginProofRecordStatus::missing;
}

const char* provisioning_runtime_state_to_string(ProvisioningRuntimeState state)
{
    switch (state) {
        case ProvisioningRuntimeState::provisioned:
            return "provisioned";
        case ProvisioningRuntimeState::provisioning:
            return "provisioning";
        case ProvisioningRuntimeState::unprovisioned:
        default:
            return "unprovisioned";
    }
}

const char* provisioning_persisted_state_to_string(ProvisioningPersistedState state)
{
    switch (state) {
        case ProvisioningPersistedState::provisioned:
            return "provisioned";
        case ProvisioningPersistedState::unprovisioned:
        default:
            return "unprovisioned";
    }
}

PersistentMaterialStatus persistent_material_status()
{
    return PersistentMaterialStatus{
        has_root_material(),
        active_policy_status(),
        local_auth_status(),
        human_approval_input_mode_status(),
        authorization_mode_status(),
        sui_account_settings_status(),
        approval_history_status(),
        policy_update_marker_status(),
        sui_zklogin_proof_record_status(),
    };
}

bool persistent_material_exists()
{
    return persistent_material_status().any_material();
}

bool persistent_material_can_reset_recoverable_settings()
{
    const PersistentMaterialStatus status = persistent_material_status();
    return status.signing_key_material_present() && status.authority_gate_active();
}

bool persistent_material_consistency_error_active()
{
    return g_consistency_error;
}

void persistent_material_begin_load()
{
    g_consistency_error = false;
}

PersistentMaterialConsistencyResult persistent_material_record_runtime_failure(
    PersistentMaterialRuntimeFailure failure,
    const PersistentMaterialOps& ops)
{
    latch_consistency_error(ops, runtime_failure_message(failure));
    return PersistentMaterialConsistencyResult::consistency_error;
}

PersistentMaterialConsistencyResult persistent_material_validate_loaded_storage_state(
    ProvisioningStateStorageStatus storage_status,
    const char* stored_state,
    ProvisioningRuntimeState* effective_state,
    const PersistentMaterialOps& ops)
{
    g_consistency_error = false;

    if (effective_state == nullptr) {
        latch_consistency_error(ops, "Persistent material state output unavailable; failing closed");
        return PersistentMaterialConsistencyResult::consistency_error;
    }

    *effective_state = ProvisioningRuntimeState::unprovisioned;

    if (storage_status == ProvisioningStateStorageStatus::missing) {
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Persistent setup material exists without provisioning state; failing closed");
            return PersistentMaterialConsistencyResult::consistency_error;
        }
        return PersistentMaterialConsistencyResult::ok;
    }

    if (storage_status == ProvisioningStateStorageStatus::unreadable) {
        latch_consistency_error(
            ops,
            "Provisioning state could not be read; failing closed");
        return PersistentMaterialConsistencyResult::state_storage_error;
    }

    ProvisioningPersistedState parsed_state = ProvisioningPersistedState::unprovisioned;
    if (!parse_persisted_provisioning_state(stored_state, &parsed_state)) {
        latch_consistency_error(
            ops,
            "Unknown provisioning state; failing closed");
        return PersistentMaterialConsistencyResult::consistency_error;
    }

    return validate_loaded_runtime_state(parsed_state, effective_state, ops);
}

bool persistent_material_validate_runtime_state(
    ProvisioningRuntimeState current_state,
    const PersistentMaterialOps& ops)
{
    const PersistentMaterialStatus status = persistent_material_status();
    if (current_state == ProvisioningRuntimeState::provisioned) {
        if (status.complete()) {
            return true;
        }
        if (!status.signing_key_material_present()) {
            latch_consistency_error(
                ops,
                "Provisioned state lost signing key material; failing closed");
            return false;
        }
        if (!status.authority_gate_active()) {
            latch_consistency_error(
                ops,
                "Provisioned state has signing key material without valid local authentication verifier; failing closed");
            return false;
        }
        latch_consistency_error(
            ops,
            "Provisioned state has signing key material and local authentication verifier without valid recoverable settings; failing closed");
        return false;
    }

    if (status.signing_key_material_present()) {
        latch_consistency_error(
            ops,
            "Signing key material exists outside provisioned state; failing closed");
        return false;
    }
    if (status.authority_gate_active() || status.recoverable_settings_material_present()) {
        latch_consistency_error(
            ops,
            "Persistent settings or authority-gate material exists without signing key material; failing closed");
        return false;
    }
    return true;
}

PersistentMaterialCommitResult persistent_material_commit_setup(
    const uint8_t* root_material,
    size_t root_material_size,
    const char* setup_pin,
    const PersistentMaterialOps& ops)
{
    if (root_material == nullptr || root_material_size != kRootMaterialBytes ||
        setup_pin == nullptr || setup_pin[0] == '\0') {
        return PersistentMaterialCommitResult::missing_input;
    }

    LocalAuthPreparedRecord prepared_auth = {};
    if (!prepare_local_pin_verifier_record(setup_pin, &prepared_auth)) {
        return PersistentMaterialCommitResult::local_auth_storage_error;
    }
    const PersistentMaterialCommitResult result =
        persistent_material_commit_setup_with_prepared_auth(
            root_material,
            root_material_size,
            &prepared_auth,
            ops);
    wipe_local_pin_verifier_record(&prepared_auth);
    return result;
}

PersistentMaterialCommitResult persistent_material_commit_setup_with_prepared_auth(
    const uint8_t* root_material,
    size_t root_material_size,
    const LocalAuthPreparedRecord* prepared_auth,
    const PersistentMaterialOps& ops)
{
    if (root_material == nullptr || root_material_size != kRootMaterialBytes ||
        prepared_auth == nullptr) {
        return PersistentMaterialCommitResult::missing_input;
    }

    if (!store_root_material(root_material, root_material_size)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Root material storage left partial persistent setup material; failing closed");
        }
        return PersistentMaterialCommitResult::root_storage_error;
    }

    if (!store_default_policy()) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Policy storage failed with persistent setup material present; failing closed");
        }
        return PersistentMaterialCommitResult::policy_storage_error;
    }

    if (!store_prepared_local_pin_verifier(prepared_auth)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Local PIN verifier storage failed with persistent setup material present; failing closed");
        }
        return PersistentMaterialCommitResult::local_auth_storage_error;
    }

    if (!store_signing_authorization_mode(AuthorizationMode::user)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Signing mode storage failed with persistent setup material present; failing closed");
        }
        return PersistentMaterialCommitResult::signing_mode_storage_error;
    }

    if (!store_human_approval_input_mode(HumanApprovalInputMode::pin)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Human approval input mode storage failed with persistent setup material present; failing closed");
        }
        return PersistentMaterialCommitResult::human_approval_setting_storage_error;
    }

    if (!store_sui_account_settings(kDefaultSuiAccountSettings)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Sui account settings storage failed with persistent setup material present; failing closed");
        }
        return PersistentMaterialCommitResult::sui_account_settings_storage_error;
    }

    if (!persist_state(ops, ProvisioningPersistedState::provisioned)) {
        rollback_setup_material();
        if (persistent_material_exists()) {
            latch_consistency_error(
                ops,
                "Provisioning state storage failed with persistent setup material present; failing closed");
        }
        return PersistentMaterialCommitResult::state_storage_error;
    }

    g_consistency_error = false;
    return PersistentMaterialCommitResult::ok;
}

PersistentMaterialWalletEraseResult persistent_material_wallet_erase()
{
    const bool root_wiped = wipe_root_material();
    const bool policy_wiped = wipe_policy();
    const bool local_auth_wiped = clear_local_auth();
    const bool human_approval_setting_wiped = wipe_human_approval_input_mode();
    const bool signing_mode_wiped = wipe_signing_authorization_mode();
    const bool sui_account_settings_wiped = wipe_sui_account_settings();
    const bool approval_history_wiped = approval_history_wipe();
    const bool policy_update_marker_wiped = policy_update_marker_clear();
    const bool zklogin_proof_wiped = wipe_sui_zklogin_proof_record();

    if (!root_wiped) {
        return PersistentMaterialWalletEraseResult::root_wipe_error;
    }
    if (!policy_wiped) {
        return PersistentMaterialWalletEraseResult::policy_wipe_error;
    }
    if (!local_auth_wiped) {
        return PersistentMaterialWalletEraseResult::local_auth_wipe_error;
    }
    if (!human_approval_setting_wiped) {
        return PersistentMaterialWalletEraseResult::human_approval_setting_wipe_error;
    }
    if (!signing_mode_wiped) {
        return PersistentMaterialWalletEraseResult::signing_mode_wipe_error;
    }
    if (!sui_account_settings_wiped) {
        return PersistentMaterialWalletEraseResult::sui_account_settings_wipe_error;
    }
    if (!approval_history_wiped) {
        return PersistentMaterialWalletEraseResult::approval_history_wipe_error;
    }
    if (!policy_update_marker_wiped) {
        return PersistentMaterialWalletEraseResult::policy_update_marker_wipe_error;
    }
    if (!zklogin_proof_wiped) {
        return PersistentMaterialWalletEraseResult::zklogin_proof_wipe_error;
    }
    if (persistent_material_exists()) {
        return PersistentMaterialWalletEraseResult::material_remaining_error;
    }
    g_consistency_error = false;
    return PersistentMaterialWalletEraseResult::ok;
}

PersistentMaterialSettingsResetResult persistent_material_reset_recoverable_settings()
{
    const PersistentMaterialStatus status = persistent_material_status();
    if (!status.signing_key_material_present()) {
        return PersistentMaterialSettingsResetResult::key_unavailable;
    }
    if (!status.authority_gate_active()) {
        return PersistentMaterialSettingsResetResult::auth_unavailable;
    }

    if (!store_default_policy()) {
        return PersistentMaterialSettingsResetResult::policy_store_error;
    }
    if (!store_human_approval_input_mode(HumanApprovalInputMode::pin)) {
        return PersistentMaterialSettingsResetResult::human_approval_setting_store_error;
    }
    if (!store_signing_authorization_mode(AuthorizationMode::user)) {
        return PersistentMaterialSettingsResetResult::signing_mode_store_error;
    }
    if (!store_sui_account_settings(kDefaultSuiAccountSettings)) {
        return PersistentMaterialSettingsResetResult::sui_account_settings_store_error;
    }
    if (!approval_history_wipe()) {
        return PersistentMaterialSettingsResetResult::approval_history_wipe_error;
    }
    if (!policy_update_marker_clear()) {
        return PersistentMaterialSettingsResetResult::policy_update_marker_wipe_error;
    }
    if (!wipe_sui_zklogin_proof_record()) {
        return PersistentMaterialSettingsResetResult::zklogin_proof_wipe_error;
    }
    if (!persistent_material_status().complete()) {
        return PersistentMaterialSettingsResetResult::material_incomplete_error;
    }
    g_consistency_error = false;
    return PersistentMaterialSettingsResetResult::ok;
}

}  // namespace signing
