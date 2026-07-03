#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_persistent_material.sh

Compiles the StackChan CoreS3 persistent material coordinator against host
stubs and verifies setup commit rollback, Device reset and internal settings repair coverage,
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
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CXX_BIN="${CXX:-c++}"

require_pattern() {
  local file="$1"
  local pattern="$2"
  local label="$3"
  if ! grep -Fq "${pattern}" "${file}"; then
    printf 'FAILED: %s\n' "${label}" >&2
    printf '  file: %s\n' "${file}" >&2
    printf '  missing: %s\n' "${pattern}" >&2
    exit 1
  fi
}

require_pattern \
  "${RUNTIME_DIR}/root_material.cpp" \
  "kNvsNamespace = kSigningKeyMaterialNvsNamespace" \
  "root material must use the protected signing-key namespace"
require_pattern \
  "${RUNTIME_DIR}/local_auth.cpp" \
  "kNvsNamespace = kAuthorityGateNvsNamespace" \
  "local authentication verifier must use the protected authority-gate namespace"
require_pattern \
  "${RUNTIME_DIR}/usb_request_server.cpp" \
  "kNvsNamespace = signing::kDeviceIdentityNvsNamespace" \
  "protocol device id must use the stable device-identity namespace"

for mutable_file in \
  provisioning_state_store.cpp \
  policy_store.cpp \
  policy_update_marker.cpp \
  signing_mode.cpp \
  human_approval_settings.cpp \
  sui_account_settings.cpp \
  sui_zklogin_proof_store.cpp \
  approval_history.cpp \
  storage_maintenance.cpp; do
  require_pattern \
    "${RUNTIME_DIR}/${mutable_file}" \
    "kNvsNamespace = kMutableSettingsNvsNamespace" \
    "${mutable_file} must use the mutable settings namespace"
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-persistent-material.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/firmware_common" "${TMP_DIR}/stubs"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once

#define ESP_LOGI(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGE(tag, format, ...) do { (void)(tag); } while (0)
H

cat >"${TMP_DIR}/persistent_material_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "human_approval_settings.h"
#include "local_auth_test.h"
#include "persistent_material.h"

namespace {

bool g_root_present = false;
bool g_policy_present = false;
bool g_auth_present = false;
bool g_human_approval_setting_present = false;
bool g_approval_history_present = false;
bool g_policy_update_marker_present = false;
bool g_zklogin_proof_present = false;
bool g_signing_mode_present = false;
bool g_sui_account_settings_present = false;
bool g_root_store_fails = false;
bool g_policy_store_fails = false;
bool g_auth_store_fails = false;
bool g_human_approval_setting_store_fails = false;
bool g_signing_mode_store_fails = false;
bool g_sui_account_settings_store_fails = false;
bool g_root_wipe_fails = false;
bool g_signing_mode_wipe_fails = false;
bool g_sui_account_settings_wipe_fails = false;
bool g_approval_history_wipe_fails = false;
bool g_policy_update_marker_wipe_fails = false;
bool g_zklogin_proof_wipe_fails = false;
bool g_persist_state_fails = false;
signing::PolicyStoreStatus g_policy_status = signing::PolicyStoreStatus::missing;
signing::LocalAuthStatus g_auth_status = signing::LocalAuthStatus::missing;
signing::AuthorizationModeStatus g_signing_mode_status =
    signing::AuthorizationModeStatus::missing;
signing::AuthorizationMode g_signing_mode =
    signing::AuthorizationMode::user;
signing::SuiAccountSettings g_sui_account_settings =
    signing::kDefaultSuiAccountSettings;
signing::SuiAccountSettingsStatus g_sui_account_settings_status =
    signing::SuiAccountSettingsStatus::missing;
signing::HumanApprovalInputMode g_human_approval_input_mode =
    signing::HumanApprovalInputMode::pin;
signing::HumanApprovalInputModeStatus g_human_approval_setting_status =
    signing::HumanApprovalInputModeStatus::missing;
signing::PolicyUpdateMarkerStatus g_policy_update_marker_status =
    signing::PolicyUpdateMarkerStatus::clear;
signing::SuiZkLoginProofRecordStatus g_zklogin_proof_status =
    signing::SuiZkLoginProofRecordStatus::missing;
signing::ApprovalHistoryStorageStatus g_approval_history_status =
    signing::ApprovalHistoryStorageStatus::missing;
signing::ProvisioningPersistedState g_persisted_state =
    signing::ProvisioningPersistedState::unprovisioned;
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
    g_sui_account_settings_present = false;
    g_root_store_fails = false;
    g_policy_store_fails = false;
    g_auth_store_fails = false;
    g_human_approval_setting_store_fails = false;
    g_signing_mode_store_fails = false;
    g_sui_account_settings_store_fails = false;
    g_root_wipe_fails = false;
    g_signing_mode_wipe_fails = false;
    g_sui_account_settings_wipe_fails = false;
    g_approval_history_wipe_fails = false;
    g_policy_update_marker_wipe_fails = false;
    g_zklogin_proof_wipe_fails = false;
    g_persist_state_fails = false;
    g_policy_status = signing::PolicyStoreStatus::missing;
    g_auth_status = signing::LocalAuthStatus::missing;
    g_signing_mode_status = signing::AuthorizationModeStatus::missing;
    g_signing_mode = signing::AuthorizationMode::user;
    g_sui_account_settings = signing::kDefaultSuiAccountSettings;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::missing;
    g_human_approval_input_mode = signing::HumanApprovalInputMode::pin;
    g_human_approval_setting_status = signing::HumanApprovalInputModeStatus::missing;
    g_policy_update_marker_status = signing::PolicyUpdateMarkerStatus::clear;
    g_zklogin_proof_status = signing::SuiZkLoginProofRecordStatus::missing;
    g_approval_history_status = signing::ApprovalHistoryStorageStatus::missing;
    g_persisted_state = signing::ProvisioningPersistedState::unprovisioned;
    g_consistency_error_count = 0;
    signing::persistent_material_begin_load();
}

bool persist_state(signing::ProvisioningPersistedState state)
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

signing::PersistentMaterialOps ops()
{
    return signing::PersistentMaterialOps{
        persist_state,
        on_consistency_error,
    };
}

}  // namespace

namespace signing {

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
    g_policy_status = PolicyStoreStatus::active;
    return true;
}

bool wipe_policy()
{
    g_policy_present = false;
    g_policy_status = PolicyStoreStatus::missing;
    return true;
}

PolicyStoreStatus active_policy_status()
{
    return g_policy_status;
}

bool read_active_policy_summary(StoredPolicySummary*)
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
    g_auth_status = LocalAuthStatus::active;
    return true;
}

bool prepare_local_pin_verifier_record(const char* pin, LocalAuthPreparedRecord* out)
{
    if (!is_valid_local_pin(pin) || out == nullptr) {
        return false;
    }
    memset(out->bytes, 0, sizeof(out->bytes));
    memcpy(out->bytes, pin, kLocalPinBufferSize);
    return true;
}

bool store_prepared_local_pin_verifier(const LocalAuthPreparedRecord* prepared)
{
    if (prepared == nullptr || g_auth_store_fails) {
        return false;
    }
    const char* pin = reinterpret_cast<const char*>(prepared->bytes);
    if (!is_valid_local_pin(pin)) {
        return false;
    }
    g_auth_present = true;
    g_auth_status = LocalAuthStatus::active;
    return true;
}

void wipe_local_pin_verifier_record(LocalAuthPreparedRecord* prepared)
{
    if (prepared != nullptr) {
        memset(prepared->bytes, 0, sizeof(prepared->bytes));
    }
}

bool verify_local_pin(const char*, bool*)
{
    return false;
}

bool clear_local_auth()
{
    g_auth_present = false;
    g_auth_status = LocalAuthStatus::missing;
    return true;
}

LocalAuthStatus local_auth_status()
{
    return g_auth_status;
}

bool read_signing_authorization_mode(AuthorizationMode* mode)
{
    if (mode == nullptr || !g_signing_mode_present ||
        g_signing_mode_status != AuthorizationModeStatus::active) {
        return false;
    }
    *mode = g_signing_mode;
    return true;
}

bool store_signing_authorization_mode(AuthorizationMode mode)
{
    if (g_signing_mode_store_fails) {
        return false;
    }
    g_signing_mode_present = true;
    g_signing_mode_status = AuthorizationModeStatus::active;
    g_signing_mode = mode;
    return true;
}

bool wipe_signing_authorization_mode()
{
    if (g_signing_mode_wipe_fails) {
        return false;
    }
    g_signing_mode_present = false;
    g_signing_mode_status = AuthorizationModeStatus::missing;
    g_signing_mode = AuthorizationMode::user;
    return true;
}

AuthorizationModeStatus authorization_mode_status()
{
    return g_signing_mode_status;
}

const char* authorization_mode_name(AuthorizationMode mode)
{
    return mode == AuthorizationMode::policy ? "policy" : "user";
}

bool read_sui_account_settings(SuiAccountSettings* settings)
{
    if (settings == nullptr || !g_sui_account_settings_present ||
        g_sui_account_settings_status != SuiAccountSettingsStatus::active) {
        if (settings != nullptr) {
            *settings = kDefaultSuiAccountSettings;
        }
        return false;
    }
    *settings = g_sui_account_settings;
    return true;
}

bool store_sui_account_settings(const SuiAccountSettings& settings)
{
    if (g_sui_account_settings_store_fails) {
        return false;
    }
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = SuiAccountSettingsStatus::active;
    g_sui_account_settings = settings;
    return true;
}

bool wipe_sui_account_settings()
{
    if (g_sui_account_settings_wipe_fails) {
        return false;
    }
    g_sui_account_settings_present = false;
    g_sui_account_settings_status = SuiAccountSettingsStatus::missing;
    g_sui_account_settings = kDefaultSuiAccountSettings;
    return true;
}

SuiAccountSettingsStatus sui_account_settings_status()
{
    return g_sui_account_settings_status;
}

bool read_human_approval_input_mode(HumanApprovalInputMode* mode)
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

bool store_human_approval_input_mode(HumanApprovalInputMode mode)
{
    if (g_human_approval_setting_store_fails) {
        return false;
    }
    g_human_approval_setting_present = true;
    g_human_approval_setting_status = HumanApprovalInputModeStatus::active;
    g_human_approval_input_mode = mode;
    return true;
}

bool wipe_human_approval_input_mode()
{
    g_human_approval_setting_present = false;
    g_human_approval_setting_status = HumanApprovalInputModeStatus::missing;
    g_human_approval_input_mode = HumanApprovalInputMode::pin;
    return true;
}

HumanApprovalInputModeStatus human_approval_input_mode_status()
{
    if (g_human_approval_setting_status != HumanApprovalInputModeStatus::missing) {
        return g_human_approval_setting_status;
    }
    return g_human_approval_setting_present
               ? HumanApprovalInputModeStatus::active
               : HumanApprovalInputModeStatus::missing;
}

bool approval_history_wipe()
{
    if (g_approval_history_wipe_fails) {
        return false;
    }
    g_approval_history_present = false;
    g_approval_history_status = ApprovalHistoryStorageStatus::missing;
    return true;
}

ApprovalHistoryStorageStatus approval_history_status()
{
    if (g_approval_history_status != ApprovalHistoryStorageStatus::missing) {
        return g_approval_history_status;
    }
    return g_approval_history_present
               ? ApprovalHistoryStorageStatus::active
               : ApprovalHistoryStorageStatus::missing;
}

PolicyUpdateMarkerStatus policy_update_marker_status()
{
    return g_policy_update_marker_status;
}

PolicyUpdateMarkerBeginResult policy_update_marker_begin(
    const uint8_t*,
    size_t policy_digest_size,
    size_t policy_count,
    PolicyUpdateHighestAction)
{
    if (policy_digest_size != kPolicyUpdateDigestBytes ||
        policy_count > kCurrentPolicyMaxTotalPolicies) {
        return PolicyUpdateMarkerBeginResult::invalid_input;
    }
    g_policy_update_marker_present = true;
    g_policy_update_marker_status = PolicyUpdateMarkerStatus::pending;
    return PolicyUpdateMarkerBeginResult::written;
}

bool policy_update_marker_clear()
{
    if (g_policy_update_marker_wipe_fails) {
        return false;
    }
    g_policy_update_marker_present = false;
    g_policy_update_marker_status = PolicyUpdateMarkerStatus::clear;
    return true;
}

signing::SuiZkLoginProofRecordStatus sui_zklogin_proof_record_status()
{
    return g_zklogin_proof_status;
}

bool wipe_sui_zklogin_proof_record()
{
    if (g_zklogin_proof_wipe_fails) {
        return false;
    }
    g_zklogin_proof_present = false;
    g_zklogin_proof_status = SuiZkLoginProofRecordStatus::missing;
    return true;
}

}  // namespace signing

int main()
{
    using State = signing::ProvisioningRuntimeState;
    using PersistedState = signing::ProvisioningPersistedState;
    using Storage = signing::ProvisioningStateStorageStatus;
    using Consistency = signing::PersistentMaterialConsistencyResult;
    using Commit = signing::PersistentMaterialCommitResult;
    using Wipe = signing::PersistentMaterialWalletEraseResult;
    using SettingsReset = signing::PersistentMaterialSettingsResetResult;

    uint8_t root[signing::kRootMaterialBytes] = {};
    State effective = State::unprovisioned;

    reset_stubs();
    expect(signing::persistent_material_record_runtime_failure(
               signing::PersistentMaterialRuntimeFailure::root_material_unreadable, ops()) ==
               Consistency::consistency_error,
           "runtime material failure is recorded as consistency error");
    expect(signing::persistent_material_consistency_error_active(),
           "runtime material failure latches consistency error");
    expect(signing::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::ok,
           "setup commit succeeds after runtime failure is resolved");
    expect(!signing::persistent_material_consistency_error_active(),
           "setup commit success clears consistency error latch");

    reset_stubs();
    expect(signing::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::ok,
           "setup commit succeeds");
    expect(g_root_present && g_policy_present && g_auth_present &&
               g_signing_mode_present && g_human_approval_setting_present &&
               g_sui_account_settings_present,
           "setup commit stores all required material, signing mode, human approval default, and Sui account settings");
    expect(g_signing_mode == signing::AuthorizationMode::user,
           "setup commit initializes signing mode to user");
    expect(g_human_approval_input_mode == signing::HumanApprovalInputMode::pin,
           "setup commit initializes human approval input mode to PIN");
    expect(!g_sui_account_settings.accept_gas_sponsor,
           "setup commit initializes Sui account settings to reject gas sponsors");
    expect(g_persisted_state == PersistedState::provisioned,
           "setup commit persists provisioned after material");

    reset_stubs();
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_signing_mode = signing::AuthorizationMode::policy;
    expect(signing::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::ok,
           "setup commit succeeds over stale signing mode material");
    expect(g_signing_mode_present && g_signing_mode == signing::AuthorizationMode::user,
           "setup commit reinitializes stale signing mode to user");

    reset_stubs();
    g_human_approval_setting_present = true;
    g_human_approval_input_mode = signing::HumanApprovalInputMode::confirm;
    expect(signing::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::ok,
           "setup commit succeeds over stale human approval input mode material");
    expect(g_human_approval_setting_present &&
               g_human_approval_input_mode == signing::HumanApprovalInputMode::pin,
           "setup commit reinitializes stale human approval input mode to PIN");

    reset_stubs();
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    g_sui_account_settings.accept_gas_sponsor = true;
    expect(signing::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::ok,
           "setup commit succeeds over stale Sui account settings material");
    expect(g_sui_account_settings_present && !g_sui_account_settings.accept_gas_sponsor,
           "setup commit reinitializes stale Sui account settings to reject gas sponsors");

    reset_stubs();
    g_policy_store_fails = true;
    expect(signing::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::policy_storage_error,
           "policy storage failure is reported");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_signing_mode_present && !g_human_approval_setting_present &&
               !g_sui_account_settings_present,
           "policy failure rolls back partial setup material");
    expect(g_consistency_error_count == 0,
           "clean rollback does not enter consistency error");

    reset_stubs();
    g_signing_mode_store_fails = true;
    expect(signing::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::signing_mode_storage_error,
           "signing mode storage failure is reported");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_signing_mode_present && !g_sui_account_settings_present,
           "signing mode failure rolls back partial setup material");
    expect(g_consistency_error_count == 0,
           "clean signing mode rollback does not enter consistency error");

    reset_stubs();
    g_human_approval_setting_store_fails = true;
    expect(signing::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::human_approval_setting_storage_error,
           "human approval input mode storage failure is reported");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_signing_mode_present && !g_human_approval_setting_present &&
               !g_sui_account_settings_present,
           "human approval input mode failure rolls back partial setup material");
    expect(g_consistency_error_count == 0,
           "clean human approval input mode rollback does not enter consistency error");

    reset_stubs();
    g_sui_account_settings_store_fails = true;
    expect(signing::persistent_material_commit_setup(root, sizeof(root), "123456", ops()) ==
               Commit::sui_account_settings_storage_error,
           "Sui account settings storage failure is reported");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_signing_mode_present && !g_human_approval_setting_present &&
               !g_sui_account_settings_present,
           "Sui account settings failure rolls back partial setup material");
    expect(g_consistency_error_count == 0,
           "clean Sui account settings rollback does not enter consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = signing::PolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    g_human_approval_setting_present = true;
    g_approval_history_present = true;
    g_policy_update_marker_present = true;
    g_policy_update_marker_status = signing::PolicyUpdateMarkerStatus::pending;
    g_zklogin_proof_present = true;
    g_zklogin_proof_status = signing::SuiZkLoginProofRecordStatus::active;
    expect(signing::persistent_material_record_runtime_failure(
               signing::PersistentMaterialRuntimeFailure::wallet_erase_root_wipe_failed, ops()) ==
               Consistency::consistency_error,
           "storage maintenance material failure latches consistency error before wipe");
    expect(signing::persistent_material_wallet_erase() == Wipe::ok,
           "Device reset succeeds");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_signing_mode_present && !g_sui_account_settings_present &&
               !g_human_approval_setting_present && !g_approval_history_present &&
               !g_policy_update_marker_present && !g_zklogin_proof_present,
           "Device reset removes required, signing-mode, Sui account settings, reset-scoped settings, approval-history, policy-update marker, and zkLogin proof material");
    expect(!signing::persistent_material_consistency_error_active(),
           "Device reset success clears consistency error latch");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = signing::PolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    expect(!signing::persistent_material_status().complete(),
           "recoverable settings are incomplete when human approval mode is missing");
    expect(!signing::persistent_material_validate_runtime_state(State::provisioned, ops()),
           "provisioned runtime fails closed when human approval mode is missing");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = signing::PolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_signing_mode = signing::AuthorizationMode::policy;
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    g_sui_account_settings.accept_gas_sponsor = true;
    g_human_approval_setting_present = true;
    g_human_approval_input_mode = signing::HumanApprovalInputMode::confirm;
    g_approval_history_present = true;
    g_policy_update_marker_present = true;
    g_policy_update_marker_status = signing::PolicyUpdateMarkerStatus::pending;
    g_zklogin_proof_present = true;
    g_zklogin_proof_status = signing::SuiZkLoginProofRecordStatus::active;
    expect(signing::persistent_material_can_reset_recoverable_settings(),
           "settings repair is available when root and local auth are valid");
    expect(signing::persistent_material_reset_recoverable_settings() == SettingsReset::ok,
           "settings repair succeeds with root and local auth");
    expect(g_root_present && g_auth_present,
           "settings repair preserves signing key material and local auth verifier");
    expect(g_policy_present && g_policy_status == signing::PolicyStoreStatus::active,
           "settings repair restores active default policy");
    expect(g_signing_mode_present && g_signing_mode == signing::AuthorizationMode::user,
           "settings repair restores user signing mode");
    expect(g_human_approval_setting_present &&
               g_human_approval_input_mode == signing::HumanApprovalInputMode::pin,
           "settings repair restores PIN approval mode");
    expect(g_sui_account_settings_present && !g_sui_account_settings.accept_gas_sponsor,
           "settings repair restores default Sui account settings");
    expect(!g_approval_history_present && !g_policy_update_marker_present && !g_zklogin_proof_present,
           "settings repair clears mutable history, pending policy marker, and zkLogin proof");

    reset_stubs();
    g_root_present = true;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    expect(signing::persistent_material_can_reset_recoverable_settings(),
           "settings repair is available with protected key and PIN verifier only");
    expect(signing::persistent_material_reset_recoverable_settings() == SettingsReset::ok,
           "settings repair rebuilds missing mutable settings from protected key and PIN verifier");
    expect(g_root_present && g_auth_present,
           "settings repair still preserves protected key and PIN verifier when mutable settings were missing");
    expect(g_policy_present && g_policy_status == signing::PolicyStoreStatus::active &&
               g_signing_mode_present && g_sui_account_settings_present &&
               g_human_approval_setting_present,
           "settings repair creates all required mutable defaults from missing settings");

    reset_stubs();
    g_root_present = true;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::invalid;
    expect(!signing::persistent_material_can_reset_recoverable_settings(),
           "settings repair is unavailable when local auth verifier is invalid");
    expect(signing::persistent_material_reset_recoverable_settings() == SettingsReset::auth_unavailable,
           "settings repair does not recreate a missing or invalid local auth verifier");
    expect(g_root_present && g_auth_present,
           "failed settings repair preserves key and invalid auth material for fail-closed handling");

    reset_stubs();
    g_policy_update_marker_status = signing::PolicyUpdateMarkerStatus::pending;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::missing, nullptr, &effective, ops()) ==
               Consistency::consistency_error,
           "missing state with policy-update marker fails closed");
    expect(g_consistency_error_count == 1,
           "missing state with policy-update marker reports consistency error");

    reset_stubs();
    g_zklogin_proof_present = true;
    g_zklogin_proof_status = signing::SuiZkLoginProofRecordStatus::active;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::missing, nullptr, &effective, ops()) ==
               Consistency::consistency_error,
           "missing state with zkLogin proof material fails closed");
    expect(g_consistency_error_count == 1,
           "missing state with zkLogin proof material reports consistency error");

    reset_stubs();
    g_approval_history_present = true;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::missing, nullptr, &effective, ops()) ==
               Consistency::consistency_error,
           "missing state with approval history material fails closed");
    expect(g_consistency_error_count == 1,
           "missing state with approval history material reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = signing::PolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    g_policy_update_marker_present = true;
    g_policy_update_marker_status = signing::PolicyUpdateMarkerStatus::pending;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "pending policy-update marker blocks provisioned material readiness");
    expect(g_consistency_error_count == 1,
           "pending policy-update marker reports consistency error");

    reset_stubs();
    g_policy_update_marker_present = true;
    g_policy_update_marker_status = signing::PolicyUpdateMarkerStatus::pending;
    g_policy_update_marker_wipe_fails = true;
    expect(signing::persistent_material_wallet_erase() == Wipe::policy_update_marker_wipe_error,
           "policy-update marker wipe failure is reported");
    expect(g_policy_update_marker_present,
           "failed policy-update marker wipe leaves marker for caller-owned fail-closed handling");

    reset_stubs();
    g_zklogin_proof_present = true;
    g_zklogin_proof_status = signing::SuiZkLoginProofRecordStatus::active;
    g_zklogin_proof_wipe_fails = true;
    expect(signing::persistent_material_wallet_erase() == Wipe::zklogin_proof_wipe_error,
           "zkLogin proof wipe failure is reported");
    expect(g_zklogin_proof_present,
           "failed zkLogin proof wipe leaves proof for caller-owned fail-closed handling");

    reset_stubs();
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_signing_mode_wipe_fails = true;
    expect(signing::persistent_material_wallet_erase() == Wipe::signing_mode_wipe_error,
           "signing mode wipe failure is reported");
    expect(g_signing_mode_present,
           "failed signing mode wipe leaves signing mode for caller-owned fail-closed handling");

    reset_stubs();
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    g_sui_account_settings_wipe_fails = true;
    expect(signing::persistent_material_wallet_erase() == Wipe::sui_account_settings_wipe_error,
           "Sui account settings wipe failure is reported");
    expect(g_sui_account_settings_present,
           "failed Sui account settings wipe leaves settings for caller-owned fail-closed handling");

    reset_stubs();
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::missing, nullptr, &effective, ops()) ==
               Consistency::ok,
           "missing state without material is valid unprovisioned");
    expect(effective == State::unprovisioned,
           "missing state effective state remains unprovisioned");

    reset_stubs();
    g_root_present = true;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::missing, nullptr, &effective, ops()) ==
               Consistency::consistency_error,
           "missing state with material fails closed");
    expect(g_consistency_error_count == 1,
           "missing state with material reports consistency error");
    expect(signing::persistent_material_consistency_error_active(),
           "missing state with material latches persistent material error");

    reset_stubs();
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_signing_mode = signing::AuthorizationMode::policy;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::missing, nullptr, &effective, ops()) ==
               Consistency::consistency_error,
           "missing state with signing mode material fails closed");
    expect(g_consistency_error_count == 1,
           "missing state with signing mode material reports consistency error");

    reset_stubs();
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::missing, nullptr, &effective, ops()) ==
               Consistency::consistency_error,
           "missing state with Sui account settings fails closed");
    expect(g_consistency_error_count == 1,
           "missing state with Sui account settings reports consistency error");

    reset_stubs();
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::unreadable, nullptr, &effective, ops()) ==
               Consistency::state_storage_error,
           "unreadable state fails closed");
    expect(g_consistency_error_count == 1,
           "unreadable state reports consistency error");
    expect(signing::persistent_material_consistency_error_active(),
           "unreadable state latches persistent material error");

    reset_stubs();
    g_persisted_state = PersistedState::provisioned;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "unknown", &effective, ops()) ==
               Consistency::consistency_error,
           "unknown state without material fails closed");
    expect(g_persisted_state == PersistedState::provisioned,
           "unknown state is not normalized to unprovisioned");
    expect(g_consistency_error_count == 1,
           "unknown state without material reports consistency error");
    expect(signing::persistent_material_consistency_error_active(),
           "unknown state without material latches persistent material error");

    reset_stubs();
    g_root_present = true;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "unknown", &effective, ops()) ==
               Consistency::consistency_error,
           "unknown state with material fails closed");
    expect(g_consistency_error_count == 1,
           "unknown state with material reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = signing::PolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    g_zklogin_proof_status = signing::SuiZkLoginProofRecordStatus::invalid;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "complete provisioned material with invalid zkLogin proof fails closed");
    expect(g_consistency_error_count == 1,
           "invalid zkLogin proof under provisioned state reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = signing::PolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    g_approval_history_status = signing::ApprovalHistoryStorageStatus::invalid;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "complete provisioned material with invalid approval history fails closed");
    expect(g_consistency_error_count == 1,
           "invalid approval history under provisioned state reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = signing::PolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    g_human_approval_setting_present = true;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::ok,
           "complete native provisioned material is valid");
    expect(effective == State::provisioned,
           "complete native provisioned material loads provisioned state");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = signing::PolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    g_human_approval_setting_present = true;
    g_zklogin_proof_present = true;
    g_zklogin_proof_status = signing::SuiZkLoginProofRecordStatus::active;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::ok,
           "complete zkLogin provisioned material is valid");
    expect(effective == State::provisioned,
           "complete zkLogin provisioned material loads provisioned state");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = signing::PolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "provisioned material without signing mode fails closed");
    expect(g_consistency_error_count == 1,
           "missing signing mode reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = signing::PolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "provisioned material without Sui account settings fails closed");
    expect(g_consistency_error_count == 1,
           "missing Sui account settings reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_present = true;
    g_policy_status = signing::PolicyStoreStatus::active;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::invalid;
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "invalid signing mode under provisioned state fails closed");
    expect(g_consistency_error_count == 1,
           "invalid signing mode reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "provisioned root plus auth without active policy fails closed");
    expect(g_consistency_error_count == 1,
           "missing active policy reports consistency error");

    reset_stubs();
    g_root_present = true;
    g_policy_status = signing::PolicyStoreStatus::invalid;
    g_auth_present = true;
    g_auth_status = signing::LocalAuthStatus::active;
    g_signing_mode_present = true;
    g_signing_mode_status = signing::AuthorizationModeStatus::active;
    g_sui_account_settings_present = true;
    g_sui_account_settings_status = signing::SuiAccountSettingsStatus::active;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "provisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "invalid policy under provisioned state fails closed");
    expect(g_consistency_error_count == 1,
           "invalid policy reports consistency error");

    reset_stubs();
    g_root_present = true;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "unprovisioned", &effective, ops()) ==
               Consistency::consistency_error,
           "material outside provisioned state fails closed");

    reset_stubs();
    g_persisted_state = PersistedState::provisioned;
    expect(signing::persistent_material_validate_loaded_storage_state(Storage::present, "provisioning", &effective, ops()) ==
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
  -I"${RUNTIME_DIR}" -I"${TMP_DIR}/firmware_common" \
  "${TMP_DIR}/persistent_material_test.cpp" \
  "${RUNTIME_DIR}/persistent_material.cpp" \
  -o "${TMP_DIR}/persistent_material_test"

"${TMP_DIR}/persistent_material_test"
