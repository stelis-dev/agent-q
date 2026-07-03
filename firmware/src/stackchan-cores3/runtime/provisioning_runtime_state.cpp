#include "provisioning_runtime_state.h"

#include "provisioning_state_store.h"
#include "esp_log.h"

namespace signing {
namespace {

constexpr const char* kTag = "ProvRuntime";
constexpr const char* kProvisioningStateError = "error";

ProvisioningRuntimeState g_state = ProvisioningRuntimeState::unprovisioned;

bool runtime_state_to_persisted(
    ProvisioningRuntimeState runtime_state,
    ProvisioningPersistedState* persisted_state)
{
    if (persisted_state == nullptr) {
        return false;
    }
    switch (runtime_state) {
        case ProvisioningRuntimeState::unprovisioned:
            *persisted_state = ProvisioningPersistedState::unprovisioned;
            return true;
        case ProvisioningRuntimeState::provisioned:
            *persisted_state = ProvisioningPersistedState::provisioned;
            return true;
        case ProvisioningRuntimeState::provisioning:
        default:
            return false;
    }
}

}  // namespace

void provisioning_runtime_state_load(
    const StorageMaintenancePersistenceOps& reset_ops,
    const PersistentMaterialOps& material_ops)
{
    g_state = ProvisioningRuntimeState::unprovisioned;
    persistent_material_begin_load();

    bool storage_action_marker_present = false;
    const StorageMaintenanceCommitResult reset_result =
        storage_maintenance_resume_pending_if_needed(reset_ops, &storage_action_marker_present);
    if (storage_action_marker_present) {
        ESP_LOGW(kTag, "Found pending storage action marker; resuming storage action before loading state");
        if (reset_result == StorageMaintenanceCommitResult::ok) {
            ESP_LOGW(kTag, "Pending storage action completed during boot");
        } else if (!persistent_material_consistency_error_active()) {
            persistent_material_record_runtime_failure(
                PersistentMaterialRuntimeFailure::pending_storage_action_resume_failed,
                material_ops);
        }
        return;
    }

    ProvisioningStateStoreRecord stored_state = {};
    if (!provisioning_state_store_load(&stored_state)) {
        stored_state.status = ProvisioningStateStorageStatus::unreadable;
        stored_state.value[0] = '\0';
    }

    ProvisioningRuntimeState effective_state =
        ProvisioningRuntimeState::unprovisioned;
    const PersistentMaterialConsistencyResult consistency_result =
        persistent_material_validate_loaded_storage_state(
            stored_state.status,
            stored_state.value,
            &effective_state,
            material_ops);
    if (stored_state.status == ProvisioningStateStorageStatus::missing &&
               consistency_result == PersistentMaterialConsistencyResult::ok) {
        ESP_LOGI(kTag, "Provisioning state not found in NVS; using unprovisioned");
    }

    g_state = effective_state;
    ESP_LOGI(kTag, "Loaded provisioning state from NVS: %s",
             provisioning_runtime_state_to_string(g_state));
}

bool provisioning_runtime_state_persist(ProvisioningRuntimeState next_state)
{
    ProvisioningPersistedState persisted_state =
        ProvisioningPersistedState::unprovisioned;
    if (!runtime_state_to_persisted(next_state, &persisted_state)) {
        ESP_LOGW(kTag, "Refusing to persist transient provisioning runtime state");
        return false;
    }

    if (!provisioning_state_store_save(persisted_state)) {
        return false;
    }

    g_state = next_state;
    ESP_LOGI(kTag, "Stored provisioning state: %s",
             provisioning_runtime_state_to_string(g_state));
    return true;
}

const char* provisioning_runtime_state_reported()
{
    if (persistent_material_consistency_error_active()) {
        return kProvisioningStateError;
    }
    return provisioning_runtime_state_to_string(g_state);
}

bool provisioning_runtime_state_is_unprovisioned()
{
    return g_state == ProvisioningRuntimeState::unprovisioned &&
           !persistent_material_consistency_error_active();
}

bool provisioning_runtime_state_is_provisioned()
{
    return g_state == ProvisioningRuntimeState::provisioned &&
           !persistent_material_consistency_error_active();
}

bool provisioning_runtime_state_refresh(const PersistentMaterialOps& material_ops)
{
    if (persistent_material_consistency_error_active()) {
        return false;
    }

    return persistent_material_validate_runtime_state(g_state, material_ops);
}

bool provisioning_runtime_state_material_ready(const PersistentMaterialOps& material_ops)
{
    return g_state == ProvisioningRuntimeState::provisioned &&
           provisioning_runtime_state_refresh(material_ops);
}

}  // namespace signing
