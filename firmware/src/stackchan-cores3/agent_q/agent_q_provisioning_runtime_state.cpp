#include "agent_q_provisioning_runtime_state.h"

#include "agent_q_provisioning_state_store.h"
#include "esp_log.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQProvRuntime";
constexpr const char* kProvisioningStateError = "error";

AgentQProvisioningRuntimeState g_state = AgentQProvisioningRuntimeState::unprovisioned;

bool runtime_state_to_persisted(
    AgentQProvisioningRuntimeState runtime_state,
    AgentQProvisioningPersistedState* persisted_state)
{
    if (persisted_state == nullptr) {
        return false;
    }
    switch (runtime_state) {
        case AgentQProvisioningRuntimeState::unprovisioned:
            *persisted_state = AgentQProvisioningPersistedState::unprovisioned;
            return true;
        case AgentQProvisioningRuntimeState::provisioned:
            *persisted_state = AgentQProvisioningPersistedState::provisioned;
            return true;
        case AgentQProvisioningRuntimeState::provisioning:
        default:
            return false;
    }
}

}  // namespace

void provisioning_runtime_state_load(
    const AgentQLocalResetPersistenceOps& reset_ops,
    const AgentQPersistentMaterialOps& material_ops)
{
    g_state = AgentQProvisioningRuntimeState::unprovisioned;
    persistent_material_begin_load();

    bool reset_marker_present = false;
    const AgentQLocalResetCommitResult reset_result =
        local_reset_resume_pending_if_needed(reset_ops, &reset_marker_present);
    if (reset_marker_present) {
        ESP_LOGW(kTag, "Found pending local reset marker; resuming material wipe before loading state");
        if (reset_result == AgentQLocalResetCommitResult::ok) {
            ESP_LOGW(kTag, "Pending local reset completed during boot");
        } else if (!persistent_material_consistency_error_active()) {
            persistent_material_record_runtime_failure(
                AgentQPersistentMaterialRuntimeFailure::pending_reset_resume_failed,
                material_ops);
        }
        return;
    }

    AgentQProvisioningStateStoreRecord stored_state = {};
    if (!provisioning_state_store_load(&stored_state)) {
        stored_state.status = AgentQProvisioningStateStorageStatus::unreadable;
        stored_state.value[0] = '\0';
    }

    AgentQProvisioningRuntimeState effective_state =
        AgentQProvisioningRuntimeState::unprovisioned;
    const AgentQPersistentMaterialConsistencyResult consistency_result =
        persistent_material_validate_loaded_storage_state(
            stored_state.status,
            stored_state.value,
            &effective_state,
            material_ops);
    if (stored_state.status == AgentQProvisioningStateStorageStatus::missing &&
               consistency_result == AgentQPersistentMaterialConsistencyResult::ok) {
        ESP_LOGI(kTag, "Provisioning state not found in NVS; using unprovisioned");
    }

    g_state = effective_state;
    ESP_LOGI(kTag, "Loaded provisioning state from NVS: %s",
             provisioning_runtime_state_to_string(g_state));
}

bool provisioning_runtime_state_persist(AgentQProvisioningRuntimeState next_state)
{
    AgentQProvisioningPersistedState persisted_state =
        AgentQProvisioningPersistedState::unprovisioned;
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
    return g_state == AgentQProvisioningRuntimeState::unprovisioned &&
           !persistent_material_consistency_error_active();
}

bool provisioning_runtime_state_is_provisioned()
{
    return g_state == AgentQProvisioningRuntimeState::provisioned &&
           !persistent_material_consistency_error_active();
}

bool provisioning_runtime_state_refresh(const AgentQPersistentMaterialOps& material_ops)
{
    if (persistent_material_consistency_error_active()) {
        return false;
    }

    return persistent_material_validate_runtime_state(g_state, material_ops);
}

bool provisioning_runtime_state_material_ready(const AgentQPersistentMaterialOps& material_ops)
{
    return g_state == AgentQProvisioningRuntimeState::provisioned &&
           provisioning_runtime_state_refresh(material_ops);
}

}  // namespace agent_q
