#pragma once

#include "local_reset.h"
#include "persistent_material.h"

namespace signing {

void provisioning_runtime_state_load(
    const LocalResetPersistenceOps& reset_ops,
    const PersistentMaterialOps& material_ops);
bool provisioning_runtime_state_persist(ProvisioningRuntimeState next_state);
const char* provisioning_runtime_state_reported();
bool provisioning_runtime_state_is_unprovisioned();
bool provisioning_runtime_state_is_provisioned();
bool provisioning_runtime_state_refresh(const PersistentMaterialOps& material_ops);
bool provisioning_runtime_state_material_ready(const PersistentMaterialOps& material_ops);

}  // namespace signing
