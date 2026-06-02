#pragma once

#include "agent_q_local_reset.h"
#include "agent_q_persistent_material.h"

namespace agent_q {

void provisioning_runtime_state_load(
    const AgentQLocalResetPersistenceOps& reset_ops,
    const AgentQPersistentMaterialOps& material_ops);
bool provisioning_runtime_state_persist(AgentQProvisioningRuntimeState next_state);
const char* provisioning_runtime_state_reported();
bool provisioning_runtime_state_is_unprovisioned();
bool provisioning_runtime_state_is_provisioned();
bool provisioning_runtime_state_refresh(const AgentQPersistentMaterialOps& material_ops);
bool provisioning_runtime_state_material_ready(const AgentQPersistentMaterialOps& material_ops);

}  // namespace agent_q
