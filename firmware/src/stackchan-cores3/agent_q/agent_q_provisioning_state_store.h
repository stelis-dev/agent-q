#pragma once

#include <stddef.h>

#include "agent_q_persistent_material.h"

namespace agent_q {

constexpr size_t kAgentQProvisioningStateStoreValueSize = 16;

struct AgentQProvisioningStateStoreRecord {
    AgentQProvisioningStateStorageStatus status;
    char value[kAgentQProvisioningStateStoreValueSize];
};

bool provisioning_state_store_load(AgentQProvisioningStateStoreRecord* output);
bool provisioning_state_store_save(AgentQProvisioningPersistedState state);

}  // namespace agent_q
