#pragma once

#include <stddef.h>

#include "persistent_material.h"

namespace signing {

constexpr size_t kProvisioningStateStoreValueSize = 16;

struct ProvisioningStateStoreRecord {
    ProvisioningStateStorageStatus status;
    char value[kProvisioningStateStoreValueSize];
};

bool provisioning_state_store_load(ProvisioningStateStoreRecord* output);
bool provisioning_state_store_save(ProvisioningPersistedState state);

}  // namespace signing
