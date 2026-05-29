#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_bip39.h"

namespace agent_q {

constexpr size_t kRootMaterialBytes = kBip39EntropyBytes;

bool has_root_material();
bool store_root_material(const uint8_t* root_material, size_t root_material_size);
bool wipe_root_material();

}  // namespace agent_q
