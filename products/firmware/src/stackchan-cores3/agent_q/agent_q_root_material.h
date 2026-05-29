#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_bip39.h"

namespace agent_q {

constexpr size_t kRootMaterialBytes = kBip39EntropyBytes;

bool has_root_material();
bool store_root_material(const uint8_t* root_material, size_t root_material_size);
bool wipe_root_material();

// Read the stored root material into a caller-owned buffer for internal
// derivation only. root_material_size must equal kRootMaterialBytes. Returns
// false (and wipes a non-null output buffer) if no valid root material is
// stored. The caller is responsible for wiping the buffer after use. This accessor is
// internal to Firmware; root material must never be placed in a protocol
// response, log, or UI.
bool read_root_material(uint8_t* root_material_out, size_t root_material_size);

}  // namespace agent_q
