#pragma once

#include <stddef.h>

namespace signing {

bool init_secure_random_from_early_boot_entropy();
bool secure_random_ready();
bool fill_secure_random(void* output, size_t size);

}  // namespace signing
