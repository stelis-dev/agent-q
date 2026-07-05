#pragma once

#include <stddef.h>

namespace stopwatch_target {

bool secure_random_init();
bool secure_random_ready();
bool secure_random_fill(void* output, size_t size);

}  // namespace stopwatch_target
