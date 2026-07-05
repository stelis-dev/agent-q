#pragma once

#include "protocol/session_id.h"

namespace stopwatch_target {

using signing::kSessionAdvertisedTtlMs;
using signing::kSessionIdSize;
using signing::SessionRandomFn;
using signing::SessionStartResult;
using signing::SessionValidationResult;
using signing::session_id_format_valid;

void session_state_init();
bool session_state_active();
const char* session_state_id();
void session_state_clear();
SessionStartResult session_state_replace(SessionRandomFn random_fn, void* random_context);
SessionValidationResult session_state_validate(const char* session_id);

}  // namespace stopwatch_target
