#pragma once

#include "protocol/session_id.h"

namespace signing {

void session_init();
bool session_active();
const char* session_id();
void session_clear();
SessionStartResult session_replace(
    SessionRandomFn random_fn,
    void* random_context);
SessionValidationResult session_validate(const char* session_id);

}  // namespace signing
