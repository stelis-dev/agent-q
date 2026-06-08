#pragma once

// Test-only entry point. Product code stores the PIN verifier via the
// prepared-record path (prepare_local_pin_verifier_record +
// store_prepared_local_pin_verifier); this one-shot variant exists only for host
// tests, so it is declared here rather than in the product header. Defined in
// agent_q_local_auth.cpp.
#include "agent_q_local_auth.h"

namespace agent_q {

bool store_local_pin_verifier(const char* pin);

}  // namespace agent_q
