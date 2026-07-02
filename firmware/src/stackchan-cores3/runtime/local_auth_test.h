#pragma once

// Test-only entry point. Product code stores the PIN verifier via the
// prepared-record path (prepare_local_pin_verifier_record +
// store_prepared_local_pin_verifier); this one-shot variant exists only for host
// tests, so it is declared here rather than in the product header. Defined in
// local_auth.cpp.
#include "local_auth.h"

namespace signing {

bool store_local_pin_verifier(const char* pin);

}  // namespace signing
