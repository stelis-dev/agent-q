#pragma once

// Test-only entry points for the user signing flow. These query the flow's
// internal state for host tests; the product itself does not call them (its own
// critical-section and session guards read the flow state directly). They are
// declared here, not in user_signing_flow.h, so the product API surface
// does not advertise test seams. The definitions live in
// user_signing_flow.cpp.
#include "user_signing_flow.h"

namespace signing {

bool user_signing_flow_in_signing_critical_section();
SessionValidationResult user_signing_flow_validate_session();

}  // namespace signing
