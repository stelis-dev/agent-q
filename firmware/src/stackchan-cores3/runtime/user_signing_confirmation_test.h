#pragma once

// Test-only entry point: reports whether confirmation PIN entry is active, for
// host tests. The product reads this state internally and does not call this
// accessor, so it is declared here rather than in the product header. Defined in
// user_signing_confirmation.cpp.
#include "user_signing_confirmation.h"

namespace signing {

bool user_signing_confirmation_pin_active();

}  // namespace signing
