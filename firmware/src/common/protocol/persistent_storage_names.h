#pragma once

namespace signing {

// Shared mutable product settings records may be rebuilt by settings repair.
// Target-specific signing material, authority-gate material, and device
// identity storage names stay with the target that owns that storage layout.
constexpr const char* kMutableSettingsNvsNamespace = "signing_state";

}  // namespace signing
