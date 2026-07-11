#pragma once

namespace signing {

// StackChan stores the encrypted keyslot and encrypted private-material
// records in this target-local namespace.
constexpr const char* kStackChanSigningKeyMaterialNvsNamespace = "signing";

// StackChan's stable device id is target-local storage state.
constexpr const char* kStackChanDeviceIdentityNvsNamespace = "device_identity";

}  // namespace signing
