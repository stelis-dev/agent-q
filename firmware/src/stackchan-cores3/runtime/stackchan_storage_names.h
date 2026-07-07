#pragma once

namespace signing {

// StackChan stores root signing material and the local authority gate in the
// same protected namespace. This is target storage layout, not a shared
// protocol contract.
constexpr const char* kStackChanSigningKeyMaterialNvsNamespace = "signing";
constexpr const char* kStackChanAuthorityGateNvsNamespace =
    kStackChanSigningKeyMaterialNvsNamespace;

// StackChan's stable device id is target-local storage state.
constexpr const char* kStackChanDeviceIdentityNvsNamespace = "device_identity";

}  // namespace signing
