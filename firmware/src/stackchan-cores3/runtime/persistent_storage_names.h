#pragma once

namespace signing {

// Protected authority records. These names are the current keystore contract
// and must not be renamed as part of mutable settings repair.
constexpr const char* kSigningKeyMaterialNvsNamespace = "signing";
constexpr const char* kAuthorityGateNvsNamespace = kSigningKeyMaterialNvsNamespace;

// Stable device identity is not signing key material, authority-gate material,
// or recoverable mutable settings.
constexpr const char* kDeviceIdentityNvsNamespace = "device_identity";

// Mutable settings records may be rebuilt by settings repair.
constexpr const char* kMutableSettingsNvsNamespace = "signing_state";

}  // namespace signing
