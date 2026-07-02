#pragma once

namespace signing {

enum class AuthorizationMode {
    user,
    policy,
};

enum class AuthorizationModeStatus {
    missing,
    active,
    invalid,
    unreadable,
};

bool read_signing_authorization_mode(AuthorizationMode* mode);
bool store_signing_authorization_mode(AuthorizationMode mode);
bool wipe_signing_authorization_mode();
AuthorizationModeStatus authorization_mode_status();
const char* authorization_mode_name(AuthorizationMode mode);

}  // namespace signing
