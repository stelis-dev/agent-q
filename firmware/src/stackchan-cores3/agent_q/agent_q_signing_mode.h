#pragma once

namespace agent_q {

enum class AgentQSigningAuthorizationMode {
    user,
    policy,
};

enum class AgentQSigningAuthorizationModeStatus {
    missing,
    active,
    invalid,
    unreadable,
};

bool read_signing_authorization_mode(AgentQSigningAuthorizationMode* mode);
bool store_signing_authorization_mode(AgentQSigningAuthorizationMode mode);
bool wipe_signing_authorization_mode();
AgentQSigningAuthorizationModeStatus signing_authorization_mode_status();
const char* signing_authorization_mode_name(AgentQSigningAuthorizationMode mode);

}  // namespace agent_q
