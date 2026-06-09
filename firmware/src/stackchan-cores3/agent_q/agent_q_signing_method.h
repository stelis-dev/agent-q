#pragma once

#include "agent_q_sign_route.h"
#include "agent_q_signing_mode.h"

namespace agent_q {

using AgentQSigningMethod = AgentQSupportedSignRoute;

inline bool signing_method_allowed_for_authorization_mode(
    AgentQSigningMethod method,
    AgentQSigningAuthorizationMode mode)
{
    if (method == AgentQSigningMethod::sui_sign_transaction) {
        return true;
    }
    return method == AgentQSigningMethod::sui_sign_personal_message &&
           mode == AgentQSigningAuthorizationMode::user;
}

inline bool signing_method_requires_message_bytes(AgentQSigningMethod method)
{
    return method == AgentQSigningMethod::sui_sign_personal_message;
}

inline const char* signing_method_wire_method(AgentQSigningMethod method)
{
    return sign_route_wire_method(method);
}

inline const char* signing_method_wire_chain(AgentQSigningMethod method)
{
    return sign_route_wire_chain(method);
}

}  // namespace agent_q
