#pragma once

#include "agent_q_sign_route.h"
#include "agent_q_signing_mode.h"

namespace agent_q {

using AgentQSigningRoute = AgentQSupportedSignRoute;

inline bool signing_route_allowed_for_authorization_mode(
    AgentQSigningRoute route,
    AgentQSigningAuthorizationMode mode)
{
    if (route == AgentQSigningRoute::sui_sign_transaction) {
        return true;
    }
    return route == AgentQSigningRoute::sui_sign_personal_message &&
           mode == AgentQSigningAuthorizationMode::user;
}

inline bool signing_route_requires_message_bytes(AgentQSigningRoute route)
{
    return route == AgentQSigningRoute::sui_sign_personal_message;
}

inline const char* signing_route_wire_method(AgentQSigningRoute route)
{
    return sign_route_wire_method(route);
}

inline const char* signing_route_wire_chain(AgentQSigningRoute route)
{
    return sign_route_wire_chain(route);
}

}  // namespace agent_q
