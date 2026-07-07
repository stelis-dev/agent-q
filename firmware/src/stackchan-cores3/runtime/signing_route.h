#pragma once

#include "protocol/sign_route.h"
#include "protocol/signing_mode.h"

namespace signing {

using Route = SupportedSignRoute;

inline bool signing_route_allowed_for_authorization_mode(
    Route route,
    AuthorizationMode mode)
{
    return sign_route_allowed_for_authorization_mode(route, mode);
}

inline bool signing_route_requires_message_bytes(Route route)
{
    return sign_route_requires_message_bytes(route);
}

inline const char* signing_route_wire_method(Route route)
{
    return sign_route_wire_method(route);
}

inline const char* signing_route_wire_chain(Route route)
{
    return sign_route_wire_chain(route);
}

}  // namespace signing
