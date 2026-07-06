#pragma once

#include "protocol/sign_route.h"
#include "protocol/signing_mode.h"

namespace signing {

using Route = SupportedSignRoute;

inline bool signing_route_allowed_for_authorization_mode(
    Route route,
    AuthorizationMode mode)
{
    if (route == Route::sui_sign_transaction) {
        return true;
    }
    return route == Route::sui_sign_personal_message &&
           mode == AuthorizationMode::user;
}

inline bool signing_route_requires_message_bytes(Route route)
{
    return route == Route::sui_sign_personal_message;
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
