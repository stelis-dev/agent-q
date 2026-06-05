#pragma once

#include "agent_q_signing_mode.h"

namespace agent_q {

enum class AgentQSigningMethod {
    unsupported,
    sui_sign_transaction,
    sui_sign_personal_message,
};

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
    switch (method) {
        case AgentQSigningMethod::sui_sign_transaction:
            return "sign_transaction";
        case AgentQSigningMethod::sui_sign_personal_message:
            return "sign_personal_message";
        case AgentQSigningMethod::unsupported:
        default:
            return "";
    }
}

inline const char* signing_method_wire_chain(AgentQSigningMethod method)
{
    switch (method) {
        case AgentQSigningMethod::sui_sign_transaction:
        case AgentQSigningMethod::sui_sign_personal_message:
            return "sui";
        case AgentQSigningMethod::unsupported:
        default:
            return "";
    }
}

}  // namespace agent_q
