#pragma once

#include <stddef.h>

namespace agent_q {

enum class AgentQSignOperation {
    sign_transaction,
    sign_personal_message,
};

enum class AgentQSupportedSignRoute {
    unsupported,
    sui_sign_transaction,
    sui_sign_personal_message,
};

enum class AgentQSignRouteResult {
    ok,
    invalid_params,
    unsupported_chain,
    unsupported_method,
};

struct AgentQSignRouteClassification {
    AgentQSignRouteResult result;
    AgentQSupportedSignRoute route;
};

inline const char* sign_route_wire_chain(AgentQSupportedSignRoute route)
{
    switch (route) {
        case AgentQSupportedSignRoute::sui_sign_transaction:
        case AgentQSupportedSignRoute::sui_sign_personal_message:
            return "sui";
        case AgentQSupportedSignRoute::unsupported:
        default:
            return "";
    }
}

inline const char* sign_route_wire_method(AgentQSupportedSignRoute route)
{
    switch (route) {
        case AgentQSupportedSignRoute::sui_sign_transaction:
            return "sign_transaction";
        case AgentQSupportedSignRoute::sui_sign_personal_message:
            return "sign_personal_message";
        case AgentQSupportedSignRoute::unsupported:
        default:
            return "";
    }
}

inline bool sign_route_identifier_valid(const char* value, size_t max_length)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }
    size_t length = 0;
    for (; value[length] != '\0'; ++length) {
        if (length >= max_length) {
            return false;
        }
        const char ch = value[length];
        if ((ch < 'a' || ch > 'z') &&
            (ch < '0' || ch > '9') &&
            ch != '_' &&
            ch != '.' &&
            ch != '-') {
            return false;
        }
        if (length == 0 && (ch < 'a' || ch > 'z')) {
            return false;
        }
    }
    return length > 0;
}

inline bool sign_route_string_equal(const char* left, const char* right)
{
    if (left == nullptr || right == nullptr) {
        return false;
    }
    size_t index = 0;
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) {
            return false;
        }
        ++index;
    }
    return left[index] == right[index];
}

inline AgentQSignRouteClassification classify_sign_route(
    AgentQSignOperation operation,
    const char* chain,
    const char* method)
{
    if (!sign_route_identifier_valid(chain, 32) ||
        !sign_route_identifier_valid(method, 64)) {
        return {
            AgentQSignRouteResult::invalid_params,
            AgentQSupportedSignRoute::unsupported,
        };
    }

    if (!sign_route_string_equal(chain, "sui")) {
        // TODO: Add a new explicit chain case only when its Firmware adapter,
        // Client validation, capabilities, provider surface, tests, docs, and
        // hardware evidence implement the same contract.
        return {
            AgentQSignRouteResult::unsupported_chain,
            AgentQSupportedSignRoute::unsupported,
        };
    }

    switch (operation) {
        case AgentQSignOperation::sign_transaction:
            if (sign_route_string_equal(method, "sign_transaction")) {
                return {
                    AgentQSignRouteResult::ok,
                    AgentQSupportedSignRoute::sui_sign_transaction,
                };
            }
            break;
        case AgentQSignOperation::sign_personal_message:
            if (sign_route_string_equal(method, "sign_personal_message")) {
                return {
                    AgentQSignRouteResult::ok,
                    AgentQSupportedSignRoute::sui_sign_personal_message,
                };
            }
            break;
    }
    return {
        AgentQSignRouteResult::unsupported_method,
        AgentQSupportedSignRoute::unsupported,
    };
}

}  // namespace agent_q
