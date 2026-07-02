#pragma once

#include <stddef.h>

namespace signing {

enum class SignOperation {
    sign_transaction,
    sign_personal_message,
};

enum class SupportedSignRoute {
    unsupported,
    sui_sign_transaction,
    sui_sign_personal_message,
};

enum class SignRouteResult {
    ok,
    invalid_params,
    unsupported_chain,
    unsupported_method,
};

struct SignRouteClassification {
    SignRouteResult result;
    SupportedSignRoute route;
};

inline const char* sign_route_wire_chain(SupportedSignRoute route)
{
    switch (route) {
        case SupportedSignRoute::sui_sign_transaction:
        case SupportedSignRoute::sui_sign_personal_message:
            return "sui";
        case SupportedSignRoute::unsupported:
        default:
            return "";
    }
}

inline const char* sign_route_wire_method(SupportedSignRoute route)
{
    switch (route) {
        case SupportedSignRoute::sui_sign_transaction:
            return "sign_transaction";
        case SupportedSignRoute::sui_sign_personal_message:
            return "sign_personal_message";
        case SupportedSignRoute::unsupported:
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

inline SignRouteClassification classify_sign_route(
    SignOperation operation,
    const char* chain,
    const char* method)
{
    if (!sign_route_identifier_valid(chain, 32) ||
        !sign_route_identifier_valid(method, 64)) {
        return {
            SignRouteResult::invalid_params,
            SupportedSignRoute::unsupported,
        };
    }

    if (!sign_route_string_equal(chain, "sui")) {
        // Keep chain support explicit. Add a chain case only when its Firmware
        // adapter, Client validation, capabilities, provider surface, tests,
        // docs, and hardware evidence implement the same contract.
        return {
            SignRouteResult::unsupported_chain,
            SupportedSignRoute::unsupported,
        };
    }

    switch (operation) {
        case SignOperation::sign_transaction:
            if (sign_route_string_equal(method, "sign_transaction")) {
                return {
                    SignRouteResult::ok,
                    SupportedSignRoute::sui_sign_transaction,
                };
            }
            break;
        case SignOperation::sign_personal_message:
            if (sign_route_string_equal(method, "sign_personal_message")) {
                return {
                    SignRouteResult::ok,
                    SupportedSignRoute::sui_sign_personal_message,
                };
            }
            break;
    }
    return {
        SignRouteResult::unsupported_method,
        SupportedSignRoute::unsupported,
    };
}

}  // namespace signing
