#pragma once

#include <stddef.h>

#include "agent_q_u64_decimal.h"

namespace agent_q {

constexpr size_t kAgentQPolicyMaxU64DecimalDigits = kAgentQU64DecimalMaxDigits;
constexpr const char* kAgentQPolicyMaxU64DecimalString = kAgentQU64DecimalMaxString;

inline bool agent_q_policy_is_decimal_u64_string(const char* value)
{
    return is_u64_decimal_string(value);
}

inline bool agent_q_policy_is_canonical_decimal_u64_string(const char* value)
{
    return is_canonical_u64_decimal_string(value);
}

inline const char* agent_q_policy_skip_leading_zeroes(const char* value)
{
    return skip_u64_decimal_leading_zeroes(value);
}

inline int agent_q_policy_compare_decimal_u64_strings(const char* left, const char* right)
{
    return compare_u64_decimal_strings(left, right);
}

}  // namespace agent_q
