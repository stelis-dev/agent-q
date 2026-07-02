#pragma once

#include <stddef.h>

#include "numeric/u64_decimal.h"

namespace signing {

constexpr size_t kPolicyMaxU64DecimalDigits = kU64DecimalMaxDigits;
constexpr const char* kPolicyMaxU64DecimalString = kU64DecimalMaxString;

inline bool policy_is_decimal_u64_string(const char* value)
{
    return is_u64_decimal_string(value);
}

inline bool policy_is_canonical_decimal_u64_string(const char* value)
{
    return is_canonical_u64_decimal_string(value);
}

inline const char* policy_skip_leading_zeroes(const char* value)
{
    return skip_u64_decimal_leading_zeroes(value);
}

inline int policy_compare_decimal_u64_strings(const char* left, const char* right)
{
    return compare_u64_decimal_strings(left, right);
}

}  // namespace signing
