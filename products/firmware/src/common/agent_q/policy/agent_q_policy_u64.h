#pragma once

#include <stddef.h>
#include <string.h>

namespace agent_q {

constexpr size_t kAgentQPolicyMaxU64DecimalDigits = 20;
constexpr const char* kAgentQPolicyMaxU64DecimalString = "18446744073709551615";

inline bool agent_q_policy_is_decimal_u64_string(const char* value)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }

    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
        ++length;
        if (length > kAgentQPolicyMaxU64DecimalDigits) {
            return false;
        }
    }
    if (length == kAgentQPolicyMaxU64DecimalDigits &&
        strcmp(value, kAgentQPolicyMaxU64DecimalString) > 0) {
        return false;
    }
    return true;
}

inline bool agent_q_policy_is_canonical_decimal_u64_string(const char* value)
{
    if (!agent_q_policy_is_decimal_u64_string(value)) {
        return false;
    }
    return value[0] != '0' || value[1] == '\0';
}

inline const char* agent_q_policy_skip_leading_zeroes(const char* value)
{
    while (value[0] == '0' && value[1] != '\0') {
        ++value;
    }
    return value;
}

inline int agent_q_policy_compare_decimal_u64_strings(const char* left, const char* right)
{
    const char* normalized_left = agent_q_policy_skip_leading_zeroes(left);
    const char* normalized_right = agent_q_policy_skip_leading_zeroes(right);
    const size_t left_len = strlen(normalized_left);
    const size_t right_len = strlen(normalized_right);
    if (left_len < right_len) {
        return -1;
    }
    if (left_len > right_len) {
        return 1;
    }
    const int cmp = strcmp(normalized_left, normalized_right);
    if (cmp < 0) {
        return -1;
    }
    if (cmp > 0) {
        return 1;
    }
    return 0;
}

}  // namespace agent_q
