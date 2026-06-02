#pragma once

#include <string.h>

#include <ArduinoJson.h>

namespace agent_q {

inline bool agent_q_json_is_whitespace(char value)
{
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

inline bool agent_q_json_line_is_single_object(const char* line)
{
    if (line == nullptr) {
        return false;
    }

    const char* cursor = line;
    while (agent_q_json_is_whitespace(*cursor)) {
        ++cursor;
    }
    if (*cursor != '{') {
        return false;
    }

    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    bool complete = false;

    for (; *cursor != '\0'; ++cursor) {
        const char value = *cursor;
        if (in_string) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (value == '\\') {
                escaped = true;
                continue;
            }
            if (value == '"') {
                in_string = false;
            }
            continue;
        }

        if (complete) {
            if (!agent_q_json_is_whitespace(value)) {
                return false;
            }
            continue;
        }

        if (value == '"') {
            in_string = true;
            continue;
        }
        if (value == '{' || value == '[') {
            ++depth;
            continue;
        }
        if (value == '}' || value == ']') {
            --depth;
            if (depth < 0) {
                return false;
            }
            if (depth == 0) {
                complete = true;
            }
        }
    }

    return complete && !in_string && !escaped && depth == 0;
}

inline bool agent_q_json_string_equals(JsonString value, const char* expected)
{
    if (!value || value.c_str() == nullptr || expected == nullptr) {
        return false;
    }
    const size_t expected_length = strlen(expected);
    return value.size() == expected_length &&
           memcmp(value.c_str(), expected, expected_length) == 0;
}

inline bool agent_q_json_value_c_string(JsonVariantConst value, const char** output)
{
    if (output == nullptr) {
        return false;
    }
    *output = nullptr;
    if (!value.is<JsonString>()) {
        return false;
    }
    const JsonString string = value.as<JsonString>();
    if (!string || string.c_str() == nullptr) {
        return false;
    }
    if (string.size() != strlen(string.c_str())) {
        return false;
    }
    *output = string.c_str();
    return true;
}

inline bool agent_q_json_optional_c_string(
    JsonVariantConst value,
    const char* default_value,
    const char** output)
{
    if (output == nullptr) {
        return false;
    }
    if (value.isNull()) {
        *output = default_value;
        return true;
    }
    return agent_q_json_value_c_string(value, output);
}

}  // namespace agent_q
