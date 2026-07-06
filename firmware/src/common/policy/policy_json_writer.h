#pragma once

#include <stddef.h>

#include <ArduinoJson.h>

#include "policy/document.h"

namespace signing {

bool write_current_policy_json(
    JsonObject policy_json,
    const char* schema,
    const char* policy_id,
    const char* default_action,
    size_t blockchain_count,
    size_t network_count,
    size_t policy_count,
    size_t condition_count,
    const CurrentPolicyDocument* document);

}  // namespace signing
