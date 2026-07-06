#pragma once

#include <stddef.h>
#include <stdint.h>

#include "policy/document.h"

namespace signing {

enum class PolicyUpdateMarkerStatus {
    clear,
    pending,
    invalid,
    storage_error,
};

enum class PolicyUpdateHighestAction {
    reject,
    sign,
};

enum class PolicyUpdateMarkerBeginResult {
    written,
    invalid_input,
    storage_error,
    pending_after_error,
};

constexpr size_t kPolicyUpdateDigestBytes = 32;

PolicyUpdateMarkerStatus policy_update_marker_status();
PolicyUpdateMarkerBeginResult policy_update_marker_begin(
    const uint8_t* policy_digest,
    size_t policy_digest_size,
    size_t policy_count,
    PolicyUpdateHighestAction highest_action);
bool policy_update_marker_clear();

}  // namespace signing
