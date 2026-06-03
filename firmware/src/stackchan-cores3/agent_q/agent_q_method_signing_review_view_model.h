#pragma once

#include <stddef.h>

#include "agent_q_method_signing_request_flow.h"

namespace agent_q {

constexpr size_t kAgentQMethodSigningReviewMaxRows = 7;
constexpr size_t kAgentQMethodSigningReviewMaxRowText = 80;

struct AgentQMethodSigningReviewRow {
    char text[kAgentQMethodSigningReviewMaxRowText];
};

struct AgentQMethodSigningReviewViewModel {
    AgentQMethodSigningReviewRow rows[kAgentQMethodSigningReviewMaxRows];
    size_t row_count;
};

bool method_signing_review_view_model_from_snapshot(
    const AgentQMethodSigningRequestSnapshot& snapshot,
    AgentQMethodSigningReviewViewModel* output);

}  // namespace agent_q
