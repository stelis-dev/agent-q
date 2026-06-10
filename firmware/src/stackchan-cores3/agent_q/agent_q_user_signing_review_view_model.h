#pragma once

#include <stddef.h>

#include "agent_q_user_signing_flow.h"

namespace agent_q {

constexpr size_t kAgentQUserSigningReviewMaxRows = 8;
constexpr size_t kAgentQUserSigningReviewLabelSize = 16;
constexpr size_t kAgentQUserSigningReviewValueSize = 80;
constexpr size_t kAgentQUserSigningReviewTitleSize = 40;

enum class AgentQUserSigningReviewBuildResult {
    ok,
    invalid_argument,
    inactive,
    wrong_stage,
    invalid_summary,
    output_too_small,
};

enum class AgentQUserSigningReviewRowKind {
    normal,
    wrapped_value,
};

struct AgentQUserSigningReviewRow {
    AgentQUserSigningReviewRowKind kind;
    char label[kAgentQUserSigningReviewLabelSize];
    char value[kAgentQUserSigningReviewValueSize];
};

struct AgentQUserSigningReviewViewModel {
    char title[kAgentQUserSigningReviewTitleSize];
    AgentQUserSigningReviewRow rows[kAgentQUserSigningReviewMaxRows];
    size_t row_count;
};

AgentQUserSigningReviewBuildResult user_signing_review_view_model_build(
    const AgentQUserSigningFlowSnapshot& snapshot,
    AgentQUserSigningReviewViewModel* output);

const char* user_signing_review_view_model_build_result_name(
    AgentQUserSigningReviewBuildResult result);

}  // namespace agent_q
