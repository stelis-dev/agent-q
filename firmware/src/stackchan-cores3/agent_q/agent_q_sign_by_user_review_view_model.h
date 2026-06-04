#pragma once

#include <stddef.h>

#include "agent_q_sign_by_user_flow.h"

namespace agent_q {

constexpr size_t kAgentQSignByUserReviewMaxRows = 8;
constexpr size_t kAgentQSignByUserReviewLabelSize = 16;
constexpr size_t kAgentQSignByUserReviewValueSize = 80;
constexpr size_t kAgentQSignByUserReviewTitleSize = 40;

enum class AgentQSignByUserReviewBuildResult {
    ok,
    invalid_argument,
    inactive,
    wrong_stage,
    invalid_summary,
    output_too_small,
};

struct AgentQSignByUserReviewRow {
    char label[kAgentQSignByUserReviewLabelSize];
    char value[kAgentQSignByUserReviewValueSize];
};

struct AgentQSignByUserReviewViewModel {
    char title[kAgentQSignByUserReviewTitleSize];
    AgentQSignByUserReviewRow rows[kAgentQSignByUserReviewMaxRows];
    size_t row_count;
};

AgentQSignByUserReviewBuildResult sign_by_user_review_view_model_build(
    const AgentQSignByUserFlowSnapshot& snapshot,
    AgentQSignByUserReviewViewModel* output);

const char* sign_by_user_review_view_model_build_result_name(
    AgentQSignByUserReviewBuildResult result);

}  // namespace agent_q
