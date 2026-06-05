#pragma once

#include <stddef.h>

#include "agent_q_sign_transaction_user_flow.h"

namespace agent_q {

constexpr size_t kAgentQSignTransactionUserReviewMaxRows = 8;
constexpr size_t kAgentQSignTransactionUserReviewLabelSize = 16;
constexpr size_t kAgentQSignTransactionUserReviewValueSize = 80;
constexpr size_t kAgentQSignTransactionUserReviewTitleSize = 40;

enum class AgentQSignTransactionUserReviewBuildResult {
    ok,
    invalid_argument,
    inactive,
    wrong_stage,
    invalid_summary,
    output_too_small,
};

struct AgentQSignTransactionUserReviewRow {
    char label[kAgentQSignTransactionUserReviewLabelSize];
    char value[kAgentQSignTransactionUserReviewValueSize];
};

struct AgentQSignTransactionUserReviewViewModel {
    char title[kAgentQSignTransactionUserReviewTitleSize];
    AgentQSignTransactionUserReviewRow rows[kAgentQSignTransactionUserReviewMaxRows];
    size_t row_count;
};

AgentQSignTransactionUserReviewBuildResult sign_transaction_user_review_view_model_build(
    const AgentQSignTransactionUserFlowSnapshot& snapshot,
    AgentQSignTransactionUserReviewViewModel* output);

const char* sign_transaction_user_review_view_model_build_result_name(
    AgentQSignTransactionUserReviewBuildResult result);

}  // namespace agent_q
