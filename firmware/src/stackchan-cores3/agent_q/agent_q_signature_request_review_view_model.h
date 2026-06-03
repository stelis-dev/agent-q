#pragma once

#include <stddef.h>

#include "agent_q_signature_request_flow.h"

namespace agent_q {

constexpr size_t kAgentQSignatureRequestReviewMaxRows = 8;
constexpr size_t kAgentQSignatureRequestReviewLabelSize = 16;
constexpr size_t kAgentQSignatureRequestReviewValueSize = 80;
constexpr size_t kAgentQSignatureRequestReviewTitleSize = 40;

enum class AgentQSignatureRequestReviewBuildResult {
    ok,
    invalid_argument,
    inactive,
    wrong_stage,
    invalid_summary,
    output_too_small,
};

struct AgentQSignatureRequestReviewRow {
    char label[kAgentQSignatureRequestReviewLabelSize];
    char value[kAgentQSignatureRequestReviewValueSize];
};

struct AgentQSignatureRequestReviewViewModel {
    char title[kAgentQSignatureRequestReviewTitleSize];
    AgentQSignatureRequestReviewRow rows[kAgentQSignatureRequestReviewMaxRows];
    size_t row_count;
};

AgentQSignatureRequestReviewBuildResult signature_request_review_view_model_build(
    const AgentQSignatureRequestFlowSnapshot& snapshot,
    AgentQSignatureRequestReviewViewModel* output);

const char* signature_request_review_view_model_build_result_name(
    AgentQSignatureRequestReviewBuildResult result);

}  // namespace agent_q
