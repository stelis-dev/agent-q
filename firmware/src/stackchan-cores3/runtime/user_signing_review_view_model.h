#pragma once

#include <stddef.h>

#include "signing/user_signing_flow.h"

namespace signing {

constexpr size_t kUserSigningReviewMaxRows = kSuiReviewSummaryMaxRows + 8;
constexpr size_t kUserSigningReviewLabelSize = kSuiReviewSummaryRowLabelSize;
constexpr size_t kUserSigningReviewValueSize = kSuiReviewSummaryRowValueSize;
constexpr size_t kUserSigningReviewTitleSize = 40;

enum class UserSigningReviewBuildResult {
    ok,
    invalid_argument,
    inactive,
    wrong_stage,
    invalid_summary,
    output_too_small,
};

enum class UserSigningReviewRowKind {
    normal,
    wrapped_value,
    section,
    warning,
};

struct UserSigningReviewRow {
    UserSigningReviewRowKind kind;
    char label[kUserSigningReviewLabelSize];
    char value[kUserSigningReviewValueSize];
};

struct UserSigningReviewViewModel {
    char title[kUserSigningReviewTitleSize];
    UserSigningReviewRow rows[kUserSigningReviewMaxRows];
    size_t row_count;
};

UserSigningReviewBuildResult user_signing_review_view_model_build(
    const UserSigningFlowSnapshot& snapshot,
    UserSigningReviewViewModel* output);

const char* user_signing_review_view_model_build_result_name(
    UserSigningReviewBuildResult result);

}  // namespace signing
