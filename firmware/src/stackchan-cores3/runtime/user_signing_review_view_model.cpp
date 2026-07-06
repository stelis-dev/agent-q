#include "user_signing_review_view_model.h"

#include <string.h>

namespace signing {
namespace {

constexpr const char* kPersonalMessageReviewTitle = "Review Sui message";

bool bounded_string_present(const char* value, size_t value_size)
{
    return value != nullptr &&
           value_size > 0 &&
           value[0] != '\0' &&
           memchr(value, '\0', value_size) != nullptr;
}

bool copy_exact_c_string(const char* input, char* output, size_t output_size)
{
    if (input == nullptr || output == nullptr || output_size == 0) {
        return false;
    }
    size_t index = 0;
    while (input[index] != '\0' && index + 1 < output_size) {
        output[index] = input[index];
        ++index;
    }
    if (input[index] != '\0') {
        output[0] = '\0';
        return false;
    }
    output[index] = '\0';
    return true;
}

bool add_row(
    UserSigningReviewViewModel* output,
    UserSigningReviewRowKind kind,
    const char* label,
    const char* value)
{
    if (output == nullptr ||
        output->row_count >= kUserSigningReviewMaxRows) {
        return false;
    }
    UserSigningReviewRow& row = output->rows[output->row_count];
    row.kind = kind;
    if (!copy_exact_c_string(label, row.label, sizeof(row.label)) ||
        !copy_exact_c_string(value, row.value, sizeof(row.value))) {
        return false;
    }
    ++output->row_count;
    return true;
}

bool add_chain_method_rows(
    UserSigningReviewViewModel* output,
    const char* wire_chain,
    const char* wire_method)
{
    return add_row(output, UserSigningReviewRowKind::normal, "Chain", wire_chain) &&
           add_row(output, UserSigningReviewRowKind::normal, "Method", wire_method);
}

bool add_review_header(
    UserSigningReviewViewModel* output,
    const char* title,
    const char* wire_chain,
    const char* wire_method)
{
    return copy_exact_c_string(title, output->title, sizeof(output->title)) &&
           add_chain_method_rows(output, wire_chain, wire_method);
}

bool common_summary_fields_valid(const UserSigningFlowSnapshot& snapshot)
{
    return snapshot.signable_payload_available &&
           snapshot.signable_payload_size > 0 &&
           bounded_string_present(snapshot.payload_digest, sizeof(snapshot.payload_digest));
}

bool summary_fields_valid(const UserSigningFlowSnapshot& snapshot)
{
    if (!common_summary_fields_valid(snapshot) ||
        (snapshot.sui_review.status != SuiReviewSummaryStatus::ok &&
         snapshot.sui_review.status != SuiReviewSummaryStatus::insufficient_review) ||
        !bounded_string_present(snapshot.sui_review.title, sizeof(snapshot.sui_review.title)) ||
        snapshot.sui_review.row_count == 0 ||
        snapshot.sui_review.row_count > kSuiReviewSummaryMaxRows) {
        return false;
    }
    for (uint16_t index = 0; index < snapshot.sui_review.row_count; ++index) {
        if (!bounded_string_present(
                snapshot.sui_review.rows[index].label,
                sizeof(snapshot.sui_review.rows[index].label)) ||
            !bounded_string_present(
                snapshot.sui_review.rows[index].value,
                sizeof(snapshot.sui_review.rows[index].value))) {
            return false;
        }
    }
    return true;
}

bool personal_message_summary_fields_valid(const UserSigningFlowSnapshot& snapshot)
{
    return common_summary_fields_valid(snapshot) &&
           snapshot.signable_payload_size <= kSuiSignPersonalMessageMaxBytes &&
           bounded_string_present(snapshot.account_address, sizeof(snapshot.account_address)) &&
           bounded_string_present(snapshot.message_preview, sizeof(snapshot.message_preview));
}

UserSigningReviewRowKind review_row_kind(SuiReviewRowKind kind)
{
    switch (kind) {
        case SuiReviewRowKind::normal:
            return UserSigningReviewRowKind::normal;
        case SuiReviewRowKind::wrapped_value:
            return UserSigningReviewRowKind::wrapped_value;
        case SuiReviewRowKind::section:
            return UserSigningReviewRowKind::section;
        case SuiReviewRowKind::warning:
            return UserSigningReviewRowKind::warning;
    }
    return UserSigningReviewRowKind::normal;
}

bool add_sui_review_rows(
    UserSigningReviewViewModel* output,
    const SuiReviewSummary& summary)
{
    for (uint16_t index = 0; index < summary.row_count; ++index) {
        if (!add_row(
                output,
                review_row_kind(summary.rows[index].kind),
                summary.rows[index].label,
                summary.rows[index].value)) {
            return false;
        }
    }
    return true;
}

bool add_blind_signing_review_rows(UserSigningReviewViewModel* output)
{
    return add_row(
               output,
               UserSigningReviewRowKind::warning,
               "Review",
               "Blind signing") &&
           add_row(
               output,
               UserSigningReviewRowKind::warning,
               "Warning",
               "Confirm only if you accept blind signing");
}

}  // namespace

UserSigningReviewBuildResult user_signing_review_view_model_build(
    const UserSigningFlowSnapshot& snapshot,
    UserSigningReviewViewModel* output)
{
    if (output == nullptr) {
        return UserSigningReviewBuildResult::invalid_argument;
    }
    memset(output, 0, sizeof(*output));

    if (!snapshot.active) {
        return UserSigningReviewBuildResult::inactive;
    }
    if (snapshot.stage != UserSigningStage::reviewing) {
        return UserSigningReviewBuildResult::wrong_stage;
    }
    const Route route = snapshot.signing_route;
    if (route == Route::unsupported) {
        return UserSigningReviewBuildResult::invalid_summary;
    }
    const char* wire_chain = sign_route_wire_chain(route);
    const char* wire_method = sign_route_wire_method(route);
    if (wire_chain == nullptr || wire_chain[0] == '\0' ||
        wire_method == nullptr || wire_method[0] == '\0') {
        return UserSigningReviewBuildResult::invalid_summary;
    }
    if (route == Route::sui_sign_personal_message) {
        if (!personal_message_summary_fields_valid(snapshot)) {
            return UserSigningReviewBuildResult::invalid_summary;
        }
        if (!add_review_header(output, kPersonalMessageReviewTitle, wire_chain, wire_method) ||
            !add_row(output, UserSigningReviewRowKind::normal, "Account", snapshot.account_address) ||
            !add_row(output, UserSigningReviewRowKind::wrapped_value, "Preview", snapshot.message_preview) ||
            !add_row(output, UserSigningReviewRowKind::normal, "Payload digest", snapshot.payload_digest)) {
            memset(output, 0, sizeof(*output));
            return UserSigningReviewBuildResult::output_too_small;
        }
    } else if (route == Route::sui_sign_transaction) {
        if (!summary_fields_valid(snapshot)) {
            return UserSigningReviewBuildResult::invalid_summary;
        }
        const bool blind_signing_review =
            snapshot.sui_review.status ==
            SuiReviewSummaryStatus::insufficient_review;
        if (!add_review_header(output, snapshot.sui_review.title, wire_chain, wire_method) ||
            (blind_signing_review && !add_blind_signing_review_rows(output)) ||
            !add_sui_review_rows(output, snapshot.sui_review) ||
            !add_row(
                output,
                UserSigningReviewRowKind::wrapped_value,
                "Payload digest",
                snapshot.payload_digest)) {
            memset(output, 0, sizeof(*output));
            return UserSigningReviewBuildResult::output_too_small;
        }
    } else {
        return UserSigningReviewBuildResult::invalid_summary;
    }

    return UserSigningReviewBuildResult::ok;
}

const char* user_signing_review_view_model_build_result_name(
    UserSigningReviewBuildResult result)
{
    switch (result) {
        case UserSigningReviewBuildResult::ok:
            return "ok";
        case UserSigningReviewBuildResult::invalid_argument:
            return "invalid_argument";
        case UserSigningReviewBuildResult::inactive:
            return "inactive";
        case UserSigningReviewBuildResult::wrong_stage:
            return "wrong_stage";
        case UserSigningReviewBuildResult::invalid_summary:
            return "invalid_summary";
        case UserSigningReviewBuildResult::output_too_small:
            return "output_too_small";
    }
    return "unknown";
}

}  // namespace signing
