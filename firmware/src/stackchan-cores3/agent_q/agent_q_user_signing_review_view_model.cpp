#include "agent_q_user_signing_review_view_model.h"

#include <string.h>

namespace agent_q {
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
    AgentQUserSigningReviewViewModel* output,
    AgentQUserSigningReviewRowKind kind,
    const char* label,
    const char* value)
{
    if (output == nullptr ||
        output->row_count >= kAgentQUserSigningReviewMaxRows) {
        return false;
    }
    AgentQUserSigningReviewRow& row = output->rows[output->row_count];
    row.kind = kind;
    if (!copy_exact_c_string(label, row.label, sizeof(row.label)) ||
        !copy_exact_c_string(value, row.value, sizeof(row.value))) {
        return false;
    }
    ++output->row_count;
    return true;
}

bool add_chain_method_rows(
    AgentQUserSigningReviewViewModel* output,
    const char* wire_chain,
    const char* wire_method)
{
    return add_row(output, AgentQUserSigningReviewRowKind::normal, "Chain", wire_chain) &&
           add_row(output, AgentQUserSigningReviewRowKind::normal, "Method", wire_method);
}

bool add_review_header(
    AgentQUserSigningReviewViewModel* output,
    const char* title,
    const char* wire_chain,
    const char* wire_method)
{
    return copy_exact_c_string(title, output->title, sizeof(output->title)) &&
           add_chain_method_rows(output, wire_chain, wire_method);
}

bool common_summary_fields_valid(const AgentQUserSigningFlowSnapshot& snapshot)
{
    return snapshot.signable_payload_available &&
           snapshot.signable_payload_size > 0 &&
           bounded_string_present(snapshot.payload_digest, sizeof(snapshot.payload_digest));
}

bool summary_fields_valid(const AgentQUserSigningFlowSnapshot& snapshot)
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

bool personal_message_summary_fields_valid(const AgentQUserSigningFlowSnapshot& snapshot)
{
    return common_summary_fields_valid(snapshot) &&
           snapshot.signable_payload_size <= kAgentQSuiSignPersonalMessageMaxBytes &&
           bounded_string_present(snapshot.account_address, sizeof(snapshot.account_address)) &&
           bounded_string_present(snapshot.message_preview, sizeof(snapshot.message_preview));
}

AgentQUserSigningReviewRowKind review_row_kind(SuiReviewRowKind kind)
{
    switch (kind) {
        case SuiReviewRowKind::normal:
            return AgentQUserSigningReviewRowKind::normal;
        case SuiReviewRowKind::wrapped_value:
            return AgentQUserSigningReviewRowKind::wrapped_value;
        case SuiReviewRowKind::section:
            return AgentQUserSigningReviewRowKind::section;
        case SuiReviewRowKind::warning:
            return AgentQUserSigningReviewRowKind::warning;
    }
    return AgentQUserSigningReviewRowKind::normal;
}

bool add_sui_review_rows(
    AgentQUserSigningReviewViewModel* output,
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

bool add_blind_signing_review_rows(AgentQUserSigningReviewViewModel* output)
{
    return add_row(
               output,
               AgentQUserSigningReviewRowKind::warning,
               "Review",
               "Blind signing") &&
           add_row(
               output,
               AgentQUserSigningReviewRowKind::warning,
               "Reason",
               "Transaction details cannot be fully shown") &&
           add_row(
               output,
               AgentQUserSigningReviewRowKind::warning,
               "Warning",
               "Confirm only if you accept blind signing");
}

}  // namespace

AgentQUserSigningReviewBuildResult user_signing_review_view_model_build(
    const AgentQUserSigningFlowSnapshot& snapshot,
    AgentQUserSigningReviewViewModel* output)
{
    if (output == nullptr) {
        return AgentQUserSigningReviewBuildResult::invalid_argument;
    }
    memset(output, 0, sizeof(*output));

    if (!snapshot.active) {
        return AgentQUserSigningReviewBuildResult::inactive;
    }
    if (snapshot.stage != AgentQUserSigningStage::reviewing) {
        return AgentQUserSigningReviewBuildResult::wrong_stage;
    }
    const AgentQSigningRoute route = snapshot.signing_route;
    if (route == AgentQSigningRoute::unsupported) {
        return AgentQUserSigningReviewBuildResult::invalid_summary;
    }
    const char* wire_chain = signing_route_wire_chain(route);
    const char* wire_method = signing_route_wire_method(route);
    if (wire_chain == nullptr || wire_chain[0] == '\0' ||
        wire_method == nullptr || wire_method[0] == '\0') {
        return AgentQUserSigningReviewBuildResult::invalid_summary;
    }
    if (route == AgentQSigningRoute::sui_sign_personal_message) {
        if (!personal_message_summary_fields_valid(snapshot)) {
            return AgentQUserSigningReviewBuildResult::invalid_summary;
        }
        if (!add_review_header(output, kPersonalMessageReviewTitle, wire_chain, wire_method) ||
            !add_row(output, AgentQUserSigningReviewRowKind::normal, "Account", snapshot.account_address) ||
            !add_row(output, AgentQUserSigningReviewRowKind::wrapped_value, "Preview", snapshot.message_preview) ||
            !add_row(output, AgentQUserSigningReviewRowKind::normal, "Payload digest", snapshot.payload_digest)) {
            memset(output, 0, sizeof(*output));
            return AgentQUserSigningReviewBuildResult::output_too_small;
        }
    } else if (route == AgentQSigningRoute::sui_sign_transaction) {
        if (!summary_fields_valid(snapshot)) {
            return AgentQUserSigningReviewBuildResult::invalid_summary;
        }
        const bool blind_signing_review =
            snapshot.sui_review.status ==
            SuiReviewSummaryStatus::insufficient_review;
        if (!add_review_header(output, snapshot.sui_review.title, wire_chain, wire_method) ||
            (blind_signing_review && !add_blind_signing_review_rows(output)) ||
            !add_sui_review_rows(output, snapshot.sui_review) ||
            !add_row(
                output,
                AgentQUserSigningReviewRowKind::wrapped_value,
                "Payload digest",
                snapshot.payload_digest)) {
            memset(output, 0, sizeof(*output));
            return AgentQUserSigningReviewBuildResult::output_too_small;
        }
    } else {
        return AgentQUserSigningReviewBuildResult::invalid_summary;
    }

    return AgentQUserSigningReviewBuildResult::ok;
}

const char* user_signing_review_view_model_build_result_name(
    AgentQUserSigningReviewBuildResult result)
{
    switch (result) {
        case AgentQUserSigningReviewBuildResult::ok:
            return "ok";
        case AgentQUserSigningReviewBuildResult::invalid_argument:
            return "invalid_argument";
        case AgentQUserSigningReviewBuildResult::inactive:
            return "inactive";
        case AgentQUserSigningReviewBuildResult::wrong_stage:
            return "wrong_stage";
        case AgentQUserSigningReviewBuildResult::invalid_summary:
            return "invalid_summary";
        case AgentQUserSigningReviewBuildResult::output_too_small:
            return "output_too_small";
    }
    return "unknown";
}

}  // namespace agent_q
