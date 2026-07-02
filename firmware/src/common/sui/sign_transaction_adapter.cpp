#include "sign_transaction_adapter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace signing {
namespace {

SuiSignTransactionAuthorizationCoverage incomplete_authorization_coverage()
{
    return SuiSignTransactionAuthorizationCoverage{
        false,
        false,
        SuiUserAuthorizationOutcome::unavailable,
        SuiPolicyAuthorizationOutcome::unavailable,
    };
}

SuiSignTransactionAuthorizationCoverage authorization_coverage_from_review(
    const SuiReviewSummary& review,
    bool policy_mode_authorization_covered)
{
    SuiSignTransactionAuthorizationCoverage coverage =
        incomplete_authorization_coverage();
    if (review.status == SuiReviewSummaryStatus::ok) {
        coverage.user_mode_authorization_covered = true;
        coverage.user_outcome =
            SuiUserAuthorizationOutcome::offline_facts_review;
    } else if (review.status == SuiReviewSummaryStatus::insufficient_review) {
        coverage.user_mode_authorization_covered = true;
        coverage.user_outcome = SuiUserAuthorizationOutcome::blind_signing;
    }
    coverage.policy_mode_authorization_covered = policy_mode_authorization_covered;
    coverage.policy_outcome =
        policy_mode_authorization_covered
            ? SuiPolicyAuthorizationOutcome::policy_evaluation
            : SuiPolicyAuthorizationOutcome::unavailable;
    return coverage;
}

bool copy_c_string(char* output, size_t output_size, const char* value)
{
    if (output == nullptr || output_size == 0 || value == nullptr) {
        return false;
    }
    const int written = snprintf(output, output_size, "%s", value);
    return written >= 0 && static_cast<size_t>(written) < output_size;
}

bool add_review_row(
    SuiReviewSummary* output,
    SuiReviewRowKind kind,
    const char* label,
    const char* value)
{
    if (output == nullptr || output->row_count >= kSuiReviewSummaryMaxRows) {
        return false;
    }
    SuiReviewRow& row = output->rows[output->row_count];
    row.kind = kind;
    if (!copy_c_string(row.label, sizeof(row.label), label) ||
        !copy_c_string(row.value, sizeof(row.value), value)) {
        return false;
    }
    ++output->row_count;
    return true;
}

bool build_minimum_policy_subject(
    const SuiMinimumTransactionFacts& minimum,
    SuiPolicySubjectFacts* output)
{
    if (output == nullptr ||
        minimum.transaction_data_version != SuiTransactionDataVersionFact::v1 ||
        minimum.transaction_kind != SuiTransactionKindFact::programmable_transaction ||
        minimum.sender[0] == '\0' ||
        minimum.gas_owner[0] == '\0') {
        return false;
    }
    memset(output, 0, sizeof(*output));
    output->transaction_data_version = minimum.transaction_data_version;
    output->transaction_kind = minimum.transaction_kind;
    return copy_c_string(output->sender, sizeof(output->sender), minimum.sender) &&
           copy_c_string(output->gas_owner, sizeof(output->gas_owner), minimum.gas_owner) &&
           copy_c_string(output->gas_price, sizeof(output->gas_price), minimum.gas_price) &&
           copy_c_string(output->gas_budget, sizeof(output->gas_budget), minimum.gas_budget);
}

bool build_minimum_review_summary(
    const SuiMinimumTransactionFacts& minimum,
    const char* reason,
    SuiReviewSummary* output)
{
    if (output == nullptr || reason == nullptr || reason[0] == '\0') {
        return false;
    }
    memset(output, 0, sizeof(*output));
    output->status = SuiReviewSummaryStatus::insufficient_review;
    output->risk = SuiReviewRiskLevel::high;
    return copy_c_string(output->title, sizeof(output->title), "Review Sui transaction") &&
           copy_c_string(output->type_summary, sizeof(output->type_summary), "Unparsed transaction") &&
           copy_c_string(output->risk_label, sizeof(output->risk_label), "High") &&
           add_review_row(output, SuiReviewRowKind::warning, "Type", output->type_summary) &&
           add_review_row(output, SuiReviewRowKind::warning, "Reason", reason) &&
           add_review_row(output, SuiReviewRowKind::wrapped_value, "Sender", minimum.sender) &&
           add_review_row(output, SuiReviewRowKind::wrapped_value, "Gas owner", minimum.gas_owner) &&
           add_review_row(output, SuiReviewRowKind::normal, "Gas max", minimum.gas_budget) &&
           add_review_row(output, SuiReviewRowKind::normal, "Gas price", minimum.gas_price);
}

const char* minimum_blind_signing_reason(SuiTransactionFactsResult result)
{
    switch (result) {
        case SuiTransactionFactsResult::too_large:
            return "Transaction details exceed parser limits";
        case SuiTransactionFactsResult::unsupported_shape:
            return "Transaction shape cannot be fully shown";
        default:
            break;
    }
    return "Transaction details cannot be fully shown";
}

bool build_minimum_outputs_for_blind_signing(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    SuiTransactionFactsResult full_parse_result,
    SuiPolicySubjectFacts* policy_subject_out,
    SuiReviewSummary* review_summary_out)
{
    SuiMinimumTransactionFacts minimum = {};
    const SuiTransactionFactsResult minimum_result =
        parse_sui_minimum_transaction_facts(tx_bytes, tx_bytes_size, &minimum);
    if (minimum_result != SuiTransactionFactsResult::ok) {
        return false;
    }
    return build_minimum_policy_subject(minimum, policy_subject_out) &&
           build_minimum_review_summary(
               minimum,
               minimum_blind_signing_reason(full_parse_result),
               review_summary_out);
}

}  // namespace

SuiSignTransactionAdapterResult classify_sui_sign_transaction(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    SuiPolicySubjectFacts* policy_subject_out,
    SuiReviewSummary* review_summary_out,
    SuiSignTransactionAuthorizationCoverage* coverage_out)
{
    if (policy_subject_out != nullptr) {
        *policy_subject_out = {};
    }
    if (review_summary_out != nullptr) {
        *review_summary_out = {};
    }
    if (coverage_out != nullptr) {
        *coverage_out = incomplete_authorization_coverage();
    }
    if (tx_bytes == nullptr ||
        tx_bytes_size == 0 ||
        policy_subject_out == nullptr ||
        review_summary_out == nullptr ||
        coverage_out == nullptr) {
        return SuiSignTransactionAdapterResult::invalid_argument;
    }

    SuiParsedTransactionFacts* parsed =
        static_cast<SuiParsedTransactionFacts*>(malloc(sizeof(SuiParsedTransactionFacts)));
    if (parsed == nullptr) {
        return SuiSignTransactionAdapterResult::unsupported_transaction;
    }
    const SuiTransactionFactsResult parse_result =
        parse_sui_parsed_transaction_facts(tx_bytes, tx_bytes_size, parsed);
    if (parse_result == SuiTransactionFactsResult::malformed) {
        free(parsed);
        return SuiSignTransactionAdapterResult::malformed_transaction;
    }
    if (parse_result != SuiTransactionFactsResult::ok) {
        if (build_minimum_outputs_for_blind_signing(
                tx_bytes,
                tx_bytes_size,
                parse_result,
                policy_subject_out,
                review_summary_out)) {
            *coverage_out = authorization_coverage_from_review(*review_summary_out, false);
            free(parsed);
            return SuiSignTransactionAdapterResult::ok;
        }
        free(parsed);
        return SuiSignTransactionAdapterResult::unsupported_transaction;
    }
    if (!build_sui_policy_subject_facts(*parsed, policy_subject_out) ||
        !build_sui_review_summary(*parsed, review_summary_out)) {
        SuiMinimumTransactionFacts minimum = {};
        minimum.transaction_data_version = parsed->transaction_data_version;
        minimum.transaction_kind = parsed->transaction_kind;
        copy_c_string(minimum.sender, sizeof(minimum.sender), parsed->sender);
        copy_c_string(minimum.gas_owner, sizeof(minimum.gas_owner), parsed->gas_owner);
        copy_c_string(minimum.gas_price, sizeof(minimum.gas_price), parsed->gas_price);
        copy_c_string(minimum.gas_budget, sizeof(minimum.gas_budget), parsed->gas_budget);
        if (build_minimum_policy_subject(minimum, policy_subject_out) &&
            build_minimum_review_summary(
                minimum,
                "Transaction review cannot be fully shown",
                review_summary_out)) {
            *coverage_out = authorization_coverage_from_review(*review_summary_out, false);
            free(parsed);
            return SuiSignTransactionAdapterResult::ok;
        }
        *policy_subject_out = {};
        *review_summary_out = {};
        free(parsed);
        return SuiSignTransactionAdapterResult::unsupported_transaction;
    }
    *coverage_out = authorization_coverage_from_review(*review_summary_out, false);
    free(parsed);
    return SuiSignTransactionAdapterResult::ok;
}

}  // namespace signing
