#include "agent_q_user_signing_review_view_model.h"

#include <string.h>

namespace agent_q {
namespace {

constexpr const char* kReviewTitle = "Review Sui transfer";
constexpr const char* kPersonalMessageReviewTitle = "Review Sui message";
constexpr const char* kSuiAsset = "0x2::sui::SUI";

bool bounded_string_present(const char* value, size_t value_size)
{
    return value != nullptr &&
           value_size > 0 &&
           value[0] != '\0' &&
           memchr(value, '\0', value_size) != nullptr;
}

bool decimal_string_valid(const char* value, size_t value_size)
{
    if (!bounded_string_present(value, value_size)) {
        return false;
    }
    for (size_t index = 0; value[index] != '\0'; ++index) {
        if (value[index] < '0' || value[index] > '9') {
            return false;
        }
    }
    return true;
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
    const SuiTransferFacts& facts = snapshot.sui_transfer;
    return common_summary_fields_valid(snapshot) &&
           bounded_string_present(facts.recipient, sizeof(facts.recipient)) &&
           bounded_string_present(facts.asset, sizeof(facts.asset)) &&
           strcmp(facts.asset, kSuiAsset) == 0 &&
           decimal_string_valid(facts.amount, sizeof(facts.amount)) &&
           decimal_string_valid(facts.gas_budget, sizeof(facts.gas_budget)) &&
           decimal_string_valid(facts.gas_price, sizeof(facts.gas_price));
}

bool personal_message_summary_fields_valid(const AgentQUserSigningFlowSnapshot& snapshot)
{
    return common_summary_fields_valid(snapshot) &&
           snapshot.signable_payload_size <= kAgentQSuiSignPersonalMessageMaxBytes &&
           bounded_string_present(snapshot.account_address, sizeof(snapshot.account_address)) &&
           bounded_string_present(snapshot.message_preview, sizeof(snapshot.message_preview));
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
        if (!add_review_header(output, kReviewTitle, wire_chain, wire_method) ||
            !add_row(output, AgentQUserSigningReviewRowKind::normal, "Amount", snapshot.sui_transfer.amount) ||
            !add_row(output, AgentQUserSigningReviewRowKind::normal, "Asset", snapshot.sui_transfer.asset) ||
            !add_row(output, AgentQUserSigningReviewRowKind::wrapped_value, "Recipient", snapshot.sui_transfer.recipient) ||
            !add_row(output, AgentQUserSigningReviewRowKind::normal, "Gas budget", snapshot.sui_transfer.gas_budget) ||
            !add_row(output, AgentQUserSigningReviewRowKind::normal, "Gas price", snapshot.sui_transfer.gas_price)) {
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
