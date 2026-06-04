#include "agent_q_signature_request_review_view_model.h"

#include <string.h>

namespace agent_q {
namespace {

constexpr const char* kReviewTitle = "Review Sui transfer";
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
    AgentQSignatureRequestReviewViewModel* output,
    const char* label,
    const char* value)
{
    if (output == nullptr ||
        output->row_count >= kAgentQSignatureRequestReviewMaxRows) {
        return false;
    }
    AgentQSignatureRequestReviewRow& row = output->rows[output->row_count];
    if (!copy_exact_c_string(label, row.label, sizeof(row.label)) ||
        !copy_exact_c_string(value, row.value, sizeof(row.value))) {
        return false;
    }
    ++output->row_count;
    return true;
}

bool summary_fields_valid(const AgentQSignatureRequestFlowSnapshot& snapshot)
{
    const SuiTransferFacts& facts = snapshot.sui_transfer;
    return snapshot.signable_payload_available &&
           snapshot.signable_payload_size > 0 &&
           bounded_string_present(snapshot.payload_digest, sizeof(snapshot.payload_digest)) &&
           bounded_string_present(snapshot.chain, sizeof(snapshot.chain)) &&
           strcmp(snapshot.chain, "sui") == 0 &&
           bounded_string_present(snapshot.method, sizeof(snapshot.method)) &&
           strcmp(snapshot.method, "sign_transaction") == 0 &&
           bounded_string_present(facts.recipient, sizeof(facts.recipient)) &&
           bounded_string_present(facts.asset, sizeof(facts.asset)) &&
           strcmp(facts.asset, kSuiAsset) == 0 &&
           decimal_string_valid(facts.amount, sizeof(facts.amount)) &&
           decimal_string_valid(facts.gas_budget, sizeof(facts.gas_budget)) &&
           decimal_string_valid(facts.gas_price, sizeof(facts.gas_price));
}

}  // namespace

AgentQSignatureRequestReviewBuildResult signature_request_review_view_model_build(
    const AgentQSignatureRequestFlowSnapshot& snapshot,
    AgentQSignatureRequestReviewViewModel* output)
{
    if (output == nullptr) {
        return AgentQSignatureRequestReviewBuildResult::invalid_argument;
    }
    memset(output, 0, sizeof(*output));

    if (!snapshot.active) {
        return AgentQSignatureRequestReviewBuildResult::inactive;
    }
    if (snapshot.stage != AgentQSignatureRequestStage::reviewing) {
        return AgentQSignatureRequestReviewBuildResult::wrong_stage;
    }
    if (!summary_fields_valid(snapshot)) {
        return AgentQSignatureRequestReviewBuildResult::invalid_summary;
    }
    if (!copy_exact_c_string(kReviewTitle, output->title, sizeof(output->title))) {
        return AgentQSignatureRequestReviewBuildResult::output_too_small;
    }

    if (!add_row(output, "Chain", snapshot.chain) ||
        !add_row(output, "Method", snapshot.method) ||
        !add_row(output, "Amount", snapshot.sui_transfer.amount) ||
        !add_row(output, "Asset", snapshot.sui_transfer.asset) ||
        !add_row(output, "Recipient", snapshot.sui_transfer.recipient) ||
        !add_row(output, "Gas budget", snapshot.sui_transfer.gas_budget) ||
        !add_row(output, "Gas price", snapshot.sui_transfer.gas_price)) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestReviewBuildResult::output_too_small;
    }

    return AgentQSignatureRequestReviewBuildResult::ok;
}

const char* signature_request_review_view_model_build_result_name(
    AgentQSignatureRequestReviewBuildResult result)
{
    switch (result) {
        case AgentQSignatureRequestReviewBuildResult::ok:
            return "ok";
        case AgentQSignatureRequestReviewBuildResult::invalid_argument:
            return "invalid_argument";
        case AgentQSignatureRequestReviewBuildResult::inactive:
            return "inactive";
        case AgentQSignatureRequestReviewBuildResult::wrong_stage:
            return "wrong_stage";
        case AgentQSignatureRequestReviewBuildResult::invalid_summary:
            return "invalid_summary";
        case AgentQSignatureRequestReviewBuildResult::output_too_small:
            return "output_too_small";
    }
    return "unknown";
}

}  // namespace agent_q
