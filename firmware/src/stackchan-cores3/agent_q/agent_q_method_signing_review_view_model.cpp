#include "agent_q_method_signing_review_view_model.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

namespace agent_q {
namespace {

constexpr size_t kRecipientFirstLineChars = 34;

bool nonempty(const char* value)
{
    return value != nullptr && value[0] != '\0';
}

bool append_row(AgentQMethodSigningReviewViewModel* output, const char* format, ...)
{
    if (output == nullptr ||
        output->row_count >= kAgentQMethodSigningReviewMaxRows ||
        format == nullptr) {
        return false;
    }

    va_list args;
    va_start(args, format);
    const int written = vsnprintf(
        output->rows[output->row_count].text,
        sizeof(output->rows[output->row_count].text),
        format,
        args);
    va_end(args);

    if (written < 0 ||
        static_cast<size_t>(written) >= sizeof(output->rows[output->row_count].text)) {
        output->rows[output->row_count].text[0] = '\0';
        return false;
    }

    ++output->row_count;
    return true;
}

bool required_summary_fields_present(const AgentQMethodSigningRequestSnapshot& snapshot)
{
    return snapshot.active &&
           snapshot.stage == AgentQMethodSigningRequestStage::awaiting_review &&
           nonempty(snapshot.chain) &&
           nonempty(snapshot.method) &&
           nonempty(snapshot.network) &&
           nonempty(snapshot.recipient) &&
           nonempty(snapshot.amount) &&
           nonempty(snapshot.asset) &&
           nonempty(snapshot.gas_budget) &&
           nonempty(snapshot.gas_price);
}

}  // namespace

bool method_signing_review_view_model_from_snapshot(
    const AgentQMethodSigningRequestSnapshot& snapshot,
    AgentQMethodSigningReviewViewModel* output)
{
    if (output == nullptr) {
        return false;
    }

    *output = AgentQMethodSigningReviewViewModel{};

    if (!required_summary_fields_present(snapshot)) {
        return false;
    }

    const size_t recipient_length = strlen(snapshot.recipient);
    const size_t recipient_first_length =
        recipient_length > kRecipientFirstLineChars ? kRecipientFirstLineChars : recipient_length;

    if (!append_row(output, "%s/%s on %s", snapshot.chain, snapshot.method, snapshot.network) ||
        !append_row(output, "Amount %s", snapshot.amount) ||
        !append_row(output, "Asset %s", snapshot.asset) ||
        !append_row(
            output,
            "To %.*s",
            static_cast<int>(recipient_first_length),
            snapshot.recipient)) {
        *output = AgentQMethodSigningReviewViewModel{};
        return false;
    }

    if (snapshot.recipient[recipient_first_length] != '\0' &&
        !append_row(output, "%s", snapshot.recipient + recipient_first_length)) {
        *output = AgentQMethodSigningReviewViewModel{};
        return false;
    }

    if (!append_row(output, "Gas budget %s", snapshot.gas_budget) ||
        !append_row(output, "Gas price %s", snapshot.gas_price)) {
        *output = AgentQMethodSigningReviewViewModel{};
        return false;
    }

    return true;
}

}  // namespace agent_q
