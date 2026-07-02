#include "policy_update_flow.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "approval_history.h"
#include "policy_proposal_parser.h"
#include "policy_store.h"
#include "policy/document.h"

namespace signing {
namespace {

constexpr size_t kPolicyUpdateReviewSummaryBytes = 8192;

struct PolicyUpdateFlowState {
    bool active = false;
    PolicyUpdateFlowStage stage = PolicyUpdateFlowStage::idle;
    char request_id[kRequestIdSize] = {};
    char session_id[kSessionIdSize] = {};
    TimeoutWindow review_window = kTimeoutWindowNone;
    ParsedPolicyProposal* parsed = nullptr;
    CurrentPolicyCanonicalDocument* canonical = nullptr;
    uint8_t* record = nullptr;
    size_t record_size = 0;
    uint8_t digest[kPolicyUpdateDigestBytes] = {};
    char policy_hash[kPolicyIdSize] = {};
    char scope_summary[96] = {};
    char review_summary[kPolicyUpdateReviewSummaryBytes] = {};
    PolicyUpdateHighestAction highest_action = PolicyUpdateHighestAction::reject;

    void clear()
    {
        if (parsed != nullptr) {
            memset(parsed, 0, sizeof(*parsed));
            free(parsed);
        }
        if (canonical != nullptr) {
            memset(canonical, 0, sizeof(*canonical));
            free(canonical);
        }
        if (record != nullptr) {
            memset(record, 0, kCurrentPolicyMaxCanonicalRecordBytes);
            free(record);
        }
        memset(this, 0, sizeof(*this));
        stage = PolicyUpdateFlowStage::idle;
        highest_action = PolicyUpdateHighestAction::reject;
    }

    bool allocate_workspaces()
    {
        parsed = static_cast<ParsedPolicyProposal*>(malloc(sizeof(*parsed)));
        canonical = static_cast<CurrentPolicyCanonicalDocument*>(malloc(sizeof(*canonical)));
        record = static_cast<uint8_t*>(malloc(kCurrentPolicyMaxCanonicalRecordBytes));
        if (parsed == nullptr || canonical == nullptr || record == nullptr) {
            clear();
            return false;
        }
        memset(parsed, 0, sizeof(*parsed));
        memset(canonical, 0, sizeof(*canonical));
        memset(record, 0, kCurrentPolicyMaxCanonicalRecordBytes);
        return true;
    }
};

PolicyUpdateFlowState g_state;

size_t current_policy_blockchain_count()
{
    return g_state.parsed != nullptr ? g_state.parsed->document.blockchain_count : 0;
}

size_t current_policy_network_count()
{
    return g_state.parsed != nullptr ? g_state.parsed->network_count : 0;
}

size_t current_policy_policy_count()
{
    return g_state.parsed != nullptr ? g_state.parsed->policy_count : 0;
}

size_t current_policy_condition_count()
{
    return g_state.parsed != nullptr ? g_state.parsed->condition_count : 0;
}

const char* current_policy_default_action_name()
{
    return g_state.parsed != nullptr
               ? current_policy_action_name(g_state.parsed->document.default_action)
               : current_policy_action_name(CurrentPolicyAction::reject);
}

bool copy_non_empty_bounded(const char* input, char* output, size_t output_size)
{
    if (input == nullptr || output == nullptr || output_size == 0) {
        return false;
    }
    const size_t length = strlen(input);
    if (length == 0 || length >= output_size) {
        return false;
    }
    memcpy(output, input, length + 1);
    return true;
}

bool digest_record(
    const uint8_t* record,
    size_t record_size,
    uint8_t* digest,
    size_t digest_size,
    char* policy_hash,
    size_t policy_hash_size)
{
    if (record == nullptr || record_size == 0 ||
        digest == nullptr || digest_size != kPolicyUpdateDigestBytes ||
        policy_hash == nullptr || policy_hash_size != kPolicyIdSize) {
        return false;
    }
    memset(digest, 0, digest_size);
    memset(policy_hash, 0, policy_hash_size);
    return policy_store_digest_for_record(record, record_size, digest, digest_size) &&
           policy_store_policy_id_for_record(record, record_size, policy_hash, policy_hash_size);
}

PolicyUpdateHighestAction highest_action_for_document(
    const CurrentPolicyDocument& document)
{
    if (document.blockchains == nullptr) {
        return PolicyUpdateHighestAction::reject;
    }
    for (size_t blockchain_index = 0; blockchain_index < document.blockchain_count; ++blockchain_index) {
        const CurrentPolicyBlockchainScope& blockchain = document.blockchains[blockchain_index];
        if (blockchain.networks == nullptr) {
            continue;
        }
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            const CurrentPolicyNetworkScope& network = blockchain.networks[network_index];
            if (network.policies == nullptr) {
                continue;
            }
            for (size_t policy_index = 0; policy_index < network.policy_count; ++policy_index) {
                if (network.policies[policy_index].action == CurrentPolicyAction::sign) {
                    return PolicyUpdateHighestAction::sign;
                }
            }
        }
    }
    return PolicyUpdateHighestAction::reject;
}

const char* highest_action_name(PolicyUpdateHighestAction action)
{
    switch (action) {
        case PolicyUpdateHighestAction::reject:
            return "reject";
        case PolicyUpdateHighestAction::sign:
            return "sign";
    }
    return "";
}

void format_policy_hash_prefix(const char* input, char* output, size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return;
    }
    output[0] = '\0';
    if (input == nullptr || strncmp(input, "sha256:", 7) != 0 || strlen(input) < 15) {
        return;
    }
    snprintf(output, output_size, "sha256:%.8s", input + 7);
}

bool append_summaryf(char* output, size_t output_size, size_t* offset, const char* format, ...)
{
    if (output == nullptr || output_size == 0 || offset == nullptr || format == nullptr ||
        *offset >= output_size) {
        return false;
    }
    va_list args;
    va_start(args, format);
    const int written = vsnprintf(output + *offset, output_size - *offset, format, args);
    va_end(args);
    if (written <= 0 || static_cast<size_t>(written) >= output_size - *offset) {
        output[output_size - 1] = '\0';
        return false;
    }
    *offset += static_cast<size_t>(written);
    return true;
}

bool append_condition_summary(
    const CurrentPolicyCondition& condition,
    char* output,
    size_t output_size,
    size_t* offset)
{
    if (condition.field == nullptr ||
        condition.value_count == 0 ||
        condition.values == nullptr ||
        !append_summaryf(
            output,
            output_size,
            offset,
            "      - %s %s ",
            condition.field,
            current_policy_operator_name(condition.op))) {
        return false;
    }
    if (condition.where_type != nullptr && condition.where_type[0] != '\0') {
        if (!append_summaryf(output, output_size, offset, "where.type=%s ", condition.where_type)) {
            return false;
        }
    }
    if (current_policy_operator_uses_value_list(condition.op)) {
        if (!append_summaryf(output, output_size, offset, "[")) {
            return false;
        }
        for (size_t value_index = 0; value_index < condition.value_count; ++value_index) {
            if (!append_summaryf(
                    output,
                    output_size,
                    offset,
                    "%s%s",
                    value_index == 0 ? "" : ",",
                    condition.values[value_index] != nullptr ? condition.values[value_index] : "")) {
                return false;
            }
        }
        return append_summaryf(output, output_size, offset, "]\n");
    }
    if (condition.value_count != 1 || condition.values[0] == nullptr) {
        return false;
    }
    return append_summaryf(output, output_size, offset, "%s\n", condition.values[0]);
}

bool build_review_summary(
    const ParsedPolicyProposal& parsed,
    const char* scope_summary,
    const char* policy_hash,
    PolicyUpdateHighestAction highest_action,
    char* output,
    size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return false;
    }
    output[0] = '\0';
    char hash_prefix[16] = {};
    format_policy_hash_prefix(policy_hash, hash_prefix, sizeof(hash_prefix));
    if (hash_prefix[0] == '\0') {
        return false;
    }
    size_t offset = 0;
    if (!append_summaryf(
        output,
        output_size,
        &offset,
        "%s b%u n%u p%u c%u reject->%s\n%s\n",
        hash_prefix,
        static_cast<unsigned>(parsed.document.blockchain_count),
        static_cast<unsigned>(parsed.network_count),
        static_cast<unsigned>(parsed.policy_count),
        static_cast<unsigned>(parsed.condition_count),
        highest_action_name(highest_action),
        scope_summary != nullptr && scope_summary[0] != '\0' ? scope_summary : "none")) {
        return false;
    }
    if (parsed.document.blockchain_count == 0) {
        return append_summaryf(output, output_size, &offset, "no scope\n");
    }
    for (size_t blockchain_index = 0; blockchain_index < parsed.document.blockchain_count; ++blockchain_index) {
        const CurrentPolicyBlockchainScope& blockchain =
            parsed.document.blockchains[blockchain_index];
        if (!append_summaryf(output, output_size, &offset, "scope %s\n", blockchain.blockchain)) {
            return false;
        }
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            const CurrentPolicyNetworkScope& network = blockchain.networks[network_index];
            if (!append_summaryf(output, output_size, &offset, "  network %s\n", network.network)) {
                return false;
            }
            if (network.policy_count == 0) {
                if (!append_summaryf(output, output_size, &offset, "    no policy entries\n")) {
                    return false;
                }
                continue;
            }
            for (size_t policy_index = 0; policy_index < network.policy_count; ++policy_index) {
                const CurrentPolicy& policy = network.policies[policy_index];
                if (!append_summaryf(
                        output,
                        output_size,
                        &offset,
                        "    policy %s %s\n",
                        policy.id,
                        current_policy_action_name(policy.action))) {
                    return false;
                }
                for (size_t condition_index = 0; condition_index < policy.condition_count; ++condition_index) {
                    if (!append_condition_summary(
                            policy.conditions[condition_index],
                            output,
                            output_size,
                            &offset)) {
                        return false;
                    }
                }
            }
        }
    }
    return true;
}

bool append_policy_update_history(const char* result, const char* reason_code, uint64_t uptime_ms)
{
    const PolicyUpdateHistoryAppendInput input{
        result,
        reason_code,
        g_state.policy_hash,
        current_policy_policy_count(),
        highest_action_name(g_state.highest_action),
    };
    return approval_history_append_required_policy_update(input, uptime_ms);
}

PolicyUpdateFlowTerminalResult terminal_result_after_history_failure(bool clear_marker)
{
    if (!clear_marker) {
        g_state.clear();
        return PolicyUpdateFlowTerminalResult::history_error;
    }
    const bool marker_cleared = policy_update_marker_clear();
    if (marker_cleared) {
        g_state.clear();
        return PolicyUpdateFlowTerminalResult::history_error;
    }
    return PolicyUpdateFlowTerminalResult::consistency_error;
}

PolicyUpdateFlowTerminalResult record_terminal_without_commit(
    const char* result,
    const char* reason_code,
    uint64_t uptime_ms,
    PolicyUpdateFlowTerminalResult terminal)
{
    if (!g_state.active) {
        return PolicyUpdateFlowTerminalResult::invalid_state;
    }
    if (!append_policy_update_history(result, reason_code, uptime_ms)) {
        g_state.clear();
        return PolicyUpdateFlowTerminalResult::history_error;
    }
    return terminal;
}

PolicyUpdateFlowTerminalResult clear_marker_or_consistency(
    PolicyUpdateFlowTerminalResult terminal)
{
    if (!policy_update_marker_clear()) {
        return PolicyUpdateFlowTerminalResult::consistency_error;
    }
    return terminal;
}

}  // namespace

bool policy_update_flow_active()
{
    return g_state.active;
}

void policy_update_flow_clear()
{
    g_state.clear();
}

PolicyUpdateFlowSnapshot policy_update_flow_snapshot()
{
    return PolicyUpdateFlowSnapshot{
        g_state.active,
        g_state.stage,
        g_state.request_id,
        g_state.session_id,
        g_state.review_window,
        g_state.policy_hash,
        current_policy_blockchain_count(),
        current_policy_network_count(),
        current_policy_policy_count(),
        current_policy_condition_count(),
        highest_action_name(g_state.highest_action),
        current_policy_default_action_name(),
        g_state.scope_summary,
        g_state.review_summary,
    };
}

PolicyUpdateFlowBeginResult policy_update_flow_begin(
    JsonVariantConst policy,
    const char* request_id,
    const char* session_id,
    TickType_t now,
    TimeoutWindow review_window)
{
    g_state.clear();
    if (!copy_non_empty_bounded(request_id, g_state.request_id, sizeof(g_state.request_id)) ||
        !copy_non_empty_bounded(session_id, g_state.session_id, sizeof(g_state.session_id))) {
        g_state.clear();
        return PolicyUpdateFlowBeginResult::invalid_argument;
    }
    if (!timeout_window_valid_and_open_at(review_window, now)) {
        g_state.clear();
        return PolicyUpdateFlowBeginResult::invalid_argument;
    }
    if (!g_state.allocate_workspaces()) {
        return PolicyUpdateFlowBeginResult::encode_error;
    }

    const PolicyProposalParseStatus parse_status =
        parse_signing_policy_proposal(
            policy,
            g_state.parsed);
    if (parse_status != PolicyProposalParseStatus::ok) {
        g_state.clear();
        switch (parse_status) {
            case PolicyProposalParseStatus::invalid_argument:
                return PolicyUpdateFlowBeginResult::invalid_argument;
            case PolicyProposalParseStatus::too_large:
                return PolicyUpdateFlowBeginResult::too_large;
            case PolicyProposalParseStatus::unsupported_field:
                return PolicyUpdateFlowBeginResult::unsupported_field;
            case PolicyProposalParseStatus::invalid_policy:
            case PolicyProposalParseStatus::ok:
            default:
                return PolicyUpdateFlowBeginResult::invalid_policy;
        }
    }

    if (canonicalize_current_policy_document(
            g_state.parsed->document,
            g_state.canonical) != CurrentPolicyDocumentStatus::ok ||
        encode_current_policy_canonical_record(
            *g_state.canonical,
            g_state.record,
            kCurrentPolicyMaxCanonicalRecordBytes,
            &g_state.record_size) != CurrentPolicyDocumentStatus::ok ||
        !digest_record(
            g_state.record,
            g_state.record_size,
            g_state.digest,
            sizeof(g_state.digest),
            g_state.policy_hash,
            sizeof(g_state.policy_hash))) {
        g_state.clear();
        return PolicyUpdateFlowBeginResult::encode_error;
    }

    g_state.highest_action = highest_action_for_document(g_state.parsed->document);
    snprintf(
        g_state.scope_summary,
        sizeof(g_state.scope_summary),
        "scopes=%u/%u policies=%u conditions=%u",
        static_cast<unsigned>(current_policy_blockchain_count()),
        static_cast<unsigned>(current_policy_network_count()),
        static_cast<unsigned>(current_policy_policy_count()),
        static_cast<unsigned>(current_policy_condition_count()));
    if (!build_review_summary(
            *g_state.parsed,
            g_state.scope_summary,
            g_state.policy_hash,
            g_state.highest_action,
            g_state.review_summary,
            sizeof(g_state.review_summary))) {
        g_state.clear();
        return PolicyUpdateFlowBeginResult::invalid_policy;
    }
    g_state.review_window = review_window;
    g_state.stage = PolicyUpdateFlowStage::reviewing;
    g_state.active = true;
    return PolicyUpdateFlowBeginResult::ok;
}

PolicyUpdateFlowTransitionResult policy_update_flow_continue_to_pin(TickType_t now)
{
    if (!g_state.active) {
        return PolicyUpdateFlowTransitionResult::inactive;
    }
    if (g_state.stage != PolicyUpdateFlowStage::reviewing) {
        return PolicyUpdateFlowTransitionResult::wrong_stage;
    }
    if (!timeout_window_valid(g_state.review_window)) {
        return PolicyUpdateFlowTransitionResult::invalid_deadline;
    }
    if (timeout_window_reached(g_state.review_window, now)) {
        return PolicyUpdateFlowTransitionResult::timed_out;
    }
    g_state.review_window = kTimeoutWindowNone;
    g_state.stage = PolicyUpdateFlowStage::pin_entry;
    return PolicyUpdateFlowTransitionResult::ok;
}

PolicyUpdateFlowTransitionResult policy_update_flow_return_to_review(
    TickType_t now,
    TimeoutWindow review_window)
{
    if (!g_state.active) {
        return PolicyUpdateFlowTransitionResult::inactive;
    }
    if (g_state.stage != PolicyUpdateFlowStage::pin_entry) {
        return PolicyUpdateFlowTransitionResult::wrong_stage;
    }
    if (!timeout_window_valid_and_open_at(review_window, now)) {
        return PolicyUpdateFlowTransitionResult::invalid_deadline;
    }
    g_state.review_window = review_window;
    g_state.stage = PolicyUpdateFlowStage::reviewing;
    return PolicyUpdateFlowTransitionResult::ok;
}

PolicyUpdateFlowTransitionResult policy_update_flow_mark_pin_verifying()
{
    if (!g_state.active) {
        return PolicyUpdateFlowTransitionResult::inactive;
    }
    if (g_state.stage != PolicyUpdateFlowStage::pin_entry) {
        return PolicyUpdateFlowTransitionResult::wrong_stage;
    }
    g_state.stage = PolicyUpdateFlowStage::pin_verifying;
    return PolicyUpdateFlowTransitionResult::ok;
}

PolicyUpdateFlowTransitionResult policy_update_flow_return_to_pin_entry()
{
    if (!g_state.active) {
        return PolicyUpdateFlowTransitionResult::inactive;
    }
    if (g_state.stage != PolicyUpdateFlowStage::pin_verifying) {
        return PolicyUpdateFlowTransitionResult::wrong_stage;
    }
    g_state.stage = PolicyUpdateFlowStage::pin_entry;
    return PolicyUpdateFlowTransitionResult::ok;
}

bool policy_update_flow_review_deadline_reached(TickType_t now)
{
    return g_state.active &&
           g_state.stage == PolicyUpdateFlowStage::reviewing &&
           timeout_window_reached(g_state.review_window, now);
}

PolicyUpdateFlowTerminalResult policy_update_flow_record_rejected(uint64_t uptime_ms)
{
    if (!g_state.active || g_state.stage != PolicyUpdateFlowStage::reviewing) {
        return PolicyUpdateFlowTerminalResult::invalid_state;
    }
    return record_terminal_without_commit(
        "rejected",
        "device_rejected",
        uptime_ms,
        PolicyUpdateFlowTerminalResult::rejected);
}

PolicyUpdateFlowTerminalResult policy_update_flow_record_timed_out(uint64_t uptime_ms)
{
    if (!g_state.active ||
        (g_state.stage != PolicyUpdateFlowStage::reviewing &&
         g_state.stage != PolicyUpdateFlowStage::pin_entry)) {
        return PolicyUpdateFlowTerminalResult::invalid_state;
    }
    return record_terminal_without_commit(
        "timed_out",
        "timeout",
        uptime_ms,
        PolicyUpdateFlowTerminalResult::timed_out);
}

PolicyUpdateFlowTerminalResult policy_update_flow_record_ui_error()
{
    if (!g_state.active) {
        return PolicyUpdateFlowTerminalResult::invalid_state;
    }
    return PolicyUpdateFlowTerminalResult::ui_error;
}

PolicyUpdateFlowTerminalResult policy_update_flow_commit(uint64_t uptime_ms)
{
    if (!g_state.active) {
        return PolicyUpdateFlowTerminalResult::invalid_state;
    }
    if (g_state.stage != PolicyUpdateFlowStage::pin_verifying) {
        return PolicyUpdateFlowTerminalResult::invalid_state;
    }
    g_state.stage = PolicyUpdateFlowStage::committing;

    const PolicyUpdateMarkerBeginResult marker_result =
        policy_update_marker_begin(
            g_state.digest,
            sizeof(g_state.digest),
            current_policy_policy_count(),
            g_state.highest_action);
    if (marker_result == PolicyUpdateMarkerBeginResult::pending_after_error) {
        return PolicyUpdateFlowTerminalResult::consistency_error;
    }
    if (marker_result != PolicyUpdateMarkerBeginResult::written) {
        const bool history_written =
            append_policy_update_history("storage_error", "storage_error", uptime_ms);
        if (history_written) {
            return PolicyUpdateFlowTerminalResult::storage_error;
        }
        g_state.clear();
        return PolicyUpdateFlowTerminalResult::history_error;
    }

    const PolicyStoreWriteResult store_result =
        store_active_policy_record(g_state.record, g_state.record_size);
    switch (store_result) {
        case PolicyStoreWriteResult::applied:
            if (!append_policy_update_history("applied", "device_confirmed", uptime_ms)) {
                return PolicyUpdateFlowTerminalResult::consistency_error;
            }
            return clear_marker_or_consistency(PolicyUpdateFlowTerminalResult::applied);

        case PolicyStoreWriteResult::unchanged_failure:
            if (!append_policy_update_history("storage_error", "storage_error", uptime_ms)) {
                return terminal_result_after_history_failure(true);
            }
            return clear_marker_or_consistency(PolicyUpdateFlowTerminalResult::storage_error);

        case PolicyStoreWriteResult::consistency_error:
        case PolicyStoreWriteResult::invalid_record:
        default:
            return PolicyUpdateFlowTerminalResult::consistency_error;
    }
}

const char* policy_update_flow_begin_result_reason(PolicyUpdateFlowBeginResult result)
{
    switch (result) {
        case PolicyUpdateFlowBeginResult::too_large:
            return "too_large";
        case PolicyUpdateFlowBeginResult::unsupported_field:
            return "unsupported_field";
        case PolicyUpdateFlowBeginResult::encode_error:
            return "encode_error";
        case PolicyUpdateFlowBeginResult::invalid_argument:
        case PolicyUpdateFlowBeginResult::invalid_policy:
        case PolicyUpdateFlowBeginResult::ok:
        default:
            return "invalid_policy";
    }
}

const char* policy_update_flow_terminal_status(PolicyUpdateFlowTerminalResult result)
{
    switch (result) {
        case PolicyUpdateFlowTerminalResult::applied:
            return "applied";
        case PolicyUpdateFlowTerminalResult::rejected:
            return "rejected";
        case PolicyUpdateFlowTerminalResult::timed_out:
            return "timed_out";
        case PolicyUpdateFlowTerminalResult::ui_error:
            return "ui_error";
        case PolicyUpdateFlowTerminalResult::storage_error:
            return "storage_error";
        case PolicyUpdateFlowTerminalResult::consistency_error:
            return "consistency_error";
        default:
            return "";
    }
}

const char* policy_update_flow_terminal_reason(PolicyUpdateFlowTerminalResult result)
{
    switch (result) {
        case PolicyUpdateFlowTerminalResult::applied:
            return "device_confirmed";
        case PolicyUpdateFlowTerminalResult::rejected:
            return "device_rejected";
        case PolicyUpdateFlowTerminalResult::timed_out:
            return "timeout";
        case PolicyUpdateFlowTerminalResult::ui_error:
            return "ui_error";
        case PolicyUpdateFlowTerminalResult::storage_error:
            return "storage_error";
        case PolicyUpdateFlowTerminalResult::consistency_error:
            return "consistency_error";
        case PolicyUpdateFlowTerminalResult::history_error:
            return "history_error";
        case PolicyUpdateFlowTerminalResult::invalid_state:
        default:
            return "invalid_state";
    }
}

}  // namespace signing
