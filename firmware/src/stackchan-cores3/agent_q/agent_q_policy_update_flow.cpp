#include "agent_q_policy_update_flow.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_approval_history.h"
#include "agent_q_policy_proposal_parser.h"
#include "agent_q_policy_store.h"
#include "agent_q_common/policy/agent_q_policy_canonical.h"
#include "agent_q_common/policy/agent_q_policy_v0.h"
#include "agent_q_common/sui/agent_q_sui_method_adapter.h"

namespace agent_q {
namespace {

constexpr size_t kPolicyUpdateMethodDescriptorCount = 1;

struct AgentQPolicyUpdateFlowState {
    bool active = false;
    AgentQPolicyUpdateFlowStage stage = AgentQPolicyUpdateFlowStage::idle;
    char request_id[kAgentQRequestIdSize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    AgentQTimeoutWindow review_window = kAgentQTimeoutWindowNone;
    AgentQParsedPolicyProposal* parsed = nullptr;
    AgentQPolicyCanonicalDocument* canonical = nullptr;
    uint8_t* record = nullptr;
    size_t record_size = 0;
    uint8_t digest[kAgentQPolicyUpdateDigestBytes] = {};
    char policy_hash[kAgentQPolicyIdSize] = {};
    char method_summary[kAgentQPolicyMaxChainIdLength + kAgentQPolicyMaxOperationLength + 2] = {};
    char review_summary[256] = {};
    AgentQPolicyUpdateHighestAction highest_action = AgentQPolicyUpdateHighestAction::reject;

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
            memset(record, 0, kAgentQPolicyMaxCanonicalRecordBytes);
            free(record);
        }
        memset(this, 0, sizeof(*this));
        stage = AgentQPolicyUpdateFlowStage::idle;
        highest_action = AgentQPolicyUpdateHighestAction::reject;
    }

    bool allocate_workspaces()
    {
        parsed = static_cast<AgentQParsedPolicyProposal*>(malloc(sizeof(*parsed)));
        canonical = static_cast<AgentQPolicyCanonicalDocument*>(malloc(sizeof(*canonical)));
        record = static_cast<uint8_t*>(malloc(kAgentQPolicyMaxCanonicalRecordBytes));
        if (parsed == nullptr || canonical == nullptr || record == nullptr) {
            clear();
            return false;
        }
        memset(parsed, 0, sizeof(*parsed));
        memset(canonical, 0, sizeof(*canonical));
        memset(record, 0, kAgentQPolicyMaxCanonicalRecordBytes);
        return true;
    }
};

AgentQPolicyUpdateFlowState g_state;

size_t current_policy_rule_count()
{
    return g_state.parsed != nullptr ? g_state.parsed->document.rule_count : 0;
}

const char* current_policy_default_action_name()
{
    return g_state.parsed != nullptr
               ? agent_q_policy_action_name(g_state.parsed->document.default_action)
               : agent_q_policy_action_name(AgentQPolicyAction::reject);
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

AgentQPolicyMethodDescriptor method_descriptor()
{
    return sui_sign_transaction_policy_method_descriptor();
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
        digest == nullptr || digest_size != kAgentQPolicyUpdateDigestBytes ||
        policy_hash == nullptr || policy_hash_size != kAgentQPolicyIdSize) {
        return false;
    }
    memset(digest, 0, digest_size);
    memset(policy_hash, 0, policy_hash_size);
    return policy_store_digest_for_record(record, record_size, digest, digest_size) &&
           policy_store_policy_id_for_record(record, record_size, policy_hash, policy_hash_size);
}

AgentQPolicyUpdateHighestAction highest_action_for_document(
    const AgentQPolicyDocument& document)
{
    for (size_t index = 0; index < document.rule_count; ++index) {
        if (document.rules != nullptr &&
            document.rules[index].action == AgentQPolicyAction::sign) {
            return AgentQPolicyUpdateHighestAction::sign;
        }
    }
    return AgentQPolicyUpdateHighestAction::reject;
}

const char* highest_action_name(AgentQPolicyUpdateHighestAction action)
{
    switch (action) {
        case AgentQPolicyUpdateHighestAction::reject:
            return "reject";
        case AgentQPolicyUpdateHighestAction::sign:
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

bool build_review_summary(
    const AgentQPolicyDocument& document,
    const char* method_summary,
    const char* policy_hash,
    AgentQPolicyUpdateHighestAction highest_action,
    char* output,
    size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return false;
    }
    output[0] = '\0';
    const AgentQPolicyRule* sign_rule = nullptr;
    for (size_t index = 0; index < document.rule_count; ++index) {
        if (document.rules != nullptr &&
            document.rules[index].action == AgentQPolicyAction::sign) {
            sign_rule = &document.rules[index];
        }
    }
    if (!agent_q_policy_sign_rule_count_is_supported(document)) {
        return false;
    }
    char hash_prefix[16] = {};
    format_policy_hash_prefix(policy_hash, hash_prefix, sizeof(hash_prefix));
    if (hash_prefix[0] == '\0') {
        return false;
    }
    if (sign_rule != nullptr) {
        char sign_summary[128] = {};
        if (!sui_sign_transaction_policy_build_sign_rule_summary(
                *sign_rule,
                sign_summary,
                sizeof(sign_summary))) {
            return false;
        }
        const int written = snprintf(
            output,
            output_size,
            "%s r%u reject->%s\n%s\n%s",
            hash_prefix,
            static_cast<unsigned>(document.rule_count),
            highest_action_name(highest_action),
            method_summary != nullptr && method_summary[0] != '\0' ? method_summary : "none",
            sign_summary);
        return written > 0 && static_cast<size_t>(written) < output_size;
    }
    const int written = snprintf(
        output,
        output_size,
        "%s r%u reject->%s\n%s reject policy",
        hash_prefix,
        static_cast<unsigned>(document.rule_count),
        highest_action_name(highest_action),
        method_summary != nullptr && method_summary[0] != '\0' ? method_summary : "none");
    return written > 0 && static_cast<size_t>(written) < output_size;
}

bool append_policy_update_history(const char* result, const char* reason_code, uint64_t uptime_ms)
{
    const AgentQPolicyUpdateHistoryAppendInput input{
        result,
        reason_code,
        g_state.policy_hash,
        current_policy_rule_count(),
        highest_action_name(g_state.highest_action),
    };
    return approval_history_append_required_policy_update(input, uptime_ms);
}

AgentQPolicyUpdateFlowTerminalResult terminal_result_after_history_failure(bool clear_marker)
{
    if (!clear_marker) {
        g_state.clear();
        return AgentQPolicyUpdateFlowTerminalResult::history_error;
    }
    const bool marker_cleared = policy_update_marker_clear();
    if (marker_cleared) {
        g_state.clear();
        return AgentQPolicyUpdateFlowTerminalResult::history_error;
    }
    return AgentQPolicyUpdateFlowTerminalResult::consistency_error;
}

AgentQPolicyUpdateFlowTerminalResult record_terminal_without_commit(
    const char* result,
    const char* reason_code,
    uint64_t uptime_ms,
    AgentQPolicyUpdateFlowTerminalResult terminal)
{
    if (!g_state.active) {
        return AgentQPolicyUpdateFlowTerminalResult::invalid_state;
    }
    if (!append_policy_update_history(result, reason_code, uptime_ms)) {
        g_state.clear();
        return AgentQPolicyUpdateFlowTerminalResult::history_error;
    }
    return terminal;
}

AgentQPolicyUpdateFlowTerminalResult clear_marker_or_consistency(
    AgentQPolicyUpdateFlowTerminalResult terminal)
{
    if (!policy_update_marker_clear()) {
        return AgentQPolicyUpdateFlowTerminalResult::consistency_error;
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

AgentQPolicyUpdateFlowSnapshot policy_update_flow_snapshot()
{
    return AgentQPolicyUpdateFlowSnapshot{
        g_state.active,
        g_state.stage,
        g_state.request_id,
        g_state.session_id,
        g_state.review_window,
        g_state.policy_hash,
        current_policy_rule_count(),
        highest_action_name(g_state.highest_action),
        current_policy_default_action_name(),
        g_state.method_summary,
        g_state.review_summary,
    };
}

AgentQPolicyUpdateFlowBeginResult policy_update_flow_begin(
    JsonVariantConst policy,
    const char* request_id,
    const char* session_id,
    TickType_t now,
    AgentQTimeoutWindow review_window)
{
    g_state.clear();
    if (!copy_non_empty_bounded(request_id, g_state.request_id, sizeof(g_state.request_id)) ||
        !copy_non_empty_bounded(session_id, g_state.session_id, sizeof(g_state.session_id))) {
        g_state.clear();
        return AgentQPolicyUpdateFlowBeginResult::invalid_argument;
    }
    if (!timeout_window_valid_and_open_at(review_window, now)) {
        g_state.clear();
        return AgentQPolicyUpdateFlowBeginResult::invalid_argument;
    }
    if (!g_state.allocate_workspaces()) {
        return AgentQPolicyUpdateFlowBeginResult::encode_error;
    }

    const AgentQPolicyMethodDescriptor descriptors[kPolicyUpdateMethodDescriptorCount] = {
        method_descriptor(),
    };

    const AgentQPolicyProposalParseStatus parse_status =
        parse_agent_q_policy_proposal(
            policy,
            descriptors,
            kPolicyUpdateMethodDescriptorCount,
            g_state.parsed);
    if (parse_status != AgentQPolicyProposalParseStatus::ok) {
        g_state.clear();
        switch (parse_status) {
            case AgentQPolicyProposalParseStatus::invalid_argument:
                return AgentQPolicyUpdateFlowBeginResult::invalid_argument;
            case AgentQPolicyProposalParseStatus::too_large:
                return AgentQPolicyUpdateFlowBeginResult::too_large;
            case AgentQPolicyProposalParseStatus::unsupported_method:
                return AgentQPolicyUpdateFlowBeginResult::unsupported_method;
            case AgentQPolicyProposalParseStatus::unsupported_field:
                return AgentQPolicyUpdateFlowBeginResult::unsupported_field;
            case AgentQPolicyProposalParseStatus::invalid_policy:
            case AgentQPolicyProposalParseStatus::ok:
            default:
                return AgentQPolicyUpdateFlowBeginResult::invalid_policy;
        }
    }

    if (canonicalize_agent_q_policy_v0(
            g_state.parsed->document,
            descriptors,
            kPolicyUpdateMethodDescriptorCount,
            g_state.canonical) != AgentQPolicyCanonicalStatus::ok ||
        encode_agent_q_policy_v0_canonical_record(
            *g_state.canonical,
            g_state.record,
            kAgentQPolicyMaxCanonicalRecordBytes,
            &g_state.record_size) != AgentQPolicyCanonicalStatus::ok ||
        !digest_record(
            g_state.record,
            g_state.record_size,
            g_state.digest,
            sizeof(g_state.digest),
            g_state.policy_hash,
            sizeof(g_state.policy_hash))) {
        g_state.clear();
        return AgentQPolicyUpdateFlowBeginResult::encode_error;
    }

    g_state.highest_action = highest_action_for_document(g_state.parsed->document);
    if (g_state.parsed->document.rule_count > 0) {
        snprintf(
            g_state.method_summary,
            sizeof(g_state.method_summary),
            "%s/%s",
            g_state.parsed->document.rules[0].chain,
            g_state.parsed->document.rules[0].operation);
    } else {
        strlcpy(g_state.method_summary, "none", sizeof(g_state.method_summary));
    }
    if (!build_review_summary(
            g_state.parsed->document,
            g_state.method_summary,
            g_state.policy_hash,
            g_state.highest_action,
            g_state.review_summary,
            sizeof(g_state.review_summary))) {
        g_state.clear();
        return AgentQPolicyUpdateFlowBeginResult::invalid_policy;
    }
    g_state.review_window = review_window;
    g_state.stage = AgentQPolicyUpdateFlowStage::reviewing;
    g_state.active = true;
    return AgentQPolicyUpdateFlowBeginResult::ok;
}

AgentQPolicyUpdateFlowTransitionResult policy_update_flow_continue_to_pin(TickType_t now)
{
    if (!g_state.active) {
        return AgentQPolicyUpdateFlowTransitionResult::inactive;
    }
    if (g_state.stage != AgentQPolicyUpdateFlowStage::reviewing) {
        return AgentQPolicyUpdateFlowTransitionResult::wrong_stage;
    }
    if (!timeout_window_valid(g_state.review_window)) {
        return AgentQPolicyUpdateFlowTransitionResult::invalid_deadline;
    }
    if (timeout_window_reached(g_state.review_window, now)) {
        return AgentQPolicyUpdateFlowTransitionResult::timed_out;
    }
    g_state.review_window = kAgentQTimeoutWindowNone;
    g_state.stage = AgentQPolicyUpdateFlowStage::pin_entry;
    return AgentQPolicyUpdateFlowTransitionResult::ok;
}

AgentQPolicyUpdateFlowTransitionResult policy_update_flow_return_to_review(
    TickType_t now,
    AgentQTimeoutWindow review_window)
{
    if (!g_state.active) {
        return AgentQPolicyUpdateFlowTransitionResult::inactive;
    }
    if (g_state.stage != AgentQPolicyUpdateFlowStage::pin_entry) {
        return AgentQPolicyUpdateFlowTransitionResult::wrong_stage;
    }
    if (!timeout_window_valid_and_open_at(review_window, now)) {
        return AgentQPolicyUpdateFlowTransitionResult::invalid_deadline;
    }
    g_state.review_window = review_window;
    g_state.stage = AgentQPolicyUpdateFlowStage::reviewing;
    return AgentQPolicyUpdateFlowTransitionResult::ok;
}

AgentQPolicyUpdateFlowTransitionResult policy_update_flow_mark_pin_verifying()
{
    if (!g_state.active) {
        return AgentQPolicyUpdateFlowTransitionResult::inactive;
    }
    if (g_state.stage != AgentQPolicyUpdateFlowStage::pin_entry) {
        return AgentQPolicyUpdateFlowTransitionResult::wrong_stage;
    }
    g_state.stage = AgentQPolicyUpdateFlowStage::pin_verifying;
    return AgentQPolicyUpdateFlowTransitionResult::ok;
}

AgentQPolicyUpdateFlowTransitionResult policy_update_flow_return_to_pin_entry()
{
    if (!g_state.active) {
        return AgentQPolicyUpdateFlowTransitionResult::inactive;
    }
    if (g_state.stage != AgentQPolicyUpdateFlowStage::pin_verifying) {
        return AgentQPolicyUpdateFlowTransitionResult::wrong_stage;
    }
    g_state.stage = AgentQPolicyUpdateFlowStage::pin_entry;
    return AgentQPolicyUpdateFlowTransitionResult::ok;
}

bool policy_update_flow_review_deadline_reached(TickType_t now)
{
    return g_state.active &&
           g_state.stage == AgentQPolicyUpdateFlowStage::reviewing &&
           timeout_window_reached(g_state.review_window, now);
}

AgentQPolicyUpdateFlowTerminalResult policy_update_flow_record_rejected(uint64_t uptime_ms)
{
    if (!g_state.active || g_state.stage != AgentQPolicyUpdateFlowStage::reviewing) {
        return AgentQPolicyUpdateFlowTerminalResult::invalid_state;
    }
    return record_terminal_without_commit(
        "rejected",
        "device_rejected",
        uptime_ms,
        AgentQPolicyUpdateFlowTerminalResult::rejected);
}

AgentQPolicyUpdateFlowTerminalResult policy_update_flow_record_timed_out(uint64_t uptime_ms)
{
    if (!g_state.active ||
        (g_state.stage != AgentQPolicyUpdateFlowStage::reviewing &&
         g_state.stage != AgentQPolicyUpdateFlowStage::pin_entry)) {
        return AgentQPolicyUpdateFlowTerminalResult::invalid_state;
    }
    return record_terminal_without_commit(
        "timed_out",
        "timeout",
        uptime_ms,
        AgentQPolicyUpdateFlowTerminalResult::timed_out);
}

AgentQPolicyUpdateFlowTerminalResult policy_update_flow_record_ui_error()
{
    if (!g_state.active) {
        return AgentQPolicyUpdateFlowTerminalResult::invalid_state;
    }
    return AgentQPolicyUpdateFlowTerminalResult::ui_error;
}

AgentQPolicyUpdateFlowTerminalResult policy_update_flow_commit(uint64_t uptime_ms)
{
    if (!g_state.active) {
        return AgentQPolicyUpdateFlowTerminalResult::invalid_state;
    }
    if (g_state.stage != AgentQPolicyUpdateFlowStage::pin_verifying) {
        return AgentQPolicyUpdateFlowTerminalResult::invalid_state;
    }
    g_state.stage = AgentQPolicyUpdateFlowStage::committing;

    const AgentQPolicyUpdateMarkerBeginResult marker_result =
        policy_update_marker_begin(
            g_state.digest,
            sizeof(g_state.digest),
            current_policy_rule_count(),
            g_state.highest_action);
    if (marker_result == AgentQPolicyUpdateMarkerBeginResult::pending_after_error) {
        return AgentQPolicyUpdateFlowTerminalResult::consistency_error;
    }
    if (marker_result != AgentQPolicyUpdateMarkerBeginResult::written) {
        const bool history_written =
            append_policy_update_history("storage_error", "storage_error", uptime_ms);
        if (history_written) {
            return AgentQPolicyUpdateFlowTerminalResult::storage_error;
        }
        g_state.clear();
        return AgentQPolicyUpdateFlowTerminalResult::history_error;
    }

    const AgentQPolicyStoreWriteResult store_result =
        store_active_policy_record(g_state.record, g_state.record_size);
    switch (store_result) {
        case AgentQPolicyStoreWriteResult::applied:
            if (!append_policy_update_history("applied", "device_confirmed", uptime_ms)) {
                return AgentQPolicyUpdateFlowTerminalResult::consistency_error;
            }
            return clear_marker_or_consistency(AgentQPolicyUpdateFlowTerminalResult::applied);

        case AgentQPolicyStoreWriteResult::unchanged_failure:
            if (!append_policy_update_history("storage_error", "storage_error", uptime_ms)) {
                return terminal_result_after_history_failure(true);
            }
            return clear_marker_or_consistency(AgentQPolicyUpdateFlowTerminalResult::storage_error);

        case AgentQPolicyStoreWriteResult::consistency_error:
        case AgentQPolicyStoreWriteResult::invalid_record:
        default:
            return AgentQPolicyUpdateFlowTerminalResult::consistency_error;
    }
}

const char* policy_update_flow_begin_result_reason(AgentQPolicyUpdateFlowBeginResult result)
{
    switch (result) {
        case AgentQPolicyUpdateFlowBeginResult::too_large:
            return "too_large";
        case AgentQPolicyUpdateFlowBeginResult::unsupported_method:
            return "unsupported_method";
        case AgentQPolicyUpdateFlowBeginResult::unsupported_field:
            return "unsupported_field";
        case AgentQPolicyUpdateFlowBeginResult::encode_error:
            return "encode_error";
        case AgentQPolicyUpdateFlowBeginResult::invalid_argument:
        case AgentQPolicyUpdateFlowBeginResult::invalid_policy:
        case AgentQPolicyUpdateFlowBeginResult::ok:
        default:
            return "invalid_policy";
    }
}

const char* policy_update_flow_terminal_status(AgentQPolicyUpdateFlowTerminalResult result)
{
    switch (result) {
        case AgentQPolicyUpdateFlowTerminalResult::applied:
            return "applied";
        case AgentQPolicyUpdateFlowTerminalResult::rejected:
            return "rejected";
        case AgentQPolicyUpdateFlowTerminalResult::timed_out:
            return "timed_out";
        case AgentQPolicyUpdateFlowTerminalResult::ui_error:
            return "ui_error";
        case AgentQPolicyUpdateFlowTerminalResult::storage_error:
            return "storage_error";
        case AgentQPolicyUpdateFlowTerminalResult::consistency_error:
            return "consistency_error";
        default:
            return "";
    }
}

const char* policy_update_flow_terminal_reason(AgentQPolicyUpdateFlowTerminalResult result)
{
    switch (result) {
        case AgentQPolicyUpdateFlowTerminalResult::applied:
            return "device_confirmed";
        case AgentQPolicyUpdateFlowTerminalResult::rejected:
            return "device_rejected";
        case AgentQPolicyUpdateFlowTerminalResult::timed_out:
            return "timeout";
        case AgentQPolicyUpdateFlowTerminalResult::ui_error:
            return "ui_error";
        case AgentQPolicyUpdateFlowTerminalResult::storage_error:
            return "storage_error";
        case AgentQPolicyUpdateFlowTerminalResult::consistency_error:
            return "consistency_error";
        case AgentQPolicyUpdateFlowTerminalResult::history_error:
            return "history_error";
        case AgentQPolicyUpdateFlowTerminalResult::invalid_state:
        default:
            return "invalid_state";
    }
}

}  // namespace agent_q
