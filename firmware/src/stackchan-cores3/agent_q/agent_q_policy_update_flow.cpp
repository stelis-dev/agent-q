#include "agent_q_policy_update_flow.h"

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
    AgentQParsedPolicyProposal parsed = {};
    AgentQPolicyCanonicalDocument canonical = {};
    uint8_t record[kAgentQPolicyMaxCanonicalRecordBytes] = {};
    size_t record_size = 0;
    uint8_t digest[kAgentQPolicyUpdateDigestBytes] = {};
    char policy_hash[kAgentQPolicyIdSize] = {};
    char method_summary[kAgentQPolicyMaxChainIdLength + kAgentQPolicyMaxOperationLength + 2] = {};
    AgentQPolicyUpdateHighestAction highest_action = AgentQPolicyUpdateHighestAction::reject;

    void clear()
    {
        memset(this, 0, sizeof(*this));
        highest_action = AgentQPolicyUpdateHighestAction::reject;
    }
};

AgentQPolicyUpdateFlowState g_state;

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
    (void)document;
    return AgentQPolicyUpdateHighestAction::reject;
}

const char* highest_action_name(AgentQPolicyUpdateHighestAction action)
{
    switch (action) {
        case AgentQPolicyUpdateHighestAction::reject:
            return "reject";
    }
    return "";
}

bool append_policy_update_history(const char* result, const char* reason_code, uint64_t uptime_ms)
{
    const AgentQPolicyUpdateHistoryAppendInput input{
        result,
        reason_code,
        g_state.policy_hash,
        g_state.parsed.document.rule_count,
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
        g_state.policy_hash,
        g_state.parsed.document.rule_count,
        highest_action_name(g_state.highest_action),
        agent_q_policy_action_name(g_state.parsed.document.default_action),
        g_state.method_summary,
    };
}

AgentQPolicyUpdateFlowBeginResult policy_update_flow_begin(JsonVariantConst policy)
{
    g_state.clear();

    const AgentQPolicyMethodDescriptor descriptors[kPolicyUpdateMethodDescriptorCount] = {
        method_descriptor(),
    };

    const AgentQPolicyProposalParseStatus parse_status =
        parse_agent_q_policy_proposal(
            policy,
            descriptors,
            kPolicyUpdateMethodDescriptorCount,
            &g_state.parsed);
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
            g_state.parsed.document,
            descriptors,
            kPolicyUpdateMethodDescriptorCount,
            &g_state.canonical) != AgentQPolicyCanonicalStatus::ok ||
        encode_agent_q_policy_v0_canonical_record(
            g_state.canonical,
            g_state.record,
            sizeof(g_state.record),
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

    g_state.highest_action = highest_action_for_document(g_state.parsed.document);
    if (g_state.parsed.document.rule_count > 0) {
        snprintf(
            g_state.method_summary,
            sizeof(g_state.method_summary),
            "%s/%s",
            g_state.parsed.document.rules[0].chain,
            g_state.parsed.document.rules[0].operation);
    } else {
        strlcpy(g_state.method_summary, "none", sizeof(g_state.method_summary));
    }
    g_state.active = true;
    return AgentQPolicyUpdateFlowBeginResult::ok;
}

AgentQPolicyUpdateFlowTerminalResult policy_update_flow_record_rejected(uint64_t uptime_ms)
{
    return record_terminal_without_commit(
        "rejected",
        "device_rejected",
        uptime_ms,
        AgentQPolicyUpdateFlowTerminalResult::rejected);
}

AgentQPolicyUpdateFlowTerminalResult policy_update_flow_record_timed_out(uint64_t uptime_ms)
{
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

    const AgentQPolicyUpdateMarkerBeginResult marker_result =
        policy_update_marker_begin(
            g_state.digest,
            sizeof(g_state.digest),
            g_state.parsed.document.rule_count,
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
