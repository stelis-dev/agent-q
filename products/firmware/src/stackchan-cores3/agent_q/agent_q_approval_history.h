#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_common/policy/agent_q_policy_schema.h"

namespace agent_q {

constexpr size_t kAgentQApprovalHistoryCapacity = 32;
constexpr size_t kAgentQApprovalHistoryPageMax = 4;
constexpr size_t kAgentQApprovalHistoryChainSize = 12;
constexpr size_t kAgentQApprovalHistoryMethodSize = 32;
constexpr size_t kAgentQApprovalHistoryReasonCodeSize = 32;
constexpr size_t kAgentQApprovalHistoryRuleRefSize = kAgentQPolicyMaxRuleIdLength + 1;
constexpr size_t kAgentQApprovalHistoryDigestSize = 72;  // "sha256:" + 64 hex chars + NUL.
constexpr uint64_t kAgentQApprovalHistoryWriteBudgetWindowMs = 60000;
constexpr size_t kAgentQApprovalHistoryWriteBudgetMax = 12;

enum class AgentQApprovalHistoryDecision {
    policy_approved,
    policy_rejected,
    user_approved,
    user_rejected,
    user_timeout,
    method_error,
};

enum class AgentQApprovalHistoryConfirmationKind {
    none,
    policy,
    physical_confirm,
};

enum class AgentQApprovalHistoryReadResult {
    ok,
    storage_error,
    invalid,
};

struct AgentQApprovalHistoryAppendInput {
    AgentQApprovalHistoryDecision decision;
    AgentQApprovalHistoryConfirmationKind confirmation_kind;
    const char* chain;
    const char* method;
    const char* reason_code;
    const char* payload_digest;
    const char* policy_hash;
    const char* rule_ref;
};

struct AgentQApprovalHistoryRecord {
    uint64_t sequence;
    uint64_t uptime_ms;
    AgentQApprovalHistoryDecision decision;
    AgentQApprovalHistoryConfirmationKind confirmation_kind;
    char chain[kAgentQApprovalHistoryChainSize];
    char method[kAgentQApprovalHistoryMethodSize];
    char reason_code[kAgentQApprovalHistoryReasonCodeSize];
    char payload_digest[kAgentQApprovalHistoryDigestSize];
    char policy_hash[kAgentQApprovalHistoryDigestSize];
    char rule_ref[kAgentQApprovalHistoryRuleRefSize];
};

struct AgentQApprovalHistoryPage {
    AgentQApprovalHistoryRecord records[kAgentQApprovalHistoryPageMax];
    size_t count;
    bool has_more;
};

bool approval_history_digest_payload(
    const uint8_t* payload,
    size_t payload_size,
    char* output,
    size_t output_size);
bool approval_history_parse_sequence(const char* value, uint64_t* output);
bool approval_history_append(
    const AgentQApprovalHistoryAppendInput& input,
    uint64_t uptime_ms);
AgentQApprovalHistoryReadResult approval_history_read_page(
    uint64_t before_sequence,
    size_t limit,
    AgentQApprovalHistoryPage* output);
bool approval_history_wipe();

const char* approval_history_decision_to_string(AgentQApprovalHistoryDecision value);
const char* approval_history_confirmation_kind_to_string(AgentQApprovalHistoryConfirmationKind value);

}  // namespace agent_q
