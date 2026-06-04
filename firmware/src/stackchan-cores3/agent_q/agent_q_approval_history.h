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
constexpr size_t kAgentQApprovalHistoryPolicyResultSize = 32;
constexpr size_t kAgentQApprovalHistoryHighestActionSize = 8;
constexpr uint64_t kAgentQApprovalHistoryWriteBudgetWindowMs = 60000;
constexpr size_t kAgentQApprovalHistoryWriteBudgetMax = 12;

enum class AgentQApprovalHistoryConfirmationKind {
    none,
    policy,
    local_pin,
};

enum class AgentQApprovalHistoryReadResult {
    ok,
    storage_error,
    invalid,
};

enum class AgentQApprovalHistoryEventKind {
    policy_update,
    signing,
};

enum class AgentQSigningHistoryRecordKind {
    none,
    confirmation,
    terminal,
};

enum class AgentQSigningHistoryTerminalResult {
    none,
    signed_success,
    user_rejected,
    user_timed_out,
    policy_rejected,
    signing_failed,
};

struct AgentQPolicyUpdateHistoryAppendInput {
    const char* result;
    const char* reason_code;
    const char* policy_hash;
    size_t rule_count;
    const char* highest_action;
};

struct AgentQSigningHistoryAppendInput {
    AgentQSigningHistoryRecordKind record_kind;
    AgentQApprovalHistoryConfirmationKind confirmation_kind;
    AgentQSigningHistoryTerminalResult terminal_result;
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
    AgentQApprovalHistoryEventKind event_kind;
    AgentQApprovalHistoryConfirmationKind confirmation_kind;
    AgentQSigningHistoryRecordKind signing_record_kind;
    AgentQSigningHistoryTerminalResult signing_terminal_result;
    char chain[kAgentQApprovalHistoryChainSize];
    char method[kAgentQApprovalHistoryMethodSize];
    char reason_code[kAgentQApprovalHistoryReasonCodeSize];
    char payload_digest[kAgentQApprovalHistoryDigestSize];
    char policy_hash[kAgentQApprovalHistoryDigestSize];
    char rule_ref[kAgentQApprovalHistoryRuleRefSize];
    char policy_result[kAgentQApprovalHistoryPolicyResultSize];
    char highest_action[kAgentQApprovalHistoryHighestActionSize];
    size_t rule_count;
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
bool approval_history_append_required_policy_update(
    const AgentQPolicyUpdateHistoryAppendInput& input,
    uint64_t uptime_ms);
bool approval_history_append_required_signing(
    const AgentQSigningHistoryAppendInput& input,
    uint64_t uptime_ms);
bool approval_history_append_budgeted_signing(
    const AgentQSigningHistoryAppendInput& input,
    uint64_t uptime_ms);
AgentQApprovalHistoryReadResult approval_history_read_page(
    uint64_t before_sequence,
    size_t limit,
    AgentQApprovalHistoryPage* output);
bool approval_history_wipe();

const char* approval_history_confirmation_kind_to_string(AgentQApprovalHistoryConfirmationKind value);
const char* approval_history_signing_record_kind_to_string(
    AgentQSigningHistoryRecordKind value);
const char* approval_history_signing_terminal_result_to_string(
    AgentQSigningHistoryTerminalResult value);

}  // namespace agent_q
