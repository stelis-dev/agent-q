#pragma once

#include <stddef.h>
#include <stdint.h>

#include "policy/document.h"

namespace signing {

#ifndef AGENT_Q_APPROVAL_HISTORY_CAPACITY
#define AGENT_Q_APPROVAL_HISTORY_CAPACITY 32
#endif

static_assert(AGENT_Q_APPROVAL_HISTORY_CAPACITY > 0,
              "Approval history capacity must be positive");
constexpr size_t kApprovalHistoryCapacity = AGENT_Q_APPROVAL_HISTORY_CAPACITY;
constexpr size_t kApprovalHistoryPageMax = 4;
constexpr size_t kApprovalHistoryChainSize = 12;
constexpr size_t kApprovalHistoryMethodSize = 32;
constexpr size_t kApprovalHistoryReasonCodeSize = 32;
constexpr size_t kApprovalHistoryRuleRefSize = kCurrentPolicyMaxPolicyIdLength + 1;
constexpr size_t kApprovalHistoryDigestSize = 72;  // "sha256:" + 64 hex chars + NUL.
constexpr size_t kApprovalHistoryPolicyResultSize = 32;
constexpr size_t kApprovalHistoryHighestActionSize = 8;
constexpr uint64_t kApprovalHistoryWriteBudgetWindowMs = 60000;
constexpr size_t kApprovalHistoryWriteBudgetMax = 12;

enum class ApprovalHistoryConfirmationKind {
    none,
    policy,
    local_pin,
    physical_confirm,
};

enum class ApprovalHistoryReadResult {
    ok,
    storage_error,
    invalid,
};

enum class ApprovalHistoryStorageStatus {
    missing,
    active,
    invalid,
    storage_error,
};

enum class ApprovalHistoryEventKind {
    policy_update,
    signing,
};

enum class HistoryRecordKind {
    none,
    confirmation,
    terminal,
};

enum class HistoryTerminalResult {
    none,
    signed_success,
    user_rejected,
    user_timed_out,
    policy_rejected,
    signing_failed,
};

struct PolicyUpdateHistoryAppendInput {
    const char* result;
    const char* reason_code;
    const char* policy_hash;
    size_t policy_count;
    const char* highest_action;
};

struct HistoryAppendInput {
    HistoryRecordKind record_kind;
    ApprovalHistoryConfirmationKind confirmation_kind;
    HistoryTerminalResult terminal_result;
    const char* chain;
    const char* method;
    const char* reason_code;
    const char* payload_digest;
    const char* policy_hash;
    const char* rule_ref;
};

struct ApprovalHistoryRecord {
    uint64_t sequence;
    uint64_t uptime_ms;
    ApprovalHistoryEventKind event_kind;
    ApprovalHistoryConfirmationKind confirmation_kind;
    HistoryRecordKind signing_record_kind;
    HistoryTerminalResult signing_terminal_result;
    char chain[kApprovalHistoryChainSize];
    char method[kApprovalHistoryMethodSize];
    char reason_code[kApprovalHistoryReasonCodeSize];
    char payload_digest[kApprovalHistoryDigestSize];
    char policy_hash[kApprovalHistoryDigestSize];
    char rule_ref[kApprovalHistoryRuleRefSize];
    char policy_result[kApprovalHistoryPolicyResultSize];
    char highest_action[kApprovalHistoryHighestActionSize];
    size_t policy_count;
};

struct ApprovalHistoryPage {
    ApprovalHistoryRecord records[kApprovalHistoryPageMax];
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
    const PolicyUpdateHistoryAppendInput& input,
    uint64_t uptime_ms);
bool approval_history_append_required_signing(
    const HistoryAppendInput& input,
    uint64_t uptime_ms);
bool approval_history_append_budgeted_signing(
    const HistoryAppendInput& input,
    uint64_t uptime_ms);
ApprovalHistoryReadResult approval_history_read_page(
    uint64_t before_sequence,
    size_t limit,
    ApprovalHistoryPage* output);
ApprovalHistoryStorageStatus approval_history_status();
bool approval_history_wipe();

const char* approval_history_confirmation_kind_to_string(ApprovalHistoryConfirmationKind value);
const char* approval_history_signing_record_kind_to_string(
    HistoryRecordKind value);
const char* approval_history_signing_terminal_result_to_string(
    HistoryTerminalResult value);

}  // namespace signing
