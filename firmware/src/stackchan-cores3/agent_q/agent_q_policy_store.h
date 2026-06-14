#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_common/policy/agent_q_policy_document.h"

namespace agent_q {

constexpr const char* kAgentQStoredPolicySchema = kAgentQCurrentPolicySchema;
constexpr size_t kAgentQPolicyIdSize = 72;  // "sha256:" + 64 hex chars + NUL.

struct AgentQStoredPolicySummary {
    const char* schema;
    char policy_id[kAgentQPolicyIdSize];
    const char* default_action;
    size_t blockchain_count;
    size_t network_count;
    size_t policy_count;
    size_t condition_count;
};

struct AgentQStoredPolicyDocument {
    const char* schema;
    char policy_id[kAgentQPolicyIdSize];
    const char* default_action;
    size_t blockchain_count;
    size_t network_count;
    size_t policy_count;
    size_t condition_count;
    const AgentQCurrentPolicyDocument* document;
};

enum class AgentQPolicyStoreStatus {
    active,
    missing,
    invalid,
    storage_error,
};

enum class AgentQPolicyStoreWriteResult {
    applied,
    unchanged_failure,
    consistency_error,
    invalid_record,
};

bool store_default_policy();
AgentQPolicyStoreWriteResult store_active_policy_record(const uint8_t* record, size_t record_size);
bool policy_store_digest_for_record(const uint8_t* record, size_t record_size, uint8_t* output, size_t output_size);
bool policy_store_policy_id_for_record(const uint8_t* record, size_t record_size, char* output, size_t output_size);
bool wipe_policy();
AgentQPolicyStoreStatus active_policy_status();

bool read_active_policy_summary(AgentQStoredPolicySummary* out);
bool read_active_policy_document(AgentQStoredPolicyDocument* out);

}  // namespace agent_q
