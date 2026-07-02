#pragma once

#include <stddef.h>
#include <stdint.h>

#include "policy/document.h"

namespace signing {

constexpr const char* kStoredPolicySchema = kCurrentPolicySchema;
constexpr size_t kPolicyIdSize = 72;  // "sha256:" + 64 hex chars + NUL.

struct StoredPolicySummary {
    const char* schema;
    char policy_id[kPolicyIdSize];
    const char* default_action;
    size_t blockchain_count;
    size_t network_count;
    size_t policy_count;
    size_t condition_count;
};

struct StoredPolicyDocument {
    const char* schema;
    char policy_id[kPolicyIdSize];
    const char* default_action;
    size_t blockchain_count;
    size_t network_count;
    size_t policy_count;
    size_t condition_count;
    const CurrentPolicyDocument* document;
};

enum class PolicyStoreStatus {
    active,
    missing,
    invalid,
    storage_error,
};

enum class PolicyStoreWriteResult {
    applied,
    unchanged_failure,
    consistency_error,
    invalid_record,
};

bool store_default_policy();
PolicyStoreWriteResult store_active_policy_record(const uint8_t* record, size_t record_size);
bool policy_store_digest_for_record(const uint8_t* record, size_t record_size, uint8_t* output, size_t output_size);
bool policy_store_policy_id_for_record(const uint8_t* record, size_t record_size, char* output, size_t output_size);
bool wipe_policy();
PolicyStoreStatus active_policy_status();

bool read_active_policy_summary(StoredPolicySummary* out);
bool read_active_policy_document(StoredPolicyDocument* out);

}  // namespace signing
