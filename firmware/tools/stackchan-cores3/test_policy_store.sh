#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_policy_store.sh

ESP-IDF must already be active in the shell so IDF_PATH points to the ESP-IDF
checkout. The test compiles the StackChan CoreS3 active policy store with NVS
stubs and ESP-IDF mbedTLS SHA-256, then checks stored default-policy metadata and
provider fail-closed behavior.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET_ROOT="${REPO_ROOT}/firmware/src/stackchan-cores3"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"

if [[ -z "${IDF_PATH:-}" ]]; then
  echo "IDF_PATH is not set. Source ESP-IDF v5.5.4 export.sh before running this test." >&2
  exit 1
fi

MBEDTLS_ROOT="${IDF_PATH}/components/mbedtls/mbedtls"
MBEDTLS_INCLUDE_DIR="${MBEDTLS_ROOT}/include"
MBEDTLS_LIBRARY_DIR="${MBEDTLS_ROOT}/library"
if [[ ! -f "${MBEDTLS_INCLUDE_DIR}/mbedtls/sha256.h" || ! -f "${MBEDTLS_LIBRARY_DIR}/sha256.c" || ! -f "${MBEDTLS_LIBRARY_DIR}/platform_util.c" ]]; then
  echo "IDF_PATH does not expose the expected ESP-IDF mbedtls sources: ${IDF_PATH}" >&2
  exit 1
fi

for required in \
  "${TARGET_ROOT}/agent_q/agent_q_policy_store.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_store.h" \
  "${COMMON_ROOT}/agent_q_u64_decimal.h" \
  "${COMMON_ROOT}/policy/agent_q_policy_canonical.cpp" \
  "${COMMON_ROOT}/policy/agent_q_policy_canonical.h" \
  "${COMMON_ROOT}/policy/agent_q_policy_schema.cpp" \
  "${COMMON_ROOT}/policy/agent_q_policy_schema.h" \
  "${COMMON_ROOT}/policy/agent_q_policy_u64.h" \
  "${COMMON_ROOT}/policy/agent_q_policy_v0.cpp" \
  "${COMMON_ROOT}/policy/agent_q_policy_runtime.cpp" \
  "${COMMON_ROOT}/sui/agent_q_sui_method_adapter.cpp" \
  "${COMMON_ROOT}/sui/agent_q_sui_method_adapter.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-policy-store.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/stubs"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"

cat >"${TMP_DIR}/stubs/esp_err.h" <<'H'
#pragma once

typedef int esp_err_t;

#define ESP_OK 0
#define ESP_ERR_NVS_NOT_FOUND 4354

static inline const char* esp_err_to_name(esp_err_t error)
{
    return error == ESP_OK ? "ESP_OK" :
           error == ESP_ERR_NVS_NOT_FOUND ? "ESP_ERR_NVS_NOT_FOUND" :
           "ESP_ERR_TEST";
}
H

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once

#define ESP_LOGI(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, format, ...) do { (void)(tag); } while (0)
H

cat >"${TMP_DIR}/stubs/nvs.h" <<'H'
#pragma once

#include <stddef.h>
#include "esp_err.h"

#define NVS_READONLY 1
#define NVS_READWRITE 2

typedef int nvs_handle_t;

extern "C" {
esp_err_t nvs_open(const char* name, int open_mode, nvs_handle_t* out_handle);
void nvs_close(nvs_handle_t handle);
esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* out_value, size_t* length);
esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length);
esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key);
esp_err_t nvs_commit(nvs_handle_t handle);
}
H

cat >"${TMP_DIR}/policy_store_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <map>
#include <string>
#include <vector>

#include "esp_err.h"
#include "nvs.h"
#include "agent_q_common/policy/agent_q_policy_canonical.h"
#include "agent_q_common/policy/agent_q_policy_schema.h"
#include "agent_q_common/sui/agent_q_sui_method_adapter.h"
#include "agent_q_policy_store.h"

namespace {

std::map<std::string, std::vector<uint8_t>> g_blobs;
bool g_open_fails = false;
bool g_commit_fails = false;
bool g_commit_fails_for_commit_record = false;
std::string g_commit_fails_for_key;
std::string g_read_size_fails_for_key;
std::string g_read_data_fails_for_key;
std::string g_set_fails_for_key;
std::string g_erase_fails_for_key;
std::string g_last_written_key;
bool g_last_operation_was_erase = false;

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

agent_q::AgentQPolicyFacts valid_facts()
{
    static const agent_q::AgentQPolicyMethodDescriptor method =
        agent_q::sui_sign_transaction_policy_method_descriptor();
    static const agent_q::AgentQPolicyFact entries[] = {
        {
            "common.chain",
            agent_q::AgentQPolicyValueType::string,
            "sui",
        },
        {
            "common.method",
            agent_q::AgentQPolicyValueType::string,
            "sign_transaction",
        },
        {
            "common.intent",
            agent_q::AgentQPolicyValueType::string,
            "single_asset_transfer",
        },
    };
    return agent_q::AgentQPolicyFacts{
        entries,
        sizeof(entries) / sizeof(entries[0]),
        method.field_descriptors,
        method.field_descriptor_count,
    };
}

agent_q::AgentQPolicyFacts mismatched_facts()
{
    static const agent_q::AgentQPolicyMethodDescriptor method =
        agent_q::sui_sign_transaction_policy_method_descriptor();
    static const agent_q::AgentQPolicyFact entries[] = {
        {
            "common.chain",
            agent_q::AgentQPolicyValueType::string,
            "sui",
        },
        {
            "common.method",
            agent_q::AgentQPolicyValueType::string,
            "sign_transaction",
        },
        {
            "common.intent",
            agent_q::AgentQPolicyValueType::string,
            "unsupported_intent",
        },
    };
    return agent_q::AgentQPolicyFacts{
        entries,
        sizeof(entries) / sizeof(entries[0]),
        method.field_descriptors,
        method.field_descriptor_count,
    };
}

agent_q::AgentQPolicyDecision evaluate_active_policy()
{
    return agent_q::evaluate_agent_q_policy_runtime(agent_q::active_policy_provider(), valid_facts());
}

agent_q::AgentQPolicyDecision evaluate_active_policy_mismatch()
{
    return agent_q::evaluate_agent_q_policy_runtime(agent_q::active_policy_provider(), mismatched_facts());
}

bool make_default_record(std::vector<uint8_t>* output)
{
    uint8_t bytes[agent_q::kAgentQPolicyDefaultCanonicalRecordBytes] = {};
    size_t size = 0;
    if (output == nullptr ||
        agent_q::encode_agent_q_policy_v0_default_record(bytes, sizeof(bytes), &size) !=
            agent_q::AgentQPolicyCanonicalStatus::ok) {
        return false;
    }
    output->assign(bytes, bytes + size);
    return true;
}

bool make_reject_rule_record(
    const char* rule_id,
    const char* intent,
    std::vector<uint8_t>* output)
{
    if (rule_id == nullptr || intent == nullptr || output == nullptr) {
        return false;
    }
    const agent_q::AgentQPolicyCriterion reject_criteria[] = {
        {
            "common.intent",
            agent_q::AgentQPolicyOperator::eq,
            intent,
            nullptr,
            0,
        },
    };
    const agent_q::AgentQPolicyRule rule = {
        rule_id,
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        reject_criteria,
        sizeof(reject_criteria) / sizeof(reject_criteria[0]),
    };
    const agent_q::AgentQPolicyDocument policy = {
        agent_q::kAgentQPolicyV0Schema,
        agent_q::AgentQPolicyAction::reject,
        &rule,
        1,
    };
    const agent_q::AgentQPolicyMethodDescriptor method =
        agent_q::sui_sign_transaction_policy_method_descriptor();
    agent_q::AgentQPolicyCanonicalDocument canonical = {};
    uint8_t bytes[agent_q::kAgentQPolicyMaxCanonicalRecordBytes] = {};
    size_t size = 0;
    if (agent_q::canonicalize_agent_q_policy_v0(policy, &method, 1, &canonical) !=
            agent_q::AgentQPolicyCanonicalStatus::ok ||
        agent_q::encode_agent_q_policy_v0_canonical_record(canonical, bytes, sizeof(bytes), &size) !=
            agent_q::AgentQPolicyCanonicalStatus::ok) {
        return false;
    }
    output->assign(bytes, bytes + size);
    return true;
}

void write_u64_be(uint64_t value, uint8_t* output)
{
    for (int index = 7; index >= 0; --index) {
        output[index] = static_cast<uint8_t>(value & 0xff);
        value >>= 8;
    }
}

void set_pending_policy_write(uint8_t commit_index, uint8_t slot, uint64_t sequence)
{
    std::vector<uint8_t> pending(16, 0);
    pending[0] = 'A';
    pending[1] = 'Q';
    pending[2] = 'P';
    pending[3] = 'P';
    pending[4] = 0;
    pending[5] = commit_index;
    pending[6] = slot;
    write_u64_be(sequence, pending.data() + 8);
    g_blobs["pol_p"] = pending;
}

bool first_commit_blob(std::string* key, std::vector<uint8_t>* blob)
{
    const char* keys[] = {"pol_c0", "pol_c1"};
    for (const char* candidate : keys) {
        auto found = g_blobs.find(candidate);
        if (found != g_blobs.end()) {
            if (key != nullptr) {
                *key = candidate;
            }
            if (blob != nullptr) {
                *blob = found->second;
            }
            return true;
        }
    }
    return false;
}

agent_q::AgentQPolicyStoreWriteResult store_record(const std::vector<uint8_t>& record)
{
    return agent_q::store_active_policy_record(record.data(), record.size());
}

bool store_record_applied(const std::vector<uint8_t>& record)
{
    return store_record(record) == agent_q::AgentQPolicyStoreWriteResult::applied;
}

}  // namespace

extern "C" {

esp_err_t nvs_open(const char* name, int open_mode, nvs_handle_t* out_handle)
{
    (void)name;
    (void)open_mode;
    if (g_open_fails) {
        return 1;
    }
    *out_handle = 1;
    return ESP_OK;
}

void nvs_close(nvs_handle_t handle)
{
    (void)handle;
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* out_value, size_t* length)
{
    (void)handle;
    auto found = g_blobs.find(key == nullptr ? "" : key);
    if (found == g_blobs.end()) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (key != nullptr && g_read_size_fails_for_key == key && out_value == nullptr) {
        return 1;
    }
    if (key != nullptr && g_read_data_fails_for_key == key && out_value != nullptr) {
        return 1;
    }
    if (length == nullptr) {
        return 1;
    }
    if (out_value == nullptr) {
        *length = found->second.size();
        return ESP_OK;
    }
    const size_t requested = *length;
    *length = found->second.size();
    if (requested < found->second.size()) {
        return 1;
    }
    memcpy(out_value, found->second.data(), found->second.size());
    return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length)
{
    (void)handle;
    g_last_written_key = key == nullptr ? "" : key;
    g_last_operation_was_erase = false;
    if (g_set_fails_for_key == g_last_written_key) {
        return 1;
    }
    const uint8_t* bytes = static_cast<const uint8_t*>(value);
    g_blobs[g_last_written_key].assign(bytes, bytes + length);
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key)
{
    (void)handle;
    g_last_written_key = key == nullptr ? "" : key;
    g_last_operation_was_erase = true;
    if (g_erase_fails_for_key == g_last_written_key) {
        return 1;
    }
    auto found = g_blobs.find(key == nullptr ? "" : key);
    if (found == g_blobs.end()) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    g_blobs.erase(found);
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t handle)
{
    (void)handle;
    if (g_commit_fails) {
        return 1;
    }
    if (g_commit_fails_for_commit_record &&
        !g_last_operation_was_erase &&
        g_last_written_key.rfind("pol_c", 0) == 0) {
        return 1;
    }
    if (!g_last_operation_was_erase &&
        !g_commit_fails_for_key.empty() &&
        g_commit_fails_for_key == g_last_written_key) {
        return 1;
    }
    return ESP_OK;
}

}  // extern "C"

int main()
{
    agent_q::AgentQStoredPolicySummary summary = {};
    std::vector<uint8_t> default_record;
    std::vector<uint8_t> custom_record;
    std::vector<uint8_t> custom_record_2;
    expect(make_default_record(&default_record), "build default record fixture");
    expect(make_reject_rule_record("reject-transfer", "single_asset_transfer", &custom_record), "build custom policy record");
    expect(make_reject_rule_record("reject-other-intent", "unsupported_intent", &custom_record_2), "build second custom policy record");

    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::missing, "missing policy status");
    expect(!agent_q::read_active_policy_summary(&summary), "missing policy summary fails closed");
    agent_q::AgentQPolicyDecision decision = evaluate_active_policy();
    expect(decision.action == agent_q::AgentQPolicyAction::reject, "missing policy rejects");
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::invalid_policy, "missing policy reason is invalid_policy");

    g_commit_fails_for_key = "pol_p";
    expect(store_record(custom_record) == agent_q::AgentQPolicyStoreWriteResult::unchanged_failure, "pending marker commit failure from missing policy is cleaned");
    g_commit_fails_for_key.clear();
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::missing, "pending marker commit failure leaves missing policy unchanged");
    expect(g_blobs.find("pol_p") == g_blobs.end(), "pending marker commit failure does not leave pending residue");

    expect(agent_q::store_default_policy(), "store default policy");
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "stored policy status");
    expect(agent_q::read_active_policy_summary(&summary), "read default policy summary");
    expect(strcmp(summary.schema, "agentq.policy.v0") == 0, "policy schema");
    expect(strcmp(summary.default_action, "reject") == 0, "policy default action");
    expect(summary.rule_count == 0, "policy rule count");
    expect(strcmp(summary.policy_id, "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3") == 0, "policy id");

    std::string active_commit_key;
    std::vector<uint8_t> active_commit_blob;
    expect(first_commit_blob(&active_commit_key, &active_commit_blob), "stored policy has commit metadata");
    expect(active_commit_blob.size() > 4 && active_commit_blob[4] == 0, "policy commit marker current version is zero");
    g_blobs[active_commit_key][4] = 1;
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::invalid,
           "nonzero policy commit marker version fails closed");
    g_blobs[active_commit_key] = active_commit_blob;
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active,
           "restored current policy commit marker is active");

    decision = evaluate_active_policy();
    expect(decision.action == agent_q::AgentQPolicyAction::reject, "default policy rejects");
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::default_reject, "default policy reason");

    set_pending_policy_write(0, 1, 2);
    expect(g_blobs["pol_p"][4] == 0, "policy pending marker current version is zero");
    g_blobs["pol_p"][4] = 1;
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::invalid,
           "nonzero policy pending marker version fails closed");
    g_blobs["pol_p"][4] = 0;
    g_blobs["pol_c0"] = {0};
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "pending torn commit metadata preserves default policy");
    decision = evaluate_active_policy();
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::default_reject, "pending torn commit metadata keeps default rule");
    g_blobs.erase("pol_p");
    g_blobs.erase("pol_c0");

    g_blobs["pol_c0"] = {0};
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::invalid, "invalid commit metadata without pending marker fails closed");
    expect(agent_q::wipe_policy(), "wipe invalid commit metadata residue");
    expect(agent_q::store_default_policy(), "restore default policy after invalid commit metadata");

    g_erase_fails_for_key = "pol_p";
    expect(store_record_applied(custom_record), "pending marker cleanup failure does not reverse committed policy");
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "pending marker cleanup failure leaves active committed policy readable");
    expect(g_blobs.find("pol_p") != g_blobs.end(), "pending marker remains when cleanup erase fails");
    g_erase_fails_for_key.clear();
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "stale matching pending marker does not block active policy");
    expect(agent_q::wipe_policy(), "wipe after pending cleanup failure");
    expect(agent_q::store_default_policy(), "restore default policy after pending cleanup failure");

    g_commit_fails_for_key = "pol_p";
    expect(store_record(custom_record) == agent_q::AgentQPolicyStoreWriteResult::unchanged_failure, "pending marker commit failure from active policy is cleaned");
    g_commit_fails_for_key.clear();
    decision = evaluate_active_policy();
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::default_reject, "pending marker commit failure preserves active default policy");
    expect(g_blobs.find("pol_p") == g_blobs.end(), "active pending marker commit failure does not leave pending residue");

    expect(store_record_applied(custom_record), "store custom policy before stale commit pre-erase test");
    g_erase_fails_for_key = "pol_c1";
    expect(store_record(custom_record_2) == agent_q::AgentQPolicyStoreWriteResult::unchanged_failure, "stale commit pre-erase failure blocks inactive slot reuse");
    g_erase_fails_for_key.clear();
    decision = evaluate_active_policy();
    expect(strcmp(decision.rule_id, "reject-transfer") == 0, "stale commit pre-erase failure preserves active policy");
    expect(agent_q::wipe_policy(), "wipe after stale commit cleanup failure");
    expect(agent_q::store_default_policy(), "restore default policy after stale commit cleanup failure");

    expect(store_record_applied(custom_record), "store custom policy record");
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "custom policy status");
    expect(agent_q::read_active_policy_summary(&summary), "custom policy summary");
    expect(summary.rule_count == 1, "custom policy rule count");
    expect(strncmp(summary.policy_id, "sha256:", 7) == 0, "custom policy id prefix");
    decision = evaluate_active_policy();
    expect(decision.action == agent_q::AgentQPolicyAction::reject, "custom policy matching rule rejects");
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::matched_rule, "custom policy match reason");
    expect(strcmp(decision.rule_id, "reject-transfer") == 0, "custom policy rule id");
    decision = evaluate_active_policy_mismatch();
    expect(decision.action == agent_q::AgentQPolicyAction::reject, "custom policy mismatch rejects");
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::default_reject, "custom policy mismatch default reason");

    set_pending_policy_write(1, 1, 3);
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::invalid, "pending marker overlapping active slot fails closed");
    expect(g_blobs.find("pol_s1") != g_blobs.end(), "overlapping pending marker does not erase active slot");
    g_blobs.erase("pol_p");
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "removing overlapping slot marker restores active policy");

    set_pending_policy_write(0, 0, 3);
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::invalid, "pending marker overlapping active commit fails closed");
    expect(g_blobs.find("pol_c0") != g_blobs.end(), "overlapping pending marker does not erase active commit");
    g_blobs.erase("pol_p");
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "removing overlapping commit marker restores active policy");

    set_pending_policy_write(1, 0, 3);
    g_blobs["pol_c1"] = {0};
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "pending torn next commit metadata preserves newest policy");
    decision = evaluate_active_policy();
    expect(strcmp(decision.rule_id, "reject-transfer") == 0, "pending torn next commit metadata keeps newest rule");
    g_blobs.erase("pol_c1");
    g_blobs.erase("pol_p");

    const std::vector<uint8_t> committed_custom_metadata = g_blobs["pol_c0"];
    g_blobs["pol_c0"][0] = 0;
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::invalid, "corrupt newest commit metadata fails closed");
    g_blobs["pol_c0"] = committed_custom_metadata;
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "restored newest commit metadata is active");

    g_blobs["pol_p"] = {0};
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::invalid, "invalid pending marker fails closed");
    g_blobs.erase("pol_p");
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "pending marker removal restores active policy");

    set_pending_policy_write(1, 0, 3);
    g_blobs["pol_s0"] = {0};
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "pending torn next slot preserves newest policy");
    decision = evaluate_active_policy();
    expect(strcmp(decision.rule_id, "reject-transfer") == 0, "pending torn next slot keeps newest rule");
    g_blobs.erase("pol_p");

    g_set_fails_for_key = "pol_c1";
    expect(store_record(custom_record_2) == agent_q::AgentQPolicyStoreWriteResult::unchanged_failure, "commit metadata set failure preserves old policy");
    g_set_fails_for_key.clear();
    decision = evaluate_active_policy();
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::matched_rule, "commit metadata set failure keeps old policy");
    expect(strcmp(decision.rule_id, "reject-transfer") == 0, "commit metadata set failure keeps old rule");

    g_commit_fails_for_commit_record = true;
    expect(store_record(custom_record_2) == agent_q::AgentQPolicyStoreWriteResult::applied, "durable commit despite commit return failure is treated as applied");
    g_commit_fails_for_commit_record = false;
    decision = evaluate_active_policy();
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::default_reject, "durable commit failure selects new policy");

    expect(store_record_applied(custom_record_2), "store second custom policy record");
    decision = evaluate_active_policy();
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::default_reject, "second custom policy does not match normal intent");
    decision = evaluate_active_policy_mismatch();
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::matched_rule, "second custom policy matches alternate intent");
    expect(strcmp(decision.rule_id, "reject-other-intent") == 0, "second custom policy rule id");

    set_pending_policy_write(1, 0, 3);
    g_blobs["pol_s0"][0] = 0;
    decision = evaluate_active_policy();
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::invalid_policy, "stale pending marker does not mask corrupt committed slot");
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::invalid, "corrupt committed slot status");
    expect(agent_q::wipe_policy(), "wipe corrupt committed slot");
    expect(store_record_applied(custom_record), "restore custom policy after corrupt committed slot");
    expect(store_record_applied(custom_record_2), "restore second custom policy after corrupt committed slot");
    g_read_size_fails_for_key = "pol_c0";
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::storage_error, "commit metadata read error fails closed");
    g_read_size_fails_for_key.clear();
    g_read_data_fails_for_key = "pol_s1";
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::storage_error, "committed slot read error fails closed");
    g_read_data_fails_for_key.clear();

    expect(agent_q::wipe_policy(), "wipe policy");
    expect(g_blobs.empty(), "all policy slots and metadata wiped");
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::missing, "wiped policy status");

    expect(agent_q::store_default_policy(), "restore default policy");
    g_blobs["pol_s0"][0] = 0;
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::invalid, "corrupt policy status");
    expect(!agent_q::read_active_policy_summary(&summary), "corrupt policy summary fails closed");
    decision = evaluate_active_policy();
    expect(decision.action == agent_q::AgentQPolicyAction::reject, "corrupt policy rejects");
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::invalid_policy, "corrupt policy reason is invalid_policy");

    expect(!agent_q::store_default_policy(), "corrupt policy cannot be overwritten without wipe");
    expect(agent_q::wipe_policy(), "wipe corrupt policy before restore");
    expect(agent_q::store_default_policy(), "restore default policy");
    g_blobs["pol_s1"].push_back(0);
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::active, "inactive slot residue does not invalidate active policy");
    expect(agent_q::store_default_policy(), "restore default policy again");
    expect(agent_q::wipe_policy(), "wipe policy");
    expect(g_blobs.empty(), "policy blob wiped");
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::missing, "wiped policy status");
    expect(!agent_q::read_active_policy_summary(&summary), "wiped policy summary fails closed");

    g_commit_fails = true;
    expect(!agent_q::store_default_policy(), "commit failure fails closed");
    g_commit_fails = false;
    const agent_q::AgentQPolicyStoreStatus failed_commit_status = agent_q::active_policy_status();
    expect(failed_commit_status == agent_q::AgentQPolicyStoreStatus::missing, "pre-write commit failure leaves policy missing");
    expect(agent_q::wipe_policy(), "wipe failed commit residue");

    g_open_fails = true;
    expect(agent_q::active_policy_status() == agent_q::AgentQPolicyStoreStatus::storage_error, "storage error policy status");
    g_open_fails = false;

    if (failures != 0) {
        fprintf(stderr, "Policy store tests failed: %d\n", failures);
        return 1;
    }
    printf("Policy store tests passed\n");
    return 0;
}
CPP

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${TARGET_ROOT}/agent_q" \
  -I"${COMMON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/policy_store_test.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_store.cpp" \
  "${COMMON_ROOT}/policy/agent_q_policy_canonical.cpp" \
  "${COMMON_ROOT}/policy/agent_q_policy_schema.cpp" \
  "${COMMON_ROOT}/policy/agent_q_policy_v0.cpp" \
  "${COMMON_ROOT}/policy/agent_q_policy_runtime.cpp" \
  "${COMMON_ROOT}/sui/agent_q_sui_method_adapter.cpp" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/policy_store_test"

"${TMP_DIR}/policy_store_test"
