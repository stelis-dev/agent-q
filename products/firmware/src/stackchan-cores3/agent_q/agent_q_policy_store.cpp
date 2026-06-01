#include "agent_q_policy_store.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "nvs.h"

#include "agent_q_common/policy/agent_q_policy_canonical.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQPolicyStore";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kPolicyKey = "policy_v0";
constexpr size_t kDefaultPolicyRecordBytes = kAgentQPolicyDefaultCanonicalRecordBytes;

void write_hex_byte(uint8_t value, char* output)
{
    constexpr char kHex[] = "0123456789abcdef";
    output[0] = kHex[(value >> 4) & 0x0F];
    output[1] = kHex[value & 0x0F];
}

bool default_policy_record(uint8_t* output, size_t output_capacity, size_t* output_size)
{
    return encode_agent_q_policy_v0_default_record(output, output_capacity, output_size) ==
               AgentQPolicyCanonicalStatus::ok &&
           *output_size == kDefaultPolicyRecordBytes;
}

bool policy_id_for_record(const uint8_t* record, size_t record_size, char* output, size_t output_size)
{
    if (record == nullptr || record_size == 0 ||
        output == nullptr || output_size != kAgentQPolicyIdSize) {
        return false;
    }
    memset(output, 0, output_size);

    uint8_t digest[32] = {};
    if (mbedtls_sha256(
            reinterpret_cast<const unsigned char*>(record),
            record_size,
            digest,
            0) != 0) {
        return false;
    }

    constexpr char kPrefix[] = "sha256:";
    memcpy(output, kPrefix, sizeof(kPrefix) - 1);
    char* cursor = output + sizeof(kPrefix) - 1;
    for (size_t index = 0; index < sizeof(digest); ++index) {
        write_hex_byte(digest[index], cursor);
        cursor += 2;
    }
    *cursor = '\0';
    return true;
}

AgentQPolicyStoreStatus read_policy_record(uint8_t* out, size_t out_capacity, size_t* out_size, bool log_failures)
{
    if (out == nullptr || out_size == nullptr) {
        return AgentQPolicyStoreStatus::storage_error;
    }
    memset(out, 0, out_capacity);
    *out_size = 0;

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result != ESP_OK) {
        if (result == ESP_ERR_NVS_NOT_FOUND) {
            return AgentQPolicyStoreStatus::missing;
        }
        if (log_failures) {
            ESP_LOGW(kTag, "NVS open failed while reading policy: %s", esp_err_to_name(result));
        }
        return AgentQPolicyStoreStatus::storage_error;
    }

    size_t policy_size = 0;
    result = nvs_get_blob(nvs, kPolicyKey, nullptr, &policy_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return AgentQPolicyStoreStatus::missing;
    }
    if (result != ESP_OK) {
        nvs_close(nvs);
        if (log_failures) {
            ESP_LOGW(kTag, "Policy size read failed: %s", esp_err_to_name(result));
        }
        return AgentQPolicyStoreStatus::storage_error;
    }
    uint8_t expected[kDefaultPolicyRecordBytes] = {};
    size_t expected_size = 0;
    if (!default_policy_record(expected, sizeof(expected), &expected_size)) {
        nvs_close(nvs);
        return AgentQPolicyStoreStatus::storage_error;
    }

    if (policy_size != expected_size || policy_size > out_capacity) {
        nvs_close(nvs);
        if (log_failures) {
            ESP_LOGW(kTag, "Policy record has invalid size: %u",
                     static_cast<unsigned>(policy_size));
        }
        return AgentQPolicyStoreStatus::invalid;
    }

    result = nvs_get_blob(nvs, kPolicyKey, out, &policy_size);
    nvs_close(nvs);

    if (result != ESP_OK || policy_size != expected_size) {
        if (log_failures) {
            ESP_LOGW(kTag, "Policy read failed: %s size=%u",
                     esp_err_to_name(result),
                     static_cast<unsigned>(policy_size));
        }
        memset(out, 0, out_capacity);
        return AgentQPolicyStoreStatus::storage_error;
    }

    if (memcmp(out, expected, expected_size) != 0) {
        if (log_failures) {
            ESP_LOGW(kTag, "Policy record validation failed");
        }
        memset(out, 0, out_capacity);
        return AgentQPolicyStoreStatus::invalid;
    }
    *out_size = expected_size;
    return AgentQPolicyStoreStatus::active;
}

bool load_active_policy(AgentQPolicyDocument* out, void* context)
{
    (void)context;
    if (out == nullptr) {
        return false;
    }
    uint8_t record[kDefaultPolicyRecordBytes] = {};
    size_t record_size = 0;
    if (read_policy_record(record, sizeof(record), &record_size, true) != AgentQPolicyStoreStatus::active) {
        return false;
    }
    *out = AgentQPolicyDocument{
        kAgentQPolicyV0Schema,
        AgentQPolicyAction::reject,
        nullptr,
        0,
    };
    return true;
}

}  // namespace

bool store_default_policy()
{
    uint8_t record[kDefaultPolicyRecordBytes] = {};
    size_t record_size = 0;
    if (!default_policy_record(record, sizeof(record), &record_size)) {
        ESP_LOGW(kTag, "Could not build default policy record");
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing policy: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_set_blob(nvs, kPolicyKey, record, record_size);
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS write failed for policy: %s", esp_err_to_name(result));
        wipe_policy();
        return false;
    }

    ESP_LOGI(kTag, "Stored active default-reject policy");
    return true;
}

bool wipe_policy()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while wiping policy: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kPolicyKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS erase failed for policy: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGI(kTag, "Active policy wiped");
    return true;
}

AgentQPolicyStoreStatus active_policy_status()
{
    uint8_t record[kDefaultPolicyRecordBytes] = {};
    size_t record_size = 0;
    return read_policy_record(record, sizeof(record), &record_size, false);
}

AgentQPolicyProvider active_policy_provider()
{
    return AgentQPolicyProvider{load_active_policy, nullptr};
}

bool read_active_policy_summary(AgentQStoredPolicySummary* out)
{
    if (out == nullptr) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    uint8_t record[kDefaultPolicyRecordBytes] = {};
    size_t record_size = 0;
    if (read_policy_record(record, sizeof(record), &record_size, true) != AgentQPolicyStoreStatus::active) {
        return false;
    }
    if (!policy_id_for_record(record, record_size, out->policy_id, sizeof(out->policy_id))) {
        return false;
    }

    out->schema = kAgentQStoredPolicySchema;
    out->default_action = "reject";
    out->rule_count = 0;
    return true;
}

}  // namespace agent_q
