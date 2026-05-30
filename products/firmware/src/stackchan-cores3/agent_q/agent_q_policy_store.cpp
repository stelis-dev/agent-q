#include "agent_q_policy_store.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "nvs.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQPolicyStore";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kPolicyKey = "policy_v0";
constexpr uint8_t kStoredPolicyFormatVersion = 1;
constexpr uint8_t kStoredPolicySchemaV0 = 1;
constexpr uint8_t kStoredPolicyActionReject = 0;

struct StoredPolicyRecord {
    uint8_t magic[4];
    uint8_t format_version;
    uint8_t schema;
    uint8_t default_action;
    uint8_t rule_count;
    uint8_t reserved[8];
};

static_assert(sizeof(StoredPolicyRecord) == 16, "Stored policy record must stay fixed-size");

StoredPolicyRecord default_policy_record()
{
    return StoredPolicyRecord{
        {'A', 'Q', 'P', '0'},
        kStoredPolicyFormatVersion,
        kStoredPolicySchemaV0,
        kStoredPolicyActionReject,
        0,
        {},
    };
}

bool validate_policy_record(const StoredPolicyRecord& record)
{
    const StoredPolicyRecord expected = default_policy_record();
    return memcmp(&record, &expected, sizeof(record)) == 0;
}

void write_hex_byte(uint8_t value, char* output)
{
    constexpr char kHex[] = "0123456789abcdef";
    output[0] = kHex[(value >> 4) & 0x0F];
    output[1] = kHex[value & 0x0F];
}

bool policy_id_for_record(const StoredPolicyRecord& record, char* output, size_t output_size)
{
    if (output == nullptr || output_size != kAgentQPolicyIdSize) {
        return false;
    }
    memset(output, 0, output_size);

    uint8_t digest[32] = {};
    if (mbedtls_sha256(
            reinterpret_cast<const unsigned char*>(&record),
            sizeof(record),
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

AgentQPolicyStoreStatus read_policy_record(StoredPolicyRecord* out, bool log_failures)
{
    if (out == nullptr) {
        return AgentQPolicyStoreStatus::storage_error;
    }
    memset(out, 0, sizeof(*out));

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
    if (policy_size != sizeof(*out)) {
        nvs_close(nvs);
        if (log_failures) {
            ESP_LOGW(kTag, "Policy record has invalid size: %u",
                     static_cast<unsigned>(policy_size));
        }
        return AgentQPolicyStoreStatus::invalid;
    }

    result = nvs_get_blob(nvs, kPolicyKey, out, &policy_size);
    nvs_close(nvs);

    if (result != ESP_OK || policy_size != sizeof(*out)) {
        if (log_failures) {
            ESP_LOGW(kTag, "Policy read failed: %s size=%u",
                     esp_err_to_name(result),
                     static_cast<unsigned>(policy_size));
        }
        memset(out, 0, sizeof(*out));
        return AgentQPolicyStoreStatus::storage_error;
    }

    if (!validate_policy_record(*out)) {
        if (log_failures) {
            ESP_LOGW(kTag, "Policy record validation failed");
        }
        memset(out, 0, sizeof(*out));
        return AgentQPolicyStoreStatus::invalid;
    }
    return AgentQPolicyStoreStatus::active;
}

bool load_active_policy(AgentQPolicyDocument* out, void* context)
{
    (void)context;
    if (out == nullptr) {
        return false;
    }
    StoredPolicyRecord record = {};
    if (read_policy_record(&record, true) != AgentQPolicyStoreStatus::active) {
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
    const StoredPolicyRecord record = default_policy_record();

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing policy: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_set_blob(nvs, kPolicyKey, &record, sizeof(record));
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

bool has_active_policy()
{
    return active_policy_status() == AgentQPolicyStoreStatus::active;
}

AgentQPolicyStoreStatus active_policy_status()
{
    StoredPolicyRecord record = {};
    return read_policy_record(&record, false);
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

    StoredPolicyRecord record = {};
    if (read_policy_record(&record, true) != AgentQPolicyStoreStatus::active) {
        return false;
    }
    if (!policy_id_for_record(record, out->policy_id, sizeof(out->policy_id))) {
        return false;
    }

    out->schema = kAgentQStoredPolicySchema;
    out->default_action = "reject";
    out->rule_count = 0;
    return true;
}

}  // namespace agent_q
