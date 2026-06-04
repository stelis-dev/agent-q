#include "agent_q_policy_update_marker.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQPolicyUpdate";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kPolicyUpdateMarkerKey = "pol_um";
constexpr uint8_t kPolicyUpdateMarkerMagic[4] = {'A', 'Q', 'P', 'U'};
constexpr uint8_t kPolicyUpdateMarkerVersion = 0;

struct StoredPolicyUpdateMarker {
    uint8_t magic[4];
    uint8_t version;
    uint8_t highest_action;
    uint16_t rule_count;
    uint8_t policy_digest[kAgentQPolicyUpdateDigestBytes];
    uint8_t reserved[8];
};

static_assert(sizeof(StoredPolicyUpdateMarker) <= 48,
              "Policy update marker must remain a small NVS record");

uint8_t stored_highest_action(AgentQPolicyUpdateHighestAction value)
{
    switch (value) {
        case AgentQPolicyUpdateHighestAction::reject:
            return 0;
        case AgentQPolicyUpdateHighestAction::sign:
            return 1;
    }
    return 0;
}

bool highest_action_input_valid(AgentQPolicyUpdateHighestAction value)
{
    return value == AgentQPolicyUpdateHighestAction::reject ||
           value == AgentQPolicyUpdateHighestAction::sign;
}

bool stored_highest_action_valid(uint8_t value)
{
    return value == 0 || value == 1;
}

bool marker_valid(const StoredPolicyUpdateMarker& marker)
{
    return marker.magic[0] == kPolicyUpdateMarkerMagic[0] &&
           marker.magic[1] == kPolicyUpdateMarkerMagic[1] &&
           marker.magic[2] == kPolicyUpdateMarkerMagic[2] &&
           marker.magic[3] == kPolicyUpdateMarkerMagic[3] &&
           marker.version == kPolicyUpdateMarkerVersion &&
           marker.rule_count <= kAgentQPolicyMaxRules &&
           stored_highest_action_valid(marker.highest_action);
}

AgentQPolicyUpdateMarkerStatus read_marker(StoredPolicyUpdateMarker* marker)
{
    if (marker == nullptr) {
        return AgentQPolicyUpdateMarkerStatus::storage_error;
    }
    memset(marker, 0, sizeof(*marker));

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result != ESP_OK) {
        if (result == ESP_ERR_NVS_NOT_FOUND) {
            return AgentQPolicyUpdateMarkerStatus::clear;
        }
        ESP_LOGW(kTag, "NVS open failed while reading policy update marker: %s", esp_err_to_name(result));
        return AgentQPolicyUpdateMarkerStatus::storage_error;
    }

    size_t marker_size = 0;
    result = nvs_get_blob(nvs, kPolicyUpdateMarkerKey, nullptr, &marker_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return AgentQPolicyUpdateMarkerStatus::clear;
    }
    if (result != ESP_OK) {
        nvs_close(nvs);
        ESP_LOGW(kTag, "Policy update marker size read failed: %s", esp_err_to_name(result));
        return AgentQPolicyUpdateMarkerStatus::storage_error;
    }
    if (marker_size != sizeof(*marker)) {
        nvs_close(nvs);
        return AgentQPolicyUpdateMarkerStatus::invalid;
    }

    result = nvs_get_blob(nvs, kPolicyUpdateMarkerKey, marker, &marker_size);
    nvs_close(nvs);
    if (result != ESP_OK || marker_size != sizeof(*marker)) {
        ESP_LOGW(kTag, "Policy update marker read failed: %s", esp_err_to_name(result));
        memset(marker, 0, sizeof(*marker));
        return AgentQPolicyUpdateMarkerStatus::storage_error;
    }

    return marker_valid(*marker)
               ? AgentQPolicyUpdateMarkerStatus::pending
               : AgentQPolicyUpdateMarkerStatus::invalid;
}

}  // namespace

AgentQPolicyUpdateMarkerStatus policy_update_marker_status()
{
    StoredPolicyUpdateMarker marker = {};
    return read_marker(&marker);
}

AgentQPolicyUpdateMarkerBeginResult policy_update_marker_begin(
    const uint8_t* policy_digest,
    size_t policy_digest_size,
    size_t rule_count,
    AgentQPolicyUpdateHighestAction highest_action)
{
    if (policy_digest == nullptr ||
        policy_digest_size != kAgentQPolicyUpdateDigestBytes ||
        rule_count > kAgentQPolicyMaxRules ||
        !highest_action_input_valid(highest_action)) {
        return AgentQPolicyUpdateMarkerBeginResult::invalid_input;
    }

    StoredPolicyUpdateMarker marker = {};
    memcpy(marker.magic, kPolicyUpdateMarkerMagic, sizeof(marker.magic));
    marker.version = kPolicyUpdateMarkerVersion;
    marker.highest_action = stored_highest_action(highest_action);
    marker.rule_count = static_cast<uint16_t>(rule_count);
    memcpy(marker.policy_digest, policy_digest, kAgentQPolicyUpdateDigestBytes);

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while writing policy update marker: %s", esp_err_to_name(result));
        return AgentQPolicyUpdateMarkerBeginResult::storage_error;
    }

    result = nvs_set_blob(nvs, kPolicyUpdateMarkerKey, &marker, sizeof(marker));
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Policy update marker write failed: %s", esp_err_to_name(result));
        return policy_update_marker_status() == AgentQPolicyUpdateMarkerStatus::pending
                   ? AgentQPolicyUpdateMarkerBeginResult::pending_after_error
                   : AgentQPolicyUpdateMarkerBeginResult::storage_error;
    }
    return policy_update_marker_status() == AgentQPolicyUpdateMarkerStatus::pending
               ? AgentQPolicyUpdateMarkerBeginResult::written
               : AgentQPolicyUpdateMarkerBeginResult::storage_error;
}

bool policy_update_marker_clear()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while clearing policy update marker: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kPolicyUpdateMarkerKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Policy update marker erase failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

}  // namespace agent_q
