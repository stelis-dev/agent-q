#include "agent_q_human_approval_settings.h"

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQHumanApproval";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kHumanApprovalInputModeKey = "human_approval";
constexpr uint8_t kHumanApprovalInputModePin = 0;
constexpr uint8_t kHumanApprovalInputModeConfirm = 1;

bool stored_value_to_mode(uint8_t value, AgentQHumanApprovalInputMode* mode)
{
    if (mode == nullptr) {
        return false;
    }
    if (value == kHumanApprovalInputModePin) {
        *mode = AgentQHumanApprovalInputMode::pin;
        return true;
    }
    if (value == kHumanApprovalInputModeConfirm) {
        *mode = AgentQHumanApprovalInputMode::confirm;
        return true;
    }
    return false;
}

uint8_t stored_value_from_mode(AgentQHumanApprovalInputMode mode)
{
    return mode == AgentQHumanApprovalInputMode::confirm
               ? kHumanApprovalInputModeConfirm
               : kHumanApprovalInputModePin;
}

}  // namespace

bool read_human_approval_input_mode(AgentQHumanApprovalInputMode* mode)
{
    if (mode != nullptr) {
        *mode = AgentQHumanApprovalInputMode::pin;
    }
    if (mode == nullptr) {
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while reading human approval input mode: %s", esp_err_to_name(result));
        return false;
    }

    uint8_t value = kHumanApprovalInputModePin;
    result = nvs_get_u8(nvs, kHumanApprovalInputModeKey, &value);
    nvs_close(nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        *mode = AgentQHumanApprovalInputMode::pin;
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Human approval input mode read failed: %s", esp_err_to_name(result));
        *mode = AgentQHumanApprovalInputMode::pin;
        return false;
    }
    if (!stored_value_to_mode(value, mode)) {
        ESP_LOGW(kTag, "Human approval input mode has invalid value: %u", static_cast<unsigned>(value));
        *mode = AgentQHumanApprovalInputMode::pin;
        return false;
    }

    return true;
}

AgentQHumanApprovalInputMode human_approval_input_mode_or_default()
{
    AgentQHumanApprovalInputMode mode = AgentQHumanApprovalInputMode::pin;
    if (!read_human_approval_input_mode(&mode)) {
        return AgentQHumanApprovalInputMode::pin;
    }
    return mode;
}

bool human_approval_requires_pin()
{
    return human_approval_input_mode_or_default() == AgentQHumanApprovalInputMode::pin;
}

bool store_human_approval_input_mode(AgentQHumanApprovalInputMode mode)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing human approval input mode: %s", esp_err_to_name(result));
        return false;
    }

    const uint8_t value = stored_value_from_mode(mode);
    result = nvs_set_u8(nvs, kHumanApprovalInputModeKey, value);
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Human approval input mode write failed: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGI(kTag, "Stored human approval input mode: %s", human_approval_input_mode_label(mode));
    return true;
}

bool wipe_human_approval_input_mode()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while wiping human approval input mode: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kHumanApprovalInputModeKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Human approval input mode wipe failed: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGI(kTag, "Wiped human approval input mode");
    return true;
}

const char* human_approval_input_mode_label(AgentQHumanApprovalInputMode mode)
{
    return mode == AgentQHumanApprovalInputMode::confirm ? "Confirm" : "PIN";
}

}  // namespace agent_q
