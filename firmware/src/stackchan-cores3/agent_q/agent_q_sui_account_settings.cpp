#include "agent_q_sui_account_settings.h"

#include <stdint.h>

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQSuiAcctSet";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kSuiAccountSettingsKey = "sui_acct_set";
constexpr uint8_t kRejectGasSponsor = 0;
constexpr uint8_t kAcceptGasSponsor = 1;

bool decode_account_settings(uint8_t value, AgentQSuiAccountSettings* settings)
{
    if (settings != nullptr) {
        *settings = kDefaultSuiAccountSettings;
    }
    if (settings == nullptr) {
        return false;
    }
    if (value == kRejectGasSponsor) {
        settings->accept_gas_sponsor = false;
        return true;
    }
    if (value == kAcceptGasSponsor) {
        settings->accept_gas_sponsor = true;
        return true;
    }
    return false;
}

}  // namespace

bool read_sui_account_settings(AgentQSuiAccountSettings* settings)
{
    if (settings != nullptr) {
        *settings = kDefaultSuiAccountSettings;
    }
    if (settings == nullptr) {
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return false;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while reading Sui account settings: %s", esp_err_to_name(result));
        return false;
    }

    uint8_t value = kRejectGasSponsor;
    result = nvs_get_u8(nvs, kSuiAccountSettingsKey, &value);
    nvs_close(nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return false;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Sui account settings read failed: %s", esp_err_to_name(result));
        *settings = kDefaultSuiAccountSettings;
        return false;
    }
    if (decode_account_settings(value, settings)) {
        return true;
    }

    ESP_LOGW(kTag, "Sui account settings have invalid value: %u", static_cast<unsigned>(value));
    *settings = kDefaultSuiAccountSettings;
    return false;
}

bool store_sui_account_settings(const AgentQSuiAccountSettings& settings)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing Sui account settings: %s", esp_err_to_name(result));
        return false;
    }

    const uint8_t value = settings.accept_gas_sponsor ? kAcceptGasSponsor : kRejectGasSponsor;
    result = nvs_set_u8(nvs, kSuiAccountSettingsKey, value);
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Sui account settings write failed: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGI(
        kTag,
        "Stored Sui account gas sponsor setting: %s",
        settings.accept_gas_sponsor ? "accept" : "reject");
    return true;
}

bool wipe_sui_account_settings()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while wiping Sui account settings: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kSuiAccountSettingsKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Sui account settings wipe failed: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGI(kTag, "Wiped Sui account settings");
    return true;
}

AgentQSuiAccountSettingsStatus sui_account_settings_status()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return AgentQSuiAccountSettingsStatus::missing;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while checking Sui account settings: %s", esp_err_to_name(result));
        return AgentQSuiAccountSettingsStatus::unreadable;
    }

    uint8_t value = kRejectGasSponsor;
    result = nvs_get_u8(nvs, kSuiAccountSettingsKey, &value);
    nvs_close(nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return AgentQSuiAccountSettingsStatus::missing;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Sui account settings status read failed: %s", esp_err_to_name(result));
        return AgentQSuiAccountSettingsStatus::unreadable;
    }
    if (value == kRejectGasSponsor ||
        value == kAcceptGasSponsor) {
        return AgentQSuiAccountSettingsStatus::active;
    }

    ESP_LOGW(kTag, "Sui account settings status found invalid value: %u", static_cast<unsigned>(value));
    return AgentQSuiAccountSettingsStatus::invalid;
}

}  // namespace agent_q
