#include "agent_q_signing_mode.h"

#include <stdint.h>

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQSigningMode";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kSigningAuthorizationModeKey = "sign_auth_mode";
constexpr uint8_t kSigningAuthorizationModeUser = 0;
constexpr uint8_t kSigningAuthorizationModePolicy = 1;

}  // namespace

bool read_signing_authorization_mode(AgentQSigningAuthorizationMode* mode)
{
    if (mode != nullptr) {
        *mode = AgentQSigningAuthorizationMode::user;
    }
    if (mode == nullptr) {
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return false;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while reading signing mode: %s", esp_err_to_name(result));
        return false;
    }

    uint8_t value = kSigningAuthorizationModeUser;
    result = nvs_get_u8(nvs, kSigningAuthorizationModeKey, &value);
    nvs_close(nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return false;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Signing mode read failed: %s", esp_err_to_name(result));
        *mode = AgentQSigningAuthorizationMode::user;
        return false;
    }
    if (value == kSigningAuthorizationModeUser) {
        *mode = AgentQSigningAuthorizationMode::user;
        return true;
    }
    if (value == kSigningAuthorizationModePolicy) {
        *mode = AgentQSigningAuthorizationMode::policy;
        return true;
    }

    ESP_LOGW(kTag, "Signing mode has invalid value: %u", static_cast<unsigned>(value));
    *mode = AgentQSigningAuthorizationMode::user;
    return false;
}

bool store_signing_authorization_mode(AgentQSigningAuthorizationMode mode)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing signing mode: %s", esp_err_to_name(result));
        return false;
    }

    const uint8_t value = mode == AgentQSigningAuthorizationMode::policy
                              ? kSigningAuthorizationModePolicy
                              : kSigningAuthorizationModeUser;
    result = nvs_set_u8(nvs, kSigningAuthorizationModeKey, value);
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Signing mode write failed: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGI(kTag, "Stored signing mode: %s", signing_authorization_mode_name(mode));
    return true;
}

AgentQSigningAuthorizationModeStatus signing_authorization_mode_status()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return AgentQSigningAuthorizationModeStatus::missing;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while checking signing mode: %s", esp_err_to_name(result));
        return AgentQSigningAuthorizationModeStatus::unreadable;
    }

    uint8_t value = kSigningAuthorizationModeUser;
    result = nvs_get_u8(nvs, kSigningAuthorizationModeKey, &value);
    nvs_close(nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return AgentQSigningAuthorizationModeStatus::missing;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Signing mode status read failed: %s", esp_err_to_name(result));
        return AgentQSigningAuthorizationModeStatus::unreadable;
    }
    if (value == kSigningAuthorizationModeUser ||
        value == kSigningAuthorizationModePolicy) {
        return AgentQSigningAuthorizationModeStatus::active;
    }

    ESP_LOGW(kTag, "Signing mode status found invalid value: %u", static_cast<unsigned>(value));
    return AgentQSigningAuthorizationModeStatus::invalid;
}

bool wipe_signing_authorization_mode()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while wiping signing mode: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kSigningAuthorizationModeKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Signing mode wipe failed: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGI(kTag, "Wiped signing mode");
    return true;
}

const char* signing_authorization_mode_name(AgentQSigningAuthorizationMode mode)
{
    return mode == AgentQSigningAuthorizationMode::policy ? "policy" : "user";
}

}  // namespace agent_q
