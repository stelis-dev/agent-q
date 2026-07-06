#include "protocol/signing_mode.h"

#include <stdint.h>

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"
#include "protocol/persistent_storage_names.h"

namespace signing {
namespace {

constexpr const char* kTag = "Mode";
constexpr const char* kNvsNamespace = kMutableSettingsNvsNamespace;
constexpr const char* kAuthorizationModeKey = "sign_auth_mode";
constexpr uint8_t kAuthorizationModeUser = 0;
constexpr uint8_t kAuthorizationModePolicy = 1;

}  // namespace

bool read_signing_authorization_mode(AuthorizationMode* mode)
{
    if (mode != nullptr) {
        *mode = AuthorizationMode::user;
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

    uint8_t value = kAuthorizationModeUser;
    result = nvs_get_u8(nvs, kAuthorizationModeKey, &value);
    nvs_close(nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return false;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Signing mode read failed: %s", esp_err_to_name(result));
        *mode = AuthorizationMode::user;
        return false;
    }
    if (value == kAuthorizationModeUser) {
        *mode = AuthorizationMode::user;
        return true;
    }
    if (value == kAuthorizationModePolicy) {
        *mode = AuthorizationMode::policy;
        return true;
    }

    ESP_LOGW(kTag, "Signing mode has invalid value: %u", static_cast<unsigned>(value));
    *mode = AuthorizationMode::user;
    return false;
}

bool store_signing_authorization_mode(AuthorizationMode mode)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing signing mode: %s", esp_err_to_name(result));
        return false;
    }

    const uint8_t value = mode == AuthorizationMode::policy
                              ? kAuthorizationModePolicy
                              : kAuthorizationModeUser;
    result = nvs_set_u8(nvs, kAuthorizationModeKey, value);
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Signing mode write failed: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGI(kTag, "Stored signing mode: %s", authorization_mode_name(mode));
    return true;
}

AuthorizationModeStatus authorization_mode_status()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return AuthorizationModeStatus::missing;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while checking signing mode: %s", esp_err_to_name(result));
        return AuthorizationModeStatus::unreadable;
    }

    uint8_t value = kAuthorizationModeUser;
    result = nvs_get_u8(nvs, kAuthorizationModeKey, &value);
    nvs_close(nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return AuthorizationModeStatus::missing;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Signing mode status read failed: %s", esp_err_to_name(result));
        return AuthorizationModeStatus::unreadable;
    }
    if (value == kAuthorizationModeUser ||
        value == kAuthorizationModePolicy) {
        return AuthorizationModeStatus::active;
    }

    ESP_LOGW(kTag, "Signing mode status found invalid value: %u", static_cast<unsigned>(value));
    return AuthorizationModeStatus::invalid;
}

bool wipe_signing_authorization_mode()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while clearing signing mode: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kAuthorizationModeKey);
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

const char* authorization_mode_name(AuthorizationMode mode)
{
    return mode == AuthorizationMode::policy ? "policy" : "user";
}

}  // namespace signing
