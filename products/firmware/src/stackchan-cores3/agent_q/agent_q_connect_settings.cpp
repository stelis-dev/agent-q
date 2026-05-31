#include "agent_q_connect_settings.h"

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQConnectSettings";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kRequirePinOnConnectKey = "pin_on_connect";

}  // namespace

bool read_require_pin_on_connect(bool* required)
{
    if (required != nullptr) {
        *required = true;
    }
    if (required == nullptr) {
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while reading connect PIN setting: %s", esp_err_to_name(result));
        return false;
    }

    uint8_t value = 1;
    result = nvs_get_u8(nvs, kRequirePinOnConnectKey, &value);
    nvs_close(nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        *required = true;
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Connect PIN setting read failed: %s", esp_err_to_name(result));
        *required = true;
        return false;
    }
    if (value > 1) {
        ESP_LOGW(kTag, "Connect PIN setting has invalid value: %u", static_cast<unsigned>(value));
        *required = true;
        return false;
    }

    *required = value == 1;
    return true;
}

bool connect_requires_pin()
{
    bool required = true;
    if (!read_require_pin_on_connect(&required)) {
        return true;
    }
    return required;
}

bool store_require_pin_on_connect(bool required)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing connect PIN setting: %s", esp_err_to_name(result));
        return false;
    }

    const uint8_t value = required ? 1 : 0;
    result = nvs_set_u8(nvs, kRequirePinOnConnectKey, value);
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Connect PIN setting write failed: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGI(kTag, "Stored connect PIN setting: %s", required ? "on" : "off");
    return true;
}

bool wipe_require_pin_on_connect()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while wiping connect PIN setting: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kRequirePinOnConnectKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Connect PIN setting wipe failed: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGI(kTag, "Wiped connect PIN setting");
    return true;
}

}  // namespace agent_q
