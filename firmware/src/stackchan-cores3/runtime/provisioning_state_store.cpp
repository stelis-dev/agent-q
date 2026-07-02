#include "provisioning_state_store.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

namespace signing {
namespace {

constexpr const char* kTag = "ProvState";
constexpr const char* kNvsNamespace = "signing";
constexpr const char* kProvisioningStateKey = "prov_state";

}  // namespace

bool provisioning_state_store_load(ProvisioningStateStoreRecord* output)
{
    if (output == nullptr) {
        return false;
    }

    output->status = ProvisioningStateStorageStatus::unreadable;
    output->value[0] = '\0';

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed for provisioning state: %s", esp_err_to_name(result));
        return true;
    }

    size_t length = sizeof(output->value);
    result = nvs_get_str(nvs, kProvisioningStateKey, output->value, &length);
    nvs_close(nvs);

    if (result == ESP_ERR_NVS_NOT_FOUND) {
        output->status = ProvisioningStateStorageStatus::missing;
        output->value[0] = '\0';
        return true;
    }
    if (result == ESP_OK) {
        output->status = ProvisioningStateStorageStatus::present;
        return true;
    }

    ESP_LOGW(kTag, "NVS read failed for provisioning state: %s", esp_err_to_name(result));
    output->status = ProvisioningStateStorageStatus::unreadable;
    output->value[0] = '\0';
    return true;
}

bool provisioning_state_store_save(ProvisioningPersistedState state)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while saving provisioning state: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_set_str(nvs, kProvisioningStateKey, provisioning_persisted_state_to_string(state));
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS write failed for provisioning state: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

}  // namespace signing
