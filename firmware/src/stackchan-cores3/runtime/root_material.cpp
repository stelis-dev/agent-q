#include "root_material.h"

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"
#include "stackchan_storage_names.h"

namespace signing {
namespace {

constexpr const char* kTag = "RootMaterial";
constexpr const char* kNvsNamespace = kStackChanSigningKeyMaterialNvsNamespace;
constexpr const char* kRootMaterialKey = "root_entropy";

}  // namespace

bool has_root_material()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while checking root material: %s", esp_err_to_name(result));
        return false;
    }

    size_t root_material_size = 0;
    result = nvs_get_blob(nvs, kRootMaterialKey, nullptr, &root_material_size);
    if (result != ESP_OK || root_material_size != kRootMaterialBytes) {
        nvs_close(nvs);
        if (result != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(kTag, "Root material check failed: %s size=%u",
                     esp_err_to_name(result),
                     static_cast<unsigned>(root_material_size));
        }
        return false;
    }

    uint8_t root_material[kRootMaterialBytes] = {};
    root_material_size = sizeof(root_material);
    result = nvs_get_blob(nvs, kRootMaterialKey, root_material, &root_material_size);
    nvs_close(nvs);
    wipe_sensitive_buffer(root_material, sizeof(root_material));
    if (result != ESP_OK || root_material_size != kRootMaterialBytes) {
        ESP_LOGW(kTag, "Root material read validation failed: %s size=%u",
                 esp_err_to_name(result),
                 static_cast<unsigned>(root_material_size));
        return false;
    }

    return true;
}

bool store_root_material(const uint8_t* root_material, size_t root_material_size)
{
    if (root_material == nullptr || root_material_size != kRootMaterialBytes) {
        ESP_LOGW(kTag, "Refusing invalid root material size: %u",
                 static_cast<unsigned>(root_material_size));
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing root material: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_set_blob(nvs, kRootMaterialKey, root_material, root_material_size);
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS write failed for root material: %s", esp_err_to_name(result));
        wipe_root_material();
        return false;
    }

    ESP_LOGW(kTag, "Stored DEV_PROFILE root material blob in NVS");
    return true;
}

bool wipe_root_material()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while erasing root material: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kRootMaterialKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS erase failed for root material: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGW(kTag, "Root material blob wiped");
    return true;
}

bool read_root_material(uint8_t* root_material_out, size_t root_material_size)
{
    if (root_material_out != nullptr && root_material_size > 0) {
        wipe_sensitive_buffer(root_material_out, root_material_size);
    }
    if (root_material_out == nullptr || root_material_size != kRootMaterialBytes) {
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result != ESP_OK) {
        wipe_sensitive_buffer(root_material_out, root_material_size);
        ESP_LOGW(kTag, "NVS open failed while reading root material: %s", esp_err_to_name(result));
        return false;
    }

    size_t blob_size = root_material_size;
    result = nvs_get_blob(nvs, kRootMaterialKey, root_material_out, &blob_size);
    nvs_close(nvs);

    if (result != ESP_OK || blob_size != kRootMaterialBytes) {
        wipe_sensitive_buffer(root_material_out, root_material_size);
        ESP_LOGW(kTag, "Root material read failed: %s size=%u",
                 esp_err_to_name(result),
                 static_cast<unsigned>(blob_size));
        return false;
    }

    return true;
}

}  // namespace signing
