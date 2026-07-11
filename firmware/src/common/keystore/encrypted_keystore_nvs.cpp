#include "keystore/encrypted_keystore_nvs.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

namespace signing {
namespace {

constexpr size_t kNvsNameMaximumBytes = 15;

bool name_valid(const char* value)
{
    return value != nullptr && value[0] != '\0' &&
           strlen(value) <= kNvsNameMaximumBytes;
}

bool config_valid(const EncryptedKeystoreNvsConfig* config)
{
    return config != nullptr && name_valid(config->namespace_name) &&
           config->log_tag != nullptr && config->log_tag[0] != '\0';
}

KeystoreBlobReadStatus read_blob(
    const char* key,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size,
    void* context)
{
    const auto* config = static_cast<const EncryptedKeystoreNvsConfig*>(context);
    if (!config_valid(config) || !name_valid(key) || output_size == nullptr ||
        (output_capacity > 0 && output == nullptr)) {
        return KeystoreBlobReadStatus::error;
    }
    *output_size = 0;
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(config->namespace_name, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return KeystoreBlobReadStatus::missing;
    }
    if (result != ESP_OK) {
        ESP_LOGW(config->log_tag, "keystore NVS open failed: %s",
                 esp_err_to_name(result));
        return KeystoreBlobReadStatus::error;
    }
    size_t stored_size = 0;
    result = nvs_get_blob(nvs, key, nullptr, &stored_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return KeystoreBlobReadStatus::missing;
    }
    if (result != ESP_OK || stored_size == 0 || stored_size > output_capacity) {
        nvs_close(nvs);
        ESP_LOGW(config->log_tag, "keystore blob size invalid");
        return KeystoreBlobReadStatus::error;
    }
    size_t read_size = stored_size;
    result = nvs_get_blob(nvs, key, output, &read_size);
    nvs_close(nvs);
    if (result != ESP_OK || read_size != stored_size) {
        encrypted_keystore_wipe(output, output_capacity);
        ESP_LOGW(config->log_tag, "keystore blob read failed: %s",
                 esp_err_to_name(result));
        return KeystoreBlobReadStatus::error;
    }
    *output_size = read_size;
    return KeystoreBlobReadStatus::found;
}

bool write_blob(
    const char* key,
    const uint8_t* value,
    size_t value_size,
    void* context)
{
    const auto* config = static_cast<const EncryptedKeystoreNvsConfig*>(context);
    if (!config_valid(config) || !name_valid(key) || value == nullptr ||
        value_size == 0) {
        return false;
    }
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(config->namespace_name, NVS_READWRITE, &nvs);
    const bool opened = result == ESP_OK;
    if (result == ESP_OK) {
        result = nvs_set_blob(nvs, key, value, value_size);
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    if (opened) {
        nvs_close(nvs);
    }
    if (result != ESP_OK) {
        ESP_LOGW(config->log_tag, "keystore blob write failed: %s",
                 esp_err_to_name(result));
    }
    return result == ESP_OK;
}

bool erase_blob(const char* key, void* context)
{
    const auto* config = static_cast<const EncryptedKeystoreNvsConfig*>(context);
    if (!config_valid(config) || !name_valid(key)) {
        return false;
    }
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(config->namespace_name, NVS_READWRITE, &nvs);
    const bool opened = result == ESP_OK;
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_erase_key(nvs, key);
        if (result == ESP_ERR_NVS_NOT_FOUND) {
            result = ESP_OK;
        }
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    if (opened) {
        nvs_close(nvs);
    }
    if (result != ESP_OK) {
        ESP_LOGW(config->log_tag, "keystore blob erase failed: %s",
                 esp_err_to_name(result));
    }
    return result == ESP_OK;
}

}  // namespace

KeystoreStorageOps encrypted_keystore_nvs_storage_ops(
    const EncryptedKeystoreNvsConfig* config)
{
    return KeystoreStorageOps{
        read_blob,
        write_blob,
        erase_blob,
        const_cast<EncryptedKeystoreNvsConfig*>(config),
    };
}

}  // namespace signing
