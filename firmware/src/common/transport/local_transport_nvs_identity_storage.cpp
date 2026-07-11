#include "transport/local_transport_nvs_identity_storage.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

namespace signing {
namespace {

constexpr size_t kNvsNameMaxBytes = 15;

bool name_valid(const char* value)
{
    return value != nullptr && value[0] != '\0' &&
           strlen(value) <= kNvsNameMaxBytes;
}

bool config_valid(const LocalTransportNvsIdentityStorageConfig* config)
{
    return config != nullptr &&
           name_valid(config->namespace_name) &&
           name_valid(config->private_key_name) &&
           name_valid(config->public_key_name) &&
           strcmp(config->private_key_name, config->public_key_name) != 0 &&
           config->log_tag != nullptr && config->log_tag[0] != '\0';
}

LocalTransportIdentityRecordReadStatus read_public_key(
    uint8_t public_key[kLocalTransportStaticKeyBytes],
    void* context)
{
    const auto* config =
        static_cast<const LocalTransportNvsIdentityStorageConfig*>(context);
    if (public_key == nullptr) {
        return LocalTransportIdentityRecordReadStatus::error;
    }
    local_transport_wipe_bytes(public_key, kLocalTransportStaticKeyBytes);
    if (!config_valid(config)) {
        return LocalTransportIdentityRecordReadStatus::error;
    }

    nvs_handle_t nvs = 0;
    const esp_err_t open_result =
        nvs_open(config->namespace_name, NVS_READONLY, &nvs);
    if (open_result == ESP_ERR_NVS_NOT_FOUND) {
        return LocalTransportIdentityRecordReadStatus::missing;
    }
    if (open_result != ESP_OK) {
        ESP_LOGW(config->log_tag, "identity NVS open failed: %s",
                 esp_err_to_name(open_result));
        return LocalTransportIdentityRecordReadStatus::error;
    }

    size_t secret_size = 0;
    size_t public_size = kLocalTransportStaticKeyBytes;
    const esp_err_t secret_result = nvs_get_blob(
        nvs,
        config->private_key_name,
        nullptr,
        &secret_size);
    const esp_err_t public_result = nvs_get_blob(
        nvs,
        config->public_key_name,
        public_key,
        &public_size);
    nvs_close(nvs);
    if (secret_result == ESP_ERR_NVS_NOT_FOUND &&
        public_result == ESP_ERR_NVS_NOT_FOUND) {
        return LocalTransportIdentityRecordReadStatus::missing;
    }
    if (secret_result != ESP_OK || public_result != ESP_OK ||
        secret_size != kLocalTransportStaticKeyBytes ||
        public_size != kLocalTransportStaticKeyBytes) {
        local_transport_wipe_bytes(public_key, kLocalTransportStaticKeyBytes);
        ESP_LOGW(config->log_tag, "identity record invalid");
        return LocalTransportIdentityRecordReadStatus::error;
    }
    return LocalTransportIdentityRecordReadStatus::found;
}

LocalTransportIdentityRecordReadStatus with_key_pair(
    LocalTransportStoredKeyPairConsumer consumer,
    void* consumer_context,
    void* storage_context)
{
    const auto* config =
        static_cast<const LocalTransportNvsIdentityStorageConfig*>(storage_context);
    if (!config_valid(config) || consumer == nullptr) {
        return LocalTransportIdentityRecordReadStatus::error;
    }

    uint8_t secret_key[kLocalTransportStaticKeyBytes] = {};
    uint8_t public_key[kLocalTransportStaticKeyBytes] = {};

    nvs_handle_t nvs = 0;
    const esp_err_t open_result =
        nvs_open(config->namespace_name, NVS_READONLY, &nvs);
    if (open_result == ESP_ERR_NVS_NOT_FOUND) {
        return LocalTransportIdentityRecordReadStatus::missing;
    }
    if (open_result != ESP_OK) {
        ESP_LOGW(config->log_tag, "identity NVS open failed: %s",
                 esp_err_to_name(open_result));
        return LocalTransportIdentityRecordReadStatus::error;
    }

    size_t secret_size = kLocalTransportStaticKeyBytes;
    size_t public_size = kLocalTransportStaticKeyBytes;
    const esp_err_t secret_result = nvs_get_blob(
        nvs,
        config->private_key_name,
        secret_key,
        &secret_size);
    const esp_err_t public_result = nvs_get_blob(
        nvs,
        config->public_key_name,
        public_key,
        &public_size);
    nvs_close(nvs);
    if (secret_result == ESP_ERR_NVS_NOT_FOUND &&
        public_result == ESP_ERR_NVS_NOT_FOUND) {
        local_transport_wipe_bytes(secret_key, sizeof(secret_key));
        local_transport_wipe_bytes(public_key, sizeof(public_key));
        return LocalTransportIdentityRecordReadStatus::missing;
    }
    if (secret_result != ESP_OK || public_result != ESP_OK ||
        secret_size != kLocalTransportStaticKeyBytes ||
        public_size != kLocalTransportStaticKeyBytes) {
        local_transport_wipe_bytes(secret_key, sizeof(secret_key));
        local_transport_wipe_bytes(public_key, sizeof(public_key));
        ESP_LOGW(config->log_tag, "identity record invalid");
        return LocalTransportIdentityRecordReadStatus::error;
    }
    const bool consumed = consumer(secret_key, public_key, consumer_context);
    local_transport_wipe_bytes(secret_key, sizeof(secret_key));
    local_transport_wipe_bytes(public_key, sizeof(public_key));
    return consumed ? LocalTransportIdentityRecordReadStatus::found
                    : LocalTransportIdentityRecordReadStatus::error;
}

bool erase_key(
    const LocalTransportNvsIdentityStorageConfig& config,
    const char* key_name)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(config.namespace_name, NVS_READWRITE, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        return false;
    }
    result = nvs_erase_key(nvs, key_name);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        result = ESP_OK;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    return result == ESP_OK;
}

bool erase_key_pair(void* context)
{
    const auto* config =
        static_cast<const LocalTransportNvsIdentityStorageConfig*>(context);
    if (!config_valid(config)) {
        return false;
    }
    const bool private_erased = erase_key(*config, config->private_key_name);
    const bool public_erased = erase_key(*config, config->public_key_name);
    if (!private_erased || !public_erased) {
        ESP_LOGW(config->log_tag, "identity wipe incomplete");
        return false;
    }
    return true;
}

bool write_key_pair(
    const uint8_t secret_key[kLocalTransportStaticKeyBytes],
    const uint8_t public_key[kLocalTransportStaticKeyBytes],
    void* context)
{
    const auto* config =
        static_cast<const LocalTransportNvsIdentityStorageConfig*>(context);
    if (!config_valid(config) || secret_key == nullptr || public_key == nullptr) {
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(config->namespace_name, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(config->log_tag, "identity NVS open for write failed: %s",
                 esp_err_to_name(result));
        return false;
    }
    result = nvs_set_blob(
        nvs,
        config->private_key_name,
        secret_key,
        kLocalTransportStaticKeyBytes);
    if (result == ESP_OK) {
        result = nvs_set_blob(
            nvs,
            config->public_key_name,
            public_key,
            kLocalTransportStaticKeyBytes);
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(config->log_tag, "identity write failed: %s",
                 esp_err_to_name(result));
        erase_key_pair(context);
        return false;
    }
    return true;
}

}  // namespace

LocalTransportIdentityStorageOps local_transport_nvs_identity_storage_ops(
    const LocalTransportNvsIdentityStorageConfig* config)
{
    return LocalTransportIdentityStorageOps{
        read_public_key,
        with_key_pair,
        write_key_pair,
        erase_key_pair,
        const_cast<LocalTransportNvsIdentityStorageConfig*>(config),
    };
}

}  // namespace signing
