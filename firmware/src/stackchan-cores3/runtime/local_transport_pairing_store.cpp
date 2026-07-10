#include "local_transport_pairing_store.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "local_transport_crypto_adapter.h"
#include "nvs.h"
#include "stackchan_storage_names.h"
#include "transport/local_transport_identity_store.h"

namespace signing {
namespace {

constexpr const char* kTag = "LocalTransportPairing";
constexpr const char* kIdentityPrivateKey = "static_priv";
constexpr const char* kIdentityPublicKey = "static_pub";

LocalTransportIdentityRecordReadStatus read_key_pair(
    uint8_t secret_key[kLocalTransportStaticKeyBytes],
    uint8_t public_key[kLocalTransportStaticKeyBytes],
    void*)
{
    if (secret_key == nullptr || public_key == nullptr) {
        return LocalTransportIdentityRecordReadStatus::error;
    }
    nvs_handle_t nvs = 0;
    const esp_err_t open_result = nvs_open(
        kStackChanPairingIdentityNvsNamespace,
        NVS_READONLY,
        &nvs);
    if (open_result == ESP_ERR_NVS_NOT_FOUND) {
        return LocalTransportIdentityRecordReadStatus::missing;
    }
    if (open_result != ESP_OK) {
        ESP_LOGW(kTag, "Pairing identity NVS open failed: %s", esp_err_to_name(open_result));
        return LocalTransportIdentityRecordReadStatus::error;
    }

    size_t secret_size = kLocalTransportStaticKeyBytes;
    size_t public_size = kLocalTransportStaticKeyBytes;
    const esp_err_t secret_result = nvs_get_blob(
        nvs,
        kIdentityPrivateKey,
        secret_key,
        &secret_size);
    const esp_err_t public_result = nvs_get_blob(
        nvs,
        kIdentityPublicKey,
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
        local_transport_wipe_bytes(secret_key, kLocalTransportStaticKeyBytes);
        local_transport_wipe_bytes(public_key, kLocalTransportStaticKeyBytes);
        ESP_LOGW(kTag, "Pairing identity record invalid");
        return LocalTransportIdentityRecordReadStatus::error;
    }
    return LocalTransportIdentityRecordReadStatus::found;
}

bool erase_key(const char* key)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(
        kStackChanPairingIdentityNvsNamespace,
        NVS_READWRITE,
        &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        return false;
    }
    result = nvs_erase_key(nvs, key);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        result = ESP_OK;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    return result == ESP_OK;
}

bool erase_key_pair(void*)
{
    const bool private_erased = erase_key(kIdentityPrivateKey);
    const bool public_erased = erase_key(kIdentityPublicKey);
    if (!private_erased || !public_erased) {
        ESP_LOGW(kTag, "Pairing identity wipe incomplete");
        return false;
    }
    return true;
}

bool write_key_pair(
    const uint8_t secret_key[kLocalTransportStaticKeyBytes],
    const uint8_t public_key[kLocalTransportStaticKeyBytes],
    void*)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(
        kStackChanPairingIdentityNvsNamespace,
        NVS_READWRITE,
        &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Pairing identity NVS open for write failed: %s", esp_err_to_name(result));
        return false;
    }
    result = nvs_set_blob(
        nvs,
        kIdentityPrivateKey,
        secret_key,
        kLocalTransportStaticKeyBytes);
    if (result == ESP_OK) {
        result = nvs_set_blob(
            nvs,
            kIdentityPublicKey,
            public_key,
            kLocalTransportStaticKeyBytes);
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Pairing identity write failed: %s", esp_err_to_name(result));
        erase_key_pair(nullptr);
        return false;
    }
    return true;
}

const LocalTransportIdentityStoreOps& identity_store_ops()
{
    static const LocalTransportIdentityStoreOps ops{
        LocalTransportIdentityStorageOps{
            read_key_pair,
            write_key_pair,
            erase_key_pair,
            nullptr,
        },
        &stackchan_local_transport_crypto_ops(),
    };
    return ops;
}

}  // namespace

bool local_transport_load_or_create_pairing_identity(LocalTransportPairingIdentity* identity)
{
    return local_transport_identity_load_or_create(identity_store_ops(), identity);
}

bool local_transport_load_pairing_identity_secret(
    LocalTransportPairingIdentitySecret* identity)
{
    return local_transport_identity_load_secret(identity_store_ops(), identity);
}

bool local_transport_wipe_pairing_store()
{
    return local_transport_identity_wipe(identity_store_ops());
}

}  // namespace signing
