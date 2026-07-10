#include "local_transport_pairing_store.h"

#include <string.h>

#include "bip39.h"
#include "entropy.h"
#include "esp_err.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "nvs.h"
#include "stackchan_storage_names.h"

extern "C" {
#include "lib/monocypher/monocypher.h"
}

namespace signing {
namespace {

constexpr const char* kTag = "LocalTransportPairing";
constexpr const char* kIdentityPrivateKey = "static_priv";
constexpr const char* kIdentityPublicKey = "static_pub";

enum class IdentityReadStatus {
    missing,
    valid,
    invalid,
};

bool compute_fingerprint(
    const uint8_t public_key[kLocalTransportStaticKeyBytes],
    uint8_t fingerprint[kLocalTransportIdentityFingerprintBytes])
{
    uint8_t digest[32] = {};
    const bool ok = mbedtls_sha256(public_key, kLocalTransportStaticKeyBytes, digest, 0) == 0;
    if (ok) {
        memcpy(fingerprint, digest, kLocalTransportIdentityFingerprintBytes);
    } else {
        memset(fingerprint, 0, kLocalTransportIdentityFingerprintBytes);
    }
    wipe_sensitive_buffer(digest, sizeof(digest));
    return ok;
}

IdentityReadStatus read_identity_secret_from_nvs(LocalTransportPairingIdentitySecret* identity);

IdentityReadStatus read_identity_from_nvs(LocalTransportPairingIdentity* identity)
{
    if (identity == nullptr) {
        return IdentityReadStatus::invalid;
    }
    memset(identity, 0, sizeof(*identity));

    LocalTransportPairingIdentitySecret secret_identity = {};
    const IdentityReadStatus status = read_identity_secret_from_nvs(&secret_identity);
    if (status != IdentityReadStatus::valid) {
        return status;
    }
    memcpy(identity->public_key, secret_identity.public_key, sizeof(identity->public_key));
    memcpy(identity->fingerprint, secret_identity.fingerprint, sizeof(identity->fingerprint));
    wipe_sensitive_buffer(
        reinterpret_cast<uint8_t*>(&secret_identity),
        sizeof(secret_identity));
    return IdentityReadStatus::valid;
}

IdentityReadStatus read_identity_secret_from_nvs(LocalTransportPairingIdentitySecret* identity)
{
    if (identity == nullptr) {
        return IdentityReadStatus::invalid;
    }
    memset(identity, 0, sizeof(*identity));

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(
        kStackChanPairingIdentityNvsNamespace,
        NVS_READONLY,
        &nvs);
    if (result != ESP_OK) {
        if (result != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(kTag, "Pairing identity NVS open failed: %s", esp_err_to_name(result));
            return IdentityReadStatus::invalid;
        }
        return IdentityReadStatus::missing;
    }

    size_t public_size = sizeof(identity->public_key);
    const esp_err_t public_result = nvs_get_blob(
        nvs,
        kIdentityPublicKey,
        identity->public_key,
        &public_size);
    size_t secret_size = sizeof(identity->secret_key);
    const esp_err_t secret_result = nvs_get_blob(
        nvs,
        kIdentityPrivateKey,
        identity->secret_key,
        &secret_size);
    nvs_close(nvs);
    if (public_result == ESP_ERR_NVS_NOT_FOUND && secret_result == ESP_ERR_NVS_NOT_FOUND) {
        wipe_sensitive_buffer(reinterpret_cast<uint8_t*>(identity), sizeof(*identity));
        return IdentityReadStatus::missing;
    }
    if (public_result != ESP_OK || secret_result != ESP_OK ||
        public_size != sizeof(identity->public_key) ||
        secret_size != sizeof(identity->secret_key)) {
        wipe_sensitive_buffer(reinterpret_cast<uint8_t*>(identity), sizeof(*identity));
        ESP_LOGW(kTag, "Pairing identity record invalid");
        return IdentityReadStatus::invalid;
    }

    uint8_t derived_public[kLocalTransportStaticKeyBytes] = {};
    crypto_x25519_public_key(derived_public, identity->secret_key);
    const bool key_pair_matches =
        memcmp(derived_public, identity->public_key, sizeof(derived_public)) == 0;
    wipe_sensitive_buffer(derived_public, sizeof(derived_public));
    if (!key_pair_matches || !compute_fingerprint(identity->public_key, identity->fingerprint)) {
        wipe_sensitive_buffer(reinterpret_cast<uint8_t*>(identity), sizeof(*identity));
        ESP_LOGW(kTag, "Pairing identity key pair invalid");
        return IdentityReadStatus::invalid;
    }
    return IdentityReadStatus::valid;
}

bool store_identity(
    const uint8_t secret[kLocalTransportStaticKeyBytes],
    const uint8_t public_key[kLocalTransportStaticKeyBytes])
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

    result = nvs_set_blob(nvs, kIdentityPrivateKey, secret, kLocalTransportStaticKeyBytes);
    if (result == ESP_OK) {
        result = nvs_set_blob(nvs, kIdentityPublicKey, public_key, kLocalTransportStaticKeyBytes);
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Pairing identity write failed: %s", esp_err_to_name(result));
        local_transport_wipe_pairing_store();
        return false;
    }
    return true;
}

bool erase_namespace_key(const char* ns_name, const char* key)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(ns_name, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        return result == ESP_ERR_NVS_NOT_FOUND;
    }
    result = nvs_erase_key(nvs, key);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    return result == ESP_OK;
}

}  // namespace

bool local_transport_load_or_create_pairing_identity(LocalTransportPairingIdentity* identity)
{
    if (identity == nullptr) {
        return false;
    }
    const IdentityReadStatus stored_status = read_identity_from_nvs(identity);
    if (stored_status == IdentityReadStatus::valid) {
        return true;
    }
    if (stored_status == IdentityReadStatus::invalid) {
        return false;
    }

    uint8_t secret[kLocalTransportStaticKeyBytes] = {};
    uint8_t public_key[kLocalTransportStaticKeyBytes] = {};
    if (!fill_secure_random(secret, sizeof(secret))) {
        ESP_LOGW(kTag, "Secure RNG unavailable for pairing identity");
        return false;
    }
    crypto_x25519_public_key(public_key, secret);
    const bool stored = store_identity(secret, public_key);
    wipe_sensitive_buffer(secret, sizeof(secret));
    if (!stored) {
        wipe_sensitive_buffer(public_key, sizeof(public_key));
        return false;
    }

    memcpy(identity->public_key, public_key, sizeof(identity->public_key));
    if (!compute_fingerprint(identity->public_key, identity->fingerprint)) {
        wipe_sensitive_buffer(reinterpret_cast<uint8_t*>(identity), sizeof(*identity));
        local_transport_wipe_pairing_store();
        wipe_sensitive_buffer(public_key, sizeof(public_key));
        return false;
    }
    wipe_sensitive_buffer(public_key, sizeof(public_key));
    return true;
}

bool local_transport_load_pairing_identity_secret(
    LocalTransportPairingIdentitySecret* identity)
{
    if (identity == nullptr) {
        return false;
    }
    return read_identity_secret_from_nvs(identity) == IdentityReadStatus::valid;
}

bool local_transport_wipe_pairing_store()
{
    const bool identity_private_wiped = erase_namespace_key(
        kStackChanPairingIdentityNvsNamespace,
        kIdentityPrivateKey);
    const bool identity_public_wiped = erase_namespace_key(
        kStackChanPairingIdentityNvsNamespace,
        kIdentityPublicKey);
    if (!identity_private_wiped || !identity_public_wiped) {
        ESP_LOGW(kTag, "Pairing store wipe incomplete");
        return false;
    }
    return true;
}

}  // namespace signing
