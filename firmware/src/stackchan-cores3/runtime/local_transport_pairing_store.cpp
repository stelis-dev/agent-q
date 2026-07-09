#include "local_transport_pairing_store.h"

#include <string.h>

#include "bip39.h"
#include "entropy.h"
#include "esp_err.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "nvs.h"
#include "stackchan_storage_names.h"
#include "transport/local_transport_peer_store.h"

extern "C" {
#include "lib/monocypher/monocypher.h"
}

namespace signing {
namespace {

constexpr const char* kTag = "LocalTransportPairing";
constexpr const char* kIdentityPrivateKey = "static_priv";
constexpr const char* kIdentityPublicKey = "static_pub";
constexpr const char* kPeerRecordsKey = "records";

void compute_fingerprint(
    const uint8_t public_key[kLocalTransportStaticKeyBytes],
    uint8_t fingerprint[kLocalTransportIdentityFingerprintBytes])
{
    uint8_t digest[32] = {};
    if (mbedtls_sha256(public_key, kLocalTransportStaticKeyBytes, digest, 0) == 0) {
        memcpy(fingerprint, digest, kLocalTransportIdentityFingerprintBytes);
    } else {
        memset(fingerprint, 0, kLocalTransportIdentityFingerprintBytes);
    }
    wipe_sensitive_buffer(digest, sizeof(digest));
}

bool read_blob_exact(
    nvs_handle_t nvs,
    const char* key,
    uint8_t* output,
    size_t output_size)
{
    if (output == nullptr || output_size != kLocalTransportStaticKeyBytes) {
        return false;
    }
    size_t stored_size = output_size;
    const esp_err_t result = nvs_get_blob(nvs, key, output, &stored_size);
    return result == ESP_OK && stored_size == output_size;
}

bool read_identity_from_nvs(LocalTransportPairingIdentity* identity)
{
    if (identity == nullptr) {
        return false;
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
        }
        return false;
    }

    const bool ok = read_blob_exact(
        nvs,
        kIdentityPublicKey,
        identity->public_key,
        sizeof(identity->public_key));
    nvs_close(nvs);
    if (!ok) {
        memset(identity, 0, sizeof(*identity));
        return false;
    }

    compute_fingerprint(identity->public_key, identity->fingerprint);
    return true;
}

bool read_identity_secret_from_nvs(LocalTransportPairingIdentitySecret* identity)
{
    if (identity == nullptr) {
        return false;
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
        }
        return false;
    }

    const bool public_ok = read_blob_exact(
        nvs,
        kIdentityPublicKey,
        identity->public_key,
        sizeof(identity->public_key));
    const bool secret_ok = read_blob_exact(
        nvs,
        kIdentityPrivateKey,
        identity->secret_key,
        sizeof(identity->secret_key));
    nvs_close(nvs);
    if (!public_ok || !secret_ok) {
        wipe_sensitive_buffer(reinterpret_cast<uint8_t*>(identity), sizeof(*identity));
        return false;
    }

    compute_fingerprint(identity->public_key, identity->fingerprint);
    return true;
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

bool read_peer_blob(LocalTransportPairedPeerBlob* blob)
{
    if (blob == nullptr) {
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kStackChanPairingPeersNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        local_transport_peer_store_init_empty(blob);
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Pairing peers NVS open failed: %s", esp_err_to_name(result));
        return false;
    }

    size_t stored_size = sizeof(*blob);
    result = nvs_get_blob(nvs, kPeerRecordsKey, blob, &stored_size);
    nvs_close(nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        local_transport_peer_store_init_empty(blob);
        return true;
    }
    if (result != ESP_OK || stored_size != sizeof(*blob) ||
        !local_transport_peer_store_valid(*blob)) {
        ESP_LOGW(kTag, "Pairing peers record invalid");
        memset(blob, 0, sizeof(*blob));
        return false;
    }
    return true;
}

bool write_peer_blob(const LocalTransportPairedPeerBlob& blob)
{
    if (!local_transport_peer_store_valid(blob)) {
        return false;
    }
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kStackChanPairingPeersNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Pairing peers NVS open for write failed: %s", esp_err_to_name(result));
        return false;
    }
    result = nvs_set_blob(nvs, kPeerRecordsKey, &blob, sizeof(blob));
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Pairing peers write failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

}  // namespace

bool local_transport_load_or_create_pairing_identity(LocalTransportPairingIdentity* identity)
{
    if (identity == nullptr) {
        return false;
    }
    if (read_identity_from_nvs(identity)) {
        return true;
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
    compute_fingerprint(identity->public_key, identity->fingerprint);
    wipe_sensitive_buffer(public_key, sizeof(public_key));
    return true;
}

bool local_transport_load_or_create_pairing_identity_secret(
    LocalTransportPairingIdentitySecret* identity)
{
    if (identity == nullptr) {
        return false;
    }
    if (read_identity_secret_from_nvs(identity)) {
        return true;
    }

    LocalTransportPairingIdentity public_identity = {};
    if (!local_transport_load_or_create_pairing_identity(&public_identity)) {
        return false;
    }
    const bool ok = read_identity_secret_from_nvs(identity);
    wipe_sensitive_buffer(reinterpret_cast<uint8_t*>(&public_identity), sizeof(public_identity));
    return ok;
}

bool local_transport_store_paired_peer(const uint8_t gateway_static_public[kLocalTransportStaticKeyBytes])
{
    if (gateway_static_public == nullptr) {
        return false;
    }

    LocalTransportPairedPeerBlob blob = {};
    if (!read_peer_blob(&blob)) {
        return false;
    }

    if (!local_transport_peer_store_upsert(&blob, gateway_static_public)) {
        ESP_LOGW(kTag, "Pairing peer store full");
        return false;
    }
    return write_peer_blob(blob);
}

bool local_transport_wipe_pairing_store()
{
    const bool identity_private_wiped = erase_namespace_key(
        kStackChanPairingIdentityNvsNamespace,
        kIdentityPrivateKey);
    const bool identity_public_wiped = erase_namespace_key(
        kStackChanPairingIdentityNvsNamespace,
        kIdentityPublicKey);
    const bool peers_wiped = erase_namespace_key(kStackChanPairingPeersNvsNamespace, kPeerRecordsKey);
    if (!identity_private_wiped || !identity_public_wiped || !peers_wiped) {
        ESP_LOGW(kTag, "Pairing store wipe incomplete");
        return false;
    }
    return true;
}

}  // namespace signing
