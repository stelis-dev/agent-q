#include "local_transport_pairing.h"

#include <string.h>

#include "esp_attr.h"
#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"
#include "secure_random.h"
#include "transport/local_transport_identity_store.h"
#include "transport/local_transport_mbedtls_crypto.h"
#include "transport/local_transport_nimble_pairing_session.h"

namespace stopwatch_target {
namespace {

constexpr const char* kTag = "StopWatchPairing";
constexpr const char* kIdentityNamespace = "pairing_id";
constexpr const char* kIdentityPrivateKey = "static_priv";
constexpr const char* kIdentityPublicKey = "static_pub";

LocalTransportRequestHandler g_request_handler = nullptr;
bool g_event_pending = false;
signing::LocalTransportPairingEvent g_last_event =
    signing::LocalTransportPairingEvent::unavailable;
EXT_RAM_BSS_ATTR uint8_t
    g_request_line_scratch[signing::kLocalTransportGatewayRequestLineCapBytes + 1];
EXT_RAM_BSS_ATTR uint8_t
    g_plain_frame_scratch[signing::kLocalTransportMaximumPlainFrameBytes];
EXT_RAM_BSS_ATTR char
    g_response_line_scratch[signing::kLocalTransportFirmwareResponseLineCapBytes + 1];
EXT_RAM_BSS_ATTR signing::LocalTransportBleInboundFrame g_ble_inbound_frame;

bool random_bytes(uint8_t* output, size_t output_len, void*)
{
    return secure_random_fill(output, output_len);
}

const signing::LocalTransportCryptoOps& crypto_ops()
{
    static signing::LocalTransportMbedtlsCryptoContext context{
        random_bytes,
        nullptr,
    };
    static const signing::LocalTransportCryptoOps ops =
        signing::local_transport_mbedtls_crypto_ops(&context);
    return ops;
}

signing::LocalTransportIdentityRecordReadStatus read_key_pair(
    uint8_t secret_key[signing::kLocalTransportStaticKeyBytes],
    uint8_t public_key[signing::kLocalTransportStaticKeyBytes],
    void*)
{
    if (secret_key == nullptr || public_key == nullptr) {
        return signing::LocalTransportIdentityRecordReadStatus::error;
    }
    nvs_handle_t nvs = 0;
    const esp_err_t open_result = nvs_open(kIdentityNamespace, NVS_READONLY, &nvs);
    if (open_result == ESP_ERR_NVS_NOT_FOUND) {
        return signing::LocalTransportIdentityRecordReadStatus::missing;
    }
    if (open_result != ESP_OK) {
        ESP_LOGW(kTag, "identity NVS open failed: %s", esp_err_to_name(open_result));
        return signing::LocalTransportIdentityRecordReadStatus::error;
    }
    size_t secret_size = signing::kLocalTransportStaticKeyBytes;
    size_t public_size = signing::kLocalTransportStaticKeyBytes;
    const esp_err_t secret_result = nvs_get_blob(
        nvs, kIdentityPrivateKey, secret_key, &secret_size);
    const esp_err_t public_result = nvs_get_blob(
        nvs, kIdentityPublicKey, public_key, &public_size);
    nvs_close(nvs);
    if (secret_result == ESP_ERR_NVS_NOT_FOUND &&
        public_result == ESP_ERR_NVS_NOT_FOUND) {
        return signing::LocalTransportIdentityRecordReadStatus::missing;
    }
    if (secret_result != ESP_OK || public_result != ESP_OK ||
        secret_size != signing::kLocalTransportStaticKeyBytes ||
        public_size != signing::kLocalTransportStaticKeyBytes) {
        signing::local_transport_wipe_bytes(
            secret_key, signing::kLocalTransportStaticKeyBytes);
        signing::local_transport_wipe_bytes(
            public_key, signing::kLocalTransportStaticKeyBytes);
        ESP_LOGW(kTag, "identity record invalid");
        return signing::LocalTransportIdentityRecordReadStatus::error;
    }
    return signing::LocalTransportIdentityRecordReadStatus::found;
}

bool erase_key(const char* key)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kIdentityNamespace, NVS_READWRITE, &nvs);
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
        ESP_LOGW(kTag, "identity wipe incomplete");
        return false;
    }
    return true;
}

bool write_key_pair(
    const uint8_t secret_key[signing::kLocalTransportStaticKeyBytes],
    const uint8_t public_key[signing::kLocalTransportStaticKeyBytes],
    void*)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kIdentityNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "identity NVS open for write failed: %s", esp_err_to_name(result));
        return false;
    }
    result = nvs_set_blob(
        nvs,
        kIdentityPrivateKey,
        secret_key,
        signing::kLocalTransportStaticKeyBytes);
    if (result == ESP_OK) {
        result = nvs_set_blob(
            nvs,
            kIdentityPublicKey,
            public_key,
            signing::kLocalTransportStaticKeyBytes);
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "identity write failed: %s", esp_err_to_name(result));
        erase_key_pair(nullptr);
        return false;
    }
    return true;
}

const signing::LocalTransportIdentityStoreOps& identity_store_ops()
{
    static const signing::LocalTransportIdentityStoreOps ops{
        signing::LocalTransportIdentityStorageOps{
            read_key_pair,
            write_key_pair,
            erase_key_pair,
            nullptr,
        },
        &crypto_ops(),
    };
    return ops;
}

bool load_or_create_identity(signing::LocalTransportPairingIdentity* identity, void*)
{
    return signing::local_transport_identity_load_or_create(identity_store_ops(), identity);
}

bool load_identity_secret(signing::LocalTransportPairingIdentitySecret* identity, void*)
{
    return signing::local_transport_identity_load_secret(identity_store_ops(), identity);
}

void notify(signing::LocalTransportPairingEvent event, void*)
{
    g_last_event = event;
    g_event_pending = true;
}

void handle_request_line(
    const char* line,
    const signing::ProtocolTransportRoute& route,
    void*)
{
    if (g_request_handler != nullptr) {
        g_request_handler(line, route);
    }
}

signing::LocalTransportPairingSessionOps session_ops(
    LocalTransportRequestHandler handler = nullptr)
{
    g_request_handler = handler;
    return signing::local_transport_nimble_pairing_session_ops({
        &g_ble_inbound_frame,
        load_or_create_identity,
        load_identity_secret,
        notify,
        handle_request_line,
        &crypto_ops(),
        signing::LocalTransportPairingScratchBuffers{
            g_request_line_scratch,
            sizeof(g_request_line_scratch),
            g_plain_frame_scratch,
            sizeof(g_plain_frame_scratch),
            g_response_line_scratch,
            sizeof(g_response_line_scratch),
        },
        nullptr,
    });
}

}  // namespace

bool local_transport_pairing_begin(TickType_t now)
{
    g_event_pending = false;
    return signing::local_transport_pairing_session_begin(now, session_ops());
}

void local_transport_pairing_cancel()
{
    signing::local_transport_pairing_session_cancel(session_ops());
}

void local_transport_pairing_handle_display_loss()
{
    signing::local_transport_pairing_session_handle_display_loss(session_ops());
}

void local_transport_pairing_poll(TickType_t now, LocalTransportRequestHandler handler)
{
    signing::local_transport_pairing_session_poll(now, session_ops(handler));
}

signing::LocalTransportPairingSnapshot local_transport_pairing_snapshot()
{
    return signing::local_transport_pairing_session_snapshot();
}

bool local_transport_pairing_active()
{
    return signing::local_transport_pairing_session_active();
}

bool local_transport_pairing_established()
{
    return signing::local_transport_pairing_session_established();
}

bool local_transport_pairing_connected()
{
    return signing::local_transport_ble_connected();
}

bool local_transport_pairing_wipe_identity()
{
    return signing::local_transport_identity_wipe(identity_store_ops());
}

bool local_transport_pairing_take_event(signing::LocalTransportPairingEvent* event)
{
    if (!g_event_pending || event == nullptr) {
        return false;
    }
    *event = g_last_event;
    g_event_pending = false;
    return true;
}

}  // namespace stopwatch_target
