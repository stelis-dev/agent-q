#include "local_transport_pairing.h"

#include "esp_attr.h"
#include "secure_random.h"
#include "transport/local_transport_identity_store.h"
#include "transport/local_transport_mbedtls_crypto.h"
#include "transport/local_transport_nimble_pairing_session.h"
#include "transport/local_transport_nvs_identity_storage.h"

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

const signing::LocalTransportIdentityStorageOps& identity_storage_ops()
{
    static const signing::LocalTransportNvsIdentityStorageConfig config{
        kIdentityNamespace,
        kIdentityPrivateKey,
        kIdentityPublicKey,
        kTag,
    };
    static const signing::LocalTransportIdentityStorageOps ops =
        signing::local_transport_nvs_identity_storage_ops(&config);
    return ops;
}

const signing::LocalTransportIdentityStoreOps& identity_store_ops()
{
    static const signing::LocalTransportIdentityStoreOps ops{
        identity_storage_ops(),
        &crypto_ops(),
    };
    return ops;
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
        &identity_store_ops(),
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
