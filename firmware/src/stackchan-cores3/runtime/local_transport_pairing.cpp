#include "local_transport_pairing.h"

#include "avatar_overlay_drawing.h"
#include "esp_attr.h"
#include "local_transport_crypto_adapter.h"
#include "stackchan_keystore.h"
#include "transport/local_transport_identity_store.h"
#include "transport/local_transport_nimble_pairing_session.h"

namespace signing {
namespace {

void (*g_request_handler)(
    const char* line,
    const ProtocolTransportRoute& route) = nullptr;
EXT_RAM_BSS_ATTR uint8_t g_request_line_scratch[kLocalTransportGatewayRequestLineCapBytes + 1];
EXT_RAM_BSS_ATTR uint8_t g_plain_frame_scratch[kLocalTransportMaximumPlainFrameBytes];
EXT_RAM_BSS_ATTR char g_response_line_scratch[kLocalTransportFirmwareResponseLineCapBytes + 1];
EXT_RAM_BSS_ATTR LocalTransportBleInboundFrame g_ble_inbound_frame;

const LocalTransportIdentityStoreOps& identity_store_ops()
{
    static const LocalTransportIdentityStoreOps ops{
        stackchan_transport_identity_storage_ops(),
        &stackchan_local_transport_crypto_ops(),
    };
    return ops;
}

void notify(LocalTransportPairingEvent event, void*)
{
    switch (event) {
        case LocalTransportPairingEvent::unavailable:
            avatar_overlay_show_message("Pairing unavailable", MessageKind::error, UiMode::result, 1800);
            break;
        case LocalTransportPairingEvent::display_failed:
            avatar_overlay_show_message("Pairing display failed", MessageKind::error, UiMode::result, 1800);
            break;
        case LocalTransportPairingEvent::failed:
            avatar_overlay_show_message("Pairing failed", MessageKind::error, UiMode::result, 1800);
            break;
        case LocalTransportPairingEvent::expired:
            avatar_overlay_show_message("Pairing expired", MessageKind::timeout, UiMode::result, 1800);
            break;
        case LocalTransportPairingEvent::connected:
            avatar_overlay_show_message("Pairing connected", MessageKind::success, UiMode::result, 1200);
            break;
    }
}

void handle_request_line(
    const char* line,
    const ProtocolTransportRoute& route,
    void*)
{
    if (g_request_handler != nullptr) {
        g_request_handler(line, route);
    }
}

LocalTransportPairingSessionOps session_ops(
    void (*handle_line)(
        const char* line,
        const ProtocolTransportRoute& route) = nullptr)
{
    g_request_handler = handle_line;
    return local_transport_nimble_pairing_session_ops({
        &g_ble_inbound_frame,
        &identity_store_ops(),
        notify,
        handle_request_line,
        &stackchan_local_transport_crypto_ops(),
        {
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
    return local_transport_pairing_session_begin(now, session_ops());
}

void local_transport_pairing_cancel()
{
    local_transport_pairing_session_cancel(session_ops());
}

void local_transport_pairing_handle_display_loss()
{
    local_transport_pairing_session_handle_display_loss(session_ops());
}

void local_transport_pairing_poll(
    TickType_t now,
    void (*handle_request_line)(
        const char* line,
        const ProtocolTransportRoute& route))
{
    local_transport_pairing_session_poll(now, session_ops(handle_request_line));
}

LocalTransportPairingSnapshot local_transport_pairing_snapshot()
{
    return local_transport_pairing_session_snapshot();
}

bool local_transport_pairing_active()
{
    return local_transport_pairing_session_active();
}

bool local_transport_pairing_established()
{
    return local_transport_pairing_session_established();
}

bool local_transport_pairing_connected()
{
    return local_transport_ble_connected();
}

}  // namespace signing
