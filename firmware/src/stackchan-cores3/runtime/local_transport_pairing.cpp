#include "local_transport_pairing.h"

#include <string.h>

#include "avatar_overlay_drawing.h"
#include "esp_attr.h"
#include "local_transport_ble.h"
#include "local_transport_crypto_adapter.h"
#include "local_transport_pairing_store.h"
#include "modal_drawing.h"
#include "transport/timeout_window.h"

namespace signing {
namespace {

void (*g_request_handler)(const char* line, const UsbOperationResponseWriter& writer) = nullptr;
EXT_RAM_BSS_ATTR uint8_t g_request_line_scratch[kLocalTransportGatewayRequestLineCapBytes + 1];
EXT_RAM_BSS_ATTR uint8_t g_plain_frame_scratch[kLocalTransportMaximumPlainFrameBytes];
EXT_RAM_BSS_ATTR char g_response_line_scratch[kLocalTransportFirmwareResponseLineCapBytes + 1];

LocalTransportPairingChannel to_pairing_channel(LocalTransportBleChannel channel)
{
    switch (channel) {
        case LocalTransportBleChannel::control:
            return LocalTransportPairingChannel::control;
        case LocalTransportBleChannel::data:
            return LocalTransportPairingChannel::data;
    }
    return LocalTransportPairingChannel::data;
}

LocalTransportBleChannel to_ble_channel(LocalTransportPairingChannel channel)
{
    switch (channel) {
        case LocalTransportPairingChannel::control:
            return LocalTransportBleChannel::control;
        case LocalTransportPairingChannel::data:
            return LocalTransportBleChannel::data;
    }
    return LocalTransportBleChannel::data;
}

bool load_or_create_identity_secret(LocalTransportPairingIdentitySecret* identity, void*)
{
    return local_transport_load_or_create_pairing_identity_secret(identity);
}

bool store_paired_peer(
    const uint8_t gateway_static_public[kLocalTransportStaticKeyBytes],
    void*)
{
    return local_transport_store_paired_peer(gateway_static_public);
}

bool start_advertising(
    const uint8_t fingerprint[kLocalTransportIdentityFingerprintBytes],
    void*)
{
    return local_transport_ble_start_pairing_advertising(fingerprint);
}

void stop_advertising(void*)
{
    local_transport_ble_stop_pairing_advertising();
}

bool advertising_active(void*)
{
    return local_transport_ble_advertising_active();
}

bool connected(void*)
{
    return local_transport_ble_connected();
}

uint16_t current_att_mtu(void*)
{
    return local_transport_ble_current_att_mtu();
}

bool receive(LocalTransportPairingInboundFrame* frame, void*)
{
    if (frame == nullptr) {
        return false;
    }
    LocalTransportBleInboundFrame ble_frame = {};
    if (!local_transport_ble_receive(&ble_frame)) {
        return false;
    }
    frame->channel = to_pairing_channel(ble_frame.channel);
    frame->att_mtu = ble_frame.att_mtu;
    frame->length = ble_frame.length;
    if (ble_frame.length > sizeof(frame->payload)) {
        return false;
    }
    memcpy(frame->payload, ble_frame.payload, ble_frame.length);
    local_transport_wipe_bytes(ble_frame.payload, sizeof(ble_frame.payload));
    return true;
}

bool send(
    LocalTransportPairingChannel channel,
    const uint8_t* payload,
    size_t payload_len,
    void*)
{
    return local_transport_ble_send_indication(
        to_ble_channel(channel),
        payload,
        payload_len);
}

bool draw_pairing_panel(
    const char* payload,
    const char* fingerprint_hex,
    TickType_t deadline,
    void*)
{
    const TimeoutWindow window =
        timeout_window_from_deadline(xTaskGetTickCount(), deadline);
    return modal_draw_local_transport_pairing_panel(payload, fingerprint_hex, window);
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
        case LocalTransportPairingEvent::store_full:
            avatar_overlay_show_message("Pairing store full", MessageKind::error, UiMode::result, 1800);
            break;
        case LocalTransportPairingEvent::connected:
            avatar_overlay_show_message("Pairing connected", MessageKind::success, UiMode::result, 1200);
            break;
    }
}

void handle_request_line(
    const char* line,
    const UsbOperationResponseWriter& writer,
    void*)
{
    if (g_request_handler != nullptr) {
        g_request_handler(line, writer);
    }
}

LocalTransportPairingSessionOps session_ops(
    void (*handle_line)(const char* line, const UsbOperationResponseWriter& writer) = nullptr)
{
    g_request_handler = handle_line;
    return {
        kLocalTransportKindBle,
        kLocalTransportBleServiceUuidHex,
        kLocalTransportPairingAdvertiseMs / 1000,
        load_or_create_identity_secret,
        store_paired_peer,
        start_advertising,
        stop_advertising,
        advertising_active,
        connected,
        current_att_mtu,
        receive,
        send,
        draw_pairing_panel,
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
    };
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

void local_transport_pairing_poll(
    TickType_t now,
    void (*handle_request_line)(const char* line, const UsbOperationResponseWriter& writer))
{
    local_transport_pairing_session_poll(now, session_ops(handle_request_line));
}

bool local_transport_pairing_expired(TickType_t now)
{
    return local_transport_pairing_session_expired(now);
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

bool local_transport_pairing_write_response(
    LocalTransportPairingResponseCallback callback,
    void* context)
{
    return local_transport_pairing_session_write_response(
        session_ops(),
        callback,
        context);
}

}  // namespace signing
