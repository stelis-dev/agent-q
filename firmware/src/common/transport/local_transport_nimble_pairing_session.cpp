#include "transport/local_transport_nimble_pairing_session.h"

#include <string.h>

#include "transport/local_transport_profile.h"

namespace signing {
namespace {

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

void poll_carrier(void*)
{
    local_transport_ble_poll();
}

bool advertising_active(void*)
{
    return local_transport_ble_advertising_active();
}

bool connected(void*)
{
    return local_transport_ble_connected();
}

void disconnect(void*)
{
    local_transport_ble_disconnect();
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
    if (ble_frame.length > sizeof(frame->payload)) {
        local_transport_wipe_bytes(ble_frame.payload, sizeof(ble_frame.payload));
        return false;
    }
    frame->channel = to_pairing_channel(ble_frame.channel);
    frame->att_mtu = ble_frame.att_mtu;
    frame->length = ble_frame.length;
    memcpy(frame->payload, ble_frame.payload, ble_frame.length);
    local_transport_wipe_bytes(ble_frame.payload, sizeof(ble_frame.payload));
    return true;
}

bool send_acknowledged(
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

}  // namespace

LocalTransportPairingSessionOps local_transport_nimble_pairing_session_ops(
    const LocalTransportNimblePairingSessionConfig& config)
{
    const LocalTransportBlePeripheralConfig peripheral_config{
        kLocalTransportBleDeviceName,
        config.inbound_frame,
    };
    if (!local_transport_ble_configure(peripheral_config)) {
        return {};
    }
    return LocalTransportPairingSessionOps{
        kLocalTransportKindBle,
        kLocalTransportBleServiceUuidHex,
        kLocalTransportPairingAdvertiseMs / 1000,
        config.identity_store,
        start_advertising,
        stop_advertising,
        poll_carrier,
        advertising_active,
        connected,
        disconnect,
        current_att_mtu,
        receive,
        send_acknowledged,
        config.notify,
        config.handle_request_line,
        config.crypto_ops,
        config.scratch,
        config.context,
    };
}

}  // namespace signing
