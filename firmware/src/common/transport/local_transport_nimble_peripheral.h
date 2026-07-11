#pragma once

#include <stdint.h>
#include <stddef.h>

namespace signing {

constexpr size_t kLocalTransportBleMaxPayloadBytes = 524;

enum class LocalTransportBleChannel : uint8_t {
    control,
    data,
};

struct LocalTransportBleInboundFrame {
    LocalTransportBleChannel channel;
    uint16_t conn_handle;
    uint16_t att_mtu;
    size_t length;
    uint8_t payload[kLocalTransportBleMaxPayloadBytes];
};

struct LocalTransportBlePeripheralConfig {
    const char* device_name;
    LocalTransportBleInboundFrame* inbound_frame;
};

bool local_transport_ble_configure(const LocalTransportBlePeripheralConfig& config);
bool local_transport_ble_start_pairing_advertising(const uint8_t fingerprint[8]);
void local_transport_ble_stop_pairing_advertising();
void local_transport_ble_poll();
bool local_transport_ble_advertising_active();
bool local_transport_ble_connected();
void local_transport_ble_disconnect();
uint16_t local_transport_ble_current_att_mtu();
bool local_transport_ble_receive(LocalTransportBleInboundFrame* frame);
bool local_transport_ble_send_indication(
    LocalTransportBleChannel channel,
    const uint8_t* payload,
    size_t payload_len);

}  // namespace signing
