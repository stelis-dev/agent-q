#pragma once

#include <stddef.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "protocol/usb_operation_response_writer.h"
#include "transport/local_transport_crypto.h"
#include "transport/local_transport_frame.h"
#include "transport/local_transport_identity.h"
#include "transport/local_transport_optical_payload.h"
#include "transport/local_transport_profile.h"

namespace signing {

constexpr size_t kLocalTransportMaxInboundPayloadBytes = 524;

enum class LocalTransportPairingChannel : uint8_t {
    control,
    data,
};

struct LocalTransportPairingInboundFrame {
    LocalTransportPairingChannel channel;
    uint16_t att_mtu;
    size_t length;
    uint8_t payload[kLocalTransportMaxInboundPayloadBytes];
};

enum class LocalTransportPairingEvent : uint8_t {
    unavailable,
    display_failed,
    failed,
    expired,
    connected,
};

struct LocalTransportPairingSnapshot {
    bool active;
    char payload[kLocalTransportOpticalPayloadMaxBytes];
    char fingerprint_hex[kLocalTransportFingerprintHexBytes];
    TickType_t deadline;
};

struct LocalTransportPairingScratchBuffers {
    uint8_t* request_line = nullptr;
    size_t request_line_size = 0;
    uint8_t* plain_frame = nullptr;
    size_t plain_frame_size = 0;
    char* response_line = nullptr;
    size_t response_line_size = 0;
};

struct LocalTransportPairingSessionOps {
    const char* transport_kind;
    const char* endpoint_descriptor_hex;
    uint32_t optical_payload_exp_seconds;
    bool (*load_or_create_identity)(LocalTransportPairingIdentity* identity, void* context);
    bool (*load_identity_secret)(LocalTransportPairingIdentitySecret* identity, void* context);
    bool (*start_advertising)(
        const uint8_t fingerprint[kLocalTransportIdentityFingerprintBytes],
        void* context);
    void (*stop_advertising)(void* context);
    bool (*advertising_active)(void* context);
    bool (*connected)(void* context);
    void (*disconnect)(void* context);
    uint16_t (*current_att_mtu)(void* context);
    bool (*receive)(LocalTransportPairingInboundFrame* frame, void* context);
    bool (*send_acknowledged)(
        LocalTransportPairingChannel channel,
        const uint8_t* payload,
        size_t payload_len,
        void* context);
    bool (*draw_pairing_panel)(
        const char* payload,
        const char* fingerprint_hex,
        TickType_t deadline,
        void* context);
    void (*notify)(LocalTransportPairingEvent event, void* context);
    void (*handle_request_line)(
        const char* line,
        const UsbOperationResponseWriter& writer,
        void* context);
    const LocalTransportCryptoOps* crypto_ops;
    LocalTransportPairingScratchBuffers scratch;
    void* context;
};

using LocalTransportPairingResponseCallback =
    bool (*)(const UsbOperationResponseWriter& writer, void* context);

bool local_transport_pairing_session_begin(
    TickType_t now,
    const LocalTransportPairingSessionOps& ops);
void local_transport_pairing_session_cancel(const LocalTransportPairingSessionOps& ops);
void local_transport_pairing_session_handle_display_loss(
    const LocalTransportPairingSessionOps& ops);
void local_transport_pairing_session_poll(
    TickType_t now,
    const LocalTransportPairingSessionOps& ops);
LocalTransportPairingSnapshot local_transport_pairing_session_snapshot();
bool local_transport_pairing_session_active();
bool local_transport_pairing_session_established();
bool local_transport_pairing_session_write_line(
    const LocalTransportPairingSessionOps& ops,
    const char* line,
    size_t line_len);
bool local_transport_pairing_session_write_response(
    const LocalTransportPairingSessionOps& ops,
    LocalTransportPairingResponseCallback callback,
    void* context);

}  // namespace signing
