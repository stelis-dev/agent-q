#pragma once

#include "freertos/FreeRTOS.h"
#include "protocol/protocol_transport.h"
#include "transport/local_transport_pairing_session.h"

namespace signing {

bool local_transport_pairing_begin(TickType_t now);
void local_transport_pairing_cancel();
void local_transport_pairing_handle_display_loss();
void local_transport_pairing_poll(
    TickType_t now,
    void (*handle_request_line)(
        const char* line,
        const ProtocolTransportRoute& route));
LocalTransportPairingSnapshot local_transport_pairing_snapshot();
bool local_transport_pairing_active();
bool local_transport_pairing_established();
bool local_transport_pairing_connected();

}  // namespace signing
