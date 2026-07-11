#pragma once

#include "transport/local_transport_pairing_session.h"

namespace stopwatch_target {

using LocalTransportRequestHandler = void (*)(
    const char* line,
    const signing::ProtocolTransportRoute& route);

bool local_transport_pairing_begin(TickType_t now);
void local_transport_pairing_cancel();
void local_transport_pairing_handle_display_loss();
void local_transport_pairing_poll(TickType_t now, LocalTransportRequestHandler handler);
signing::LocalTransportPairingSnapshot local_transport_pairing_snapshot();
bool local_transport_pairing_active();
bool local_transport_pairing_established();
bool local_transport_pairing_connected();
bool local_transport_pairing_take_event(signing::LocalTransportPairingEvent* event);

}  // namespace stopwatch_target
