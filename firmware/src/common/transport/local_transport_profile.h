#pragma once

#include <stdint.h>

namespace signing {

constexpr uint32_t kLocalTransportPairingAdvertiseMs = 120000;
constexpr uint32_t kLocalTransportPairingHandshakeMs = 10000;
constexpr uint32_t kLocalTransportRequestReassemblyMs = 8000;
constexpr uint32_t kLocalTransportResponseMs = 185000;
constexpr uint32_t kLocalTransportCarrierAckTimeoutMs = 5000;
constexpr uint8_t kLocalTransportHandshakeReadySignal = 0x01;

}  // namespace signing
