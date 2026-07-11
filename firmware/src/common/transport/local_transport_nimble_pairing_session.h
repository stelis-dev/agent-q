#pragma once

#include "transport/local_transport_nimble_peripheral.h"
#include "transport/local_transport_pairing_session.h"

namespace signing {

struct LocalTransportNimblePairingSessionConfig {
    LocalTransportBleInboundFrame* inbound_frame;
    const LocalTransportIdentityStoreOps* identity_store;
    void (*notify)(LocalTransportPairingEvent event, void* context);
    void (*handle_request_line)(
        const char* line,
        const ProtocolTransportRoute& route,
        void* context);
    const LocalTransportCryptoOps* crypto_ops;
    LocalTransportPairingScratchBuffers scratch;
    void* context;
};

LocalTransportPairingSessionOps local_transport_nimble_pairing_session_ops(
    const LocalTransportNimblePairingSessionConfig& config);

}  // namespace signing
