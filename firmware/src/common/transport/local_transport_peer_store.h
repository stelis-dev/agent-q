#pragma once

#include <stddef.h>
#include <stdint.h>

#include "transport/local_transport_identity.h"

namespace signing {

constexpr uint8_t kLocalTransportPeerStoreVersion = 1;
constexpr size_t kLocalTransportMaxPairedPeers = 4;
constexpr size_t kLocalTransportPeerLabelBytes = 32;

struct LocalTransportPairedPeerRecord {
    uint8_t gateway_static_public[kLocalTransportStaticKeyBytes];
    uint8_t label_len;
    uint8_t label[kLocalTransportPeerLabelBytes];
    uint32_t first_paired_seq;
    uint32_t last_seen_seq;
};

struct LocalTransportPairedPeerBlob {
    uint8_t version;
    uint8_t count;
    uint16_t reserved;
    uint32_t next_seq;
    LocalTransportPairedPeerRecord records[kLocalTransportMaxPairedPeers];
};

void local_transport_peer_store_init_empty(LocalTransportPairedPeerBlob* blob);
bool local_transport_peer_store_valid(const LocalTransportPairedPeerBlob& blob);
bool local_transport_peer_store_upsert(
    LocalTransportPairedPeerBlob* blob,
    const uint8_t gateway_static_public[kLocalTransportStaticKeyBytes]);

}  // namespace signing
