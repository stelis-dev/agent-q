#include "transport/local_transport_peer_store.h"

#include <string.h>

namespace signing {

void local_transport_peer_store_init_empty(LocalTransportPairedPeerBlob* blob)
{
    if (blob == nullptr) {
        return;
    }
    memset(blob, 0, sizeof(*blob));
    blob->version = kLocalTransportPeerStoreVersion;
    blob->count = 0;
    blob->next_seq = 1;
}

bool local_transport_peer_store_valid(const LocalTransportPairedPeerBlob& blob)
{
    return blob.version == kLocalTransportPeerStoreVersion &&
           blob.count <= kLocalTransportMaxPairedPeers &&
           blob.next_seq != 0;
}

bool local_transport_peer_store_upsert(
    LocalTransportPairedPeerBlob* blob,
    const uint8_t gateway_static_public[kLocalTransportX25519KeyBytes])
{
    if (blob == nullptr || gateway_static_public == nullptr ||
        !local_transport_peer_store_valid(*blob)) {
        return false;
    }

    for (size_t index = 0; index < blob->count; ++index) {
        if (memcmp(blob->records[index].gateway_static_public,
                   gateway_static_public,
                   kLocalTransportX25519KeyBytes) == 0) {
            blob->records[index].last_seen_seq = blob->next_seq++;
            if (blob->next_seq == 0) {
                blob->next_seq = 1;
            }
            return true;
        }
    }

    if (blob->count >= kLocalTransportMaxPairedPeers) {
        return false;
    }

    LocalTransportPairedPeerRecord& record = blob->records[blob->count++];
    memset(&record, 0, sizeof(record));
    memcpy(record.gateway_static_public, gateway_static_public, kLocalTransportX25519KeyBytes);
    record.first_paired_seq = blob->next_seq;
    record.last_seen_seq = blob->next_seq;
    ++blob->next_seq;
    if (blob->next_seq == 0) {
        blob->next_seq = 1;
    }
    return true;
}

}  // namespace signing
