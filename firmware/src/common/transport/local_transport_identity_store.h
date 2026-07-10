#pragma once

#include "transport/local_transport_crypto.h"
#include "transport/local_transport_identity.h"

namespace signing {

enum class LocalTransportIdentityRecordReadStatus {
    missing,
    found,
    error,
};

struct LocalTransportIdentityStorageOps {
    LocalTransportIdentityRecordReadStatus (*read_key_pair)(
        uint8_t secret_key[kLocalTransportStaticKeyBytes],
        uint8_t public_key[kLocalTransportStaticKeyBytes],
        void* context);
    bool (*write_key_pair)(
        const uint8_t secret_key[kLocalTransportStaticKeyBytes],
        const uint8_t public_key[kLocalTransportStaticKeyBytes],
        void* context);
    bool (*erase_key_pair)(void* context);
    void* context;
};

struct LocalTransportIdentityStoreOps {
    LocalTransportIdentityStorageOps storage;
    const LocalTransportCryptoOps* crypto;
};

bool local_transport_identity_load_or_create(
    const LocalTransportIdentityStoreOps& ops,
    LocalTransportPairingIdentity* identity);
bool local_transport_identity_load_secret(
    const LocalTransportIdentityStoreOps& ops,
    LocalTransportPairingIdentitySecret* identity);
bool local_transport_identity_wipe(const LocalTransportIdentityStoreOps& ops);

}  // namespace signing
