#pragma once

#include "transport/local_transport_crypto.h"
#include "transport/local_transport_identity.h"

namespace signing {

enum class LocalTransportIdentityRecordReadStatus {
    missing,
    found,
    error,
};

using LocalTransportStoredKeyPairConsumer = bool (*)(
    const uint8_t secret_key[kLocalTransportStaticKeyBytes],
    const uint8_t public_key[kLocalTransportStaticKeyBytes],
    void* context);

using LocalTransportIdentitySecretConsumer = bool (*)(
    const uint8_t secret_key[kLocalTransportStaticKeyBytes],
    const uint8_t public_key[kLocalTransportStaticKeyBytes],
    const uint8_t fingerprint[kLocalTransportIdentityFingerprintBytes],
    void* context);

struct LocalTransportIdentityStorageOps {
    // Returns only the public key to the caller. A storage backend may still
    // authenticate and decrypt a bounded key-pair record into wiped scratch.
    LocalTransportIdentityRecordReadStatus (*read_public_key)(
        uint8_t public_key[kLocalTransportStaticKeyBytes],
        void* context);
    LocalTransportIdentityRecordReadStatus (*with_key_pair)(
        LocalTransportStoredKeyPairConsumer consumer,
        void* consumer_context,
        void* storage_context);
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
bool local_transport_identity_with_secret(
    const LocalTransportIdentityStoreOps& ops,
    LocalTransportIdentitySecretConsumer consumer,
    void* consumer_context);
bool local_transport_identity_wipe(const LocalTransportIdentityStoreOps& ops);

}  // namespace signing
