#include "transport/local_transport_identity_store.h"

#include <string.h>

namespace signing {
namespace {

bool ops_valid(const LocalTransportIdentityStoreOps& ops)
{
    return ops.storage.read_public_key != nullptr &&
           ops.storage.read_key_pair != nullptr &&
           ops.storage.write_key_pair != nullptr &&
           ops.storage.erase_key_pair != nullptr &&
           ops.crypto != nullptr &&
           local_transport_crypto_ops_valid(*ops.crypto);
}

bool compute_fingerprint(
    const LocalTransportCryptoOps& crypto,
    const uint8_t public_key[kLocalTransportStaticKeyBytes],
    uint8_t fingerprint[kLocalTransportIdentityFingerprintBytes]);

LocalTransportIdentityRecordReadStatus read_public_identity(
    const LocalTransportIdentityStoreOps& ops,
    LocalTransportPairingIdentity* identity)
{
    if (identity == nullptr) {
        return LocalTransportIdentityRecordReadStatus::error;
    }
    local_transport_wipe_bytes(
        reinterpret_cast<uint8_t*>(identity),
        sizeof(*identity));
    if (!ops_valid(ops)) {
        return LocalTransportIdentityRecordReadStatus::error;
    }

    const LocalTransportIdentityRecordReadStatus status =
        ops.storage.read_public_key(
            identity->public_key,
            ops.storage.context);
    if (status != LocalTransportIdentityRecordReadStatus::found) {
        local_transport_wipe_bytes(
            reinterpret_cast<uint8_t*>(identity),
            sizeof(*identity));
        return status;
    }
    if (!compute_fingerprint(
            *ops.crypto,
            identity->public_key,
            identity->fingerprint)) {
        local_transport_wipe_bytes(
            reinterpret_cast<uint8_t*>(identity),
            sizeof(*identity));
        return LocalTransportIdentityRecordReadStatus::error;
    }
    return LocalTransportIdentityRecordReadStatus::found;
}

bool compute_fingerprint(
    const LocalTransportCryptoOps& crypto,
    const uint8_t public_key[kLocalTransportStaticKeyBytes],
    uint8_t fingerprint[kLocalTransportIdentityFingerprintBytes])
{
    uint8_t digest[kLocalTransportCryptoHashBytes] = {};
    const LocalTransportCryptoBuffer part{public_key, kLocalTransportStaticKeyBytes};
    const bool ok = crypto.sha256(
        &part,
        1,
        digest,
        crypto.context);
    if (ok) {
        memcpy(fingerprint, digest, kLocalTransportIdentityFingerprintBytes);
    } else {
        memset(fingerprint, 0, kLocalTransportIdentityFingerprintBytes);
    }
    local_transport_wipe_bytes(digest, sizeof(digest));
    return ok;
}

LocalTransportIdentityRecordReadStatus read_validated_identity(
    const LocalTransportIdentityStoreOps& ops,
    LocalTransportPairingIdentitySecret* identity)
{
    if (identity == nullptr) {
        return LocalTransportIdentityRecordReadStatus::error;
    }
    local_transport_wipe_bytes(
        reinterpret_cast<uint8_t*>(identity),
        sizeof(*identity));
    if (!ops_valid(ops)) {
        return LocalTransportIdentityRecordReadStatus::error;
    }

    const LocalTransportIdentityRecordReadStatus status =
        ops.storage.read_key_pair(
            identity->secret_key,
            identity->public_key,
            ops.storage.context);
    if (status != LocalTransportIdentityRecordReadStatus::found) {
        local_transport_wipe_bytes(
            reinterpret_cast<uint8_t*>(identity),
            sizeof(*identity));
        return status;
    }

    uint8_t derived_public[kLocalTransportStaticKeyBytes] = {};
    const bool valid = ops.crypto->x25519_public_key(
                           derived_public,
                           identity->secret_key,
                           ops.crypto->context) &&
                       memcmp(
                           derived_public,
                           identity->public_key,
                           sizeof(derived_public)) == 0 &&
                       compute_fingerprint(
                           *ops.crypto,
                           identity->public_key,
                           identity->fingerprint);
    local_transport_wipe_bytes(derived_public, sizeof(derived_public));
    if (!valid) {
        local_transport_wipe_bytes(
            reinterpret_cast<uint8_t*>(identity),
            sizeof(*identity));
        return LocalTransportIdentityRecordReadStatus::error;
    }
    return LocalTransportIdentityRecordReadStatus::found;
}

}  // namespace

bool local_transport_identity_load_or_create(
    const LocalTransportIdentityStoreOps& ops,
    LocalTransportPairingIdentity* identity)
{
    if (identity == nullptr) {
        return false;
    }
    local_transport_wipe_bytes(
        reinterpret_cast<uint8_t*>(identity),
        sizeof(*identity));
    if (!ops_valid(ops)) {
        return false;
    }

    LocalTransportPairingIdentity stored = {};
    const LocalTransportIdentityRecordReadStatus status =
        read_public_identity(ops, &stored);
    if (status == LocalTransportIdentityRecordReadStatus::found) {
        memcpy(identity->public_key, stored.public_key, sizeof(identity->public_key));
        memcpy(identity->fingerprint, stored.fingerprint, sizeof(identity->fingerprint));
        local_transport_wipe_bytes(reinterpret_cast<uint8_t*>(&stored), sizeof(stored));
        return true;
    }
    local_transport_wipe_bytes(reinterpret_cast<uint8_t*>(&stored), sizeof(stored));
    if (status != LocalTransportIdentityRecordReadStatus::missing) {
        return false;
    }

    uint8_t secret_key[kLocalTransportStaticKeyBytes] = {};
    uint8_t public_key[kLocalTransportStaticKeyBytes] = {};
    const bool generated =
        ops.crypto->random_bytes(
            secret_key,
            sizeof(secret_key),
            ops.crypto->context) &&
        ops.crypto->x25519_public_key(
            public_key,
            secret_key,
            ops.crypto->context);
    if (!generated) {
        local_transport_wipe_bytes(secret_key, sizeof(secret_key));
        local_transport_wipe_bytes(public_key, sizeof(public_key));
        return false;
    }

    memcpy(identity->public_key, public_key, sizeof(identity->public_key));
    const bool fingerprinted = compute_fingerprint(
        *ops.crypto,
        identity->public_key,
        identity->fingerprint);
    const bool stored_pair = fingerprinted &&
        ops.storage.write_key_pair(
            secret_key,
            public_key,
            ops.storage.context);
    local_transport_wipe_bytes(secret_key, sizeof(secret_key));
    local_transport_wipe_bytes(public_key, sizeof(public_key));
    if (!stored_pair) {
        memset(identity, 0, sizeof(*identity));
        return false;
    }
    return true;
}

bool local_transport_identity_load_secret(
    const LocalTransportIdentityStoreOps& ops,
    LocalTransportPairingIdentitySecret* identity)
{
    return read_validated_identity(ops, identity) ==
           LocalTransportIdentityRecordReadStatus::found;
}

bool local_transport_identity_wipe(const LocalTransportIdentityStoreOps& ops)
{
    return ops.storage.erase_key_pair != nullptr &&
           ops.storage.erase_key_pair(ops.storage.context);
}

}  // namespace signing
