#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <assert.h>
#include <string.h>

#include "transport/local_transport_identity_store.h"

using namespace signing;

namespace {

struct Store {
    LocalTransportIdentityRecordReadStatus status =
        LocalTransportIdentityRecordReadStatus::missing;
    uint8_t secret[kLocalTransportStaticKeyBytes] = {};
    uint8_t public_key[kLocalTransportStaticKeyBytes] = {};
    int public_reads = 0;
    int pair_reads = 0;
    int writes = 0;
    int erases = 0;
};

int random_calls = 0;

bool all_zero(const uint8_t* bytes, size_t size)
{
    for (size_t index = 0; index < size; ++index) {
        if (bytes[index] != 0) {
            return false;
        }
    }
    return true;
}

bool random_bytes(uint8_t* output, size_t size, void*)
{
    ++random_calls;
    for (size_t i = 0; i < size; ++i) {
        output[i] = static_cast<uint8_t>(i + 1);
    }
    return true;
}

bool public_key(uint8_t* output, const uint8_t* secret, void*)
{
    for (size_t i = 0; i < kLocalTransportCryptoKeyBytes; ++i) {
        output[i] = static_cast<uint8_t>(secret[i] ^ 0xA5U);
    }
    return true;
}

bool shared_secret(uint8_t*, const uint8_t*, const uint8_t*, void*) { return true; }

bool sha256(
    const LocalTransportCryptoBuffer* parts,
    size_t count,
    uint8_t output[kLocalTransportCryptoHashBytes],
    void*)
{
    if (parts == nullptr || count != 1 || parts[0].length != kLocalTransportStaticKeyBytes) {
        return false;
    }
    memcpy(output, parts[0].data, kLocalTransportCryptoHashBytes);
    return true;
}

bool hmac(
    const uint8_t*, size_t, const LocalTransportCryptoBuffer*, size_t,
    uint8_t[kLocalTransportCryptoHashBytes], void*) { return true; }
bool encrypt(
    const uint8_t*, const uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t,
    uint8_t*, uint8_t*, void*) { return true; }
bool decrypt(
    const uint8_t*, const uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t,
    const uint8_t*, uint8_t*, void*) { return true; }

LocalTransportIdentityRecordReadStatus with_pair(
    LocalTransportStoredKeyPairConsumer consumer,
    void* consumer_context,
    void* storage_context)
{
    Store* store = static_cast<Store*>(storage_context);
    ++store->pair_reads;
    if (store->status != LocalTransportIdentityRecordReadStatus::found) {
        return store->status;
    }
    return consumer != nullptr &&
                   consumer(store->secret, store->public_key, consumer_context)
               ? LocalTransportIdentityRecordReadStatus::found
               : LocalTransportIdentityRecordReadStatus::error;
}

LocalTransportIdentityRecordReadStatus read_public(
    uint8_t* public_value,
    void* context)
{
    Store* store = static_cast<Store*>(context);
    ++store->public_reads;
    memset(public_value, 0, kLocalTransportStaticKeyBytes);
    if (store->status == LocalTransportIdentityRecordReadStatus::found) {
        memcpy(public_value, store->public_key, sizeof(store->public_key));
    }
    return store->status;
}

bool write_pair(const uint8_t* secret, const uint8_t* public_value, void* context)
{
    Store* store = static_cast<Store*>(context);
    ++store->writes;
    memcpy(store->secret, secret, sizeof(store->secret));
    memcpy(store->public_key, public_value, sizeof(store->public_key));
    store->status = LocalTransportIdentityRecordReadStatus::found;
    return true;
}

bool erase_pair(void* context)
{
    Store* store = static_cast<Store*>(context);
    ++store->erases;
    memset(store->secret, 0, sizeof(store->secret));
    memset(store->public_key, 0, sizeof(store->public_key));
    store->status = LocalTransportIdentityRecordReadStatus::missing;
    return true;
}

LocalTransportIdentityStoreOps make_ops(Store* store)
{
    static const LocalTransportCryptoOps crypto{
        random_bytes,
        public_key,
        shared_secret,
        sha256,
        hmac,
        encrypt,
        decrypt,
        nullptr,
    };
    return LocalTransportIdentityStoreOps{
        LocalTransportIdentityStorageOps{
            read_public,
            with_pair,
            write_pair,
            erase_pair,
            store,
        },
        &crypto,
    };
}

struct SecretObservation {
    bool called = false;
    uint8_t secret[kLocalTransportStaticKeyBytes] = {};
};

bool observe_secret(
    const uint8_t* secret,
    const uint8_t*,
    const uint8_t*,
    void* context)
{
    auto* observation = static_cast<SecretObservation*>(context);
    if (observation == nullptr || secret == nullptr) {
        return false;
    }
    observation->called = true;
    memcpy(observation->secret, secret, sizeof(observation->secret));
    return true;
}

}  // namespace

int main()
{
    Store store;
    const LocalTransportIdentityStoreOps ops = make_ops(&store);
    LocalTransportPairingIdentity identity = {};
    assert(local_transport_identity_load_or_create(ops, &identity));
    assert(store.public_reads == 1 && store.pair_reads == 0);
    assert(store.writes == 1 && random_calls == 1);
    assert(memcmp(identity.public_key, store.public_key, sizeof(identity.public_key)) == 0);
    assert(memcmp(identity.fingerprint, store.public_key, sizeof(identity.fingerprint)) == 0);

    LocalTransportPairingIdentity second = {};
    assert(local_transport_identity_load_or_create(ops, &second));
    assert(store.public_reads == 2 && store.pair_reads == 0);
    assert(store.writes == 1 && random_calls == 1);
    assert(memcmp(&identity, &second, sizeof(identity)) == 0);

    SecretObservation secret = {};
    assert(local_transport_identity_with_secret(ops, observe_secret, &secret));
    assert(store.pair_reads == 1);
    assert(secret.called);
    assert(memcmp(secret.secret, store.secret, sizeof(secret.secret)) == 0);

    store.public_key[0] ^= 1U;
    LocalTransportPairingIdentity projected = {};
    assert(local_transport_identity_load_or_create(ops, &projected));
    assert(store.public_reads == 3 && store.pair_reads == 1);
    secret = {};
    assert(!local_transport_identity_with_secret(ops, observe_secret, &secret));
    assert(store.pair_reads == 2);
    assert(!secret.called);
    assert(store.writes == 1 && random_calls == 1);

    LocalTransportIdentityStoreOps invalid_ops = {};
    memset(&projected, 0xa5, sizeof(projected));
    assert(!local_transport_identity_load_or_create(invalid_ops, &projected));
    assert(all_zero(reinterpret_cast<const uint8_t*>(&projected), sizeof(projected)));
    secret = {};
    assert(!local_transport_identity_with_secret(
        invalid_ops, observe_secret, &secret));
    assert(!secret.called);

    LocalTransportIdentityStoreOps wipe_only = {};
    wipe_only.storage.erase_key_pair = erase_pair;
    wipe_only.storage.context = &store;
    assert(local_transport_identity_wipe(wipe_only));
    assert(store.erases == 1);
    return 0;
}
CPP

${CXX:-c++} -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_ROOT}/transport/local_transport_crypto.cpp" \
  "${COMMON_ROOT}/transport/local_transport_identity_store.cpp" \
  -o "${TMP_DIR}/test"
"${TMP_DIR}/test"
echo "local transport identity store tests passed"
