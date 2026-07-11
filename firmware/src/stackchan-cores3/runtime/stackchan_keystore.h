#pragma once

#include <stddef.h>
#include <stdint.h>

#include "bip39.h"
#include "keystore/encrypted_keystore.h"
#include "pin_policy.h"
#include "transport/local_transport_identity_store.h"

namespace signing {

constexpr size_t kStackChanRootMaterialBytes = kBip39EntropyBytes;
constexpr KeystoreKdfProfile kStackChanKeystoreKdfProfile{512, 6, 1};
constexpr size_t kStackChanKeystoreKdfWorkAreaBytes =
    kStackChanKeystoreKdfProfile.memory_kib * 1024u;

enum class StackChanKeystoreMaterialStatus {
    missing,
    active,
    busy,
    invalid,
    storage_error,
};

KeystoreState stackchan_keystore_initialize();
KeystoreState stackchan_keystore_state();
StackChanKeystoreMaterialStatus stackchan_keystore_status();
StackChanKeystoreMaterialStatus stackchan_keystore_root_status();

KeystoreOperationStatus stackchan_keystore_create(
    char pin[kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size);
KeystoreOperationStatus stackchan_keystore_unlock(
    char pin[kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size);
KeystoreOperationStatus stackchan_keystore_authenticate_pin(
    char pin[kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size);
KeystoreOperationStatus stackchan_keystore_rewrap(
    char current_pin[kKeystorePinBufferBytes],
    char new_pin[kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size);

KeystoreOperationStatus stackchan_keystore_with_root(
    KeystoreRecordConsumer consumer,
    void* consumer_context);
KeystoreOperationStatus stackchan_keystore_replace_root(
    const uint8_t root[kStackChanRootMaterialBytes]);

const LocalTransportIdentityStorageOps&
stackchan_transport_identity_storage_ops();

KeystoreOperationStatus stackchan_keystore_erase();

}  // namespace signing
