#pragma once

#include <stddef.h>
#include <stdint.h>

#include "keystore/encrypted_keystore.h"
#include "pin_policy.h"
#include "transport/local_transport_identity_store.h"

namespace stopwatch_target {

constexpr signing::KeystoreKdfProfile kStopWatchKeystoreKdfProfile{512, 5, 1};
constexpr size_t kStopWatchKeystoreKdfWorkAreaBytes =
    kStopWatchKeystoreKdfProfile.memory_kib * 1024u;
constexpr size_t kStopWatchCredentialPlaintextMaxBytes = 4096;

signing::KeystoreState stopwatch_keystore_initialize();
signing::KeystoreState stopwatch_keystore_state();
bool stopwatch_keystore_storage_consistent();

signing::KeystoreOperationStatus stopwatch_keystore_create(
    char pin[signing::kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size);
signing::KeystoreOperationStatus stopwatch_keystore_unlock(
    char pin[signing::kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size);
signing::KeystoreOperationStatus stopwatch_keystore_authenticate_pin(
    char pin[signing::kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size);
signing::KeystoreOperationStatus stopwatch_keystore_lock();

signing::KeystoreOperationStatus stopwatch_keystore_credential_status();
signing::KeystoreOperationStatus stopwatch_keystore_with_credential(
    signing::KeystoreRecordConsumer consumer,
    void* consumer_context);
signing::KeystoreOperationStatus stopwatch_keystore_replace_credential(
    const uint8_t* plaintext,
    size_t plaintext_size);

bool stopwatch_keystore_transport_identity_valid_or_missing();
const signing::LocalTransportIdentityStorageOps&
stopwatch_transport_identity_storage_ops();

signing::KeystoreOperationStatus stopwatch_keystore_erase();

}  // namespace stopwatch_target
