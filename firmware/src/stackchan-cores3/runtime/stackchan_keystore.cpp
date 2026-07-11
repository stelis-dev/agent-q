#include "stackchan_keystore.h"

#include <string.h>

#include "entropy.h"
#include "keystore/encrypted_keystore_nvs.h"
#include "stackchan_storage_names.h"

namespace signing {
namespace {

constexpr uint8_t kTargetLabel[] = "stackchan-cores3";
constexpr uint8_t kRootRecordId[] = "root";
constexpr uint8_t kTransportIdentityRecordId[] = "transport_identity";
constexpr size_t kTransportIdentityBytes = 2 * kLocalTransportStaticKeyBytes;
constexpr const char* kKeyslotStorageKey = "keyslot";
constexpr const char* kRootStorageKey = "root";
constexpr const char* kTransportIdentityStorageKey = "transport_id";

constexpr KeystoreRecord kRootRecord{
    kRootStorageKey,
    kRootRecordId,
    sizeof(kRootRecordId) - 1,
    kStackChanRootMaterialBytes,
};
constexpr KeystoreRecord kTransportIdentityRecord{
    kTransportIdentityStorageKey,
    kTransportIdentityRecordId,
    sizeof(kTransportIdentityRecordId) - 1,
    kTransportIdentityBytes,
};

EncryptedKeystore g_keystore;

bool fill_random(uint8_t* output, size_t output_size, void*)
{
    return fill_secure_random(output, output_size);
}

const EncryptedKeystoreConfig& keystore_config()
{
    static const EncryptedKeystoreNvsConfig nvs_config{
        kStackChanSigningKeyMaterialNvsNamespace,
        "StackChanKeystore",
    };
    static const EncryptedKeystoreConfig config{
        kTargetLabel,
        sizeof(kTargetLabel) - 1,
        kKeyslotStorageKey,
        kStackChanKeystoreKdfProfile,
        encrypted_keystore_nvs_storage_ops(&nvs_config),
        {fill_random, nullptr},
    };
    return config;
}

template <size_t PlaintextBytes>
struct RecordScratch {
    static constexpr size_t kBlobBytes =
        kKeystoreRecordOverheadBytes + PlaintextBytes;
    uint8_t previous[kBlobBytes] = {};
    uint8_t candidate[kBlobBytes] = {};
    uint8_t readback[kBlobBytes] = {};
    uint8_t plaintext[PlaintextBytes] = {};

    KeystoreRecordScratch view()
    {
        return {
            previous,
            candidate,
            readback,
            sizeof(previous),
            plaintext,
            sizeof(plaintext),
        };
    }
};

StackChanKeystoreMaterialStatus material_status_from_operation(
    KeystoreOperationStatus status)
{
    switch (status) {
        case KeystoreOperationStatus::success:
            return StackChanKeystoreMaterialStatus::active;
        case KeystoreOperationStatus::missing:
            return StackChanKeystoreMaterialStatus::missing;
        case KeystoreOperationStatus::busy:
            return StackChanKeystoreMaterialStatus::busy;
        case KeystoreOperationStatus::invalid_record:
        case KeystoreOperationStatus::invalid_input:
            return StackChanKeystoreMaterialStatus::invalid;
        case KeystoreOperationStatus::storage_error:
        case KeystoreOperationStatus::locked:
        case KeystoreOperationStatus::wrong_pin:
        case KeystoreOperationStatus::unchanged:
        case KeystoreOperationStatus::consumer_failed:
            return StackChanKeystoreMaterialStatus::storage_error;
    }
    return StackChanKeystoreMaterialStatus::storage_error;
}

template <size_t PlaintextBytes>
StackChanKeystoreMaterialStatus record_status(const KeystoreRecord& record)
{
    uint8_t scratch[kKeystoreRecordOverheadBytes + PlaintextBytes] = {};
    return material_status_from_operation(encrypted_keystore_check_record(
        &g_keystore, record, scratch, sizeof(scratch)));
}

StackChanKeystoreMaterialStatus transport_identity_status()
{
    return record_status<kTransportIdentityBytes>(
        kTransportIdentityRecord);
}

template <size_t PlaintextBytes>
KeystoreOperationStatus with_record(
    const KeystoreRecord& record,
    KeystoreRecordConsumer consumer,
    void* consumer_context)
{
    RecordScratch<PlaintextBytes> scratch;
    KeystoreRecordScratch view = scratch.view();
    return encrypted_keystore_with_record(
        &g_keystore, record, &view, consumer, consumer_context);
}

template <size_t PlaintextBytes>
KeystoreOperationStatus replace_record(
    const KeystoreRecord& record,
    const uint8_t* plaintext)
{
    RecordScratch<PlaintextBytes> scratch;
    KeystoreRecordScratch view = scratch.view();
    return encrypted_keystore_replace_record(
        &g_keystore, record, plaintext, PlaintextBytes, &view);
}

bool validate_record_size(
    const uint8_t*,
    size_t plaintext_size,
    void* expected_size_ptr)
{
    return expected_size_ptr != nullptr &&
           plaintext_size == *static_cast<const size_t*>(expected_size_ptr);
}

LocalTransportIdentityRecordReadStatus identity_status(
    KeystoreOperationStatus status)
{
    if (status == KeystoreOperationStatus::success) {
        return LocalTransportIdentityRecordReadStatus::found;
    }
    return status == KeystoreOperationStatus::missing
        ? LocalTransportIdentityRecordReadStatus::missing
        : LocalTransportIdentityRecordReadStatus::error;
}

bool copy_identity_public_key(
    const uint8_t* identity,
    size_t identity_size,
    void* context)
{
    if (identity == nullptr || identity_size != kTransportIdentityBytes ||
        context == nullptr) {
        return false;
    }
    memcpy(
        context,
        identity + kLocalTransportStaticKeyBytes,
        kLocalTransportStaticKeyBytes);
    return true;
}

LocalTransportIdentityRecordReadStatus read_identity_public_key(
    uint8_t public_key[kLocalTransportStaticKeyBytes],
    void*)
{
    if (public_key == nullptr) {
        return LocalTransportIdentityRecordReadStatus::error;
    }
    encrypted_keystore_wipe(public_key, kLocalTransportStaticKeyBytes);
    return identity_status(with_record<kTransportIdentityBytes>(
        kTransportIdentityRecord,
        copy_identity_public_key,
        public_key));
}

struct StoredIdentityConsumerContext {
    LocalTransportStoredKeyPairConsumer consumer = nullptr;
    void* consumer_context = nullptr;
};

bool consume_stored_identity(
    const uint8_t* identity,
    size_t identity_size,
    void* context_ptr)
{
    auto* context = static_cast<StoredIdentityConsumerContext*>(context_ptr);
    return context != nullptr && context->consumer != nullptr &&
           identity != nullptr && identity_size == kTransportIdentityBytes &&
           context->consumer(
               identity,
               identity + kLocalTransportStaticKeyBytes,
               context->consumer_context);
}

LocalTransportIdentityRecordReadStatus with_identity_key_pair(
    LocalTransportStoredKeyPairConsumer consumer,
    void* consumer_context,
    void*)
{
    if (consumer == nullptr) {
        return LocalTransportIdentityRecordReadStatus::error;
    }
    StoredIdentityConsumerContext context{consumer, consumer_context};
    return identity_status(with_record<kTransportIdentityBytes>(
        kTransportIdentityRecord,
        consume_stored_identity,
        &context));
}

bool write_identity_key_pair(
    const uint8_t secret_key[kLocalTransportStaticKeyBytes],
    const uint8_t public_key[kLocalTransportStaticKeyBytes],
    void*)
{
    if (secret_key == nullptr || public_key == nullptr) {
        return false;
    }
    uint8_t identity[kTransportIdentityBytes] = {};
    memcpy(identity, secret_key, kLocalTransportStaticKeyBytes);
    memcpy(
        identity + kLocalTransportStaticKeyBytes,
        public_key,
        kLocalTransportStaticKeyBytes);
    const KeystoreOperationStatus status = replace_record<kTransportIdentityBytes>(
        kTransportIdentityRecord,
        identity);
    encrypted_keystore_wipe(identity, sizeof(identity));
    return status == KeystoreOperationStatus::success;
}

KeystoreOperationStatus validate_unlocked_records()
{
    size_t root_size = kStackChanRootMaterialBytes;
    KeystoreOperationStatus status = stackchan_keystore_with_root(
        validate_record_size,
        &root_size);
    if (status != KeystoreOperationStatus::success) {
        return status;
    }

    const StackChanKeystoreMaterialStatus identity_status =
        transport_identity_status();
    if (identity_status == StackChanKeystoreMaterialStatus::missing) {
        return KeystoreOperationStatus::success;
    }
    if (identity_status != StackChanKeystoreMaterialStatus::active) {
        return identity_status == StackChanKeystoreMaterialStatus::storage_error
            ? KeystoreOperationStatus::storage_error
            : KeystoreOperationStatus::invalid_record;
    }
    size_t identity_size = kTransportIdentityBytes;
    return with_record<kTransportIdentityBytes>(
        kTransportIdentityRecord,
        validate_record_size,
        &identity_size);
}

}  // namespace

KeystoreState stackchan_keystore_initialize()
{
    return encrypted_keystore_initialize(&g_keystore, &keystore_config());
}

KeystoreState stackchan_keystore_state()
{
    return encrypted_keystore_state(&g_keystore);
}

StackChanKeystoreMaterialStatus stackchan_keystore_status()
{
    switch (stackchan_keystore_state()) {
        case KeystoreState::absent:
            return StackChanKeystoreMaterialStatus::missing;
        case KeystoreState::locked:
        case KeystoreState::unlocked:
            return StackChanKeystoreMaterialStatus::active;
        case KeystoreState::unlocking:
            return StackChanKeystoreMaterialStatus::busy;
        case KeystoreState::invalid:
            return StackChanKeystoreMaterialStatus::invalid;
        case KeystoreState::storage_error:
            return StackChanKeystoreMaterialStatus::storage_error;
    }
    return StackChanKeystoreMaterialStatus::storage_error;
}

StackChanKeystoreMaterialStatus stackchan_keystore_root_status()
{
    return record_status<kStackChanRootMaterialBytes>(kRootRecord);
}

KeystoreOperationStatus stackchan_keystore_create(
    char pin[kKeystorePinDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    return encrypted_keystore_create(
        &g_keystore, pin, kdf_work_area, kdf_work_area_size);
}

KeystoreOperationStatus stackchan_keystore_unlock(
    char pin[kKeystorePinDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    const KeystoreOperationStatus status = encrypted_keystore_unlock(
        &g_keystore, pin, kdf_work_area, kdf_work_area_size);
    if (status != KeystoreOperationStatus::success) {
        return status;
    }
    const KeystoreOperationStatus validation_status = validate_unlocked_records();
    if (validation_status == KeystoreOperationStatus::success) {
        return KeystoreOperationStatus::success;
    }
    encrypted_keystore_lock(&g_keystore);
    return validation_status;
}

KeystoreOperationStatus stackchan_keystore_authenticate_pin(
    char pin[kKeystorePinDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    return encrypted_keystore_authenticate_pin(
        &g_keystore, pin, kdf_work_area, kdf_work_area_size);
}

KeystoreOperationStatus stackchan_keystore_rewrap(
    char current_pin[kKeystorePinDigits + 1],
    char new_pin[kKeystorePinDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    return encrypted_keystore_rewrap(
        &g_keystore,
        current_pin,
        new_pin,
        kdf_work_area,
        kdf_work_area_size);
}

KeystoreOperationStatus stackchan_keystore_with_root(
    KeystoreRecordConsumer consumer,
    void* consumer_context)
{
    return with_record<kStackChanRootMaterialBytes>(
        kRootRecord, consumer, consumer_context);
}

KeystoreOperationStatus stackchan_keystore_replace_root(
    const uint8_t root[kStackChanRootMaterialBytes])
{
    return root == nullptr
        ? KeystoreOperationStatus::invalid_input
        : replace_record<kStackChanRootMaterialBytes>(kRootRecord, root);
}

const LocalTransportIdentityStorageOps&
stackchan_transport_identity_storage_ops()
{
    static const LocalTransportIdentityStorageOps ops{
        read_identity_public_key,
        with_identity_key_pair,
        write_identity_key_pair,
        nullptr,
        nullptr,
    };
    return ops;
}

KeystoreOperationStatus stackchan_keystore_erase()
{
    const KeystoreRecord records[] = {kRootRecord, kTransportIdentityRecord};
    return encrypted_keystore_erase(
        &g_keystore, records, sizeof(records) / sizeof(records[0]));
}

}  // namespace signing
