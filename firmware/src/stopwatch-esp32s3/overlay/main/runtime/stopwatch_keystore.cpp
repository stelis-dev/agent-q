#include "stopwatch_keystore.h"

#include <stdlib.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "keystore/encrypted_keystore_nvs.h"
#include "secure_random.h"

namespace stopwatch_target {
namespace {

constexpr uint8_t kTargetLabel[] = "stopwatch-esp32s3";
constexpr uint8_t kCredentialRecordId[] = "credential";
constexpr uint8_t kTransportIdentityRecordId[] = "transport_identity";
constexpr size_t kTransportIdentityBytes =
    2 * signing::kLocalTransportStaticKeyBytes;
constexpr const char* kNvsNamespace = "sw_keystore";
constexpr const char* kKeyslotStorageKey = "keyslot";
constexpr const char* kCredentialStorageKey = "credential";
constexpr const char* kTransportIdentityStorageKey = "transport_id";

constexpr signing::KeystoreRecord kCredentialRecord{
    kCredentialStorageKey,
    kCredentialRecordId,
    sizeof(kCredentialRecordId) - 1,
    kStopWatchCredentialPlaintextMaxBytes,
};
constexpr signing::KeystoreRecord kTransportIdentityRecord{
    kTransportIdentityStorageKey,
    kTransportIdentityRecordId,
    sizeof(kTransportIdentityRecordId) - 1,
    kTransportIdentityBytes,
};

signing::EncryptedKeystore g_keystore;

bool fill_random(uint8_t* output, size_t output_size, void*)
{
    return secure_random_fill(output, output_size);
}

const signing::EncryptedKeystoreConfig& keystore_config()
{
    static const signing::EncryptedKeystoreNvsConfig nvs_config{
        kNvsNamespace,
        "StopWatchKeystore",
    };
    static const signing::EncryptedKeystoreConfig config{
        kTargetLabel,
        sizeof(kTargetLabel) - 1,
        kKeyslotStorageKey,
        kLocalAuthMinDigits,
        kLocalAuthMaxDigits,
        kStopWatchKeystoreKdfProfile,
        signing::encrypted_keystore_nvs_storage_ops(&nvs_config),
        {fill_random, nullptr},
    };
    return config;
}

class RecordScratchAllocation {
public:
    explicit RecordScratchAllocation(size_t plaintext_capacity)
        : plaintext_capacity_(plaintext_capacity),
          blob_capacity_(signing::kKeystoreRecordOverheadBytes + plaintext_capacity)
    {
        if (plaintext_capacity_ == 0 ||
            blob_capacity_ > (SIZE_MAX - plaintext_capacity_) / 3) {
            return;
        }
        allocation_size_ = blob_capacity_ * 3 + plaintext_capacity_;
        bytes_ = static_cast<uint8_t*>(heap_caps_calloc(
            1,
            allocation_size_,
            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    }

    ~RecordScratchAllocation()
    {
        signing::encrypted_keystore_wipe(bytes_, allocation_size_);
        free(bytes_);
    }

    RecordScratchAllocation(const RecordScratchAllocation&) = delete;
    RecordScratchAllocation& operator=(const RecordScratchAllocation&) = delete;

    bool valid() const { return bytes_ != nullptr; }

    signing::KeystoreRecordScratch view()
    {
        if (!valid()) {
            return {};
        }
        return {
            bytes_,
            bytes_ + blob_capacity_,
            bytes_ + blob_capacity_ * 2,
            blob_capacity_,
            bytes_ + blob_capacity_ * 3,
            plaintext_capacity_,
        };
    }

private:
    uint8_t* bytes_ = nullptr;
    size_t plaintext_capacity_ = 0;
    size_t blob_capacity_ = 0;
    size_t allocation_size_ = 0;
};

signing::KeystoreOperationStatus check_record(
    const signing::KeystoreRecord& record)
{
    const size_t scratch_size =
        signing::kKeystoreRecordOverheadBytes + record.maximum_plaintext_size;
    uint8_t* scratch = static_cast<uint8_t*>(heap_caps_calloc(
        1,
        scratch_size,
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (scratch == nullptr) {
        return signing::KeystoreOperationStatus::storage_error;
    }
    const signing::KeystoreOperationStatus status =
        signing::encrypted_keystore_check_record(
            &g_keystore,
            record,
            scratch,
            scratch_size);
    signing::encrypted_keystore_wipe(scratch, scratch_size);
    free(scratch);
    return status;
}

signing::KeystoreOperationStatus with_record(
    const signing::KeystoreRecord& record,
    signing::KeystoreRecordConsumer consumer,
    void* consumer_context)
{
    RecordScratchAllocation allocation(record.maximum_plaintext_size);
    if (!allocation.valid()) {
        return signing::KeystoreOperationStatus::storage_error;
    }
    signing::KeystoreRecordScratch scratch = allocation.view();
    return signing::encrypted_keystore_with_record(
        &g_keystore,
        record,
        &scratch,
        consumer,
        consumer_context);
}

signing::KeystoreOperationStatus replace_record(
    const signing::KeystoreRecord& record,
    const uint8_t* plaintext,
    size_t plaintext_size)
{
    RecordScratchAllocation allocation(record.maximum_plaintext_size);
    if (!allocation.valid()) {
        return signing::KeystoreOperationStatus::storage_error;
    }
    signing::KeystoreRecordScratch scratch = allocation.view();
    return signing::encrypted_keystore_replace_record(
        &g_keystore,
        record,
        plaintext,
        plaintext_size,
        &scratch);
}

bool validate_exact_record_size(
    const uint8_t*,
    size_t plaintext_size,
    void* context)
{
    return context != nullptr &&
           plaintext_size == *static_cast<const size_t*>(context);
}

signing::LocalTransportIdentityRecordReadStatus identity_status(
    signing::KeystoreOperationStatus status)
{
    if (status == signing::KeystoreOperationStatus::success) {
        return signing::LocalTransportIdentityRecordReadStatus::found;
    }
    return status == signing::KeystoreOperationStatus::missing
        ? signing::LocalTransportIdentityRecordReadStatus::missing
        : signing::LocalTransportIdentityRecordReadStatus::error;
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
        identity + signing::kLocalTransportStaticKeyBytes,
        signing::kLocalTransportStaticKeyBytes);
    return true;
}

signing::LocalTransportIdentityRecordReadStatus read_identity_public_key(
    uint8_t public_key[signing::kLocalTransportStaticKeyBytes],
    void*)
{
    if (public_key == nullptr) {
        return signing::LocalTransportIdentityRecordReadStatus::error;
    }
    signing::encrypted_keystore_wipe(
        public_key,
        signing::kLocalTransportStaticKeyBytes);
    return identity_status(with_record(
        kTransportIdentityRecord,
        copy_identity_public_key,
        public_key));
}

struct StoredIdentityConsumerContext {
    signing::LocalTransportStoredKeyPairConsumer consumer = nullptr;
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
               identity + signing::kLocalTransportStaticKeyBytes,
               context->consumer_context);
}

signing::LocalTransportIdentityRecordReadStatus with_identity_key_pair(
    signing::LocalTransportStoredKeyPairConsumer consumer,
    void* consumer_context,
    void*)
{
    if (consumer == nullptr) {
        return signing::LocalTransportIdentityRecordReadStatus::error;
    }
    StoredIdentityConsumerContext context{consumer, consumer_context};
    return identity_status(with_record(
        kTransportIdentityRecord,
        consume_stored_identity,
        &context));
}

bool write_identity_key_pair(
    const uint8_t secret_key[signing::kLocalTransportStaticKeyBytes],
    const uint8_t public_key[signing::kLocalTransportStaticKeyBytes],
    void*)
{
    if (secret_key == nullptr || public_key == nullptr) {
        return false;
    }
    uint8_t identity[kTransportIdentityBytes] = {};
    memcpy(identity, secret_key, signing::kLocalTransportStaticKeyBytes);
    memcpy(
        identity + signing::kLocalTransportStaticKeyBytes,
        public_key,
        signing::kLocalTransportStaticKeyBytes);
    const signing::KeystoreOperationStatus status = replace_record(
        kTransportIdentityRecord,
        identity,
        sizeof(identity));
    signing::encrypted_keystore_wipe(identity, sizeof(identity));
    return status == signing::KeystoreOperationStatus::success;
}

}  // namespace

signing::KeystoreState stopwatch_keystore_initialize()
{
    return signing::encrypted_keystore_initialize(&g_keystore, &keystore_config());
}

signing::KeystoreState stopwatch_keystore_state()
{
    return signing::encrypted_keystore_state(&g_keystore);
}

bool stopwatch_keystore_storage_consistent()
{
    const signing::KeystoreOperationStatus credential_status =
        check_record(kCredentialRecord);
    const signing::KeystoreOperationStatus identity_status =
        check_record(kTransportIdentityRecord);
    const signing::KeystoreState state = stopwatch_keystore_state();
    if (state == signing::KeystoreState::absent) {
        return credential_status == signing::KeystoreOperationStatus::missing &&
               identity_status == signing::KeystoreOperationStatus::missing;
    }
    if (state != signing::KeystoreState::locked &&
        state != signing::KeystoreState::unlocked) {
        return false;
    }
    const auto record_consistent = [](signing::KeystoreOperationStatus status) {
        return status == signing::KeystoreOperationStatus::missing ||
               status == signing::KeystoreOperationStatus::success;
    };
    return record_consistent(credential_status) &&
           record_consistent(identity_status);
}

signing::KeystoreOperationStatus stopwatch_keystore_create(
    char pin[signing::kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    if (!stopwatch_keystore_storage_consistent() ||
        stopwatch_keystore_state() != signing::KeystoreState::absent) {
        return stopwatch_keystore_state() == signing::KeystoreState::storage_error
            ? signing::KeystoreOperationStatus::storage_error
            : signing::KeystoreOperationStatus::invalid_record;
    }
    return signing::encrypted_keystore_create(
        &g_keystore,
        pin,
        kdf_work_area,
        kdf_work_area_size);
}

signing::KeystoreOperationStatus stopwatch_keystore_unlock(
    char pin[signing::kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    return signing::encrypted_keystore_unlock(
        &g_keystore,
        pin,
        kdf_work_area,
        kdf_work_area_size);
}

signing::KeystoreOperationStatus stopwatch_keystore_authenticate_pin(
    char pin[signing::kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    return signing::encrypted_keystore_authenticate_pin(
        &g_keystore,
        pin,
        kdf_work_area,
        kdf_work_area_size);
}

signing::KeystoreOperationStatus stopwatch_keystore_lock()
{
    return signing::encrypted_keystore_lock(&g_keystore);
}

signing::KeystoreOperationStatus stopwatch_keystore_credential_status()
{
    return check_record(kCredentialRecord);
}

signing::KeystoreOperationStatus stopwatch_keystore_with_credential(
    signing::KeystoreRecordConsumer consumer,
    void* consumer_context)
{
    return with_record(kCredentialRecord, consumer, consumer_context);
}

signing::KeystoreOperationStatus stopwatch_keystore_replace_credential(
    const uint8_t* plaintext,
    size_t plaintext_size)
{
    return replace_record(kCredentialRecord, plaintext, plaintext_size);
}

bool stopwatch_keystore_transport_identity_valid_or_missing()
{
    const signing::KeystoreOperationStatus status =
        check_record(kTransportIdentityRecord);
    if (status == signing::KeystoreOperationStatus::missing) {
        return true;
    }
    if (status != signing::KeystoreOperationStatus::success) {
        return false;
    }
    size_t expected_size = kTransportIdentityBytes;
    return with_record(
               kTransportIdentityRecord,
               validate_exact_record_size,
               &expected_size) == signing::KeystoreOperationStatus::success;
}

const signing::LocalTransportIdentityStorageOps&
stopwatch_transport_identity_storage_ops()
{
    static const signing::LocalTransportIdentityStorageOps ops{
        read_identity_public_key,
        with_identity_key_pair,
        write_identity_key_pair,
        nullptr,
        nullptr,
    };
    return ops;
}

signing::KeystoreOperationStatus stopwatch_keystore_erase()
{
    const signing::KeystoreRecord records[] = {
        kCredentialRecord,
        kTransportIdentityRecord,
    };
    return signing::encrypted_keystore_erase(
        &g_keystore,
        records,
        sizeof(records) / sizeof(records[0]));
}

}  // namespace stopwatch_target
