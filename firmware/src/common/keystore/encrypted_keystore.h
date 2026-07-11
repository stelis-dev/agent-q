#pragma once

#include <stddef.h>
#include <stdint.h>

namespace signing {

constexpr size_t kKeystoreMasterKeyBytes = 32;
constexpr size_t kKeystoreSaltBytes = 16;
constexpr size_t kKeystoreNonceBytes = 24;
constexpr size_t kKeystoreTagBytes = 16;
constexpr size_t kKeystoreConfirmationBytes = 16;
constexpr size_t kKeystoreKdfWorkAreaAlignment = alignof(uint64_t);
constexpr size_t kKeystoreKeyslotBytes = 116;
constexpr size_t kKeystoreRecordHeaderBytes = 36;
constexpr size_t kKeystoreRecordOverheadBytes =
    kKeystoreRecordHeaderBytes + kKeystoreTagBytes;
constexpr size_t kKeystoreMaximumBindingBytes = 32;
constexpr size_t kKeystoreMaximumPinDigits = 6;
constexpr size_t kKeystorePinBufferBytes = kKeystoreMaximumPinDigits + 1;

enum class KeystoreState {
    absent,
    locked,
    unlocking,
    unlocked,
    invalid,
    storage_error,
};

enum class KeystoreBlobReadStatus {
    missing,
    found,
    error,
};

enum class KeystoreOperationStatus {
    success,
    missing,
    locked,
    busy,
    wrong_pin,
    invalid_input,
    invalid_record,
    unchanged,
    storage_error,
    consumer_failed,
};

struct KeystoreKdfProfile {
    uint32_t memory_kib = 0;
    uint32_t passes = 0;
    uint32_t lanes = 0;
};

struct KeystoreStorageOps {
    KeystoreBlobReadStatus (*read_blob)(
        const char* key,
        uint8_t* output,
        size_t output_capacity,
        size_t* output_size,
        void* context) = nullptr;
    bool (*write_blob)(
        const char* key,
        const uint8_t* value,
        size_t value_size,
        void* context) = nullptr;
    bool (*erase_blob)(const char* key, void* context) = nullptr;
    void* context = nullptr;
};

struct KeystoreRandomOps {
    bool (*fill)(uint8_t* output, size_t output_size, void* context) = nullptr;
    void* context = nullptr;
};

struct EncryptedKeystoreConfig {
    // The config and every pointer it contains must remain valid for the
    // lifetime of the initialized keystore.
    const uint8_t* target_label = nullptr;
    size_t target_label_size = 0;
    const char* keyslot_storage_key = nullptr;
    size_t minimum_pin_digits = 0;
    size_t maximum_pin_digits = 0;
    KeystoreKdfProfile kdf;
    KeystoreStorageOps storage;
    KeystoreRandomOps random;
};

struct EncryptedKeystoreInternalAccess;

class alignas(void*) EncryptedKeystore {
public:
    EncryptedKeystore();
    ~EncryptedKeystore();
    EncryptedKeystore(const EncryptedKeystore&) = delete;
    EncryptedKeystore& operator=(const EncryptedKeystore&) = delete;

private:
    friend struct EncryptedKeystoreInternalAccess;
    uint8_t opaque_[48] = {};
};

struct KeystoreRecord {
    const char* storage_key = nullptr;
    const uint8_t* record_id = nullptr;
    size_t record_id_size = 0;
    size_t maximum_plaintext_size = 0;
};

struct KeystoreRecordScratch {
    uint8_t* previous_blob = nullptr;
    uint8_t* candidate_blob = nullptr;
    uint8_t* readback_blob = nullptr;
    size_t blob_capacity = 0;
    uint8_t* plaintext = nullptr;
    size_t plaintext_capacity = 0;
};

using KeystoreRecordConsumer = bool (*)(
    // Plaintext is valid only for this callback and is wiped before the
    // enclosing keystore operation returns.
    const uint8_t* plaintext,
    size_t plaintext_size,
    void* context);

inline bool keystore_pin_policy_valid(
    size_t minimum_pin_digits,
    size_t maximum_pin_digits)
{
    return minimum_pin_digits > 0 &&
           minimum_pin_digits <= maximum_pin_digits &&
           maximum_pin_digits <= kKeystoreMaximumPinDigits;
}

inline bool keystore_pin_valid(
    const char* pin,
    size_t minimum_pin_digits,
    size_t maximum_pin_digits,
    size_t* pin_length = nullptr)
{
    if (pin == nullptr ||
        !keystore_pin_policy_valid(
            minimum_pin_digits, maximum_pin_digits)) {
        return false;
    }
    for (size_t index = 0; index < maximum_pin_digits; ++index) {
        if (pin[index] == '\0') {
            if (index < minimum_pin_digits) {
                return false;
            }
            if (pin_length != nullptr) {
                *pin_length = index;
            }
            return true;
        }
        if (pin[index] < '0' || pin[index] > '9') {
            return false;
        }
    }
    if (pin[maximum_pin_digits] != '\0') {
        return false;
    }
    if (pin_length != nullptr) {
        *pin_length = maximum_pin_digits;
    }
    return true;
}

bool keystore_kdf_profile_valid(const KeystoreKdfProfile& profile);
bool encrypted_keystore_config_valid(const EncryptedKeystoreConfig& config);

KeystoreState encrypted_keystore_initialize(
    EncryptedKeystore* keystore,
    const EncryptedKeystoreConfig* config);

KeystoreState encrypted_keystore_state(const EncryptedKeystore* keystore);

KeystoreOperationStatus encrypted_keystore_create(
    EncryptedKeystore* keystore,
    char pin[kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size);

KeystoreOperationStatus encrypted_keystore_unlock(
    EncryptedKeystore* keystore,
    char pin[kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size);

KeystoreOperationStatus encrypted_keystore_authenticate_pin(
    EncryptedKeystore* keystore,
    char pin[kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size);

KeystoreOperationStatus encrypted_keystore_rewrap(
    EncryptedKeystore* keystore,
    char current_pin[kKeystorePinBufferBytes],
    char new_pin[kKeystorePinBufferBytes],
    void* kdf_work_area,
    size_t kdf_work_area_size);

KeystoreOperationStatus encrypted_keystore_lock(EncryptedKeystore* keystore);

KeystoreOperationStatus encrypted_keystore_check_record(
    EncryptedKeystore* keystore,
    const KeystoreRecord& record,
    uint8_t* blob_scratch,
    size_t blob_scratch_size);

KeystoreOperationStatus encrypted_keystore_with_record(
    EncryptedKeystore* keystore,
    const KeystoreRecord& record,
    KeystoreRecordScratch* scratch,
    KeystoreRecordConsumer consumer,
    void* consumer_context);

KeystoreOperationStatus encrypted_keystore_replace_record(
    EncryptedKeystore* keystore,
    const KeystoreRecord& record,
    const uint8_t* plaintext,
    size_t plaintext_size,
    KeystoreRecordScratch* scratch);

KeystoreOperationStatus encrypted_keystore_erase(
    EncryptedKeystore* keystore,
    const KeystoreRecord* records,
    size_t record_count);

void encrypted_keystore_wipe(void* bytes, size_t byte_count);

}  // namespace signing
