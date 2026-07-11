#include "keystore/encrypted_keystore.h"

#include <atomic>
#include <new>
#include <string.h>

extern "C" {
#include "lib/monocypher/monocypher.h"
}

namespace signing {

struct KeystoreRuntime {
    const EncryptedKeystoreConfig* config = nullptr;
    std::atomic<KeystoreState> state{KeystoreState::storage_error};
    std::atomic_flag operation = ATOMIC_FLAG_INIT;
    uint8_t master_key[kKeystoreMasterKeyBytes] = {};
};

struct EncryptedKeystoreInternalAccess {
    static uint8_t* bytes(EncryptedKeystore& keystore)
    {
        return keystore.opaque_;
    }

    static const uint8_t* bytes(const EncryptedKeystore& keystore)
    {
        return keystore.opaque_;
    }
};

namespace {

constexpr uint8_t kKeyslotMagic[4] = {'A', 'Q', 'K', 'S'};
constexpr uint8_t kRecordMagic[4] = {'A', 'Q', 'K', 'R'};
constexpr uint8_t kFormatVersion = 1;
constexpr uint8_t kArgon2idAlgorithm = 1;
constexpr size_t kKdfOutputBytes = 64;
constexpr size_t kKeyslotHeaderBytes = 52;
constexpr size_t kKeyslotCiphertextOffset = kKeyslotHeaderBytes;
constexpr size_t kKeyslotTagOffset =
    kKeyslotCiphertextOffset + kKeystoreMasterKeyBytes;
constexpr size_t kKeyslotConfirmationOffset =
    kKeyslotTagOffset + kKeystoreTagBytes;
constexpr size_t kRecordNonceOffset = 12;
constexpr size_t kRecordCiphertextOffset = kKeystoreRecordHeaderBytes;
constexpr uint32_t kMinimumKdfMemoryKib = 64;
constexpr uint32_t kMaximumKdfMemoryKib = 512;
constexpr size_t kMaximumAadBytes = 128;

constexpr uint8_t kWrappingKeyLabel[] = "agent-q-keystore-wrapping-key-v1";
constexpr uint8_t kConfirmationKeyLabel[] = "agent-q-keystore-confirmation-key-v1";
constexpr uint8_t kConfirmationLabel[] = "agent-q-keystore-confirmation-v1";
constexpr uint8_t kKeyslotAadLabel[] = "agent-q-keystore-keyslot-v1";
constexpr uint8_t kRecordAadLabel[] = "agent-q-keystore-record-v1";

static_assert(sizeof(KeystoreRuntime) <= 48);
static_assert(alignof(EncryptedKeystore) >= alignof(KeystoreRuntime));

KeystoreRuntime& runtime(EncryptedKeystore& keystore)
{
    return *std::launder(reinterpret_cast<KeystoreRuntime*>(
        EncryptedKeystoreInternalAccess::bytes(keystore)));
}

const KeystoreRuntime& runtime(const EncryptedKeystore& keystore)
{
    return *std::launder(
        reinterpret_cast<const KeystoreRuntime*>(
            EncryptedKeystoreInternalAccess::bytes(keystore)));
}

class KeystoreOperationGuard {
public:
    explicit KeystoreOperationGuard(EncryptedKeystore& keystore)
        : state_(&runtime(keystore)),
          acquired_(!state_->operation.test_and_set(std::memory_order_acquire))
    {
    }

    ~KeystoreOperationGuard()
    {
        if (acquired_) {
            state_->operation.clear(std::memory_order_release);
        }
    }

    bool acquired() const
    {
        return acquired_;
    }

private:
    KeystoreRuntime* state_;
    bool acquired_;
};

void store_u32_le(uint8_t output[4], uint32_t value)
{
    output[0] = static_cast<uint8_t>(value);
    output[1] = static_cast<uint8_t>(value >> 8);
    output[2] = static_cast<uint8_t>(value >> 16);
    output[3] = static_cast<uint8_t>(value >> 24);
}

uint32_t load_u32_le(const uint8_t input[4])
{
    return static_cast<uint32_t>(input[0]) |
           (static_cast<uint32_t>(input[1]) << 8) |
           (static_cast<uint32_t>(input[2]) << 16) |
           (static_cast<uint32_t>(input[3]) << 24);
}

bool text_key_valid(const char* key)
{
    return key != nullptr && key[0] != '\0';
}

bool binding_valid(const uint8_t* binding, size_t binding_size)
{
    return binding != nullptr && binding_size > 0 &&
           binding_size <= kKeystoreMaximumBindingBytes;
}

bool memory_ranges_overlap(
    const void* first,
    size_t first_size,
    const void* second,
    size_t second_size)
{
    if (first == nullptr || second == nullptr || first_size == 0 ||
        second_size == 0) {
        return false;
    }
    const uintptr_t first_start = reinterpret_cast<uintptr_t>(first);
    const uintptr_t second_start = reinterpret_cast<uintptr_t>(second);
    if (first_start > UINTPTR_MAX - first_size ||
        second_start > UINTPTR_MAX - second_size) {
        return true;
    }
    return first_start < second_start + second_size &&
           second_start < first_start + first_size;
}

bool pin_shape_valid(const char* pin)
{
    if (pin == nullptr) {
        return false;
    }
    for (size_t index = 0; index < kKeystorePinDigits; ++index) {
        if (pin[index] < '0' || pin[index] > '9') {
            return false;
        }
    }
    return pin[kKeystorePinDigits] == '\0';
}

bool kdf_work_area_valid(
    const EncryptedKeystoreConfig& config,
    const void* work_area,
    size_t work_area_size)
{
    return work_area != nullptr &&
           work_area_size == static_cast<size_t>(config.kdf.memory_kib) * 1024u &&
           reinterpret_cast<uintptr_t>(work_area) %
                   kKeystoreKdfWorkAreaAlignment ==
               0;
}

bool kdf_inputs_valid(
    const EncryptedKeystoreConfig& config,
    const char* pin,
    const void* work_area,
    size_t work_area_size)
{
    return pin_shape_valid(pin) &&
           kdf_work_area_valid(config, work_area, work_area_size) &&
           !memory_ranges_overlap(
               pin,
               kKeystorePinBufferBytes,
               work_area,
               work_area_size);
}

bool append_bytes(
    uint8_t* output,
    size_t capacity,
    size_t* size,
    const uint8_t* bytes,
    size_t byte_count)
{
    if (output == nullptr || size == nullptr ||
        (byte_count > 0 && bytes == nullptr) || *size > capacity ||
        byte_count > capacity - *size) {
        return false;
    }
    if (byte_count > 0) {
        memcpy(output + *size, bytes, byte_count);
    }
    *size += byte_count;
    return true;
}

bool build_keyslot_aad(
    const EncryptedKeystoreConfig& config,
    const uint8_t keyslot[kKeystoreKeyslotBytes],
    uint8_t aad[kMaximumAadBytes],
    size_t* aad_size)
{
    *aad_size = 0;
    const uint8_t label_size = static_cast<uint8_t>(config.target_label_size);
    return append_bytes(aad, kMaximumAadBytes, aad_size,
                        kKeyslotAadLabel, sizeof(kKeyslotAadLabel) - 1) &&
           append_bytes(aad, kMaximumAadBytes, aad_size, &label_size, 1) &&
           append_bytes(aad, kMaximumAadBytes, aad_size,
                        config.target_label, config.target_label_size) &&
           append_bytes(aad, kMaximumAadBytes, aad_size,
                        keyslot, kKeyslotHeaderBytes);
}

bool build_record_aad(
    const EncryptedKeystoreConfig& config,
    const KeystoreRecord& record,
    const uint8_t* blob,
    uint8_t aad[kMaximumAadBytes],
    size_t* aad_size)
{
    *aad_size = 0;
    const uint8_t target_size = static_cast<uint8_t>(config.target_label_size);
    const uint8_t record_size = static_cast<uint8_t>(record.record_id_size);
    return append_bytes(aad, kMaximumAadBytes, aad_size,
                        kRecordAadLabel, sizeof(kRecordAadLabel) - 1) &&
           append_bytes(aad, kMaximumAadBytes, aad_size, &target_size, 1) &&
           append_bytes(aad, kMaximumAadBytes, aad_size,
                        config.target_label, config.target_label_size) &&
           append_bytes(aad, kMaximumAadBytes, aad_size, &record_size, 1) &&
           append_bytes(aad, kMaximumAadBytes, aad_size,
                        record.record_id, record.record_id_size) &&
           append_bytes(aad, kMaximumAadBytes, aad_size,
                        blob, kKeystoreRecordHeaderBytes);
}

bool keyslot_header_valid(
    const EncryptedKeystoreConfig& config,
    const uint8_t keyslot[kKeystoreKeyslotBytes])
{
    return memcmp(keyslot, kKeyslotMagic, sizeof(kKeyslotMagic)) == 0 &&
           keyslot[4] == kFormatVersion &&
           keyslot[5] == kArgon2idAlgorithm &&
           keyslot[6] == config.kdf.lanes &&
           keyslot[7] == config.kdf.passes &&
           load_u32_le(keyslot + 8) == config.kdf.memory_kib;
}

bool record_valid(
    const EncryptedKeystoreConfig& config,
    const KeystoreRecord& record)
{
    return text_key_valid(record.storage_key) &&
           strcmp(record.storage_key, config.keyslot_storage_key) != 0 &&
           binding_valid(record.record_id, record.record_id_size) &&
           record.maximum_plaintext_size > 0 &&
           record.maximum_plaintext_size <=
               UINT32_MAX - kKeystoreRecordOverheadBytes;
}

bool scratch_valid(
    const KeystoreRecord& record,
    const KeystoreRecordScratch* scratch)
{
    if (scratch == nullptr || scratch->previous_blob == nullptr ||
        scratch->candidate_blob == nullptr || scratch->readback_blob == nullptr ||
        scratch->plaintext == nullptr ||
        scratch->plaintext_capacity < record.maximum_plaintext_size) {
        return false;
    }
    if (scratch->blob_capacity <
        kKeystoreRecordOverheadBytes + record.maximum_plaintext_size) {
        return false;
    }
    return !memory_ranges_overlap(
               scratch->previous_blob,
               scratch->blob_capacity,
               scratch->candidate_blob,
               scratch->blob_capacity) &&
           !memory_ranges_overlap(
               scratch->previous_blob,
               scratch->blob_capacity,
               scratch->readback_blob,
               scratch->blob_capacity) &&
           !memory_ranges_overlap(
               scratch->candidate_blob,
               scratch->blob_capacity,
               scratch->readback_blob,
               scratch->blob_capacity) &&
           !memory_ranges_overlap(
               scratch->plaintext,
               scratch->plaintext_capacity,
               scratch->previous_blob,
               scratch->blob_capacity) &&
           !memory_ranges_overlap(
               scratch->plaintext,
               scratch->plaintext_capacity,
               scratch->candidate_blob,
               scratch->blob_capacity) &&
           !memory_ranges_overlap(
               scratch->plaintext,
               scratch->plaintext_capacity,
               scratch->readback_blob,
               scratch->blob_capacity);
}

bool plaintext_separate_from_scratch(
    const uint8_t* plaintext,
    size_t plaintext_size,
    const KeystoreRecordScratch* scratch)
{
    if (plaintext == nullptr || plaintext_size == 0 || scratch == nullptr) {
        return false;
    }
    return !memory_ranges_overlap(
               plaintext,
               plaintext_size,
               scratch->previous_blob,
               scratch->blob_capacity) &&
           !memory_ranges_overlap(
               plaintext,
               plaintext_size,
               scratch->candidate_blob,
               scratch->blob_capacity) &&
           !memory_ranges_overlap(
               plaintext,
               plaintext_size,
               scratch->readback_blob,
               scratch->blob_capacity) &&
           !memory_ranges_overlap(
               plaintext,
               plaintext_size,
               scratch->plaintext,
               scratch->plaintext_capacity);
}

void wipe_record_scratch(KeystoreRecordScratch* scratch)
{
    if (scratch == nullptr) {
        return;
    }
    encrypted_keystore_wipe(scratch->previous_blob, scratch->blob_capacity);
    encrypted_keystore_wipe(scratch->candidate_blob, scratch->blob_capacity);
    encrypted_keystore_wipe(scratch->readback_blob, scratch->blob_capacity);
    encrypted_keystore_wipe(scratch->plaintext, scratch->plaintext_capacity);
}

bool derive_keys(
    const EncryptedKeystoreConfig& config,
    char pin[kKeystorePinDigits + 1],
    const uint8_t salt[kKeystoreSaltBytes],
    void* work_area,
    size_t work_area_size,
    uint8_t wrapping_key[kKeystoreMasterKeyBytes],
    uint8_t confirmation_key[kKeystoreMasterKeyBytes])
{
    uint8_t output[kKdfOutputBytes] = {};
    const bool ok = kdf_inputs_valid(
        config, pin, work_area, work_area_size);
    if (ok) {
        const crypto_argon2_config argon_config{
            CRYPTO_ARGON2_ID,
            config.kdf.memory_kib,
            config.kdf.passes,
            config.kdf.lanes,
        };
        const crypto_argon2_inputs inputs{
            reinterpret_cast<const uint8_t*>(pin),
            salt,
            static_cast<uint32_t>(kKeystorePinDigits),
            static_cast<uint32_t>(kKeystoreSaltBytes),
        };
        const crypto_argon2_extras extras{
            nullptr,
            config.target_label,
            0,
            static_cast<uint32_t>(config.target_label_size),
        };
        crypto_argon2(
            output, sizeof(output), work_area, argon_config, inputs, extras);
        crypto_blake2b_keyed(
            wrapping_key, kKeystoreMasterKeyBytes,
            output, sizeof(output),
            kWrappingKeyLabel, sizeof(kWrappingKeyLabel) - 1);
        crypto_blake2b_keyed(
            confirmation_key, kKeystoreMasterKeyBytes,
            output, sizeof(output),
            kConfirmationKeyLabel, sizeof(kConfirmationKeyLabel) - 1);
    }
    encrypted_keystore_wipe(pin, pin == nullptr ? 0 : kKeystorePinDigits + 1);
    encrypted_keystore_wipe(output, sizeof(output));
    encrypted_keystore_wipe(work_area, work_area_size);
    if (!ok) {
        encrypted_keystore_wipe(wrapping_key, kKeystoreMasterKeyBytes);
        encrypted_keystore_wipe(confirmation_key, kKeystoreMasterKeyBytes);
    }
    return ok;
}

void compute_confirmation(
    const uint8_t confirmation_key[kKeystoreMasterKeyBytes],
    const uint8_t keyslot[kKeystoreKeyslotBytes],
    uint8_t output[kKeystoreConfirmationBytes])
{
    crypto_blake2b_ctx context;
    crypto_blake2b_keyed_init(
        &context, kKeystoreConfirmationBytes,
        confirmation_key, kKeystoreMasterKeyBytes);
    crypto_blake2b_update(
        &context, kConfirmationLabel, sizeof(kConfirmationLabel) - 1);
    crypto_blake2b_update(&context, keyslot, kKeyslotConfirmationOffset);
    crypto_blake2b_final(&context, output);
    encrypted_keystore_wipe(&context, sizeof(context));
}

bool seal_keyslot(
    const EncryptedKeystoreConfig& config,
    const uint8_t master_key[kKeystoreMasterKeyBytes],
    const uint8_t salt[kKeystoreSaltBytes],
    const uint8_t nonce[kKeystoreNonceBytes],
    const uint8_t wrapping_key[kKeystoreMasterKeyBytes],
    const uint8_t confirmation_key[kKeystoreMasterKeyBytes],
    uint8_t keyslot[kKeystoreKeyslotBytes])
{
    memset(keyslot, 0, kKeystoreKeyslotBytes);
    memcpy(keyslot, kKeyslotMagic, sizeof(kKeyslotMagic));
    keyslot[4] = kFormatVersion;
    keyslot[5] = kArgon2idAlgorithm;
    keyslot[6] = static_cast<uint8_t>(config.kdf.lanes);
    keyslot[7] = static_cast<uint8_t>(config.kdf.passes);
    store_u32_le(keyslot + 8, config.kdf.memory_kib);
    memcpy(keyslot + 12, salt, kKeystoreSaltBytes);
    memcpy(keyslot + 28, nonce, kKeystoreNonceBytes);
    uint8_t aad[kMaximumAadBytes] = {};
    size_t aad_size = 0;
    const bool aad_ok = build_keyslot_aad(config, keyslot, aad, &aad_size);
    if (aad_ok) {
        crypto_aead_lock(
            keyslot + kKeyslotCiphertextOffset,
            keyslot + kKeyslotTagOffset,
            wrapping_key,
            nonce,
            aad,
            aad_size,
            master_key,
            kKeystoreMasterKeyBytes);
        compute_confirmation(
            confirmation_key,
            keyslot,
            keyslot + kKeyslotConfirmationOffset);
    }
    encrypted_keystore_wipe(aad, sizeof(aad));
    return aad_ok;
}

bool open_keyslot(
    const EncryptedKeystoreConfig& config,
    const uint8_t keyslot[kKeystoreKeyslotBytes],
    const uint8_t wrapping_key[kKeystoreMasterKeyBytes],
    const uint8_t confirmation_key[kKeystoreMasterKeyBytes],
    uint8_t master_key[kKeystoreMasterKeyBytes])
{
    if (!keyslot_header_valid(config, keyslot)) {
        return false;
    }
    uint8_t expected[kKeystoreConfirmationBytes] = {};
    compute_confirmation(confirmation_key, keyslot, expected);
    const bool confirmation_ok =
        crypto_verify16(expected, keyslot + kKeyslotConfirmationOffset) == 0;
    encrypted_keystore_wipe(expected, sizeof(expected));
    if (!confirmation_ok) {
        return false;
    }
    uint8_t aad[kMaximumAadBytes] = {};
    size_t aad_size = 0;
    const bool aad_ok = build_keyslot_aad(config, keyslot, aad, &aad_size);
    const bool opened = aad_ok &&
        crypto_aead_unlock(
            master_key,
            keyslot + kKeyslotTagOffset,
            wrapping_key,
            keyslot + 28,
            aad,
            aad_size,
            keyslot + kKeyslotCiphertextOffset,
            kKeystoreMasterKeyBytes) == 0;
    encrypted_keystore_wipe(aad, sizeof(aad));
    if (!opened) {
        encrypted_keystore_wipe(master_key, kKeystoreMasterKeyBytes);
    }
    return opened;
}

KeystoreBlobReadStatus read_keyslot(
    const EncryptedKeystoreConfig& config,
    uint8_t keyslot[kKeystoreKeyslotBytes])
{
    size_t size = 0;
    const KeystoreBlobReadStatus status = config.storage.read_blob(
        config.keyslot_storage_key,
        keyslot,
        kKeystoreKeyslotBytes,
        &size,
        config.storage.context);
    if (status == KeystoreBlobReadStatus::found &&
        size != kKeystoreKeyslotBytes) {
        encrypted_keystore_wipe(keyslot, kKeystoreKeyslotBytes);
        return KeystoreBlobReadStatus::error;
    }
    return status;
}

void wipe_kdf_inputs(char* pin, void* work_area, size_t work_area_size)
{
    encrypted_keystore_wipe(
        pin, pin == nullptr ? 0 : kKeystorePinDigits + 1);
    encrypted_keystore_wipe(work_area, work_area_size);
}

KeystoreOperationStatus open_current_keyslot(
    const EncryptedKeystoreConfig& config,
    char pin[kKeystorePinDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size,
    uint8_t keyslot[kKeystoreKeyslotBytes],
    uint8_t master_key[kKeystoreMasterKeyBytes])
{
    const KeystoreBlobReadStatus read_status = read_keyslot(config, keyslot);
    if (read_status != KeystoreBlobReadStatus::found ||
        !keyslot_header_valid(config, keyslot)) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        encrypted_keystore_wipe(master_key, kKeystoreMasterKeyBytes);
        return read_status == KeystoreBlobReadStatus::error
            ? KeystoreOperationStatus::storage_error
            : KeystoreOperationStatus::invalid_record;
    }

    uint8_t wrapping_key[kKeystoreMasterKeyBytes] = {};
    uint8_t confirmation_key[kKeystoreMasterKeyBytes] = {};
    const bool derived = derive_keys(
        config,
        pin,
        keyslot + 12,
        kdf_work_area,
        kdf_work_area_size,
        wrapping_key,
        confirmation_key);
    const bool opened = derived && open_keyslot(
        config,
        keyslot,
        wrapping_key,
        confirmation_key,
        master_key);
    encrypted_keystore_wipe(wrapping_key, sizeof(wrapping_key));
    encrypted_keystore_wipe(confirmation_key, sizeof(confirmation_key));
    if (!opened) {
        encrypted_keystore_wipe(master_key, kKeystoreMasterKeyBytes);
    }
    return opened ? KeystoreOperationStatus::success
                  : (derived ? KeystoreOperationStatus::wrong_pin
                             : KeystoreOperationStatus::invalid_input);
}

KeystoreOperationStatus commit_keyslot(
    EncryptedKeystore* keystore,
    const uint8_t candidate[kKeystoreKeyslotBytes],
    const uint8_t* previous,
    bool previous_exists)
{
    KeystoreRuntime& state = runtime(*keystore);
    state.config->storage.write_blob(
        state.config->keyslot_storage_key,
        candidate,
        kKeystoreKeyslotBytes,
        state.config->storage.context);
    uint8_t readback[kKeystoreKeyslotBytes] = {};
    const KeystoreBlobReadStatus status = read_keyslot(*state.config, readback);
    const bool matches_new = status == KeystoreBlobReadStatus::found &&
                             memcmp(readback, candidate, sizeof(readback)) == 0;
    const bool matches_previous = previous_exists &&
        status == KeystoreBlobReadStatus::found &&
        memcmp(readback, previous, sizeof(readback)) == 0;
    const bool remains_missing = !previous_exists &&
        status == KeystoreBlobReadStatus::missing;
    encrypted_keystore_wipe(readback, sizeof(readback));
    if (matches_new) {
        return KeystoreOperationStatus::success;
    }
    if (matches_previous || remains_missing) {
        return KeystoreOperationStatus::unchanged;
    }
    encrypted_keystore_wipe(state.master_key, sizeof(state.master_key));
    state.state = KeystoreState::storage_error;
    return KeystoreOperationStatus::storage_error;
}

bool sealed_record_shape_valid(
    const KeystoreRecord& record,
    const uint8_t* blob,
    size_t blob_size,
    size_t* plaintext_size)
{
    if (blob == nullptr || plaintext_size == nullptr ||
        blob_size < kKeystoreRecordOverheadBytes ||
        memcmp(blob, kRecordMagic, sizeof(kRecordMagic)) != 0 ||
        blob[4] != kFormatVersion || blob[5] != 0 || blob[6] != 0 ||
        blob[7] != 0) {
        return false;
    }
    const uint32_t stored_size = load_u32_le(blob + 8);
    if (stored_size == 0 || stored_size > record.maximum_plaintext_size ||
        blob_size != kKeystoreRecordOverheadBytes + stored_size) {
        return false;
    }
    *plaintext_size = stored_size;
    return true;
}

bool open_record(
    const EncryptedKeystore& keystore,
    const KeystoreRecord& record,
    const uint8_t* blob,
    size_t blob_size,
    uint8_t* plaintext,
    size_t plaintext_capacity,
    size_t* plaintext_size)
{
    const KeystoreRuntime& state = runtime(keystore);
    if (!sealed_record_shape_valid(record, blob, blob_size, plaintext_size) ||
        plaintext_capacity < *plaintext_size) {
        return false;
    }
    uint8_t aad[kMaximumAadBytes] = {};
    size_t aad_size = 0;
    const bool aad_ok = build_record_aad(
        *state.config, record, blob, aad, &aad_size);
    const bool opened = aad_ok && crypto_aead_unlock(
        plaintext,
        blob + kRecordCiphertextOffset + *plaintext_size,
        state.master_key,
        blob + kRecordNonceOffset,
        aad,
        aad_size,
        blob + kRecordCiphertextOffset,
        *plaintext_size) == 0;
    encrypted_keystore_wipe(aad, sizeof(aad));
    if (!opened) {
        encrypted_keystore_wipe(plaintext, plaintext_capacity);
    }
    return opened;
}

bool seal_record(
    EncryptedKeystore& keystore,
    const KeystoreRecord& record,
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size)
{
    KeystoreRuntime& state = runtime(keystore);
    if (plaintext == nullptr || plaintext_size == 0 ||
        plaintext_size > record.maximum_plaintext_size ||
        output_capacity < kKeystoreRecordOverheadBytes + plaintext_size) {
        return false;
    }
    *output_size = kKeystoreRecordOverheadBytes + plaintext_size;
    memset(output, 0, *output_size);
    memcpy(output, kRecordMagic, sizeof(kRecordMagic));
    output[4] = kFormatVersion;
    store_u32_le(output + 8, static_cast<uint32_t>(plaintext_size));
    if (!state.config->random.fill(
            output + kRecordNonceOffset,
            kKeystoreNonceBytes,
            state.config->random.context)) {
        return false;
    }
    uint8_t aad[kMaximumAadBytes] = {};
    size_t aad_size = 0;
    const bool aad_ok = build_record_aad(
        *state.config, record, output, aad, &aad_size);
    if (aad_ok) {
        crypto_aead_lock(
            output + kRecordCiphertextOffset,
            output + kRecordCiphertextOffset + plaintext_size,
            state.master_key,
            output + kRecordNonceOffset,
            aad,
            aad_size,
            plaintext,
            plaintext_size);
    }
    encrypted_keystore_wipe(aad, sizeof(aad));
    return aad_ok;
}

KeystoreBlobReadStatus read_record_blob(
    const EncryptedKeystore& keystore,
    const KeystoreRecord& record,
    uint8_t* output,
    size_t capacity,
    size_t* size)
{
    const KeystoreRuntime& state = runtime(keystore);
    return state.config->storage.read_blob(
        record.storage_key,
        output,
        capacity,
        size,
        state.config->storage.context);
}

void set_material_error(EncryptedKeystore* keystore, KeystoreState state)
{
    KeystoreRuntime& current = runtime(*keystore);
    encrypted_keystore_wipe(current.master_key, sizeof(current.master_key));
    current.state = state;
}

}  // namespace

EncryptedKeystore::EncryptedKeystore()
{
    new (EncryptedKeystoreInternalAccess::bytes(*this)) KeystoreRuntime();
}

EncryptedKeystore::~EncryptedKeystore()
{
    KeystoreRuntime& state = runtime(*this);
    encrypted_keystore_wipe(state.master_key, sizeof(state.master_key));
    state.~KeystoreRuntime();
    encrypted_keystore_wipe(
        EncryptedKeystoreInternalAccess::bytes(*this), 48);
}

bool keystore_kdf_profile_valid(const KeystoreKdfProfile& profile)
{
    return profile.memory_kib >= kMinimumKdfMemoryKib &&
           profile.memory_kib <= kMaximumKdfMemoryKib &&
           profile.memory_kib % 4 == 0 &&
           profile.passes >= 3 && profile.passes <= UINT8_MAX &&
           profile.lanes == 1;
}

bool keystore_pin_valid(const char* pin)
{
    return pin_shape_valid(pin);
}

bool encrypted_keystore_config_valid(const EncryptedKeystoreConfig& config)
{
    return binding_valid(config.target_label, config.target_label_size) &&
           text_key_valid(config.keyslot_storage_key) &&
           keystore_kdf_profile_valid(config.kdf) &&
           config.storage.read_blob != nullptr &&
           config.storage.write_blob != nullptr &&
           config.storage.erase_blob != nullptr &&
           config.random.fill != nullptr;
}

KeystoreState encrypted_keystore_initialize(
    EncryptedKeystore* keystore,
    const EncryptedKeystoreConfig* config)
{
    if (keystore == nullptr) {
        return KeystoreState::storage_error;
    }
    KeystoreOperationGuard operation(*keystore);
    if (!operation.acquired()) {
        return encrypted_keystore_state(keystore);
    }
    KeystoreRuntime& state = runtime(*keystore);
    encrypted_keystore_wipe(state.master_key, sizeof(state.master_key));
    state.config = config;
    state.state = KeystoreState::storage_error;
    if (config == nullptr || !encrypted_keystore_config_valid(*config)) {
        state.state = KeystoreState::storage_error;
        return state.state;
    }
    uint8_t keyslot[kKeystoreKeyslotBytes] = {};
    const KeystoreBlobReadStatus status = read_keyslot(*config, keyslot);
    if (status == KeystoreBlobReadStatus::missing) {
        state.state = KeystoreState::absent;
    } else if (status == KeystoreBlobReadStatus::error) {
        state.state = KeystoreState::storage_error;
    } else {
        state.state = keyslot_header_valid(*config, keyslot)
            ? KeystoreState::locked
            : KeystoreState::invalid;
    }
    encrypted_keystore_wipe(keyslot, sizeof(keyslot));
    return state.state;
}

KeystoreState encrypted_keystore_state(const EncryptedKeystore* keystore)
{
    return keystore == nullptr ? KeystoreState::storage_error
                               : runtime(*keystore).state.load();
}

KeystoreOperationStatus encrypted_keystore_create(
    EncryptedKeystore* keystore,
    char pin[kKeystorePinDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    if (keystore == nullptr) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::invalid_input;
    }
    KeystoreOperationGuard operation(*keystore);
    if (!operation.acquired()) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::busy;
    }
    KeystoreRuntime& state = runtime(*keystore);
    if (state.config == nullptr || state.state != KeystoreState::absent) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::invalid_input;
    }
    if (!kdf_inputs_valid(
            *state.config, pin, kdf_work_area, kdf_work_area_size)) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::invalid_input;
    }
    state.state = KeystoreState::unlocking;
    uint8_t salt[kKeystoreSaltBytes] = {};
    uint8_t nonce[kKeystoreNonceBytes] = {};
    uint8_t master_key[kKeystoreMasterKeyBytes] = {};
    uint8_t wrapping_key[kKeystoreMasterKeyBytes] = {};
    uint8_t confirmation_key[kKeystoreMasterKeyBytes] = {};
    uint8_t candidate[kKeystoreKeyslotBytes] = {};
    const bool prepared =
        state.config->random.fill(
            salt, sizeof(salt), state.config->random.context) &&
        state.config->random.fill(
            nonce, sizeof(nonce), state.config->random.context) &&
        state.config->random.fill(
            master_key, sizeof(master_key), state.config->random.context) &&
        derive_keys(
            *state.config,
            pin,
            salt,
            kdf_work_area,
            kdf_work_area_size,
            wrapping_key,
            confirmation_key) &&
        seal_keyslot(
            *state.config,
            master_key,
            salt,
            nonce,
            wrapping_key,
            confirmation_key,
            candidate);
    wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
    KeystoreOperationStatus status = KeystoreOperationStatus::invalid_input;
    if (prepared) {
        status = commit_keyslot(keystore, candidate, nullptr, false);
        if (status == KeystoreOperationStatus::success) {
            memcpy(state.master_key, master_key, sizeof(master_key));
            state.state = KeystoreState::unlocked;
        } else if (status == KeystoreOperationStatus::unchanged) {
            state.state = KeystoreState::absent;
        }
    } else {
        state.state = KeystoreState::absent;
    }
    encrypted_keystore_wipe(salt, sizeof(salt));
    encrypted_keystore_wipe(nonce, sizeof(nonce));
    encrypted_keystore_wipe(master_key, sizeof(master_key));
    encrypted_keystore_wipe(wrapping_key, sizeof(wrapping_key));
    encrypted_keystore_wipe(confirmation_key, sizeof(confirmation_key));
    encrypted_keystore_wipe(candidate, sizeof(candidate));
    return status;
}

KeystoreOperationStatus encrypted_keystore_unlock(
    EncryptedKeystore* keystore,
    char pin[kKeystorePinDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    if (keystore == nullptr) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::locked;
    }
    KeystoreOperationGuard operation(*keystore);
    if (!operation.acquired()) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::busy;
    }
    KeystoreRuntime& state = runtime(*keystore);
    if (state.config == nullptr || state.state != KeystoreState::locked) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::locked;
    }
    if (!kdf_inputs_valid(
            *state.config, pin, kdf_work_area, kdf_work_area_size)) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::invalid_input;
    }
    state.state = KeystoreState::unlocking;
    uint8_t keyslot[kKeystoreKeyslotBytes] = {};
    uint8_t master_key[kKeystoreMasterKeyBytes] = {};
    const KeystoreOperationStatus status = open_current_keyslot(
        *state.config,
        pin,
        kdf_work_area,
        kdf_work_area_size,
        keyslot,
        master_key);
    if (status == KeystoreOperationStatus::success) {
        memcpy(state.master_key, master_key, sizeof(master_key));
        state.state = KeystoreState::unlocked;
    } else if (status == KeystoreOperationStatus::wrong_pin ||
               status == KeystoreOperationStatus::invalid_input) {
        state.state = KeystoreState::locked;
    } else {
        set_material_error(
            keystore,
            status == KeystoreOperationStatus::storage_error
                ? KeystoreState::storage_error
                : KeystoreState::invalid);
    }
    encrypted_keystore_wipe(keyslot, sizeof(keyslot));
    encrypted_keystore_wipe(master_key, sizeof(master_key));
    return status;
}

KeystoreOperationStatus encrypted_keystore_authenticate_pin(
    EncryptedKeystore* keystore,
    char pin[kKeystorePinDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    if (keystore == nullptr) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::locked;
    }
    KeystoreOperationGuard operation(*keystore);
    if (!operation.acquired()) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::busy;
    }
    KeystoreRuntime& state = runtime(*keystore);
    if (state.config == nullptr || state.state != KeystoreState::unlocked) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::locked;
    }
    if (!kdf_inputs_valid(
            *state.config, pin, kdf_work_area, kdf_work_area_size)) {
        wipe_kdf_inputs(pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::invalid_input;
    }

    state.state = KeystoreState::unlocking;
    uint8_t keyslot[kKeystoreKeyslotBytes] = {};
    uint8_t authenticated_master_key[kKeystoreMasterKeyBytes] = {};
    const KeystoreOperationStatus status = open_current_keyslot(
        *state.config,
        pin,
        kdf_work_area,
        kdf_work_area_size,
        keyslot,
        authenticated_master_key);
    const bool matches = status == KeystoreOperationStatus::success &&
        crypto_verify32(authenticated_master_key, state.master_key) == 0;

    KeystoreOperationStatus result = status;
    if (matches) {
        state.state = KeystoreState::unlocked;
    } else if (status == KeystoreOperationStatus::success) {
        set_material_error(keystore, KeystoreState::invalid);
        result = KeystoreOperationStatus::invalid_record;
    } else if (status == KeystoreOperationStatus::wrong_pin ||
               status == KeystoreOperationStatus::invalid_input) {
        state.state = KeystoreState::unlocked;
    } else {
        set_material_error(
            keystore,
            status == KeystoreOperationStatus::storage_error
                ? KeystoreState::storage_error
                : KeystoreState::invalid);
    }

    encrypted_keystore_wipe(keyslot, sizeof(keyslot));
    encrypted_keystore_wipe(
        authenticated_master_key, sizeof(authenticated_master_key));
    return result;
}

KeystoreOperationStatus encrypted_keystore_rewrap(
    EncryptedKeystore* keystore,
    char current_pin[kKeystorePinDigits + 1],
    char new_pin[kKeystorePinDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    if (keystore == nullptr) {
        encrypted_keystore_wipe(
            current_pin,
            current_pin == nullptr ? 0 : kKeystorePinDigits + 1);
        wipe_kdf_inputs(new_pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::locked;
    }
    KeystoreOperationGuard operation(*keystore);
    if (!operation.acquired()) {
        encrypted_keystore_wipe(
            current_pin,
            current_pin == nullptr ? 0 : kKeystorePinDigits + 1);
        wipe_kdf_inputs(new_pin, kdf_work_area, kdf_work_area_size);
        return KeystoreOperationStatus::busy;
    }
    KeystoreRuntime& state = runtime(*keystore);
    if (state.config == nullptr || state.state != KeystoreState::unlocked ||
        !kdf_inputs_valid(
            *state.config,
            current_pin,
            kdf_work_area,
            kdf_work_area_size) ||
        !pin_shape_valid(new_pin) ||
        memory_ranges_overlap(
            new_pin,
            new_pin == nullptr ? 0 : kKeystorePinBufferBytes,
            kdf_work_area,
            kdf_work_area_size) ||
        memory_ranges_overlap(
            current_pin,
            current_pin == nullptr ? 0 : kKeystorePinDigits + 1,
            new_pin,
            new_pin == nullptr ? 0 : kKeystorePinDigits + 1)) {
        encrypted_keystore_wipe(
            current_pin,
            current_pin == nullptr ? 0 : kKeystorePinDigits + 1);
        wipe_kdf_inputs(new_pin, kdf_work_area, kdf_work_area_size);
        return state.state == KeystoreState::unlocked
            ? KeystoreOperationStatus::invalid_input
            : KeystoreOperationStatus::locked;
    }
    state.state = KeystoreState::unlocking;
    uint8_t previous[kKeystoreKeyslotBytes] = {};
    uint8_t authenticated_master_key[kKeystoreMasterKeyBytes] = {};
    const KeystoreOperationStatus current_status = open_current_keyslot(
        *state.config,
        current_pin,
        kdf_work_area,
        kdf_work_area_size,
        previous,
        authenticated_master_key);
    const bool current_matches =
        current_status == KeystoreOperationStatus::success &&
        crypto_verify32(authenticated_master_key, state.master_key) == 0;
    encrypted_keystore_wipe(
        authenticated_master_key, sizeof(authenticated_master_key));
    if (!current_matches) {
        wipe_kdf_inputs(new_pin, kdf_work_area, kdf_work_area_size);
        encrypted_keystore_wipe(previous, sizeof(previous));
        if (current_status == KeystoreOperationStatus::success) {
            set_material_error(keystore, KeystoreState::invalid);
            return KeystoreOperationStatus::invalid_record;
        }
        if (current_status == KeystoreOperationStatus::wrong_pin ||
            current_status == KeystoreOperationStatus::invalid_input) {
            state.state = KeystoreState::unlocked;
        } else {
            set_material_error(
                keystore,
                current_status == KeystoreOperationStatus::storage_error
                    ? KeystoreState::storage_error
                    : KeystoreState::invalid);
        }
        return current_status;
    }
    uint8_t salt[kKeystoreSaltBytes] = {};
    uint8_t nonce[kKeystoreNonceBytes] = {};
    uint8_t wrapping_key[kKeystoreMasterKeyBytes] = {};
    uint8_t confirmation_key[kKeystoreMasterKeyBytes] = {};
    uint8_t candidate[kKeystoreKeyslotBytes] = {};
    const bool prepared =
        state.config->random.fill(
            salt, sizeof(salt), state.config->random.context) &&
        state.config->random.fill(
            nonce, sizeof(nonce), state.config->random.context) &&
        derive_keys(
            *state.config,
            new_pin,
            salt,
            kdf_work_area,
            kdf_work_area_size,
            wrapping_key,
            confirmation_key) &&
        seal_keyslot(
            *state.config,
            state.master_key,
            salt,
            nonce,
            wrapping_key,
            confirmation_key,
            candidate);
    wipe_kdf_inputs(new_pin, kdf_work_area, kdf_work_area_size);
    KeystoreOperationStatus status = KeystoreOperationStatus::invalid_input;
    if (prepared) {
        status = commit_keyslot(keystore, candidate, previous, true);
    }
    if (status == KeystoreOperationStatus::success ||
        status == KeystoreOperationStatus::unchanged ||
        status == KeystoreOperationStatus::invalid_input) {
        state.state = KeystoreState::unlocked;
    }
    encrypted_keystore_wipe(previous, sizeof(previous));
    encrypted_keystore_wipe(salt, sizeof(salt));
    encrypted_keystore_wipe(nonce, sizeof(nonce));
    encrypted_keystore_wipe(wrapping_key, sizeof(wrapping_key));
    encrypted_keystore_wipe(confirmation_key, sizeof(confirmation_key));
    encrypted_keystore_wipe(candidate, sizeof(candidate));
    return status;
}

KeystoreOperationStatus encrypted_keystore_lock(EncryptedKeystore* keystore)
{
    if (keystore == nullptr) {
        return KeystoreOperationStatus::invalid_input;
    }
    KeystoreOperationGuard operation(*keystore);
    if (!operation.acquired()) {
        return KeystoreOperationStatus::busy;
    }
    KeystoreRuntime& state = runtime(*keystore);
    encrypted_keystore_wipe(state.master_key, sizeof(state.master_key));
    if (state.state == KeystoreState::unlocked ||
        state.state == KeystoreState::unlocking) {
        state.state = KeystoreState::locked;
    }
    return KeystoreOperationStatus::success;
}

KeystoreOperationStatus encrypted_keystore_check_record(
    EncryptedKeystore* keystore,
    const KeystoreRecord& record,
    uint8_t* blob_scratch,
    size_t blob_scratch_size)
{
    if (keystore == nullptr) {
        encrypted_keystore_wipe(blob_scratch, blob_scratch_size);
        return KeystoreOperationStatus::invalid_input;
    }
    KeystoreOperationGuard operation(*keystore);
    if (!operation.acquired()) {
        encrypted_keystore_wipe(blob_scratch, blob_scratch_size);
        return KeystoreOperationStatus::busy;
    }
    KeystoreRuntime& state = runtime(*keystore);
    if (state.config == nullptr || !record_valid(*state.config, record) ||
        blob_scratch == nullptr ||
        blob_scratch_size <
            kKeystoreRecordOverheadBytes + record.maximum_plaintext_size) {
        encrypted_keystore_wipe(blob_scratch, blob_scratch_size);
        return KeystoreOperationStatus::invalid_input;
    }

    size_t blob_size = 0;
    const KeystoreBlobReadStatus read_status = read_record_blob(
        *keystore,
        record,
        blob_scratch,
        blob_scratch_size,
        &blob_size);
    if (read_status == KeystoreBlobReadStatus::missing) {
        encrypted_keystore_wipe(blob_scratch, blob_scratch_size);
        return KeystoreOperationStatus::missing;
    }
    if (read_status != KeystoreBlobReadStatus::found) {
        set_material_error(keystore, KeystoreState::storage_error);
        encrypted_keystore_wipe(blob_scratch, blob_scratch_size);
        return KeystoreOperationStatus::storage_error;
    }

    size_t plaintext_size = 0;
    const bool valid = sealed_record_shape_valid(
        record, blob_scratch, blob_size, &plaintext_size);
    encrypted_keystore_wipe(blob_scratch, blob_scratch_size);
    if (!valid) {
        set_material_error(keystore, KeystoreState::invalid);
        return KeystoreOperationStatus::invalid_record;
    }
    return KeystoreOperationStatus::success;
}

KeystoreOperationStatus encrypted_keystore_with_record(
    EncryptedKeystore* keystore,
    const KeystoreRecord& record,
    KeystoreRecordScratch* scratch,
    KeystoreRecordConsumer consumer,
    void* consumer_context)
{
    if (keystore == nullptr ||
        runtime(*keystore).state != KeystoreState::unlocked) {
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::locked;
    }
    KeystoreOperationGuard operation(*keystore);
    if (!operation.acquired()) {
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::busy;
    }
    if (runtime(*keystore).state != KeystoreState::unlocked) {
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::locked;
    }
    if (!record_valid(*runtime(*keystore).config, record) ||
        !scratch_valid(record, scratch) ||
        consumer == nullptr) {
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::invalid_input;
    }
    size_t blob_size = 0;
    const KeystoreBlobReadStatus status = read_record_blob(
        *keystore,
        record,
        scratch->readback_blob,
        scratch->blob_capacity,
        &blob_size);
    if (status == KeystoreBlobReadStatus::missing) {
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::missing;
    }
    if (status != KeystoreBlobReadStatus::found) {
        set_material_error(keystore, KeystoreState::storage_error);
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::storage_error;
    }
    size_t plaintext_size = 0;
    if (!open_record(
            *keystore,
            record,
            scratch->readback_blob,
            blob_size,
            scratch->plaintext,
            scratch->plaintext_capacity,
            &plaintext_size)) {
        set_material_error(keystore, KeystoreState::invalid);
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::invalid_record;
    }
    const bool consumed = consumer(
        scratch->plaintext, plaintext_size, consumer_context);
    wipe_record_scratch(scratch);
    return consumed ? KeystoreOperationStatus::success
                    : KeystoreOperationStatus::consumer_failed;
}

KeystoreOperationStatus encrypted_keystore_replace_record(
    EncryptedKeystore* keystore,
    const KeystoreRecord& record,
    const uint8_t* plaintext,
    size_t plaintext_size,
    KeystoreRecordScratch* scratch)
{
    if (keystore == nullptr ||
        runtime(*keystore).state != KeystoreState::unlocked) {
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::locked;
    }
    KeystoreOperationGuard operation(*keystore);
    if (!operation.acquired()) {
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::busy;
    }
    if (runtime(*keystore).state != KeystoreState::unlocked) {
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::locked;
    }
    if (!record_valid(*runtime(*keystore).config, record) ||
        !scratch_valid(record, scratch) ||
        plaintext == nullptr || plaintext_size == 0 ||
        plaintext_size > record.maximum_plaintext_size ||
        !plaintext_separate_from_scratch(plaintext, plaintext_size, scratch)) {
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::invalid_input;
    }
    size_t previous_size = 0;
    const KeystoreBlobReadStatus previous_status = read_record_blob(
        *keystore,
        record,
        scratch->previous_blob,
        scratch->blob_capacity,
        &previous_size);
    if (previous_status == KeystoreBlobReadStatus::error) {
        set_material_error(keystore, KeystoreState::storage_error);
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::storage_error;
    }
    if (previous_status == KeystoreBlobReadStatus::found) {
        size_t old_plaintext_size = 0;
        if (!open_record(
                *keystore,
                record,
                scratch->previous_blob,
                previous_size,
                scratch->plaintext,
                scratch->plaintext_capacity,
                &old_plaintext_size)) {
            set_material_error(keystore, KeystoreState::invalid);
            wipe_record_scratch(scratch);
            return KeystoreOperationStatus::invalid_record;
        }
        encrypted_keystore_wipe(scratch->plaintext, scratch->plaintext_capacity);
    }
    size_t candidate_size = 0;
    if (!seal_record(
            *keystore,
            record,
            plaintext,
            plaintext_size,
            scratch->candidate_blob,
            scratch->blob_capacity,
            &candidate_size)) {
        wipe_record_scratch(scratch);
        return KeystoreOperationStatus::invalid_input;
    }
    KeystoreRuntime& state = runtime(*keystore);
    state.config->storage.write_blob(
        record.storage_key,
        scratch->candidate_blob,
        candidate_size,
        state.config->storage.context);
    size_t readback_size = 0;
    const KeystoreBlobReadStatus readback_status = read_record_blob(
        *keystore,
        record,
        scratch->readback_blob,
        scratch->blob_capacity,
        &readback_size);
    const bool matches_new =
        readback_status == KeystoreBlobReadStatus::found &&
        readback_size == candidate_size &&
        memcmp(scratch->readback_blob, scratch->candidate_blob, candidate_size) == 0;
    if (matches_new) {
        size_t verified_size = 0;
        const bool opened = open_record(
            *keystore,
            record,
            scratch->readback_blob,
            readback_size,
            scratch->plaintext,
            scratch->plaintext_capacity,
            &verified_size);
        const bool exact = opened && verified_size == plaintext_size &&
                           memcmp(scratch->plaintext, plaintext, plaintext_size) == 0;
        wipe_record_scratch(scratch);
        if (exact) {
            return KeystoreOperationStatus::success;
        }
        set_material_error(keystore, KeystoreState::storage_error);
        return KeystoreOperationStatus::storage_error;
    }
    const bool matches_previous =
        previous_status == KeystoreBlobReadStatus::found &&
        readback_status == KeystoreBlobReadStatus::found &&
        readback_size == previous_size &&
        memcmp(scratch->readback_blob, scratch->previous_blob, previous_size) == 0;
    const bool remains_missing =
        previous_status == KeystoreBlobReadStatus::missing &&
        readback_status == KeystoreBlobReadStatus::missing;
    wipe_record_scratch(scratch);
    if (matches_previous || remains_missing) {
        return KeystoreOperationStatus::unchanged;
    }
    set_material_error(keystore, KeystoreState::storage_error);
    return KeystoreOperationStatus::storage_error;
}

KeystoreOperationStatus encrypted_keystore_erase(
    EncryptedKeystore* keystore,
    const KeystoreRecord* records,
    size_t record_count)
{
    if (keystore == nullptr ||
        (record_count > 0 && records == nullptr)) {
        return KeystoreOperationStatus::invalid_input;
    }
    KeystoreOperationGuard operation(*keystore);
    if (!operation.acquired()) {
        return KeystoreOperationStatus::busy;
    }
    KeystoreRuntime& state = runtime(*keystore);
    if (state.config == nullptr) {
        return KeystoreOperationStatus::invalid_input;
    }
    encrypted_keystore_wipe(state.master_key, sizeof(state.master_key));
    if (state.state == KeystoreState::unlocked ||
        state.state == KeystoreState::unlocking) {
        state.state = KeystoreState::locked;
    }
    bool ok = true;
    for (size_t index = 0; index < record_count; ++index) {
        if (!record_valid(*state.config, records[index]) ||
            !state.config->storage.erase_blob(
                records[index].storage_key,
                state.config->storage.context)) {
            ok = false;
        }
    }
    if (!state.config->storage.erase_blob(
            state.config->keyslot_storage_key,
            state.config->storage.context)) {
        ok = false;
    }
    for (size_t index = 0; index < record_count; ++index) {
        if (!record_valid(*state.config, records[index])) {
            ok = false;
            continue;
        }
        size_t ignored_size = 0;
        if (state.config->storage.read_blob(
                records[index].storage_key,
                nullptr,
                0,
                &ignored_size,
                state.config->storage.context) !=
            KeystoreBlobReadStatus::missing) {
            ok = false;
        }
    }
    if (!ok) {
        state.state = KeystoreState::storage_error;
        return KeystoreOperationStatus::storage_error;
    }
    uint8_t keyslot[kKeystoreKeyslotBytes] = {};
    const KeystoreBlobReadStatus status = read_keyslot(*state.config, keyslot);
    encrypted_keystore_wipe(keyslot, sizeof(keyslot));
    if (status != KeystoreBlobReadStatus::missing) {
        state.state = KeystoreState::storage_error;
        return KeystoreOperationStatus::storage_error;
    }
    state.state = KeystoreState::absent;
    return KeystoreOperationStatus::success;
}

void encrypted_keystore_wipe(void* bytes, size_t byte_count)
{
    if (bytes != nullptr && byte_count > 0) {
        crypto_wipe(bytes, byte_count);
    }
}

}  // namespace signing
