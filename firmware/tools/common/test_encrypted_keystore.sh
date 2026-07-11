#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
MONOCYPHER_ROOT="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib/src/microsui_core"
CXX_BIN="${CXX:-c++}"
CC_BIN="${CC:-cc}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/encrypted-keystore.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "keystore/encrypted_keystore.h"

namespace {

using signing::EncryptedKeystore;
using signing::EncryptedKeystoreConfig;
using signing::KeystoreBlobReadStatus;
using signing::KeystoreOperationStatus;
using signing::KeystoreRecord;
using signing::KeystoreRecordScratch;
using signing::KeystoreState;

constexpr uint8_t kTargetLabel[] = "test-target";
constexpr uint8_t kOtherTargetLabel[] = "other-target";
constexpr uint8_t kRecordId[] = "root";
constexpr uint8_t kWrongRecordId[] = "credential";
constexpr size_t kPlaintextBytes = 32;
constexpr size_t kBlobBytes =
    signing::kKeystoreRecordOverheadBytes + kPlaintextBytes;

const uint8_t kExpectedKeyslot[signing::kKeystoreKeyslotBytes] = {
    0x41,0x51,0x4b,0x53,0x01,0x01,0x01,0x03,0x40,0x00,0x00,0x00,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
    0x1c,0x1d,0x1e,0x1f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
    0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,
    0x64,0x65,0x66,0x67,0xd2,0x74,0xca,0x4d,0xb4,0x20,0x3f,0x5e,
    0x9d,0x8f,0x2a,0xf6,0x17,0xff,0xbe,0x49,0xd9,0xe8,0x59,0x43,
    0x55,0x08,0x7a,0xc4,0xad,0xcc,0xbc,0x35,0xef,0x30,0x91,0xec,
    0x58,0xee,0x58,0x24,0xbb,0xf4,0x94,0x48,0x8b,0x63,0xf0,0x1c,
    0xf7,0x14,0xc3,0x8c,0x8a,0x44,0x90,0x3f,0x26,0x68,0x83,0x75,
    0xbc,0x41,0xc4,0xbb,0x53,0xc6,0x43,0xf0,
};

const uint8_t kExpectedOneDigitKeyslot[signing::kKeystoreKeyslotBytes] = {
    0x41,0x51,0x4b,0x53,0x01,0x01,0x01,0x03,0x40,0x00,0x00,0x00,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
    0x1c,0x1d,0x1e,0x1f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
    0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,
    0x64,0x65,0x66,0x67,0xf9,0xc3,0x90,0x5b,0x4c,0x0b,0x25,0xee,
    0x2d,0xe6,0x10,0xc5,0xb4,0x56,0xa4,0x5d,0x46,0x59,0x01,0xb8,
    0xda,0x80,0x00,0x9b,0x71,0x97,0x21,0x70,0x39,0x65,0xee,0x3a,
    0x53,0xff,0xec,0xaf,0x83,0x4b,0xb1,0xcd,0x8e,0x57,0x34,0x09,
    0x9c,0x60,0x76,0x07,0x06,0x7c,0x28,0xcc,0x05,0xd7,0xe9,0x49,
    0x15,0x58,0xf2,0x13,0x47,0xdc,0x5e,0xfd,
};

const uint8_t kExpectedRootRecord[kBlobBytes] = {
    0x41,0x51,0x4b,0x52,0x01,0x00,0x00,0x00,0x20,0x00,0x00,0x00,
    0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xdb,
    0xdc,0xdd,0xde,0xdf,0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,
    0x4d,0xdc,0x5c,0xf4,0x53,0xcf,0xcb,0xe7,0xaa,0x49,0x62,0xda,
    0x5e,0xba,0xde,0x46,0x1c,0x89,0xd3,0xd4,0xcd,0x46,0x5c,0x15,
    0x3c,0xda,0x3f,0x11,0x57,0x30,0xcd,0xc3,0xcb,0x83,0xda,0x8a,
    0xb2,0x5a,0xa3,0x6e,0x69,0x00,0x6e,0x72,0x70,0x04,0x1d,0xe0,
};

enum class WriteMode {
    normal,
    fail_before_write,
    apply_then_fail,
    corrupt_after_write,
};

struct FakeStore {
    std::map<std::string, std::vector<uint8_t>> blobs;
    WriteMode next_write = WriteMode::normal;
    bool read_error = false;
    bool erase_error = false;
    bool erase_without_change = false;
    size_t read_count = 0;
};

struct FakeRandom {
    uint8_t next = 0x10;
    bool fail = false;
    size_t fill_count = 0;
};

struct Scratch {
    uint8_t previous[kBlobBytes] = {};
    uint8_t candidate[kBlobBytes] = {};
    uint8_t readback[kBlobBytes] = {};
    uint8_t plaintext[kPlaintextBytes] = {};

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

bool all_zero(const void* bytes, size_t size)
{
    const auto* cursor = static_cast<const uint8_t*>(bytes);
    for (size_t index = 0; index < size; ++index) {
        if (cursor[index] != 0) {
            return false;
        }
    }
    return true;
}

bool contains_sequence(
    const uint8_t* bytes,
    size_t byte_count,
    const uint8_t* needle,
    size_t needle_count)
{
    if (bytes == nullptr || needle == nullptr || needle_count == 0 ||
        needle_count > byte_count) {
        return false;
    }
    for (size_t offset = 0; offset <= byte_count - needle_count; ++offset) {
        if (memcmp(bytes + offset, needle, needle_count) == 0) {
            return true;
        }
    }
    return false;
}

KeystoreBlobReadStatus read_blob(
    const char* key,
    uint8_t* output,
    size_t capacity,
    size_t* size,
    void* context)
{
    auto* store = static_cast<FakeStore*>(context);
    if (store == nullptr || key == nullptr || size == nullptr) {
        return KeystoreBlobReadStatus::error;
    }
    ++store->read_count;
    if (store->read_error) {
        return KeystoreBlobReadStatus::error;
    }
    const auto found = store->blobs.find(key);
    if (found == store->blobs.end()) {
        *size = 0;
        return KeystoreBlobReadStatus::missing;
    }
    if (output == nullptr || capacity < found->second.size()) {
        return KeystoreBlobReadStatus::error;
    }
    memcpy(output, found->second.data(), found->second.size());
    *size = found->second.size();
    return KeystoreBlobReadStatus::found;
}

bool write_blob(
    const char* key,
    const uint8_t* value,
    size_t size,
    void* context)
{
    auto* store = static_cast<FakeStore*>(context);
    const WriteMode mode = store->next_write;
    store->next_write = WriteMode::normal;
    if (mode == WriteMode::fail_before_write) {
        return false;
    }
    store->blobs[key] = std::vector<uint8_t>(value, value + size);
    if (mode == WriteMode::corrupt_after_write) {
        store->blobs[key][0] ^= 0x80;
        return false;
    }
    return mode != WriteMode::apply_then_fail;
}

bool erase_blob(const char* key, void* context)
{
    auto* store = static_cast<FakeStore*>(context);
    if (store->erase_error) {
        return false;
    }
    if (store->erase_without_change) {
        return true;
    }
    store->blobs.erase(key);
    return true;
}

bool fill_random(uint8_t* output, size_t size, void* context)
{
    auto* random = static_cast<FakeRandom*>(context);
    if (random == nullptr || output == nullptr || random->fail) {
        return false;
    }
    ++random->fill_count;
    for (size_t index = 0; index < size; ++index) {
        output[index] = static_cast<uint8_t>(random->next + index);
    }
    random->next = static_cast<uint8_t>(random->next + 0x40);
    return true;
}

EncryptedKeystoreConfig config_for(
    FakeStore* store,
    FakeRandom* random,
    const uint8_t* target = kTargetLabel,
    size_t target_size = sizeof(kTargetLabel) - 1,
    size_t minimum_pin_digits = 6,
    size_t maximum_pin_digits = 6)
{
    return {
        target,
        target_size,
        "keyslot",
        minimum_pin_digits,
        maximum_pin_digits,
        {64, 3, 1},
        {read_blob, write_blob, erase_blob, store},
        {fill_random, random},
    };
}

KeystoreRecord record_for(const uint8_t* id = kRecordId, size_t id_size = sizeof(kRecordId) - 1)
{
    return {"root", id, id_size, kPlaintextBytes};
}

void set_pin(char output[signing::kKeystorePinBufferBytes], const char* pin)
{
    memset(output, 0, signing::kKeystorePinBufferBytes);
    memcpy(output, pin, strlen(pin));
}

bool capture_consumer(const uint8_t* plaintext, size_t size, void* context)
{
    auto* output = static_cast<std::vector<uint8_t>*>(context);
    output->assign(plaintext, plaintext + size);
    return true;
}

bool reject_consumer(const uint8_t*, size_t, void*)
{
    return false;
}

struct ReentrantLockContext {
    EncryptedKeystore* keystore = nullptr;
    KeystoreOperationStatus status = KeystoreOperationStatus::invalid_input;
};

bool attempt_reentrant_lock(const uint8_t*, size_t, void* context)
{
    auto* lock = static_cast<ReentrantLockContext*>(context);
    lock->status = signing::encrypted_keystore_lock(lock->keystore);
    return true;
}

struct ReentrantAuthenticationContext {
    EncryptedKeystore* keystore = nullptr;
    char pin[signing::kKeystorePinBufferBytes] = {};
    std::vector<uint8_t> work;
    KeystoreOperationStatus status = KeystoreOperationStatus::invalid_input;
};

bool attempt_reentrant_authentication(const uint8_t*, size_t, void* context)
{
    auto* authentication =
        static_cast<ReentrantAuthenticationContext*>(context);
    authentication->status = signing::encrypted_keystore_authenticate_pin(
        authentication->keystore,
        authentication->pin,
        authentication->work.data(),
        authentication->work.size());
    return true;
}

void expect_scratch_wiped(const Scratch& scratch)
{
    assert(all_zero(&scratch, sizeof(scratch)));
}

}  // namespace

int main()
{
    assert(!signing::keystore_pin_policy_valid(0, 4));
    assert(!signing::keystore_pin_policy_valid(4, 3));
    assert(!signing::keystore_pin_policy_valid(
        1, signing::kKeystoreMaximumPinDigits + 1));
    assert(signing::keystore_pin_policy_valid(1, 4));
    assert(signing::keystore_pin_policy_valid(6, 6));
    assert(signing::keystore_pin_valid("1", 1, 4));
    assert(signing::keystore_pin_valid("1234", 1, 4));
    assert(!signing::keystore_pin_valid("", 1, 4));
    assert(!signing::keystore_pin_valid("12345", 1, 4));
    assert(!signing::keystore_pin_valid("12a4", 1, 4));
    assert(!signing::keystore_pin_valid("1234", 6, 6));
    assert(signing::keystore_pin_valid("123456", 6, 6));

    for (const char* accepted_pin : {"1", "12", "123", "1234"}) {
        FakeStore variable_store;
        FakeRandom variable_random;
        EncryptedKeystoreConfig variable_config = config_for(
            &variable_store,
            &variable_random,
            kTargetLabel,
            sizeof(kTargetLabel) - 1,
            1,
            4);
        EncryptedKeystore variable_keystore;
        assert(signing::encrypted_keystore_initialize(
                   &variable_keystore, &variable_config) ==
               KeystoreState::absent);
        std::vector<uint8_t> variable_work(
            variable_config.kdf.memory_kib * 1024, 0xA5);
        char variable_pin[signing::kKeystorePinBufferBytes] = {};
        set_pin(variable_pin, accepted_pin);
        assert(signing::encrypted_keystore_create(
                   &variable_keystore,
                   variable_pin,
                   variable_work.data(),
                   variable_work.size()) == KeystoreOperationStatus::success);
        assert(all_zero(variable_pin, sizeof(variable_pin)));
        assert(all_zero(variable_work.data(), variable_work.size()));
        assert(signing::encrypted_keystore_lock(&variable_keystore) ==
               KeystoreOperationStatus::success);
        set_pin(variable_pin, accepted_pin);
        memset(variable_work.data(), 0xA5, variable_work.size());
        assert(signing::encrypted_keystore_unlock(
                   &variable_keystore,
                   variable_pin,
                   variable_work.data(),
                   variable_work.size()) == KeystoreOperationStatus::success);
    }

    {
        FakeStore one_digit_store;
        FakeRandom one_digit_random;
        EncryptedKeystoreConfig one_digit_config = config_for(
            &one_digit_store,
            &one_digit_random,
            kTargetLabel,
            sizeof(kTargetLabel) - 1,
            1,
            4);
        EncryptedKeystore one_digit_keystore;
        assert(signing::encrypted_keystore_initialize(
                   &one_digit_keystore, &one_digit_config) ==
               KeystoreState::absent);
        std::vector<uint8_t> one_digit_work(
            one_digit_config.kdf.memory_kib * 1024, 0xA5);
        char one_digit_pin[signing::kKeystorePinBufferBytes] = {};
        set_pin(one_digit_pin, "1");
        assert(signing::encrypted_keystore_create(
                   &one_digit_keystore,
                   one_digit_pin,
                   one_digit_work.data(),
                   one_digit_work.size()) == KeystoreOperationStatus::success);
        assert(one_digit_store.blobs.at("keyslot").size() ==
               sizeof(kExpectedOneDigitKeyslot));
        assert(memcmp(
                   one_digit_store.blobs.at("keyslot").data(),
                   kExpectedOneDigitKeyslot,
                   sizeof(kExpectedOneDigitKeyslot)) == 0);
        assert(signing::encrypted_keystore_lock(&one_digit_keystore) ==
               KeystoreOperationStatus::success);
        set_pin(one_digit_pin, "01");
        memset(one_digit_work.data(), 0xA5, one_digit_work.size());
        assert(signing::encrypted_keystore_unlock(
                   &one_digit_keystore,
                   one_digit_pin,
                   one_digit_work.data(),
                   one_digit_work.size()) == KeystoreOperationStatus::wrong_pin);
    }

    for (const auto invalid_policy : {
             std::pair<size_t, size_t>{0, 4},
             std::pair<size_t, size_t>{4, 3},
             std::pair<size_t, size_t>{1, 7}}) {
        FakeStore invalid_policy_store;
        FakeRandom invalid_policy_random;
        EncryptedKeystoreConfig invalid_policy_config = config_for(
            &invalid_policy_store,
            &invalid_policy_random,
            kTargetLabel,
            sizeof(kTargetLabel) - 1,
            invalid_policy.first,
            invalid_policy.second);
        EncryptedKeystore invalid_policy_keystore;
        assert(signing::encrypted_keystore_initialize(
                   &invalid_policy_keystore, &invalid_policy_config) ==
               KeystoreState::storage_error);
    }

    assert(!signing::keystore_kdf_profile_valid({63, 3, 1}));
    assert(signing::keystore_kdf_profile_valid({64, 3, 1}));
    assert(signing::keystore_kdf_profile_valid({512, 255, 1}));
    assert(!signing::keystore_kdf_profile_valid({513, 3, 1}));
    assert(!signing::keystore_kdf_profile_valid({64, 2, 1}));
    assert(!signing::keystore_kdf_profile_valid({64, 3, 2}));

    // Pre-KDF failures still wipe PIN and the entire caller-owned work area.
    {
        FakeStore failed_store;
        FakeRandom failed_random;
        failed_random.fail = true;
        EncryptedKeystoreConfig failed_config =
            config_for(&failed_store, &failed_random);
        EncryptedKeystore failed_keystore;
        assert(signing::encrypted_keystore_initialize(
                   &failed_keystore, &failed_config) == KeystoreState::absent);
        std::vector<uint8_t> failed_work(
            failed_config.kdf.memory_kib * 1024, 0xA5);
        char failed_pin[signing::kKeystorePinBufferBytes];
        set_pin(failed_pin, "123456");
        assert(signing::encrypted_keystore_create(
                   &failed_keystore,
                   failed_pin,
                   failed_work.data(),
                   failed_work.size()) == KeystoreOperationStatus::invalid_input);
        assert(all_zero(failed_pin, sizeof(failed_pin)));
        assert(all_zero(failed_work.data(), failed_work.size()));
    }
    {
        FakeStore misaligned_store;
        FakeRandom misaligned_random;
        EncryptedKeystoreConfig misaligned_config =
            config_for(&misaligned_store, &misaligned_random);
        EncryptedKeystore misaligned_keystore;
        assert(signing::encrypted_keystore_initialize(
                   &misaligned_keystore, &misaligned_config) ==
               KeystoreState::absent);
        const size_t work_size = misaligned_config.kdf.memory_kib * 1024u;
        std::vector<uint8_t> raw_work(work_size + 1, 0xA5);
        uint8_t* misaligned_work = raw_work.data() + 1;
        assert(reinterpret_cast<uintptr_t>(misaligned_work) %
                   signing::kKeystoreKdfWorkAreaAlignment !=
               0);
        char misaligned_pin[signing::kKeystorePinBufferBytes];
        set_pin(misaligned_pin, "123456");
        assert(signing::encrypted_keystore_create(
                   &misaligned_keystore,
                   misaligned_pin,
                   misaligned_work,
                   work_size) == KeystoreOperationStatus::invalid_input);
        assert(all_zero(misaligned_pin, sizeof(misaligned_pin)));
        assert(all_zero(misaligned_work, work_size));
        assert(misaligned_random.fill_count == 0);
        assert(misaligned_store.blobs.empty());
        assert(signing::encrypted_keystore_state(&misaligned_keystore) ==
               KeystoreState::absent);
    }

    // Initialization and first commit classify storage results by readback.
    {
        FakeStore commit_store;
        FakeRandom commit_random;
        EncryptedKeystoreConfig commit_config =
            config_for(&commit_store, &commit_random);
        EncryptedKeystore commit_keystore;
        commit_store.read_error = true;
        assert(signing::encrypted_keystore_initialize(
                   &commit_keystore, &commit_config) ==
               KeystoreState::storage_error);
        commit_store.read_error = false;
        assert(signing::encrypted_keystore_initialize(
                   &commit_keystore, &commit_config) == KeystoreState::absent);
        std::vector<uint8_t> commit_work(
            commit_config.kdf.memory_kib * 1024, 0xA5);
        char commit_pin[signing::kKeystorePinBufferBytes];
        commit_store.next_write = WriteMode::fail_before_write;
        set_pin(commit_pin, "111111");
        assert(signing::encrypted_keystore_create(
                   &commit_keystore,
                   commit_pin,
                   commit_work.data(),
                   commit_work.size()) == KeystoreOperationStatus::unchanged);
        assert(signing::encrypted_keystore_state(&commit_keystore) ==
               KeystoreState::absent);
        commit_store.next_write = WriteMode::apply_then_fail;
        set_pin(commit_pin, "111111");
        assert(signing::encrypted_keystore_create(
                   &commit_keystore,
                   commit_pin,
                   commit_work.data(),
                   commit_work.size()) == KeystoreOperationStatus::success);
        assert(signing::encrypted_keystore_state(&commit_keystore) ==
               KeystoreState::unlocked);
    }

    // Rewrap authenticates the current persisted keyslot, not only RAM state.
    {
        FakeStore primary_store;
        FakeRandom primary_random;
        EncryptedKeystoreConfig primary_config =
            config_for(&primary_store, &primary_random);
        EncryptedKeystore primary;
        assert(signing::encrypted_keystore_initialize(&primary, &primary_config) ==
               KeystoreState::absent);
        std::vector<uint8_t> primary_work(
            primary_config.kdf.memory_kib * 1024, 0xA5);
        char primary_pin[signing::kKeystorePinBufferBytes];
        set_pin(primary_pin, "111111");
        assert(signing::encrypted_keystore_create(
                   &primary,
                   primary_pin,
                   primary_work.data(),
                   primary_work.size()) == KeystoreOperationStatus::success);

        FakeStore foreign_store;
        FakeRandom foreign_random;
        foreign_random.next = 0x33;
        EncryptedKeystoreConfig foreign_config =
            config_for(&foreign_store, &foreign_random);
        EncryptedKeystore foreign;
        assert(signing::encrypted_keystore_initialize(&foreign, &foreign_config) ==
               KeystoreState::absent);
        std::vector<uint8_t> foreign_work(
            foreign_config.kdf.memory_kib * 1024, 0xA5);
        char foreign_pin[signing::kKeystorePinBufferBytes];
        set_pin(foreign_pin, "444444");
        assert(signing::encrypted_keystore_create(
                   &foreign,
                   foreign_pin,
                   foreign_work.data(),
                   foreign_work.size()) == KeystoreOperationStatus::success);

        FakeStore authentication_store = primary_store;
        FakeRandom authentication_random;
        EncryptedKeystoreConfig authentication_config =
            config_for(&authentication_store, &authentication_random);
        EncryptedKeystore authentication_keystore;
        assert(signing::encrypted_keystore_initialize(
                   &authentication_keystore, &authentication_config) ==
               KeystoreState::locked);
        std::vector<uint8_t> authentication_work(
            authentication_config.kdf.memory_kib * 1024, 0xA5);
        char authentication_pin[signing::kKeystorePinBufferBytes];
        set_pin(authentication_pin, "111111");
        assert(signing::encrypted_keystore_unlock(
                   &authentication_keystore,
                   authentication_pin,
                   authentication_work.data(),
                   authentication_work.size()) ==
               KeystoreOperationStatus::success);
        authentication_store.blobs["keyslot"] =
            foreign_store.blobs.at("keyslot");
        set_pin(authentication_pin, "444444");
        memset(authentication_work.data(), 0xA5, authentication_work.size());
        assert(signing::encrypted_keystore_authenticate_pin(
                   &authentication_keystore,
                   authentication_pin,
                   authentication_work.data(),
                   authentication_work.size()) ==
               KeystoreOperationStatus::invalid_record);
        assert(signing::encrypted_keystore_state(&authentication_keystore) ==
               KeystoreState::invalid);
        assert(all_zero(authentication_pin, sizeof(authentication_pin)));
        assert(all_zero(
            authentication_work.data(), authentication_work.size()));

        primary_store.blobs["keyslot"] = foreign_store.blobs.at("keyslot");
        char replacement_pin[signing::kKeystorePinBufferBytes];
        set_pin(foreign_pin, "444444");
        set_pin(replacement_pin, "555555");
        memset(primary_work.data(), 0xA5, primary_work.size());
        assert(signing::encrypted_keystore_rewrap(
                   &primary,
                   foreign_pin,
                   replacement_pin,
                   primary_work.data(),
                   primary_work.size()) == KeystoreOperationStatus::invalid_record);
        assert(signing::encrypted_keystore_state(&primary) ==
               KeystoreState::invalid);
    }

    FakeStore store;
    FakeRandom random;
    EncryptedKeystoreConfig config = config_for(&store, &random);
    EncryptedKeystore keystore;
    assert(signing::encrypted_keystore_initialize(&keystore, &config) ==
           KeystoreState::absent);

    std::vector<uint8_t> work(config.kdf.memory_kib * 1024, 0xA5);
    char pin[signing::kKeystorePinBufferBytes];
    set_pin(pin, "123456");
    assert(signing::encrypted_keystore_create(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::success);
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::unlocked);
    assert(all_zero(pin, sizeof(pin)));
    assert(all_zero(work.data(), work.size()));
    assert(store.blobs.at("keyslot").size() == sizeof(kExpectedKeyslot));
    assert(memcmp(store.blobs.at("keyslot").data(),
                  kExpectedKeyslot, sizeof(kExpectedKeyslot)) == 0);

    const std::vector<uint8_t> authentication_keyslot =
        store.blobs.at("keyslot");
    set_pin(pin, "123456");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_authenticate_pin(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::success);
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::unlocked);
    assert(all_zero(pin, sizeof(pin)) && all_zero(work.data(), work.size()));

    set_pin(pin, "654321");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_authenticate_pin(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::wrong_pin);
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::unlocked);
    assert(store.blobs.at("keyslot") == authentication_keyslot);
    assert(all_zero(pin, sizeof(pin)) && all_zero(work.data(), work.size()));

    assert(signing::encrypted_keystore_lock(&keystore) ==
           KeystoreOperationStatus::success);
    const size_t locked_read_count = store.read_count;
    set_pin(pin, "123456");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_authenticate_pin(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::locked);
    assert(store.read_count == locked_read_count);
    assert(all_zero(pin, sizeof(pin)) && all_zero(work.data(), work.size()));
    set_pin(pin, "123456");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_unlock(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::success);

    {
        FakeStore read_error_store = store;
        FakeRandom read_error_random;
        EncryptedKeystoreConfig read_error_config =
            config_for(&read_error_store, &read_error_random);
        EncryptedKeystore read_error_keystore;
        assert(signing::encrypted_keystore_initialize(
                   &read_error_keystore, &read_error_config) ==
               KeystoreState::locked);
        std::vector<uint8_t> read_error_work(
            read_error_config.kdf.memory_kib * 1024, 0xA5);
        char read_error_pin[signing::kKeystorePinBufferBytes];
        set_pin(read_error_pin, "123456");
        assert(signing::encrypted_keystore_unlock(
                   &read_error_keystore,
                   read_error_pin,
                   read_error_work.data(),
                   read_error_work.size()) ==
               KeystoreOperationStatus::success);
        read_error_store.read_error = true;
        set_pin(read_error_pin, "123456");
        memset(read_error_work.data(), 0xA5, read_error_work.size());
        assert(signing::encrypted_keystore_authenticate_pin(
                   &read_error_keystore,
                   read_error_pin,
                   read_error_work.data(),
                   read_error_work.size()) ==
               KeystoreOperationStatus::storage_error);
        assert(signing::encrypted_keystore_state(&read_error_keystore) ==
               KeystoreState::storage_error);
        assert(all_zero(read_error_pin, sizeof(read_error_pin)));
        assert(all_zero(read_error_work.data(), read_error_work.size()));
    }

    // Every authenticated keyslot field rejects mutation.
    for (const size_t offset : {size_t{28}, size_t{52}, size_t{84}, size_t{100}}) {
        FakeStore mutated_store = store;
        mutated_store.blobs["keyslot"][offset] ^= 0x01;
        FakeRandom mutated_random;
        EncryptedKeystoreConfig mutated_config =
            config_for(&mutated_store, &mutated_random);
        EncryptedKeystore mutated_keystore;
        assert(signing::encrypted_keystore_initialize(
                   &mutated_keystore, &mutated_config) == KeystoreState::locked);
        char mutated_pin[signing::kKeystorePinBufferBytes];
        set_pin(mutated_pin, "123456");
        std::vector<uint8_t> mutated_work(
            mutated_config.kdf.memory_kib * 1024, 0xA5);
        assert(signing::encrypted_keystore_unlock(
                   &mutated_keystore,
                   mutated_pin,
                   mutated_work.data(),
                   mutated_work.size()) == KeystoreOperationStatus::wrong_pin);
        assert(signing::encrypted_keystore_state(&mutated_keystore) ==
               KeystoreState::locked);
    }
    {
        FakeStore malformed_store = store;
        malformed_store.blobs["keyslot"][4] = 2;
        FakeRandom malformed_random;
        EncryptedKeystoreConfig malformed_config =
            config_for(&malformed_store, &malformed_random);
        EncryptedKeystore malformed_keystore;
        assert(signing::encrypted_keystore_initialize(
                   &malformed_keystore, &malformed_config) ==
               KeystoreState::invalid);
    }

    uint8_t root[kPlaintextBytes];
    memset(root, 0xA7, sizeof(root));
    Scratch scratch;
    auto scratch_view = scratch.view();
    assert(signing::encrypted_keystore_replace_record(
               &keystore, record_for(), root, sizeof(root), &scratch_view) ==
           KeystoreOperationStatus::success);
    expect_scratch_wiped(scratch);

    uint8_t structural_scratch[kBlobBytes] = {};
    assert(signing::encrypted_keystore_check_record(
               &keystore,
               record_for(),
               structural_scratch,
               sizeof(structural_scratch)) == KeystoreOperationStatus::success);
    assert(all_zero(structural_scratch, sizeof(structural_scratch)));
    assert(signing::encrypted_keystore_check_record(
               &keystore,
               {"missing", kRecordId, sizeof(kRecordId) - 1, kPlaintextBytes},
               structural_scratch,
               sizeof(structural_scratch)) == KeystoreOperationStatus::missing);
    assert(all_zero(structural_scratch, sizeof(structural_scratch)));

    Scratch aliased_scratch;
    memset(aliased_scratch.previous, 0xA5, sizeof(aliased_scratch.previous));
    memset(aliased_scratch.readback, 0xA5, sizeof(aliased_scratch.readback));
    memset(aliased_scratch.plaintext, 0xA5, sizeof(aliased_scratch.plaintext));
    auto aliased_view = aliased_scratch.view();
    aliased_view.candidate_blob = aliased_view.previous_blob;
    assert(signing::encrypted_keystore_replace_record(
               &keystore,
               record_for(),
               root,
               sizeof(root),
               &aliased_view) == KeystoreOperationStatus::invalid_input);
    expect_scratch_wiped(aliased_scratch);
    assert(store.blobs.at("root").size() == kBlobBytes);
    assert(memcmp(store.blobs.at("root").data(),
                  kExpectedRootRecord, sizeof(kExpectedRootRecord)) == 0);
    assert(!contains_sequence(
        store.blobs.at("root").data(), kBlobBytes, root, sizeof(root)));

    const std::vector<uint8_t> record_before_input_alias =
        store.blobs.at("root");
    const size_t random_calls_before_input_alias = random.fill_count;
    Scratch input_aliased_scratch;
    memset(
        input_aliased_scratch.plaintext,
        0xB4,
        sizeof(input_aliased_scratch.plaintext));
    auto input_aliased_view = input_aliased_scratch.view();
    assert(signing::encrypted_keystore_replace_record(
               &keystore,
               record_for(),
               input_aliased_scratch.plaintext,
               sizeof(input_aliased_scratch.plaintext),
               &input_aliased_view) == KeystoreOperationStatus::invalid_input);
    expect_scratch_wiped(input_aliased_scratch);
    assert(store.blobs.at("root") == record_before_input_alias);
    assert(random.fill_count == random_calls_before_input_alias);

    // Ciphertext, nonce, tag, truncation, and oversize mutations all fail closed.
    for (const size_t offset : {size_t{12}, size_t{36}, size_t{kBlobBytes - 1}}) {
        FakeStore mutated_store = store;
        mutated_store.blobs["root"][offset] ^= 0x01;
        FakeRandom mutated_random;
        EncryptedKeystoreConfig mutated_config =
            config_for(&mutated_store, &mutated_random);
        EncryptedKeystore mutated_keystore;
        assert(signing::encrypted_keystore_initialize(
                   &mutated_keystore, &mutated_config) == KeystoreState::locked);
        char mutated_pin[signing::kKeystorePinBufferBytes];
        set_pin(mutated_pin, "123456");
        std::vector<uint8_t> mutated_work(
            mutated_config.kdf.memory_kib * 1024, 0xA5);
        assert(signing::encrypted_keystore_unlock(
                   &mutated_keystore,
                   mutated_pin,
                   mutated_work.data(),
                   mutated_work.size()) == KeystoreOperationStatus::success);
        Scratch mutated_scratch;
        auto mutated_view = mutated_scratch.view();
        std::vector<uint8_t> mutated_output;
        assert(signing::encrypted_keystore_with_record(
                   &mutated_keystore,
                   record_for(),
                   &mutated_view,
                   capture_consumer,
                   &mutated_output) == KeystoreOperationStatus::invalid_record);
        assert(mutated_output.empty());
        assert(signing::encrypted_keystore_state(&mutated_keystore) ==
               KeystoreState::invalid);
        expect_scratch_wiped(mutated_scratch);
    }
    for (const bool truncate : {true, false}) {
        FakeStore malformed_store = store;
        if (truncate) {
            malformed_store.blobs["root"].pop_back();
        } else {
            malformed_store.blobs["root"].push_back(0x00);
        }
        FakeRandom malformed_random;
        EncryptedKeystoreConfig malformed_config =
            config_for(&malformed_store, &malformed_random);
        EncryptedKeystore malformed_keystore;
        assert(signing::encrypted_keystore_initialize(
                   &malformed_keystore, &malformed_config) == KeystoreState::locked);
        char malformed_pin[signing::kKeystorePinBufferBytes];
        set_pin(malformed_pin, "123456");
        std::vector<uint8_t> malformed_work(
            malformed_config.kdf.memory_kib * 1024, 0xA5);
        assert(signing::encrypted_keystore_unlock(
                   &malformed_keystore,
                   malformed_pin,
                   malformed_work.data(),
                   malformed_work.size()) == KeystoreOperationStatus::success);
        Scratch malformed_scratch;
        auto malformed_view = malformed_scratch.view();
        std::vector<uint8_t> malformed_output;
        const KeystoreOperationStatus malformed_status =
            signing::encrypted_keystore_with_record(
                &malformed_keystore,
                record_for(),
                &malformed_view,
                capture_consumer,
                &malformed_output);
        assert(malformed_status == KeystoreOperationStatus::invalid_record ||
               malformed_status == KeystoreOperationStatus::storage_error);
        assert(malformed_output.empty());
    }

    ReentrantLockContext reentrant_lock{&keystore};
    scratch_view = scratch.view();
    assert(signing::encrypted_keystore_with_record(
               &keystore,
               record_for(),
               &scratch_view,
               attempt_reentrant_lock,
               &reentrant_lock) == KeystoreOperationStatus::success);
    assert(reentrant_lock.status == KeystoreOperationStatus::busy);
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::unlocked);
    expect_scratch_wiped(scratch);

    ReentrantAuthenticationContext reentrant_authentication;
    reentrant_authentication.keystore = &keystore;
    set_pin(reentrant_authentication.pin, "123456");
    reentrant_authentication.work.assign(
        config.kdf.memory_kib * 1024, 0xA5);
    scratch_view = scratch.view();
    assert(signing::encrypted_keystore_with_record(
               &keystore,
               record_for(),
               &scratch_view,
               attempt_reentrant_authentication,
               &reentrant_authentication) == KeystoreOperationStatus::success);
    assert(reentrant_authentication.status == KeystoreOperationStatus::busy);
    assert(all_zero(
        reentrant_authentication.pin,
        sizeof(reentrant_authentication.pin)));
    assert(all_zero(
        reentrant_authentication.work.data(),
        reentrant_authentication.work.size()));
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::unlocked);
    expect_scratch_wiped(scratch);

    assert(signing::encrypted_keystore_lock(&keystore) ==
           KeystoreOperationStatus::success);
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::locked);
    std::vector<uint8_t> captured;
    scratch_view = scratch.view();
    assert(signing::encrypted_keystore_with_record(
               &keystore, record_for(), &scratch_view,
               capture_consumer, &captured) == KeystoreOperationStatus::locked);
    assert(captured.empty());
    expect_scratch_wiped(scratch);

    set_pin(pin, "654321");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_unlock(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::wrong_pin);
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::locked);
    assert(all_zero(pin, sizeof(pin)) && all_zero(work.data(), work.size()));

    set_pin(pin, "123456");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_unlock(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::success);
    scratch_view = scratch.view();
    assert(signing::encrypted_keystore_with_record(
               &keystore, record_for(), &scratch_view,
               capture_consumer, &captured) == KeystoreOperationStatus::success);
    assert(captured == std::vector<uint8_t>(root, root + sizeof(root)));
    expect_scratch_wiped(scratch);

    const std::vector<uint8_t> root_ciphertext = store.blobs.at("root");
    const std::vector<uint8_t> original_keyslot = store.blobs.at("keyslot");
    char current_pin[signing::kKeystorePinBufferBytes];
    set_pin(current_pin, "123456");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_rewrap(
               &keystore,
               current_pin,
               current_pin,
               work.data(),
               work.size()) == KeystoreOperationStatus::invalid_input);
    assert(all_zero(current_pin, sizeof(current_pin)));
    assert(all_zero(work.data(), work.size()));

    set_pin(current_pin, "654321");
    set_pin(pin, "222222");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_rewrap(
               &keystore, current_pin, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::wrong_pin);
    assert(store.blobs.at("keyslot") == original_keyslot);
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::unlocked);
    assert(all_zero(current_pin, sizeof(current_pin)));
    assert(all_zero(pin, sizeof(pin)));
    assert(all_zero(work.data(), work.size()));

    set_pin(current_pin, "123456");
    set_pin(pin, "222222");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_rewrap(
               &keystore, current_pin, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::success);
    assert(store.blobs.at("root") == root_ciphertext);
    assert(signing::encrypted_keystore_lock(&keystore) ==
           KeystoreOperationStatus::success);
    set_pin(pin, "123456");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_unlock(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::wrong_pin);
    set_pin(pin, "222222");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_unlock(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::success);

    // Keyslot replacement also distinguishes exact previous and exact new.
    store.next_write = WriteMode::fail_before_write;
    set_pin(current_pin, "222222");
    set_pin(pin, "333333");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_rewrap(
               &keystore, current_pin, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::unchanged);
    assert(signing::encrypted_keystore_lock(&keystore) ==
           KeystoreOperationStatus::success);
    set_pin(pin, "333333");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_unlock(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::wrong_pin);
    set_pin(pin, "222222");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_unlock(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::success);

    store.next_write = WriteMode::apply_then_fail;
    set_pin(current_pin, "222222");
    set_pin(pin, "333333");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_rewrap(
               &keystore, current_pin, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::success);
    signing::encrypted_keystore_lock(&keystore);
    set_pin(pin, "222222");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_unlock(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::wrong_pin);
    set_pin(pin, "333333");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_unlock(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::success);

    // A keyslot storage key can never be reused as a protected-record key.
    const KeystoreRecord colliding_record{
        "keyslot", kRecordId, sizeof(kRecordId) - 1, kPlaintextBytes};
    scratch_view = scratch.view();
    assert(signing::encrypted_keystore_replace_record(
               &keystore,
               colliding_record,
               root,
               sizeof(root),
               &scratch_view) == KeystoreOperationStatus::invalid_input);
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::unlocked);
    expect_scratch_wiped(scratch);

    scratch_view = scratch.view();
    assert(signing::encrypted_keystore_with_record(
               &keystore, record_for(), &scratch_view,
               reject_consumer, nullptr) == KeystoreOperationStatus::consumer_failed);
    expect_scratch_wiped(scratch);

    // A failed write is unchanged only when readback proves the previous value.
    uint8_t replacement[kPlaintextBytes];
    memset(replacement, 0xB8, sizeof(replacement));
    store.next_write = WriteMode::fail_before_write;
    scratch_view = scratch.view();
    assert(signing::encrypted_keystore_replace_record(
               &keystore, record_for(), replacement, sizeof(replacement),
               &scratch_view) == KeystoreOperationStatus::unchanged);
    assert(store.blobs.at("root") == root_ciphertext);
    expect_scratch_wiped(scratch);

    // A reported write failure is success when readback proves the exact new value.
    store.next_write = WriteMode::apply_then_fail;
    scratch_view = scratch.view();
    assert(signing::encrypted_keystore_replace_record(
               &keystore, record_for(), replacement, sizeof(replacement),
               &scratch_view) == KeystoreOperationStatus::success);
    expect_scratch_wiped(scratch);

    // Wrong record or target binding never authenticates.
    scratch_view = scratch.view();
    assert(signing::encrypted_keystore_with_record(
               &keystore,
               record_for(kWrongRecordId, sizeof(kWrongRecordId) - 1),
               &scratch_view,
               capture_consumer,
               &captured) == KeystoreOperationStatus::invalid_record);
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::invalid);

    EncryptedKeystore other;
    FakeRandom other_random;
    EncryptedKeystoreConfig other_config = config_for(
        &store, &other_random, kOtherTargetLabel, sizeof(kOtherTargetLabel) - 1);
    assert(signing::encrypted_keystore_initialize(&other, &other_config) ==
           KeystoreState::locked);
    set_pin(pin, "333333");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_unlock(
               &other, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::wrong_pin);

    // Neither exact old nor exact new is a storage error and wipes authority.
    assert(signing::encrypted_keystore_initialize(&keystore, &config) ==
           KeystoreState::locked);
    set_pin(pin, "333333");
    memset(work.data(), 0xA5, work.size());
    assert(signing::encrypted_keystore_unlock(
               &keystore, pin, work.data(), work.size()) ==
           KeystoreOperationStatus::success);
    store.next_write = WriteMode::corrupt_after_write;
    scratch_view = scratch.view();
    assert(signing::encrypted_keystore_replace_record(
               &keystore, record_for(), root, sizeof(root), &scratch_view) ==
           KeystoreOperationStatus::storage_error);
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::storage_error);
    expect_scratch_wiped(scratch);

    // Erase success is not trusted until every protected key is absent.
    assert(signing::encrypted_keystore_initialize(&keystore, &config) ==
           KeystoreState::locked);
    const KeystoreRecord records[] = {record_for()};
    store.erase_without_change = true;
    assert(signing::encrypted_keystore_erase(&keystore, records, 1) ==
           KeystoreOperationStatus::storage_error);
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::storage_error);
    assert(!store.blobs.empty());

    store.erase_without_change = false;
    assert(signing::encrypted_keystore_initialize(&keystore, &config) ==
           KeystoreState::locked);
    assert(signing::encrypted_keystore_erase(&keystore, records, 1) ==
           KeystoreOperationStatus::success);
    assert(signing::encrypted_keystore_state(&keystore) ==
           KeystoreState::absent);
    assert(store.blobs.empty());

    puts("encrypted keystore tests passed");
    return 0;
}
CPP

"${CC_BIN}" -std=c11 -Wall -Wextra -Werror \
  -I"${MONOCYPHER_ROOT}" \
  -c "${MONOCYPHER_ROOT}/lib/monocypher/monocypher.c" \
  -o "${TMP_DIR}/monocypher.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_ROOT}" \
  -I"${MONOCYPHER_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_ROOT}/keystore/encrypted_keystore.cpp" \
  "${TMP_DIR}/monocypher.o" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
