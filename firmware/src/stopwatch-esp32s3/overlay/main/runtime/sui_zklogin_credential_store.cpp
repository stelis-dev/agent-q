#include "sui_zklogin_credential_store.h"

#include <string.h>

#include "sensitive_memory.h"

#include "stopwatch_keystore.h"

namespace stopwatch_target {
namespace {

constexpr uint8_t kStoredRecordMagic[4] = {'S', 'W', 'Z', 'L'};
constexpr uint8_t kStoredRecordVersion = 1;

struct StoredSuiZkLoginCredentialRecord {
    uint8_t magic[4];
    uint8_t version;
    uint8_t public_key_size_be[2];
    uint8_t reserved;
    char network[kSuiNetworkBufferSize];
    char address[kSuiAddressBufferSize];
    uint8_t public_key[kSuiZkLoginPublicKeyMaxBytes];
    char issuer[kSuiZkLoginIssuerBufferSize];
    char address_seed[kSuiZkLoginAddressSeedBufferSize];
    char max_epoch[kSuiZkLoginMaxEpochBufferSize];
    SuiZkLoginSignatureInputs inputs;
    char proof_hash[kSuiZkLoginProofHashBufferSize];
    uint8_t prepared_seed[kSuiEd25519SeedBytes];
};

static_assert(
    sizeof(StoredSuiZkLoginCredentialRecord) <= kStopWatchCredentialPlaintextMaxBytes,
    "StopWatch zkLogin credential record must stay within the SS-3 storage cap");
StoredSuiZkLoginCredentialRecord g_stored_work = {};
SuiZkLoginCredentialRecord g_credential_work = {};

void clear_credential(SuiZkLoginCredentialRecord* record)
{
    if (record != nullptr) {
        wipe_sensitive_buffer(record, sizeof(*record));
    }
}

void clear_stored_record(StoredSuiZkLoginCredentialRecord* stored)
{
    if (stored != nullptr) {
        wipe_sensitive_buffer(stored, sizeof(*stored));
    }
}

void clear_projection(SuiZkLoginAccountProjection* projection)
{
    if (projection != nullptr) {
        memset(projection, 0, sizeof(*projection));
        projection->status = SuiZkLoginCredentialStatus::missing;
    }
}

void set_u16_be(uint16_t value, uint8_t out[2])
{
    out[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[1] = static_cast<uint8_t>(value & 0xFF);
}

uint16_t read_u16_be(const uint8_t in[2])
{
    return static_cast<uint16_t>((static_cast<uint16_t>(in[0]) << 8) | in[1]);
}

bool credential_to_stored(
    const SuiZkLoginCredentialRecord& record,
    StoredSuiZkLoginCredentialRecord* stored)
{
    if (stored == nullptr || !validate_sui_zklogin_credential_record(&record)) {
        return false;
    }
    memset(stored, 0, sizeof(*stored));
    memcpy(stored->magic, kStoredRecordMagic, sizeof(kStoredRecordMagic));
    stored->version = kStoredRecordVersion;
    set_u16_be(static_cast<uint16_t>(record.proof.public_key_size), stored->public_key_size_be);
    memcpy(stored->network, record.proof.network, sizeof(stored->network));
    memcpy(stored->address, record.proof.address, sizeof(stored->address));
    memcpy(stored->public_key, record.proof.public_key, record.proof.public_key_size);
    memcpy(stored->issuer, record.proof.issuer, sizeof(stored->issuer));
    memcpy(stored->address_seed, record.proof.address_seed, sizeof(stored->address_seed));
    memcpy(stored->max_epoch, record.proof.max_epoch, sizeof(stored->max_epoch));
    memcpy(&stored->inputs, &record.proof.inputs, sizeof(stored->inputs));
    memcpy(stored->proof_hash, record.proof.proof_hash, sizeof(stored->proof_hash));
    memcpy(stored->prepared_seed, record.prepared_seed, sizeof(stored->prepared_seed));
    return true;
}

bool stored_to_credential(
    const StoredSuiZkLoginCredentialRecord& stored,
    SuiZkLoginCredentialRecord* record)
{
    if (record == nullptr) {
        return false;
    }
    clear_credential(record);
    if (memcmp(stored.magic, kStoredRecordMagic, sizeof(kStoredRecordMagic)) != 0 ||
        stored.version != kStoredRecordVersion ||
        stored.reserved != 0) {
        return false;
    }

    const uint16_t public_key_size = read_u16_be(stored.public_key_size_be);
    if (public_key_size > kSuiZkLoginPublicKeyMaxBytes) {
        return false;
    }

    memcpy(record->proof.network, stored.network, sizeof(record->proof.network));
    memcpy(record->proof.address, stored.address, sizeof(record->proof.address));
    memcpy(record->proof.public_key, stored.public_key, public_key_size);
    record->proof.public_key_size = public_key_size;
    memcpy(record->proof.issuer, stored.issuer, sizeof(record->proof.issuer));
    memcpy(record->proof.address_seed, stored.address_seed, sizeof(record->proof.address_seed));
    memcpy(record->proof.max_epoch, stored.max_epoch, sizeof(record->proof.max_epoch));
    memcpy(&record->proof.inputs, &stored.inputs, sizeof(record->proof.inputs));
    memcpy(record->proof.proof_hash, stored.proof_hash, sizeof(record->proof.proof_hash));
    memcpy(record->prepared_seed, stored.prepared_seed, sizeof(record->prepared_seed));
    if (!validate_sui_zklogin_credential_record(record)) {
        clear_credential(record);
        return false;
    }
    return true;
}

struct CredentialConsumerContext {
    SuiZkLoginCredentialConsumer consumer = nullptr;
    void* consumer_context = nullptr;
    bool decoded = false;
    bool consumer_called = false;
};

bool consume_encrypted_credential(
    const uint8_t* plaintext,
    size_t plaintext_size,
    void* context_ptr)
{
    auto* context = static_cast<CredentialConsumerContext*>(context_ptr);
    clear_stored_record(&g_stored_work);
    clear_credential(&g_credential_work);
    if (context == nullptr || context->consumer == nullptr ||
        plaintext == nullptr ||
        plaintext_size != sizeof(StoredSuiZkLoginCredentialRecord)) {
        return false;
    }
    memcpy(&g_stored_work, plaintext, sizeof(g_stored_work));
    context->decoded = stored_to_credential(g_stored_work, &g_credential_work);
    clear_stored_record(&g_stored_work);
    if (!context->decoded) {
        clear_credential(&g_credential_work);
        return false;
    }
    context->consumer_called = true;
    const bool consumed = context->consumer(
        g_credential_work,
        context->consumer_context);
    clear_credential(&g_credential_work);
    return consumed;
}

bool validate_credential_consumer(
    const SuiZkLoginCredentialRecord& credential,
    void*)
{
    return validate_sui_zklogin_credential_record(&credential);
}

bool project_credential_consumer(
    const SuiZkLoginCredentialRecord& credential,
    void* context)
{
    auto* projection = static_cast<SuiZkLoginAccountProjection*>(context);
    if (projection == nullptr) {
        return false;
    }
    projection->active = true;
    memcpy(projection->address, credential.proof.address, sizeof(projection->address));
    memcpy(
        projection->public_key,
        credential.proof.public_key,
        credential.proof.public_key_size);
    projection->public_key_size = credential.proof.public_key_size;
    return true;
}

SuiZkLoginCredentialStatus map_structural_status(
    signing::KeystoreOperationStatus status)
{
    switch (status) {
        case signing::KeystoreOperationStatus::success:
            return SuiZkLoginCredentialStatus::active;
        case signing::KeystoreOperationStatus::missing:
            return SuiZkLoginCredentialStatus::missing;
        case signing::KeystoreOperationStatus::invalid_record:
        case signing::KeystoreOperationStatus::invalid_input:
            return SuiZkLoginCredentialStatus::invalid;
        default:
            return SuiZkLoginCredentialStatus::storage_error;
    }
}

}  // namespace

bool validate_sui_zklogin_credential_record(const SuiZkLoginCredentialRecord* record)
{
    if (record == nullptr || !validate_sui_zklogin_proof_record(&record->proof)) {
        return false;
    }
    SuiEd25519Preparation preparation = {};
    const SuiPublicMaterialResult result =
        derive_sui_ed25519_preparation_from_seed(record->prepared_seed, &preparation);
    return result == SuiPublicMaterialResult::ok;
}

SuiZkLoginCredentialStatus sui_zklogin_credential_status()
{
    const SuiZkLoginCredentialStatus structural = map_structural_status(
        stopwatch_keystore_credential_status());
    if (structural != SuiZkLoginCredentialStatus::active ||
        stopwatch_keystore_state() != signing::KeystoreState::unlocked) {
        return structural;
    }
    switch (with_sui_zklogin_credential(validate_credential_consumer, nullptr)) {
        case SuiZkLoginCredentialAccessResult::consumed:
            return SuiZkLoginCredentialStatus::active;
        case SuiZkLoginCredentialAccessResult::missing:
            return SuiZkLoginCredentialStatus::missing;
        case SuiZkLoginCredentialAccessResult::invalid:
        case SuiZkLoginCredentialAccessResult::consumer_failed:
            return SuiZkLoginCredentialStatus::invalid;
        case SuiZkLoginCredentialAccessResult::locked:
        case SuiZkLoginCredentialAccessResult::storage_error:
            return SuiZkLoginCredentialStatus::storage_error;
    }
    return SuiZkLoginCredentialStatus::storage_error;
}

SuiZkLoginCredentialAccessResult with_sui_zklogin_credential(
    SuiZkLoginCredentialConsumer consumer,
    void* consumer_context)
{
    if (consumer == nullptr) {
        return SuiZkLoginCredentialAccessResult::consumer_failed;
    }
    CredentialConsumerContext context{consumer, consumer_context, false, false};
    const signing::KeystoreOperationStatus status =
        stopwatch_keystore_with_credential(
            consume_encrypted_credential,
            &context);
    switch (status) {
        case signing::KeystoreOperationStatus::success:
            return SuiZkLoginCredentialAccessResult::consumed;
        case signing::KeystoreOperationStatus::missing:
            return SuiZkLoginCredentialAccessResult::missing;
        case signing::KeystoreOperationStatus::locked:
            return SuiZkLoginCredentialAccessResult::locked;
        case signing::KeystoreOperationStatus::invalid_record:
            return SuiZkLoginCredentialAccessResult::invalid;
        case signing::KeystoreOperationStatus::consumer_failed:
            return context.decoded && context.consumer_called
                ? SuiZkLoginCredentialAccessResult::consumer_failed
                : SuiZkLoginCredentialAccessResult::invalid;
        default:
            return SuiZkLoginCredentialAccessResult::storage_error;
    }
}

SuiZkLoginCredentialWriteResult store_sui_zklogin_credential(
    const SuiZkLoginCredentialRecord* record)
{
    if (!validate_sui_zklogin_credential_record(record)) {
        return SuiZkLoginCredentialWriteResult::invalid_record;
    }

    clear_stored_record(&g_stored_work);
    if (!credential_to_stored(*record, &g_stored_work)) {
        clear_stored_record(&g_stored_work);
        return SuiZkLoginCredentialWriteResult::invalid_record;
    }
    const signing::KeystoreOperationStatus status =
        stopwatch_keystore_replace_credential(
            reinterpret_cast<const uint8_t*>(&g_stored_work),
            sizeof(g_stored_work));
    clear_stored_record(&g_stored_work);
    switch (status) {
        case signing::KeystoreOperationStatus::success:
            return SuiZkLoginCredentialWriteResult::stored;
        case signing::KeystoreOperationStatus::unchanged:
            return SuiZkLoginCredentialWriteResult::consistency_error;
        case signing::KeystoreOperationStatus::invalid_input:
        case signing::KeystoreOperationStatus::invalid_record:
            return SuiZkLoginCredentialWriteResult::invalid_record;
        default:
            return SuiZkLoginCredentialWriteResult::storage_error;
    }
}

SuiZkLoginAccountProjection sui_zklogin_account_projection()
{
    SuiZkLoginAccountProjection projection = {};
    clear_projection(&projection);

    const SuiZkLoginCredentialAccessResult access =
        with_sui_zklogin_credential(project_credential_consumer, &projection);
    switch (access) {
        case SuiZkLoginCredentialAccessResult::consumed:
            projection.status = SuiZkLoginCredentialStatus::active;
            break;
        case SuiZkLoginCredentialAccessResult::missing:
            projection.status = SuiZkLoginCredentialStatus::missing;
            break;
        case SuiZkLoginCredentialAccessResult::invalid:
        case SuiZkLoginCredentialAccessResult::consumer_failed:
            projection.status = SuiZkLoginCredentialStatus::invalid;
            break;
        case SuiZkLoginCredentialAccessResult::locked:
        case SuiZkLoginCredentialAccessResult::storage_error:
            projection.status = SuiZkLoginCredentialStatus::storage_error;
            break;
    }
    return projection;
}

}  // namespace stopwatch_target
