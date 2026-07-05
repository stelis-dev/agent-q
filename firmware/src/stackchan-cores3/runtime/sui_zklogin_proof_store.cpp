#include "sui_zklogin_proof_store.h"

#include <string.h>

#include "bip39.h"
#include "sui_account_store.h"
#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"
#include "persistent_storage_names.h"

namespace signing {
namespace {

constexpr const char* kTag = "SuiZkLogin";
constexpr const char* kNvsNamespace = kMutableSettingsNvsNamespace;
constexpr const char* kProofRecordKey = "sui_zkl_proof";
constexpr uint8_t kStoredRecordMagic[4] = {'A', 'Q', 'Z', 'L'};
constexpr uint8_t kStoredRecordVersion = 0;

struct StoredSuiZkLoginProofRecord {
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
};

static_assert(
    sizeof(StoredSuiZkLoginProofRecord) <= kSuiZkLoginProofRecordMaxBytes,
    "Sui zkLogin proof record must stay within the Step 0 storage cap");

void clear_record(SuiZkLoginProofRecord* record)
{
    if (record != nullptr) {
        memset(record, 0, sizeof(*record));
    }
}

void clear_identity(SuiActiveIdentity* identity)
{
    if (identity != nullptr) {
        memset(identity, 0, sizeof(*identity));
        identity->kind = SuiActiveIdentityKind::error;
        identity->error = SuiActiveIdentityError::native_account_unavailable;
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

bool record_to_stored(
    const SuiZkLoginProofRecord& record,
    StoredSuiZkLoginProofRecord* stored)
{
    if (stored == nullptr || !validate_sui_zklogin_proof_record(&record)) {
        return false;
    }
    memset(stored, 0, sizeof(*stored));
    memcpy(stored->magic, kStoredRecordMagic, sizeof(kStoredRecordMagic));
    stored->version = kStoredRecordVersion;
    set_u16_be(static_cast<uint16_t>(record.public_key_size), stored->public_key_size_be);
    memcpy(stored->network, record.network, sizeof(stored->network));
    memcpy(stored->address, record.address, sizeof(stored->address));
    memcpy(stored->public_key, record.public_key, record.public_key_size);
    memcpy(stored->issuer, record.issuer, sizeof(stored->issuer));
    memcpy(stored->address_seed, record.address_seed, sizeof(stored->address_seed));
    memcpy(stored->max_epoch, record.max_epoch, sizeof(stored->max_epoch));
    memcpy(&stored->inputs, &record.inputs, sizeof(stored->inputs));
    memcpy(stored->proof_hash, record.proof_hash, sizeof(stored->proof_hash));
    return true;
}

bool stored_to_record(
    const StoredSuiZkLoginProofRecord& stored,
    SuiZkLoginProofRecord* record)
{
    if (record == nullptr) {
        return false;
    }
    clear_record(record);
    if (memcmp(stored.magic, kStoredRecordMagic, sizeof(kStoredRecordMagic)) != 0 ||
        stored.version != kStoredRecordVersion ||
        stored.reserved != 0) {
        return false;
    }

    const uint16_t public_key_size = read_u16_be(stored.public_key_size_be);
    if (public_key_size > kSuiZkLoginPublicKeyMaxBytes) {
        return false;
    }

    memcpy(record->network, stored.network, sizeof(record->network));
    memcpy(record->address, stored.address, sizeof(record->address));
    memcpy(record->public_key, stored.public_key, public_key_size);
    record->public_key_size = public_key_size;
    memcpy(record->issuer, stored.issuer, sizeof(record->issuer));
    memcpy(record->address_seed, stored.address_seed, sizeof(record->address_seed));
    memcpy(record->max_epoch, stored.max_epoch, sizeof(record->max_epoch));
    memcpy(&record->inputs, &stored.inputs, sizeof(record->inputs));
    memcpy(record->proof_hash, stored.proof_hash, sizeof(record->proof_hash));
    if (!validate_sui_zklogin_proof_record(record)) {
        clear_record(record);
        return false;
    }
    return true;
}

SuiZkLoginProofRecordStatus read_stored_record(
    StoredSuiZkLoginProofRecord* stored,
    bool log_failures)
{
    if (stored == nullptr) {
        return SuiZkLoginProofRecordStatus::storage_error;
    }
    memset(stored, 0, sizeof(*stored));

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return SuiZkLoginProofRecordStatus::missing;
    }
    if (result != ESP_OK) {
        if (log_failures) {
            ESP_LOGW(kTag, "NVS open failed while reading zkLogin proof: %s", esp_err_to_name(result));
        }
        return SuiZkLoginProofRecordStatus::storage_error;
    }

    size_t blob_size = 0;
    result = nvs_get_blob(nvs, kProofRecordKey, nullptr, &blob_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return SuiZkLoginProofRecordStatus::missing;
    }
    if (result != ESP_OK) {
        nvs_close(nvs);
        if (log_failures) {
            ESP_LOGW(kTag, "zkLogin proof size read failed: %s", esp_err_to_name(result));
        }
        return SuiZkLoginProofRecordStatus::storage_error;
    }
    if (blob_size != sizeof(*stored)) {
        nvs_close(nvs);
        return SuiZkLoginProofRecordStatus::invalid;
    }

    result = nvs_get_blob(nvs, kProofRecordKey, stored, &blob_size);
    nvs_close(nvs);
    if (result != ESP_OK || blob_size != sizeof(*stored)) {
        memset(stored, 0, sizeof(*stored));
        if (log_failures) {
            ESP_LOGW(kTag, "zkLogin proof read failed: %s", esp_err_to_name(result));
        }
        return SuiZkLoginProofRecordStatus::storage_error;
    }
    return SuiZkLoginProofRecordStatus::active;
}

bool write_stored_record(const StoredSuiZkLoginProofRecord& stored)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing zkLogin proof: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_set_blob(nvs, kProofRecordKey, &stored, sizeof(stored));
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "zkLogin proof write failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

}  // namespace

SuiZkLoginProofRecordStatus sui_zklogin_proof_record_status()
{
    StoredSuiZkLoginProofRecord stored = {};
    const SuiZkLoginProofRecordStatus status = read_stored_record(&stored, false);
    if (status != SuiZkLoginProofRecordStatus::active) {
        return status;
    }
    SuiZkLoginProofRecord record = {};
    return stored_to_record(stored, &record)
               ? SuiZkLoginProofRecordStatus::active
               : SuiZkLoginProofRecordStatus::invalid;
}

SuiZkLoginProofRecordStatus read_sui_zklogin_proof_record(
    SuiZkLoginProofRecord* out)
{
    clear_record(out);
    if (out == nullptr) {
        return SuiZkLoginProofRecordStatus::storage_error;
    }

    StoredSuiZkLoginProofRecord stored = {};
    const SuiZkLoginProofRecordStatus status = read_stored_record(&stored, true);
    if (status != SuiZkLoginProofRecordStatus::active) {
        return status;
    }
    if (!stored_to_record(stored, out)) {
        return SuiZkLoginProofRecordStatus::invalid;
    }
    return SuiZkLoginProofRecordStatus::active;
}

SuiZkLoginProofRecordWriteResult store_sui_zklogin_proof_record(
    const SuiZkLoginProofRecord* record)
{
    if (!validate_sui_zklogin_proof_record(record)) {
        return SuiZkLoginProofRecordWriteResult::invalid_record;
    }

    StoredSuiZkLoginProofRecord stored = {};
    if (!record_to_stored(*record, &stored)) {
        return SuiZkLoginProofRecordWriteResult::invalid_record;
    }
    if (!write_stored_record(stored)) {
        return SuiZkLoginProofRecordWriteResult::storage_error;
    }

    StoredSuiZkLoginProofRecord readback = {};
    if (read_stored_record(&readback, true) != SuiZkLoginProofRecordStatus::active ||
        memcmp(&readback, &stored, sizeof(stored)) != 0) {
        return SuiZkLoginProofRecordWriteResult::consistency_error;
    }
    return SuiZkLoginProofRecordWriteResult::stored;
}

bool wipe_sui_zklogin_proof_record()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while clearing zkLogin proof: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kProofRecordKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "zkLogin proof wipe failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

SuiActiveIdentity resolve_active_sui_identity()
{
    SuiActiveIdentity identity = {};
    clear_identity(&identity);

    SuiZkLoginProofRecord proof = {};
    const SuiZkLoginProofRecordStatus proof_status =
        read_sui_zklogin_proof_record(&proof);
    if (proof_status == SuiZkLoginProofRecordStatus::active) {
        identity.kind = SuiActiveIdentityKind::zklogin;
        identity.error = SuiActiveIdentityError::none;
        memcpy(identity.address, proof.address, sizeof(identity.address));
        memcpy(identity.public_key, proof.public_key, proof.public_key_size);
        identity.public_key_size = proof.public_key_size;
        memcpy(&identity.zklogin, &proof, sizeof(identity.zklogin));
        return identity;
    }
    if (proof_status == SuiZkLoginProofRecordStatus::invalid ||
        proof_status == SuiZkLoginProofRecordStatus::storage_error) {
        identity.kind = SuiActiveIdentityKind::error;
        identity.error = SuiActiveIdentityError::proof_storage_error;
        return identity;
    }

    uint8_t raw_public_key[kSuiEd25519PublicKeyBytes] = {};
    char address[kSuiAddressBufferSize] = {};
    const SuiAccountDerivationResult account_result =
        derive_sui_ed25519_account_from_stored_root(
            raw_public_key,
            address,
            sizeof(address));
    if (account_result != SuiAccountDerivationResult::ok) {
        wipe_sensitive_buffer(raw_public_key, sizeof(raw_public_key));
        identity.kind = SuiActiveIdentityKind::error;
        identity.error = SuiActiveIdentityError::native_account_unavailable;
        return identity;
    }

    identity.kind = SuiActiveIdentityKind::native;
    identity.error = SuiActiveIdentityError::none;
    memcpy(identity.address, address, sizeof(identity.address));
    identity.public_key[0] = kSuiSignatureSchemeFlagEd25519;
    memcpy(identity.public_key + 1, raw_public_key, sizeof(raw_public_key));
    identity.public_key_size = kSuiSchemePrefixedEd25519PublicKeyBytes;
    wipe_sensitive_buffer(raw_public_key, sizeof(raw_public_key));
    return identity;
}

}  // namespace signing
