#include "sui_zklogin_credential_store.h"

#include <string.h>

#include "sensitive_memory.h"

#ifdef STOPWATCH_ZKLOGIN_CREDENTIAL_STORE_HOST_TEST
#include <vector>
#else
#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"
#endif

namespace stopwatch_target {
namespace {

#ifndef STOPWATCH_ZKLOGIN_CREDENTIAL_STORE_HOST_TEST
constexpr const char* kTag = "StopWatchZkLogin";
constexpr const char* kNvsNamespace = "sui_credential";
constexpr const char* kCredentialKey = "active";
#endif
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
    sizeof(StoredSuiZkLoginCredentialRecord) <= kSuiZkLoginCredentialRecordMaxBytes,
    "StopWatch zkLogin credential record must stay within the SS-3 storage cap");

#ifdef STOPWATCH_ZKLOGIN_CREDENTIAL_STORE_HOST_TEST
std::vector<uint8_t> g_test_store;
bool g_test_write_failure = false;
bool g_test_read_failure = false;
#endif
StoredSuiZkLoginCredentialRecord g_stored_work = {};
StoredSuiZkLoginCredentialRecord g_readback_work = {};
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

#ifdef STOPWATCH_ZKLOGIN_CREDENTIAL_STORE_HOST_TEST
SuiZkLoginCredentialStatus read_stored_record(
    StoredSuiZkLoginCredentialRecord* stored,
    bool)
{
    if (stored == nullptr || g_test_read_failure) {
        return SuiZkLoginCredentialStatus::storage_error;
    }
    memset(stored, 0, sizeof(*stored));
    if (g_test_store.empty()) {
        return SuiZkLoginCredentialStatus::missing;
    }
    if (g_test_store.size() != sizeof(*stored)) {
        return SuiZkLoginCredentialStatus::invalid;
    }
    memcpy(stored, g_test_store.data(), sizeof(*stored));
    return SuiZkLoginCredentialStatus::active;
}

bool write_stored_record(const StoredSuiZkLoginCredentialRecord& stored)
{
    if (g_test_write_failure) {
        return false;
    }
    g_test_store.assign(
        reinterpret_cast<const uint8_t*>(&stored),
        reinterpret_cast<const uint8_t*>(&stored) + sizeof(stored));
    return true;
}
#else
SuiZkLoginCredentialStatus read_stored_record(
    StoredSuiZkLoginCredentialRecord* stored,
    bool log_failures)
{
    if (stored == nullptr) {
        return SuiZkLoginCredentialStatus::storage_error;
    }
    memset(stored, 0, sizeof(*stored));

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return SuiZkLoginCredentialStatus::missing;
    }
    if (result != ESP_OK) {
        if (log_failures) {
            ESP_LOGW(kTag, "NVS open failed while reading zkLogin credential: %s", esp_err_to_name(result));
        }
        return SuiZkLoginCredentialStatus::storage_error;
    }

    size_t blob_size = 0;
    result = nvs_get_blob(nvs, kCredentialKey, nullptr, &blob_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return SuiZkLoginCredentialStatus::missing;
    }
    if (result != ESP_OK) {
        nvs_close(nvs);
        if (log_failures) {
            ESP_LOGW(kTag, "zkLogin credential size read failed: %s", esp_err_to_name(result));
        }
        return SuiZkLoginCredentialStatus::storage_error;
    }
    if (blob_size != sizeof(*stored)) {
        nvs_close(nvs);
        return SuiZkLoginCredentialStatus::invalid;
    }

    result = nvs_get_blob(nvs, kCredentialKey, stored, &blob_size);
    nvs_close(nvs);
    if (result != ESP_OK || blob_size != sizeof(*stored)) {
        memset(stored, 0, sizeof(*stored));
        if (log_failures) {
            ESP_LOGW(kTag, "zkLogin credential read failed: %s", esp_err_to_name(result));
        }
        return SuiZkLoginCredentialStatus::storage_error;
    }
    return SuiZkLoginCredentialStatus::active;
}

bool write_stored_record(const StoredSuiZkLoginCredentialRecord& stored)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing zkLogin credential: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_set_blob(nvs, kCredentialKey, &stored, sizeof(stored));
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "zkLogin credential write failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}
#endif

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
    clear_stored_record(&g_stored_work);
    clear_credential(&g_credential_work);
    const SuiZkLoginCredentialStatus status = read_stored_record(&g_stored_work, false);
    if (status != SuiZkLoginCredentialStatus::active) {
        clear_stored_record(&g_stored_work);
        return status;
    }
    const bool valid = stored_to_credential(g_stored_work, &g_credential_work);
    clear_stored_record(&g_stored_work);
    clear_credential(&g_credential_work);
    return valid ? SuiZkLoginCredentialStatus::active : SuiZkLoginCredentialStatus::invalid;
}

SuiZkLoginCredentialStatus read_sui_zklogin_credential(
    SuiZkLoginCredentialRecord* out)
{
    clear_credential(out);
    if (out == nullptr) {
        return SuiZkLoginCredentialStatus::storage_error;
    }

    clear_stored_record(&g_stored_work);
    const SuiZkLoginCredentialStatus status = read_stored_record(&g_stored_work, true);
    if (status != SuiZkLoginCredentialStatus::active) {
        clear_stored_record(&g_stored_work);
        return status;
    }
    if (!stored_to_credential(g_stored_work, out)) {
        clear_stored_record(&g_stored_work);
        return SuiZkLoginCredentialStatus::invalid;
    }
    clear_stored_record(&g_stored_work);
    return SuiZkLoginCredentialStatus::active;
}

SuiZkLoginCredentialWriteResult store_sui_zklogin_credential(
    const SuiZkLoginCredentialRecord* record)
{
    if (!validate_sui_zklogin_credential_record(record)) {
        return SuiZkLoginCredentialWriteResult::invalid_record;
    }

    clear_stored_record(&g_stored_work);
    clear_stored_record(&g_readback_work);
    if (!credential_to_stored(*record, &g_stored_work)) {
        clear_stored_record(&g_stored_work);
        return SuiZkLoginCredentialWriteResult::invalid_record;
    }
    if (!write_stored_record(g_stored_work)) {
        clear_stored_record(&g_stored_work);
        return SuiZkLoginCredentialWriteResult::storage_error;
    }

    if (read_stored_record(&g_readback_work, true) != SuiZkLoginCredentialStatus::active ||
        memcmp(&g_readback_work, &g_stored_work, sizeof(g_stored_work)) != 0) {
        clear_stored_record(&g_stored_work);
        clear_stored_record(&g_readback_work);
        return SuiZkLoginCredentialWriteResult::consistency_error;
    }
    clear_stored_record(&g_stored_work);
    clear_stored_record(&g_readback_work);
    return SuiZkLoginCredentialWriteResult::stored;
}

bool wipe_sui_zklogin_credential()
{
#ifdef STOPWATCH_ZKLOGIN_CREDENTIAL_STORE_HOST_TEST
    g_test_store.clear();
    return true;
#else
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while clearing zkLogin credential: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kCredentialKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "zkLogin credential wipe failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
#endif
}

SuiZkLoginAccountProjection sui_zklogin_account_projection()
{
    SuiZkLoginAccountProjection projection = {};
    clear_projection(&projection);

    clear_credential(&g_credential_work);
    const SuiZkLoginCredentialStatus status = read_sui_zklogin_credential(&g_credential_work);
    projection.status = status;
    if (status != SuiZkLoginCredentialStatus::active) {
        clear_credential(&g_credential_work);
        return projection;
    }
    projection.active = true;
    memcpy(projection.address, g_credential_work.proof.address, sizeof(projection.address));
    memcpy(projection.public_key, g_credential_work.proof.public_key, g_credential_work.proof.public_key_size);
    projection.public_key_size = g_credential_work.proof.public_key_size;
    clear_credential(&g_credential_work);
    return projection;
}

#ifdef STOPWATCH_ZKLOGIN_CREDENTIAL_STORE_HOST_TEST
void sui_zklogin_credential_test_reset_store()
{
    g_test_store.clear();
    g_test_write_failure = false;
    g_test_read_failure = false;
}

void sui_zklogin_credential_test_corrupt_store()
{
    g_test_store.assign(sizeof(StoredSuiZkLoginCredentialRecord), 0xA5);
}

void sui_zklogin_credential_test_set_write_failure(bool enabled)
{
    g_test_write_failure = enabled;
}

void sui_zklogin_credential_test_set_read_failure(bool enabled)
{
    g_test_read_failure = enabled;
}
#endif

}  // namespace stopwatch_target
