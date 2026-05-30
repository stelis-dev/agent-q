#include "agent_q_local_auth.h"

#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_entropy.h"
#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

extern "C" {
#include "lib/monocypher/monocypher.h"
}

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQLocalAuth";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kLocalAuthKey = "pin_auth";
constexpr uint8_t kRecordFormatVersion = 1;
constexpr uint8_t kKdfPbkdf2HmacSha512 = 1;
constexpr uint32_t kPbkdf2Iterations = 20000;
constexpr size_t kSaltBytes = 16;
constexpr size_t kVerifierBytes = 64;
constexpr size_t kPbkdf2BlockBytes = kSaltBytes + 4;

struct StoredLocalAuthRecord {
    uint8_t magic[4];
    uint8_t format_version;
    uint8_t kdf_id;
    uint8_t pin_digits;
    uint8_t reserved0;
    uint32_t iterations;
    uint8_t salt[kSaltBytes];
    uint8_t verifier[kVerifierBytes];
    uint8_t reserved[8];
};

static_assert(sizeof(StoredLocalAuthRecord) == 100, "Local auth record must stay fixed-size");

bool derive_pin_verifier(
    const char* pin,
    const uint8_t salt[kSaltBytes],
    uint8_t verifier[kVerifierBytes])
{
    if (!is_valid_local_pin(pin) || salt == nullptr || verifier == nullptr) {
        return false;
    }

    uint8_t block[kPbkdf2BlockBytes] = {};
    memcpy(block, salt, kSaltBytes);
    block[kSaltBytes + 0] = 0x00;
    block[kSaltBytes + 1] = 0x00;
    block[kSaltBytes + 2] = 0x00;
    block[kSaltBytes + 3] = 0x01;

    uint8_t u[kVerifierBytes] = {};
    uint8_t t[kVerifierBytes] = {};
    crypto_sha512_hmac(
        u,
        reinterpret_cast<const uint8_t*>(pin),
        kLocalPinDigits,
        block,
        sizeof(block));
    memcpy(t, u, sizeof(t));
    for (uint32_t iteration = 1; iteration < kPbkdf2Iterations; ++iteration) {
        crypto_sha512_hmac(
            u,
            reinterpret_cast<const uint8_t*>(pin),
            kLocalPinDigits,
            u,
            sizeof(u));
        for (size_t index = 0; index < sizeof(t); ++index) {
            t[index] ^= u[index];
        }
    }
    memcpy(verifier, t, kVerifierBytes);

    crypto_wipe(u, sizeof(u));
    crypto_wipe(t, sizeof(t));
    crypto_wipe(block, sizeof(block));
    return true;
}

bool constant_time_equal(const uint8_t* left, const uint8_t* right, size_t size)
{
    if (left == nullptr || right == nullptr) {
        return false;
    }

    uint8_t difference = 0;
    for (size_t index = 0; index < size; ++index) {
        difference |= static_cast<uint8_t>(left[index] ^ right[index]);
    }
    return difference == 0;
}

StoredLocalAuthRecord make_empty_record()
{
    StoredLocalAuthRecord record = {};
    record.magic[0] = 'A';
    record.magic[1] = 'Q';
    record.magic[2] = 'P';
    record.magic[3] = 'N';
    record.format_version = kRecordFormatVersion;
    record.kdf_id = kKdfPbkdf2HmacSha512;
    record.pin_digits = static_cast<uint8_t>(kLocalPinDigits);
    record.iterations = kPbkdf2Iterations;
    return record;
}

bool validate_local_auth_record(const StoredLocalAuthRecord& record)
{
    if (record.magic[0] != 'A' || record.magic[1] != 'Q' ||
        record.magic[2] != 'P' || record.magic[3] != 'N') {
        return false;
    }
    if (record.format_version != kRecordFormatVersion ||
        record.kdf_id != kKdfPbkdf2HmacSha512 ||
        record.pin_digits != kLocalPinDigits ||
        record.reserved0 != 0 ||
        record.iterations != kPbkdf2Iterations) {
        return false;
    }
    for (const uint8_t value : record.reserved) {
        if (value != 0) {
            return false;
        }
    }
    return true;
}

AgentQLocalAuthStatus read_local_auth_record(StoredLocalAuthRecord* out, bool log_failures)
{
    if (out == nullptr) {
        return AgentQLocalAuthStatus::storage_error;
    }
    memset(out, 0, sizeof(*out));

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result != ESP_OK) {
        if (result == ESP_ERR_NVS_NOT_FOUND) {
            return AgentQLocalAuthStatus::missing;
        }
        if (log_failures) {
            ESP_LOGW(kTag, "NVS open failed while reading local auth: %s", esp_err_to_name(result));
        }
        return AgentQLocalAuthStatus::storage_error;
    }

    size_t record_size = 0;
    result = nvs_get_blob(nvs, kLocalAuthKey, nullptr, &record_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return AgentQLocalAuthStatus::missing;
    }
    if (result != ESP_OK) {
        nvs_close(nvs);
        if (log_failures) {
            ESP_LOGW(kTag, "Local auth size read failed: %s", esp_err_to_name(result));
        }
        return AgentQLocalAuthStatus::storage_error;
    }
    if (record_size != sizeof(*out)) {
        nvs_close(nvs);
        if (log_failures) {
            ESP_LOGW(kTag, "Local auth record has invalid size: %u",
                     static_cast<unsigned>(record_size));
        }
        return AgentQLocalAuthStatus::invalid;
    }

    result = nvs_get_blob(nvs, kLocalAuthKey, out, &record_size);
    nvs_close(nvs);

    if (result != ESP_OK || record_size != sizeof(*out)) {
        if (log_failures) {
            ESP_LOGW(kTag, "Local auth read failed: %s size=%u",
                     esp_err_to_name(result),
                     static_cast<unsigned>(record_size));
        }
        memset(out, 0, sizeof(*out));
        return AgentQLocalAuthStatus::storage_error;
    }

    if (!validate_local_auth_record(*out)) {
        if (log_failures) {
            ESP_LOGW(kTag, "Local auth record validation failed");
        }
        memset(out, 0, sizeof(*out));
        return AgentQLocalAuthStatus::invalid;
    }
    return AgentQLocalAuthStatus::active;
}

}  // namespace

bool is_valid_local_pin(const char* pin)
{
    if (pin == nullptr) {
        return false;
    }
    for (size_t index = 0; index < kLocalPinDigits; ++index) {
        if (pin[index] < '0' || pin[index] > '9') {
            return false;
        }
    }
    return pin[kLocalPinDigits] == '\0';
}

bool store_local_pin_verifier(const char* pin)
{
    if (!is_valid_local_pin(pin)) {
        ESP_LOGW(kTag, "Refusing invalid local PIN shape");
        return false;
    }

    StoredLocalAuthRecord record = make_empty_record();
    if (!fill_secure_random(record.salt, sizeof(record.salt))) {
        ESP_LOGE(kTag, "Secure RNG unavailable for local PIN salt");
        wipe_sensitive_buffer(&record, sizeof(record));
        return false;
    }
    if (!derive_pin_verifier(pin, record.salt, record.verifier)) {
        wipe_sensitive_buffer(&record, sizeof(record));
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing local auth: %s", esp_err_to_name(result));
        wipe_sensitive_buffer(&record, sizeof(record));
        return false;
    }

    result = nvs_set_blob(nvs, kLocalAuthKey, &record, sizeof(record));
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    wipe_sensitive_buffer(&record, sizeof(record));

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS write failed for local auth: %s", esp_err_to_name(result));
        wipe_local_auth();
        return false;
    }

    ESP_LOGI(kTag, "Stored DEV_PROFILE local PIN verifier");
    return true;
}

bool verify_local_pin(const char* pin, bool* verified)
{
    if (verified != nullptr) {
        *verified = false;
    }
    if (verified == nullptr || !is_valid_local_pin(pin)) {
        return false;
    }

    StoredLocalAuthRecord record = {};
    if (read_local_auth_record(&record, true) != AgentQLocalAuthStatus::active) {
        return false;
    }

    uint8_t candidate[kVerifierBytes] = {};
    const bool derived = derive_pin_verifier(pin, record.salt, candidate);
    if (!derived) {
        wipe_sensitive_buffer(&record, sizeof(record));
        wipe_sensitive_buffer(candidate, sizeof(candidate));
        return false;
    }

    *verified = constant_time_equal(candidate, record.verifier, sizeof(candidate));
    wipe_sensitive_buffer(&record, sizeof(record));
    wipe_sensitive_buffer(candidate, sizeof(candidate));
    return true;
}

bool wipe_local_auth()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while wiping local auth: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kLocalAuthKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS erase failed for local auth: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGI(kTag, "Local PIN verifier wiped");
    return true;
}

AgentQLocalAuthStatus local_auth_status()
{
    StoredLocalAuthRecord record = {};
    return read_local_auth_record(&record, false);
}

}  // namespace agent_q
