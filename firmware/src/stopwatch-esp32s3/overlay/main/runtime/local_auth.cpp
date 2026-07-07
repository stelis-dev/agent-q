#include "local_auth.h"

#include <stdint.h>
#include <string.h>

#include "sensitive_memory.h"

#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
#include <vector>
#else
#include "esp_err.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/md.h"
#include "nvs.h"
#endif

namespace stopwatch_target {
namespace {

constexpr const char* kTag = "StopWatchAuth";
constexpr const char* kNvsNamespace = "local_auth";
constexpr const char* kNvsKey = "verifier";
constexpr uint8_t kRecordVersion = 1;
constexpr uint8_t kKdfPbkdf2HmacSha256 = 1;
constexpr uint32_t kKdfIterations = 20000;
constexpr size_t kSaltBytes = 16;
constexpr size_t kVerifierBytes = 32;
constexpr uint32_t kFirstLockAttempt = 5;
constexpr uint64_t kMinuteMs = 60ULL * 1000ULL;
constexpr uint64_t kHourMs = 60ULL * kMinuteMs;

struct StoredLocalAuthRecord {
    uint8_t magic[4];
    uint8_t version;
    uint8_t kdf_id;
    uint8_t code_length;
    uint8_t reserved0;
    uint32_t iterations;
    uint32_t failed_attempts;
    uint8_t lock_tier;
    uint8_t reserved1[3];
    uint64_t lock_deadline_ms;
    uint64_t lock_duration_ms;
    uint8_t salt[kSaltBytes];
    uint8_t verifier[kVerifierBytes];
    uint8_t reserved2[16];
};

static_assert(sizeof(StoredLocalAuthRecord) == 104, "Local auth record must stay fixed-size");

#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
std::vector<uint8_t> g_test_store;
bool g_test_write_failure = false;
uint32_t g_test_read_count = 0;
uint32_t g_test_write_count = 0;
uint32_t g_test_erase_count = 0;
#endif

struct LocalAuthRuntimeSnapshotCache {
    bool loaded;
    LocalAuthStoreStatus status;
    uint8_t code_length;
    uint32_t failed_attempts;
    uint8_t lock_tier;
    uint64_t lock_deadline_ms;
};

LocalAuthRuntimeSnapshotCache g_snapshot_cache = {};

uint64_t lock_duration_for_tier(uint8_t tier);

StoredLocalAuthRecord empty_record()
{
    StoredLocalAuthRecord record = {};
    record.magic[0] = 'S';
    record.magic[1] = 'W';
    record.magic[2] = 'L';
    record.magic[3] = 'A';
    record.version = kRecordVersion;
    record.kdf_id = kKdfPbkdf2HmacSha256;
    record.iterations = kKdfIterations;
    return record;
}

bool record_magic_valid(const StoredLocalAuthRecord& record)
{
    return record.magic[0] == 'S' && record.magic[1] == 'W' &&
           record.magic[2] == 'L' && record.magic[3] == 'A';
}

bool code_length_valid(size_t length)
{
    return length >= kLocalAuthMinDigits && length <= kLocalAuthMaxDigits;
}

bool record_valid(const StoredLocalAuthRecord& record)
{
    if (!record_magic_valid(record) ||
        record.version != kRecordVersion ||
        record.kdf_id != kKdfPbkdf2HmacSha256 ||
        !code_length_valid(record.code_length) ||
        record.iterations != kKdfIterations) {
        return false;
    }
    if (record.lock_tier > 4) {
        return false;
    }
    if (record.lock_tier == 0) {
        if (record.lock_deadline_ms != 0 || record.lock_duration_ms != 0) {
            return false;
        }
    } else if (record.lock_duration_ms != lock_duration_for_tier(record.lock_tier) ||
               record.lock_deadline_ms == 0) {
        return false;
    }
    for (const uint8_t value : record.reserved1) {
        if (value != 0) {
            return false;
        }
    }
    for (const uint8_t value : record.reserved2) {
        if (value != 0) {
            return false;
        }
    }
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

uint8_t lock_tier_for_attempts(uint32_t failed_attempts)
{
    if (failed_attempts < kFirstLockAttempt) {
        return 0;
    }
    if (failed_attempts < 10) {
        return 1;
    }
    if (failed_attempts < 15) {
        return 2;
    }
    if (failed_attempts < 20) {
        return 3;
    }
    return 4;
}

uint64_t lock_duration_for_tier(uint8_t tier)
{
    switch (tier) {
        case 1:
            return 5ULL * kMinuteMs;
        case 2:
            return 30ULL * kMinuteMs;
        case 3:
            return 2ULL * kHourMs;
        case 4:
            return 24ULL * kHourMs;
        default:
            return 0;
    }
}

uint64_t remaining_lock_ms(const StoredLocalAuthRecord& record, uint64_t now_ms)
{
    if (record.lock_tier == 0 || record.lock_deadline_ms == 0) {
        return 0;
    }
    if (now_ms >= record.lock_deadline_ms) {
        return 0;
    }
    return record.lock_deadline_ms - now_ms;
}

void arm_lock_from_duration(StoredLocalAuthRecord* record, uint64_t now_ms)
{
    if (record == nullptr || record->lock_tier == 0) {
        return;
    }
    record->lock_duration_ms = lock_duration_for_tier(record->lock_tier);
    record->lock_deadline_ms = now_ms + record->lock_duration_ms;
}

void clear_lock(StoredLocalAuthRecord* record)
{
    if (record == nullptr) {
        return;
    }
    record->lock_tier = 0;
    record->lock_deadline_ms = 0;
    record->lock_duration_ms = 0;
}

void clear_snapshot_fields()
{
    g_snapshot_cache.code_length = 0;
    g_snapshot_cache.failed_attempts = 0;
    g_snapshot_cache.lock_tier = 0;
    g_snapshot_cache.lock_deadline_ms = 0;
}

void cache_storage_status(LocalAuthStoreStatus status)
{
    g_snapshot_cache.loaded = true;
    g_snapshot_cache.status = status;
    clear_snapshot_fields();
}

void cache_active_record(const StoredLocalAuthRecord& record)
{
    g_snapshot_cache.loaded = true;
    g_snapshot_cache.status = LocalAuthStoreStatus::active;
    g_snapshot_cache.code_length = record.code_length;
    g_snapshot_cache.failed_attempts = record.failed_attempts;
    g_snapshot_cache.lock_tier = record.lock_tier;
    g_snapshot_cache.lock_deadline_ms = record.lock_deadline_ms;
}

LocalAuthSnapshot snapshot_from_cache(uint64_t now_ms)
{
    LocalAuthSnapshot snapshot{
        g_snapshot_cache.status,
        0,
        0,
        0,
        false,
        0,
    };
    if (!g_snapshot_cache.loaded) {
        snapshot.status = LocalAuthStoreStatus::storage_error;
        return snapshot;
    }
    if (g_snapshot_cache.status != LocalAuthStoreStatus::active) {
        return snapshot;
    }
    snapshot.code_length = g_snapshot_cache.code_length;
    snapshot.failed_attempts = g_snapshot_cache.failed_attempts;
    snapshot.lock_tier = g_snapshot_cache.lock_tier;
    if (g_snapshot_cache.lock_tier != 0 && g_snapshot_cache.lock_deadline_ms > now_ms) {
        snapshot.locked = true;
        snapshot.lock_remaining_ms = g_snapshot_cache.lock_deadline_ms - now_ms;
    }
    return snapshot;
}

void fill_random(uint8_t* output, size_t size)
{
#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
    for (size_t index = 0; index < size; ++index) {
        output[index] = static_cast<uint8_t>(0x51U + index * 17U);
    }
#else
    esp_fill_random(output, size);
#endif
}

#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
bool derive_verifier(
    const char* code,
    size_t length,
    const uint8_t salt[kSaltBytes],
    uint8_t verifier[kVerifierBytes])
{
    if (!local_auth_code_shape_valid(code, length) || salt == nullptr || verifier == nullptr) {
        return false;
    }
    uint8_t state[kVerifierBytes] = {};
    for (size_t index = 0; index < kVerifierBytes; ++index) {
        state[index] = static_cast<uint8_t>(salt[index % kSaltBytes] ^ 0xA5U ^ index);
    }
    for (uint32_t iteration = 0; iteration < 64; ++iteration) {
        for (size_t index = 0; index < kVerifierBytes; ++index) {
            const uint8_t input = static_cast<uint8_t>(code[(index + iteration) % length]);
            state[index] = static_cast<uint8_t>(
                (state[index] << 1) ^ (state[index] >> 3) ^ input ^ static_cast<uint8_t>(iteration));
        }
    }
    memcpy(verifier, state, kVerifierBytes);
    wipe_sensitive_buffer(state, sizeof(state));
    return true;
}
#else
bool derive_verifier(
    const char* code,
    size_t length,
    const uint8_t salt[kSaltBytes],
    uint8_t verifier[kVerifierBytes])
{
    if (!local_auth_code_shape_valid(code, length) || salt == nullptr || verifier == nullptr) {
        return false;
    }

    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == nullptr) {
        return false;
    }

    uint8_t block[kSaltBytes + 4] = {};
    memcpy(block, salt, kSaltBytes);
    block[kSaltBytes + 3] = 1;

    uint8_t u[kVerifierBytes] = {};
    uint8_t t[kVerifierBytes] = {};
    if (mbedtls_md_hmac(md, reinterpret_cast<const unsigned char*>(code), length, block, sizeof(block), u) != 0) {
        wipe_sensitive_buffer(block, sizeof(block));
        wipe_sensitive_buffer(u, sizeof(u));
        return false;
    }
    memcpy(t, u, sizeof(t));
    for (uint32_t iteration = 1; iteration < kKdfIterations; ++iteration) {
        if (mbedtls_md_hmac(md, reinterpret_cast<const unsigned char*>(code), length, u, sizeof(u), u) != 0) {
            wipe_sensitive_buffer(block, sizeof(block));
            wipe_sensitive_buffer(u, sizeof(u));
            wipe_sensitive_buffer(t, sizeof(t));
            return false;
        }
        for (size_t index = 0; index < sizeof(t); ++index) {
            t[index] ^= u[index];
        }
    }
    memcpy(verifier, t, kVerifierBytes);
    wipe_sensitive_buffer(block, sizeof(block));
    wipe_sensitive_buffer(u, sizeof(u));
    wipe_sensitive_buffer(t, sizeof(t));
    return true;
}
#endif

LocalAuthStoreStatus read_record(StoredLocalAuthRecord* out)
{
    if (out == nullptr) {
        return LocalAuthStoreStatus::storage_error;
    }
    memset(out, 0, sizeof(*out));

#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
    ++g_test_read_count;
    if (g_test_store.empty()) {
        return LocalAuthStoreStatus::missing;
    }
    if (g_test_store.size() != sizeof(*out)) {
        return LocalAuthStoreStatus::invalid;
    }
    memcpy(out, g_test_store.data(), sizeof(*out));
#else
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return LocalAuthStoreStatus::missing;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while reading local auth: %s", esp_err_to_name(result));
        return LocalAuthStoreStatus::storage_error;
    }
    size_t record_size = 0;
    result = nvs_get_blob(nvs, kNvsKey, nullptr, &record_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return LocalAuthStoreStatus::missing;
    }
    if (result != ESP_OK || record_size != sizeof(*out)) {
        nvs_close(nvs);
        return result == ESP_OK ? LocalAuthStoreStatus::invalid : LocalAuthStoreStatus::storage_error;
    }
    result = nvs_get_blob(nvs, kNvsKey, out, &record_size);
    nvs_close(nvs);
    if (result != ESP_OK || record_size != sizeof(*out)) {
        memset(out, 0, sizeof(*out));
        return LocalAuthStoreStatus::storage_error;
    }
#endif

    if (!record_valid(*out)) {
        memset(out, 0, sizeof(*out));
        return LocalAuthStoreStatus::invalid;
    }
    return LocalAuthStoreStatus::active;
}

bool write_record(const StoredLocalAuthRecord& record)
{
    if (!record_valid(record)) {
        return false;
    }
#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
    ++g_test_write_count;
    if (g_test_write_failure) {
        return false;
    }
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&record);
    g_test_store.assign(bytes, bytes + sizeof(record));
    return true;
#else
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing local auth: %s", esp_err_to_name(result));
        return false;
    }
    result = nvs_set_blob(nvs, kNvsKey, &record, sizeof(record));
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS write failed while storing local auth: %s", esp_err_to_name(result));
        return false;
    }
    return true;
#endif
}

bool persist_active_record(const StoredLocalAuthRecord& record)
{
    const bool stored = write_record(record);
    if (stored) {
        cache_active_record(record);
    } else {
        cache_storage_status(LocalAuthStoreStatus::storage_error);
    }
    return stored;
}

bool erase_record()
{
#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
    ++g_test_erase_count;
    if (g_test_write_failure) {
        return false;
    }
    g_test_store.clear();
    return true;
#else
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while clearing local auth: %s", esp_err_to_name(result));
        return false;
    }
    result = nvs_erase_key(nvs, kNvsKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        result = ESP_OK;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS erase failed while clearing local auth: %s", esp_err_to_name(result));
        return false;
    }
    return true;
#endif
}

bool erase_record_and_cache()
{
    const bool erased = erase_record();
    cache_storage_status(erased ? LocalAuthStoreStatus::missing : LocalAuthStoreStatus::storage_error);
    return erased;
}

enum class LockRefreshResult {
    unlocked,
    locked,
    storage_error,
};

LockRefreshResult refresh_record_lock(StoredLocalAuthRecord* record, uint64_t now_ms)
{
    if (record == nullptr) {
        return LockRefreshResult::storage_error;
    }
    if (remaining_lock_ms(*record, now_ms) > 0) {
        return LockRefreshResult::locked;
    }
    if (record->lock_tier != 0 || record->lock_deadline_ms != 0 || record->lock_duration_ms != 0) {
        clear_lock(record);
        if (!persist_active_record(*record)) {
            return LockRefreshResult::storage_error;
        }
    }
    return LockRefreshResult::unlocked;
}

LocalAuthSnapshot refresh_snapshot_cache_from_storage(uint64_t now_ms)
{
    StoredLocalAuthRecord record = {};
    const LocalAuthStoreStatus status = read_record(&record);
    if (status != LocalAuthStoreStatus::active) {
        cache_storage_status(status);
        wipe_sensitive_buffer(&record, sizeof(record));
        return snapshot_from_cache(now_ms);
    }

    const LockRefreshResult lock_result = refresh_record_lock(&record, now_ms);
    if (lock_result == LockRefreshResult::storage_error) {
        cache_storage_status(LocalAuthStoreStatus::storage_error);
        wipe_sensitive_buffer(&record, sizeof(record));
        return snapshot_from_cache(now_ms);
    }
    cache_active_record(record);
    wipe_sensitive_buffer(&record, sizeof(record));
    return snapshot_from_cache(now_ms);
}

}  // namespace

void local_auth_init(uint64_t now_ms)
{
    StoredLocalAuthRecord record = {};
    const LocalAuthStoreStatus status = read_record(&record);
    if (status == LocalAuthStoreStatus::invalid) {
#ifndef STOPWATCH_LOCAL_AUTH_HOST_TEST
        ESP_LOGW(kTag, "Local auth record is invalid; failing closed");
#endif
    }
    if (status == LocalAuthStoreStatus::active && record.lock_tier != 0) {
        arm_lock_from_duration(&record, now_ms);
        if (!persist_active_record(record)) {
#ifndef STOPWATCH_LOCAL_AUTH_HOST_TEST
            ESP_LOGW(kTag, "Local auth lock re-anchor failed; failing closed until storage recovers");
#endif
            wipe_sensitive_buffer(&record, sizeof(record));
            return;
        }
    }
    if (status == LocalAuthStoreStatus::active) {
        cache_active_record(record);
    } else {
        cache_storage_status(status);
    }
    wipe_sensitive_buffer(&record, sizeof(record));
}

bool local_auth_code_shape_valid(const char* code, size_t length)
{
    if (code == nullptr || !code_length_valid(length)) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        if (code[index] < '0' || code[index] > '9') {
            return false;
        }
    }
    return code[length] == '\0';
}

bool local_auth_store_new_code(const char* code, size_t length)
{
    if (!local_auth_code_shape_valid(code, length)) {
        return false;
    }
    StoredLocalAuthRecord record = empty_record();
    record.code_length = static_cast<uint8_t>(length);
    fill_random(record.salt, sizeof(record.salt));
    const bool derived = derive_verifier(code, length, record.salt, record.verifier);
    if (!derived) {
        wipe_sensitive_buffer(&record, sizeof(record));
        return false;
    }
    const bool stored = persist_active_record(record);
    wipe_sensitive_buffer(&record, sizeof(record));
    return stored;
}

LocalAuthVerifyResult local_auth_verify_code(const char* code, size_t length, uint64_t now_ms)
{
    StoredLocalAuthRecord record = {};
    const LocalAuthStoreStatus status = read_record(&record);
    if (status != LocalAuthStoreStatus::active) {
        cache_storage_status(status);
        wipe_sensitive_buffer(&record, sizeof(record));
        switch (status) {
            case LocalAuthStoreStatus::missing:
                return LocalAuthVerifyResult::missing;
            case LocalAuthStoreStatus::invalid:
                return LocalAuthVerifyResult::invalid;
            case LocalAuthStoreStatus::storage_error:
                return LocalAuthVerifyResult::storage_error;
            case LocalAuthStoreStatus::active:
                break;
        }
    }

    const LockRefreshResult lock_result = refresh_record_lock(&record, now_ms);
    if (lock_result == LockRefreshResult::storage_error) {
        cache_storage_status(LocalAuthStoreStatus::storage_error);
        wipe_sensitive_buffer(&record, sizeof(record));
        return LocalAuthVerifyResult::storage_error;
    }
    if (lock_result == LockRefreshResult::locked) {
        cache_active_record(record);
        wipe_sensitive_buffer(&record, sizeof(record));
        return LocalAuthVerifyResult::locked;
    }

    uint8_t candidate[kVerifierBytes] = {};
    const bool shape_valid = local_auth_code_shape_valid(code, length) && length == record.code_length;
    const bool derived = shape_valid && derive_verifier(code, length, record.salt, candidate);
    const bool verified = derived && constant_time_equal(candidate, record.verifier, sizeof(candidate));
    wipe_sensitive_buffer(candidate, sizeof(candidate));

    if (verified) {
        record.failed_attempts = 0;
        clear_lock(&record);
        const bool stored = persist_active_record(record);
        wipe_sensitive_buffer(&record, sizeof(record));
        return stored ? LocalAuthVerifyResult::verified : LocalAuthVerifyResult::storage_error;
    }

    if (record.failed_attempts < UINT32_MAX) {
        ++record.failed_attempts;
    }
    const uint8_t next_tier = lock_tier_for_attempts(record.failed_attempts);
    if (next_tier != 0) {
        record.lock_tier = next_tier;
        record.lock_duration_ms = lock_duration_for_tier(next_tier);
        record.lock_deadline_ms = now_ms + record.lock_duration_ms;
    }
    const bool stored = persist_active_record(record);
    wipe_sensitive_buffer(&record, sizeof(record));
    if (!stored) {
        return LocalAuthVerifyResult::storage_error;
    }
    return next_tier != 0 ? LocalAuthVerifyResult::locked : LocalAuthVerifyResult::rejected;
}

LocalAuthSnapshot local_auth_snapshot(uint64_t now_ms)
{
    if (!g_snapshot_cache.loaded) {
        return refresh_snapshot_cache_from_storage(now_ms);
    }
    if (g_snapshot_cache.status == LocalAuthStoreStatus::active &&
        g_snapshot_cache.lock_tier != 0 &&
        g_snapshot_cache.lock_deadline_ms != 0 &&
        now_ms >= g_snapshot_cache.lock_deadline_ms) {
        return refresh_snapshot_cache_from_storage(now_ms);
    }
    return snapshot_from_cache(now_ms);
}

bool local_auth_clear()
{
    return erase_record_and_cache();
}

#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
void invalidate_snapshot_cache()
{
    g_snapshot_cache = {};
}

void local_auth_test_reset_store()
{
    g_test_store.clear();
    g_test_write_failure = false;
    invalidate_snapshot_cache();
    local_auth_test_reset_io_counters();
}

void local_auth_test_corrupt_record()
{
    g_test_store.assign(sizeof(StoredLocalAuthRecord), 0xA5);
    invalidate_snapshot_cache();
}

bool local_auth_test_record_contains(const char* text)
{
    if (text == nullptr || g_test_store.empty()) {
        return false;
    }
    const size_t text_size = strlen(text);
    if (text_size == 0 || text_size > g_test_store.size()) {
        return false;
    }
    for (size_t offset = 0; offset + text_size <= g_test_store.size(); ++offset) {
        if (memcmp(g_test_store.data() + offset, text, text_size) == 0) {
            return true;
        }
    }
    return false;
}

void local_auth_test_set_write_failure(bool enabled)
{
    g_test_write_failure = enabled;
}

void local_auth_test_reset_io_counters()
{
    g_test_read_count = 0;
    g_test_write_count = 0;
    g_test_erase_count = 0;
}

uint32_t local_auth_test_read_count()
{
    return g_test_read_count;
}

uint32_t local_auth_test_write_count()
{
    return g_test_write_count;
}

uint32_t local_auth_test_erase_count()
{
    return g_test_erase_count;
}
#endif

}  // namespace stopwatch_target
