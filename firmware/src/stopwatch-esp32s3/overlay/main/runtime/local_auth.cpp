#include "local_auth.h"

#include <stdint.h>
#include <string.h>

#include "sensitive_memory.h"
#include "stopwatch_keystore.h"

#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
#include <vector>
#else
#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"
#endif

namespace stopwatch_target {
namespace {

constexpr const char* kTag = "StopWatchAuth";
constexpr const char* kNvsNamespace = "auth_state";
constexpr const char* kNvsKey = "lockout";
constexpr uint8_t kRecordVersion = 1;
constexpr uint32_t kFirstLockAttempt = 5;
constexpr uint64_t kMinuteMs = 60ULL * 1000ULL;
constexpr uint64_t kHourMs = 60ULL * kMinuteMs;

struct StoredLocalAuthRecord {
    uint8_t magic[4];
    uint8_t version;
    uint8_t lock_tier;
    uint8_t reserved0[2];
    uint32_t failed_attempts;
    uint64_t lock_deadline_ms;
    uint64_t lock_duration_ms;
    uint8_t reserved1[16];
};

static_assert(
    sizeof(StoredLocalAuthRecord) == 48,
    "Local authentication metadata must stay fixed-size");

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
    record.magic[2] = 'A';
    record.magic[3] = 'M';
    record.version = kRecordVersion;
    return record;
}

bool record_valid(const StoredLocalAuthRecord& record)
{
    if (record.magic[0] != 'S' || record.magic[1] != 'W' ||
        record.magic[2] != 'A' || record.magic[3] != 'M' ||
        record.version != kRecordVersion || record.lock_tier > 4) {
        return false;
    }
    for (uint8_t value : record.reserved0) {
        if (value != 0) {
            return false;
        }
    }
    for (uint8_t value : record.reserved1) {
        if (value != 0) {
            return false;
        }
    }
    if (record.lock_tier == 0) {
        return record.lock_deadline_ms == 0 && record.lock_duration_ms == 0;
    }
    return record.lock_deadline_ms != 0 &&
           record.lock_duration_ms == lock_duration_for_tier(record.lock_tier);
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
    if (record.lock_tier == 0 || record.lock_deadline_ms == 0 ||
        now_ms >= record.lock_deadline_ms) {
        return 0;
    }
    return record.lock_deadline_ms - now_ms;
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

void cache_storage_status(LocalAuthStoreStatus status)
{
    g_snapshot_cache.loaded = true;
    g_snapshot_cache.status = status;
    g_snapshot_cache.failed_attempts = 0;
    g_snapshot_cache.lock_tier = 0;
    g_snapshot_cache.lock_deadline_ms = 0;
}

void cache_active_record(const StoredLocalAuthRecord& record)
{
    g_snapshot_cache.loaded = true;
    g_snapshot_cache.status = LocalAuthStoreStatus::active;
    g_snapshot_cache.failed_attempts = record.failed_attempts;
    g_snapshot_cache.lock_tier = record.lock_tier;
    g_snapshot_cache.lock_deadline_ms = record.lock_deadline_ms;
}

LocalAuthSnapshot snapshot_from_cache(uint64_t now_ms)
{
    LocalAuthSnapshot snapshot{
        g_snapshot_cache.loaded ? g_snapshot_cache.status
                                : LocalAuthStoreStatus::storage_error,
        0,
        0,
        false,
        0,
    };
    if (!g_snapshot_cache.loaded ||
        g_snapshot_cache.status != LocalAuthStoreStatus::active) {
        return snapshot;
    }
    snapshot.failed_attempts = g_snapshot_cache.failed_attempts;
    snapshot.lock_tier = g_snapshot_cache.lock_tier;
    if (g_snapshot_cache.lock_tier != 0 &&
        g_snapshot_cache.lock_deadline_ms > now_ms) {
        snapshot.locked = true;
        snapshot.lock_remaining_ms =
            g_snapshot_cache.lock_deadline_ms - now_ms;
    }
    return snapshot;
}

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
        ESP_LOGW(kTag, "NVS open failed while reading auth metadata: %s",
                 esp_err_to_name(result));
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
        return result == ESP_OK ? LocalAuthStoreStatus::invalid
                                : LocalAuthStoreStatus::storage_error;
    }
    result = nvs_get_blob(nvs, kNvsKey, out, &record_size);
    nvs_close(nvs);
    if (result != ESP_OK || record_size != sizeof(*out)) {
        wipe_sensitive_buffer(out, sizeof(*out));
        return LocalAuthStoreStatus::storage_error;
    }
#endif
    if (!record_valid(*out)) {
        wipe_sensitive_buffer(out, sizeof(*out));
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
        ESP_LOGW(kTag, "NVS open failed while storing auth metadata: %s",
                 esp_err_to_name(result));
        return false;
    }
    result = nvs_set_blob(nvs, kNvsKey, &record, sizeof(record));
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS write failed while storing auth metadata: %s",
                 esp_err_to_name(result));
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
        ESP_LOGW(kTag, "NVS open failed while clearing auth metadata: %s",
                 esp_err_to_name(result));
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
        ESP_LOGW(kTag, "NVS erase failed while clearing auth metadata: %s",
                 esp_err_to_name(result));
        return false;
    }
    return true;
#endif
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
    if (record->lock_tier != 0 || record->lock_deadline_ms != 0 ||
        record->lock_duration_ms != 0) {
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

LocalAuthStoreStatus combine_with_keystore(LocalAuthStoreStatus metadata_status)
{
    switch (stopwatch_keystore_state()) {
        case signing::KeystoreState::absent:
            if (metadata_status == LocalAuthStoreStatus::storage_error) {
                return LocalAuthStoreStatus::storage_error;
            }
            return metadata_status == LocalAuthStoreStatus::missing
                ? LocalAuthStoreStatus::missing
                : LocalAuthStoreStatus::invalid;
        case signing::KeystoreState::unlocking:
            return metadata_status == LocalAuthStoreStatus::missing
                ? LocalAuthStoreStatus::missing
                : metadata_status;
        case signing::KeystoreState::locked:
        case signing::KeystoreState::unlocked:
            if (metadata_status == LocalAuthStoreStatus::active ||
                metadata_status == LocalAuthStoreStatus::storage_error) {
                return metadata_status;
            }
            return LocalAuthStoreStatus::invalid;
        case signing::KeystoreState::invalid:
            return LocalAuthStoreStatus::invalid;
        case signing::KeystoreState::storage_error:
            return LocalAuthStoreStatus::storage_error;
    }
    return LocalAuthStoreStatus::storage_error;
}

LocalAuthVerifyResult fail_material(LocalAuthVerifyResult result)
{
    stopwatch_keystore_lock();
    return result;
}

}  // namespace

void local_auth_init(uint64_t now_ms)
{
    StoredLocalAuthRecord record = {};
    const LocalAuthStoreStatus status = read_record(&record);
    if (status == LocalAuthStoreStatus::active && record.lock_tier != 0) {
        record.lock_duration_ms = lock_duration_for_tier(record.lock_tier);
        record.lock_deadline_ms = now_ms + record.lock_duration_ms;
        if (!persist_active_record(record)) {
            stopwatch_keystore_lock();
            wipe_sensitive_buffer(&record, sizeof(record));
            return;
        }
    } else if (status == LocalAuthStoreStatus::active) {
        cache_active_record(record);
    } else {
        cache_storage_status(status);
    }
    wipe_sensitive_buffer(&record, sizeof(record));
}

bool local_auth_store_initial_metadata()
{
    const StoredLocalAuthRecord record = empty_record();
    return persist_active_record(record);
}

LocalAuthVerifyResult local_auth_record_keystore_result(
    signing::KeystoreOperationStatus result,
    uint64_t now_ms)
{
    StoredLocalAuthRecord record = {};
    const LocalAuthStoreStatus status = read_record(&record);
    if (status != LocalAuthStoreStatus::active) {
        cache_storage_status(status);
        wipe_sensitive_buffer(&record, sizeof(record));
        if (status == LocalAuthStoreStatus::missing) {
            return fail_material(LocalAuthVerifyResult::missing);
        }
        return fail_material(
            status == LocalAuthStoreStatus::invalid
                ? LocalAuthVerifyResult::invalid
                : LocalAuthVerifyResult::storage_error);
    }

    if (result == signing::KeystoreOperationStatus::success) {
        record.failed_attempts = 0;
        clear_lock(&record);
        const bool stored = persist_active_record(record);
        wipe_sensitive_buffer(&record, sizeof(record));
        return stored ? LocalAuthVerifyResult::verified
                      : fail_material(LocalAuthVerifyResult::storage_error);
    }

    if (result != signing::KeystoreOperationStatus::wrong_pin) {
        wipe_sensitive_buffer(&record, sizeof(record));
        return fail_material(
            result == signing::KeystoreOperationStatus::invalid_record
                ? LocalAuthVerifyResult::invalid
                : LocalAuthVerifyResult::storage_error);
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
        return fail_material(LocalAuthVerifyResult::storage_error);
    }
    if (next_tier != 0) {
        stopwatch_keystore_lock();
        return LocalAuthVerifyResult::locked;
    }
    return LocalAuthVerifyResult::rejected;
}

LocalAuthSnapshot local_auth_snapshot(uint64_t now_ms)
{
    LocalAuthSnapshot snapshot = !g_snapshot_cache.loaded
        ? refresh_snapshot_cache_from_storage(now_ms)
        : snapshot_from_cache(now_ms);
    if (snapshot.status == LocalAuthStoreStatus::active &&
        g_snapshot_cache.lock_tier != 0 &&
        g_snapshot_cache.lock_deadline_ms != 0 &&
        now_ms >= g_snapshot_cache.lock_deadline_ms) {
        snapshot = refresh_snapshot_cache_from_storage(now_ms);
    }
    snapshot.status = combine_with_keystore(snapshot.status);
    if (snapshot.status != LocalAuthStoreStatus::active) {
        snapshot.failed_attempts = 0;
        snapshot.lock_tier = 0;
        snapshot.locked = false;
        snapshot.lock_remaining_ms = 0;
    }
    return snapshot;
}

bool local_auth_clear()
{
    const bool erased = erase_record();
    cache_storage_status(
        erased ? LocalAuthStoreStatus::missing
               : LocalAuthStoreStatus::storage_error);
    return erased;
}

#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
void local_auth_test_reset_store()
{
    g_test_store.clear();
    g_test_write_failure = false;
    g_snapshot_cache = {};
    local_auth_test_reset_io_counters();
}

void local_auth_test_corrupt_record()
{
    g_test_store.assign(sizeof(StoredLocalAuthRecord), 0xA5);
    g_snapshot_cache = {};
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

uint32_t local_auth_test_read_count() { return g_test_read_count; }
uint32_t local_auth_test_write_count() { return g_test_write_count; }
uint32_t local_auth_test_erase_count() { return g_test_erase_count; }
#endif

}  // namespace stopwatch_target
