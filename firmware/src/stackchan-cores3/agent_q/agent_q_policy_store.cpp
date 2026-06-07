#include "agent_q_policy_store.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "nvs.h"

#include "agent_q_common/policy/agent_q_policy_canonical.h"
#include "agent_q_common/sui/agent_q_sui_method_adapter.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQPolicyStore";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kPolicySlotKeys[2] = {"pol_s0", "pol_s1"};
constexpr const char* kPolicyCommitKeys[2] = {"pol_c0", "pol_c1"};
constexpr const char* kPolicyPendingKey = "pol_p";
constexpr uint8_t kCommitRecordMagic[4] = {'A', 'Q', 'P', 'C'};
constexpr uint8_t kPendingRecordMagic[4] = {'A', 'Q', 'P', 'P'};
constexpr uint8_t kCommitRecordVersion = 0;
constexpr uint8_t kPendingRecordVersion = 0;
constexpr size_t kCommitRecordBytes = 48;
constexpr size_t kPendingRecordBytes = 16;
constexpr size_t kCommitHashOffset = 16;
constexpr size_t kDefaultPolicyRecordBytes = kAgentQPolicyDefaultCanonicalRecordBytes;

static AgentQPolicyCanonicalDocument g_policy_document;
static AgentQPolicyRuntimeView g_policy_runtime_view;
static uint8_t g_policy_record_buffer[kAgentQPolicyMaxCanonicalRecordBytes];
static uint8_t g_policy_encoded_buffer[kAgentQPolicyMaxCanonicalRecordBytes];
static uint8_t g_policy_scratch_buffer[kAgentQPolicyMaxCanonicalRecordBytes];

struct PolicyCommit {
    bool present;
    bool metadata_valid;
    bool valid;
    uint8_t slot;
    uint64_t sequence;
    uint8_t record_hash[32];
};

struct PolicyPendingWrite {
    bool present;
    bool valid;
    uint8_t commit_index;
    uint8_t slot;
    uint64_t sequence;
};

struct ActivePolicySelection {
    AgentQPolicyStoreStatus status;
    uint8_t slot;
    uint64_t sequence;
    size_t record_size;
};

AgentQPolicyStoreStatus select_active_policy(ActivePolicySelection* out, bool log_failures);
AgentQPolicyStoreStatus read_commit_record(uint8_t commit_index, PolicyCommit* out, bool log_failures);
AgentQPolicyStoreStatus read_pending_record(PolicyPendingWrite* out, bool log_failures);

void write_hex_byte(uint8_t value, char* output)
{
    constexpr char kHex[] = "0123456789abcdef";
    output[0] = kHex[(value >> 4) & 0x0F];
    output[1] = kHex[value & 0x0F];
}

void write_u64_be(uint64_t value, uint8_t* output)
{
    for (size_t index = 0; index < 8; ++index) {
        output[index] = static_cast<uint8_t>((value >> ((7 - index) * 8)) & 0xFF);
    }
}

uint64_t read_u64_be(const uint8_t* input)
{
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value = (value << 8) | input[index];
    }
    return value;
}

bool sha256_for_record(const uint8_t* record, size_t record_size, uint8_t* output, size_t output_size)
{
    if (record == nullptr || record_size == 0 ||
        output == nullptr || output_size != 32) {
        return false;
    }
    return mbedtls_sha256(
               reinterpret_cast<const unsigned char*>(record),
               record_size,
               output,
               0) == 0;
}

bool policy_id_for_record(const uint8_t* record, size_t record_size, char* output, size_t output_size)
{
    if (output == nullptr || output_size != kAgentQPolicyIdSize) {
        return false;
    }
    memset(output, 0, output_size);

    uint8_t digest[32] = {};
    if (!sha256_for_record(record, record_size, digest, sizeof(digest))) {
        return false;
    }

    constexpr char kPrefix[] = "sha256:";
    memcpy(output, kPrefix, sizeof(kPrefix) - 1);
    char* cursor = output + sizeof(kPrefix) - 1;
    for (size_t index = 0; index < sizeof(digest); ++index) {
        write_hex_byte(digest[index], cursor);
        cursor += 2;
    }
    *cursor = '\0';
    return true;
}

bool default_policy_record(uint8_t* output, size_t output_capacity, size_t* output_size)
{
    return encode_agent_q_policy_v0_default_record(output, output_capacity, output_size) ==
               AgentQPolicyCanonicalStatus::ok &&
           *output_size == kDefaultPolicyRecordBytes;
}

bool validate_policy_record(const uint8_t* record, size_t record_size)
{
    if (record == nullptr || record_size == 0 ||
        record_size > kAgentQPolicyMaxCanonicalRecordBytes) {
        return false;
    }
    if (decode_agent_q_policy_v0_canonical_record(
            record,
            record_size,
            &g_policy_document) != AgentQPolicyCanonicalStatus::ok) {
        return false;
    }

    const AgentQPolicyMethodDescriptor supported_methods[] = {
        sui_sign_transaction_policy_method_descriptor(),
    };
    if (validate_agent_q_policy_v0_canonical_document(
            g_policy_document,
            supported_methods,
            sizeof(supported_methods) / sizeof(supported_methods[0])) !=
        AgentQPolicyCanonicalStatus::ok) {
        return false;
    }

    size_t encoded_size = 0;
    if (encode_agent_q_policy_v0_canonical_record(
            g_policy_document,
            g_policy_encoded_buffer,
            sizeof(g_policy_encoded_buffer),
            &encoded_size) != AgentQPolicyCanonicalStatus::ok ||
        encoded_size != record_size ||
        memcmp(g_policy_encoded_buffer, record, record_size) != 0) {
        return false;
    }
    return true;
}

AgentQPolicyStoreStatus read_blob(
    const char* key,
    uint8_t* out,
    size_t out_capacity,
    size_t* out_size,
    bool log_failures)
{
    if (key == nullptr || out == nullptr || out_size == nullptr) {
        return AgentQPolicyStoreStatus::storage_error;
    }
    memset(out, 0, out_capacity);
    *out_size = 0;

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result != ESP_OK) {
        if (result == ESP_ERR_NVS_NOT_FOUND) {
            return AgentQPolicyStoreStatus::missing;
        }
        if (log_failures) {
            ESP_LOGW(kTag, "NVS open failed while reading %s: %s", key, esp_err_to_name(result));
        }
        return AgentQPolicyStoreStatus::storage_error;
    }

    size_t blob_size = 0;
    result = nvs_get_blob(nvs, key, nullptr, &blob_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return AgentQPolicyStoreStatus::missing;
    }
    if (result != ESP_OK) {
        nvs_close(nvs);
        if (log_failures) {
            ESP_LOGW(kTag, "Policy blob size read failed for %s: %s", key, esp_err_to_name(result));
        }
        return AgentQPolicyStoreStatus::storage_error;
    }
    if (blob_size == 0 || blob_size > out_capacity) {
        nvs_close(nvs);
        return AgentQPolicyStoreStatus::invalid;
    }

    result = nvs_get_blob(nvs, key, out, &blob_size);
    nvs_close(nvs);
    if (result != ESP_OK || blob_size > out_capacity) {
        if (log_failures) {
            ESP_LOGW(kTag, "Policy blob read failed for %s: %s", key, esp_err_to_name(result));
        }
        memset(out, 0, out_capacity);
        return AgentQPolicyStoreStatus::storage_error;
    }

    *out_size = blob_size;
    return AgentQPolicyStoreStatus::active;
}

bool write_blob(const char* key, const uint8_t* record, size_t record_size)
{
    if (key == nullptr || record == nullptr || record_size == 0) {
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while writing %s: %s", key, esp_err_to_name(result));
        return false;
    }

    result = nvs_set_blob(nvs, key, record, record_size);
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS write failed for %s: %s", key, esp_err_to_name(result));
        return false;
    }
    return true;
}

bool erase_key_if_present(nvs_handle_t nvs, const char* key)
{
    esp_err_t result = nvs_erase_key(nvs, key);
    return result == ESP_OK || result == ESP_ERR_NVS_NOT_FOUND;
}

bool erase_policy_key(const char* key)
{
    if (key == nullptr) {
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while erasing %s: %s", key, esp_err_to_name(result));
        return false;
    }

    const bool erased = erase_key_if_present(nvs, key);
    if (erased) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (!erased || result != ESP_OK) {
        ESP_LOGW(kTag, "NVS erase failed for %s: %s", key, esp_err_to_name(result));
        return false;
    }
    return true;
}

bool erase_policy_write_target(uint8_t commit_index, uint8_t slot)
{
    if (commit_index >= 2 || slot >= 2) {
        return false;
    }
    return erase_policy_key(kPolicyCommitKeys[commit_index]) &&
           erase_policy_key(kPolicySlotKeys[slot]);
}

bool erase_interrupted_policy_write(const PolicyPendingWrite& pending)
{
    if (!pending.valid) {
        return false;
    }
    return erase_policy_write_target(pending.commit_index, pending.slot) &&
           erase_policy_key(kPolicyPendingKey);
}

bool pending_matches_selection(
    const PolicyPendingWrite& pending,
    uint8_t selected_index,
    const PolicyCommit& selected)
{
    return pending.valid &&
           pending.commit_index == selected_index &&
           pending.sequence == selected.sequence &&
           pending.slot == selected.slot;
}

bool pending_overlaps_selection(
    const PolicyPendingWrite& pending,
    uint8_t selected_index,
    const PolicyCommit& selected)
{
    return pending.valid &&
           (pending.commit_index == selected_index ||
            pending.slot == selected.slot);
}

bool selections_refer_to_same_policy(const ActivePolicySelection& left, const ActivePolicySelection& right)
{
    if (left.status != AgentQPolicyStoreStatus::active ||
        right.status != AgentQPolicyStoreStatus::active ||
        left.sequence != right.sequence) {
        return false;
    }
    return left.slot == right.slot;
}

bool selection_matches_written_policy(
    const ActivePolicySelection& selection,
    uint8_t slot,
    uint64_t sequence,
    const uint8_t* record,
    size_t record_size)
{
    return selection.status == AgentQPolicyStoreStatus::active &&
           selection.slot == slot &&
           selection.sequence == sequence &&
           selection.record_size == record_size &&
           record != nullptr &&
           memcmp(g_policy_record_buffer, record, record_size) == 0;
}

AgentQPolicyStoreWriteResult classify_policy_write_terminal_state(
    AgentQPolicyStoreStatus previous_status,
    const ActivePolicySelection& previous,
    uint8_t slot,
    uint8_t commit_index,
    uint64_t sequence,
    const uint8_t* record,
    size_t record_size,
    bool may_cleanup_target)
{
    ActivePolicySelection current = {};
    AgentQPolicyStoreStatus status = select_active_policy(&current, true);
    if (status == AgentQPolicyStoreStatus::active) {
        if (selection_matches_written_policy(current, slot, sequence, record, record_size)) {
            return AgentQPolicyStoreWriteResult::applied;
        }
        if (previous_status == AgentQPolicyStoreStatus::active &&
            selections_refer_to_same_policy(previous, current)) {
            return AgentQPolicyStoreWriteResult::unchanged_failure;
        }
        return AgentQPolicyStoreWriteResult::consistency_error;
    }
    if (previous_status != AgentQPolicyStoreStatus::active &&
        status == previous_status) {
        return AgentQPolicyStoreWriteResult::unchanged_failure;
    }

    if (may_cleanup_target &&
        erase_interrupted_policy_write(PolicyPendingWrite{true, true, commit_index, slot, sequence})) {
        status = select_active_policy(&current, true);
        if (status == AgentQPolicyStoreStatus::active) {
            if (selection_matches_written_policy(current, slot, sequence, record, record_size)) {
                return AgentQPolicyStoreWriteResult::applied;
            }
            if (previous_status == AgentQPolicyStoreStatus::active &&
                selections_refer_to_same_policy(previous, current)) {
                return AgentQPolicyStoreWriteResult::unchanged_failure;
            }
        } else if (previous_status != AgentQPolicyStoreStatus::active &&
                   status == previous_status) {
            return AgentQPolicyStoreWriteResult::unchanged_failure;
        }
    }

    return AgentQPolicyStoreWriteResult::consistency_error;
}

AgentQPolicyStoreWriteResult classify_pending_write_failure_terminal_state(
    AgentQPolicyStoreStatus previous_status,
    const ActivePolicySelection& previous,
    uint8_t slot,
    uint8_t commit_index,
    uint64_t sequence,
    const uint8_t* record,
    size_t record_size)
{
    if (erase_policy_key(kPolicyPendingKey)) {
        return classify_policy_write_terminal_state(
            previous_status,
            previous,
            slot,
            commit_index,
            sequence,
            record,
            record_size,
            false);
    }

    PolicyPendingWrite pending = {};
    const AgentQPolicyStoreStatus pending_status = read_pending_record(&pending, true);
    if (pending_status == AgentQPolicyStoreStatus::storage_error ||
        pending_status == AgentQPolicyStoreStatus::invalid ||
        (pending.valid &&
         pending.commit_index == commit_index &&
         pending.slot == slot &&
         pending.sequence == sequence)) {
        return AgentQPolicyStoreWriteResult::consistency_error;
    }

    return classify_policy_write_terminal_state(
        previous_status,
        previous,
        slot,
        commit_index,
        sequence,
        record,
        record_size,
        false);
}

AgentQPolicyStoreStatus read_policy_record_key(
    const char* key,
    uint8_t* out,
    size_t out_capacity,
    size_t* out_size,
    bool log_failures)
{
    const AgentQPolicyStoreStatus read_status =
        read_blob(key, out, out_capacity, out_size, log_failures);
    if (read_status != AgentQPolicyStoreStatus::active) {
        return read_status;
    }
    if (!validate_policy_record(out, *out_size)) {
        if (log_failures) {
            ESP_LOGW(kTag, "Policy record validation failed for %s", key);
        }
        memset(out, 0, out_capacity);
        *out_size = 0;
        return AgentQPolicyStoreStatus::invalid;
    }
    return AgentQPolicyStoreStatus::active;
}

AgentQPolicyStoreStatus read_policy_slot(
    uint8_t slot,
    uint8_t* out,
    size_t out_capacity,
    size_t* out_size,
    bool log_failures)
{
    if (slot >= 2) {
        return AgentQPolicyStoreStatus::storage_error;
    }
    return read_policy_record_key(
        kPolicySlotKeys[slot],
        out,
        out_capacity,
        out_size,
        log_failures);
}

AgentQPolicyStoreStatus read_commit_record(uint8_t commit_index, PolicyCommit* out, bool log_failures)
{
    if (commit_index >= 2 || out == nullptr) {
        return AgentQPolicyStoreStatus::storage_error;
    }
    *out = {};
    uint8_t commit[kCommitRecordBytes] = {};
    size_t commit_size = 0;
    const AgentQPolicyStoreStatus status =
        read_blob(kPolicyCommitKeys[commit_index], commit, sizeof(commit), &commit_size, log_failures);
    if (status == AgentQPolicyStoreStatus::missing) {
        return AgentQPolicyStoreStatus::missing;
    }
    out->present = true;
    if (status == AgentQPolicyStoreStatus::storage_error) {
        return AgentQPolicyStoreStatus::storage_error;
    }
    if (status != AgentQPolicyStoreStatus::active || commit_size != sizeof(commit) ||
        memcmp(commit, kCommitRecordMagic, sizeof(kCommitRecordMagic)) != 0 ||
        commit[4] != kCommitRecordVersion ||
        commit[5] >= 2 ||
        commit[6] != 0 ||
        commit[7] != 0) {
        return AgentQPolicyStoreStatus::invalid;
    }
    out->slot = commit[5];
    out->sequence = read_u64_be(commit + 8);
    if (out->sequence == 0) {
        return AgentQPolicyStoreStatus::invalid;
    }
    memcpy(out->record_hash, commit + kCommitHashOffset, sizeof(out->record_hash));
    out->metadata_valid = true;

    size_t record_size = 0;
    uint8_t digest[32] = {};
    const AgentQPolicyStoreStatus slot_status =
        read_policy_slot(out->slot, g_policy_scratch_buffer, sizeof(g_policy_scratch_buffer), &record_size, log_failures);
    if (slot_status == AgentQPolicyStoreStatus::storage_error) {
        return AgentQPolicyStoreStatus::storage_error;
    }
    if (slot_status != AgentQPolicyStoreStatus::active ||
        !sha256_for_record(g_policy_scratch_buffer, record_size, digest, sizeof(digest)) ||
        memcmp(digest, out->record_hash, sizeof(digest)) != 0) {
        return AgentQPolicyStoreStatus::invalid;
    }
    out->valid = true;
    return AgentQPolicyStoreStatus::active;
}

void build_commit_record(uint8_t slot, uint64_t sequence, const uint8_t* hash, uint8_t* output)
{
    memset(output, 0, kCommitRecordBytes);
    memcpy(output, kCommitRecordMagic, sizeof(kCommitRecordMagic));
    output[4] = kCommitRecordVersion;
    output[5] = slot;
    write_u64_be(sequence, output + 8);
    memcpy(output + kCommitHashOffset, hash, 32);
}

AgentQPolicyStoreStatus read_pending_record(PolicyPendingWrite* out, bool log_failures)
{
    if (out == nullptr) {
        return AgentQPolicyStoreStatus::storage_error;
    }
    *out = {};
    uint8_t pending[kPendingRecordBytes] = {};
    size_t pending_size = 0;
    const AgentQPolicyStoreStatus status =
        read_blob(kPolicyPendingKey, pending, sizeof(pending), &pending_size, log_failures);
    if (status == AgentQPolicyStoreStatus::missing) {
        return AgentQPolicyStoreStatus::missing;
    }
    out->present = true;
    if (status == AgentQPolicyStoreStatus::storage_error) {
        return AgentQPolicyStoreStatus::storage_error;
    }
    if (status != AgentQPolicyStoreStatus::active ||
        pending_size != sizeof(pending) ||
        memcmp(pending, kPendingRecordMagic, sizeof(kPendingRecordMagic)) != 0 ||
        pending[4] != kPendingRecordVersion ||
        pending[5] >= 2 ||
        pending[6] >= 2 ||
        pending[7] != 0) {
        return AgentQPolicyStoreStatus::invalid;
    }
    out->commit_index = pending[5];
    out->slot = pending[6];
    out->sequence = read_u64_be(pending + 8);
    if (out->sequence == 0) {
        return AgentQPolicyStoreStatus::invalid;
    }
    out->valid = true;
    return AgentQPolicyStoreStatus::active;
}

void build_pending_record(uint8_t commit_index, uint8_t slot, uint64_t sequence, uint8_t* output)
{
    memset(output, 0, kPendingRecordBytes);
    memcpy(output, kPendingRecordMagic, sizeof(kPendingRecordMagic));
    output[4] = kPendingRecordVersion;
    output[5] = commit_index;
    output[6] = slot;
    write_u64_be(sequence, output + 8);
}

AgentQPolicyStoreStatus select_active_policy(ActivePolicySelection* out, bool log_failures)
{
    if (out == nullptr) {
        return AgentQPolicyStoreStatus::storage_error;
    }
    *out = {};
    out->status = AgentQPolicyStoreStatus::missing;

    PolicyPendingWrite pending = {};
    const AgentQPolicyStoreStatus pending_status = read_pending_record(&pending, log_failures);
    if (pending_status == AgentQPolicyStoreStatus::storage_error ||
        pending_status == AgentQPolicyStoreStatus::invalid) {
        out->status = pending_status;
        return out->status;
    }

    PolicyCommit commits[2] = {};
    for (uint8_t index = 0; index < 2; ++index) {
        const AgentQPolicyStoreStatus commit_status =
            read_commit_record(index, &commits[index], log_failures);
        if (commit_status == AgentQPolicyStoreStatus::storage_error) {
            out->status = commit_status;
            return out->status;
        }
        if (commit_status == AgentQPolicyStoreStatus::invalid &&
            commits[index].metadata_valid) {
            out->status = AgentQPolicyStoreStatus::invalid;
            return out->status;
        }
        if (commit_status == AgentQPolicyStoreStatus::invalid &&
            (!pending.valid || pending.commit_index != index)) {
            out->status = AgentQPolicyStoreStatus::invalid;
            return out->status;
        }
    }

    const PolicyCommit* selected = nullptr;
    uint8_t selected_index = 0;
    const PolicyCommit* newest_metadata = nullptr;
    uint8_t newest_metadata_index = 0;
    bool metadata_sequence_conflict = false;
    for (uint8_t index = 0; index < 2; ++index) {
        const PolicyCommit& commit = commits[index];
        if (commit.metadata_valid) {
            if (pending.valid &&
                pending.commit_index == index &&
                pending.sequence == commit.sequence &&
                commit.slot != pending.slot) {
                out->status = AgentQPolicyStoreStatus::invalid;
                return out->status;
            }
            if (newest_metadata == nullptr || commit.sequence > newest_metadata->sequence) {
                newest_metadata = &commit;
                newest_metadata_index = index;
                metadata_sequence_conflict = false;
            } else if (commit.sequence == newest_metadata->sequence &&
                       (commit.slot != newest_metadata->slot ||
                        memcmp(commit.record_hash, newest_metadata->record_hash, sizeof(commit.record_hash)) != 0)) {
                metadata_sequence_conflict = true;
            }
        }
        if (!commit.valid) {
            continue;
        }
        if (selected == nullptr || commit.sequence > selected->sequence) {
            selected = &commit;
            selected_index = index;
        } else if (commit.sequence == selected->sequence &&
                   (commit.slot != selected->slot ||
                    memcmp(commit.record_hash, selected->record_hash, sizeof(commit.record_hash)) != 0)) {
            out->status = AgentQPolicyStoreStatus::invalid;
            return out->status;
        }
    }

    if (metadata_sequence_conflict ||
        (selected != nullptr &&
         newest_metadata != nullptr &&
         newest_metadata->sequence > selected->sequence &&
         (!pending.valid ||
          pending.sequence != newest_metadata->sequence ||
          pending.commit_index != newest_metadata_index))) {
        out->status = AgentQPolicyStoreStatus::invalid;
        return out->status;
    }

    if (selected != nullptr) {
        out->slot = selected->slot;
        out->sequence = selected->sequence;
        if (pending.valid) {
            const bool pending_selected = pending_matches_selection(pending, selected_index, *selected);
            if (!pending_selected && pending_overlaps_selection(pending, selected_index, *selected)) {
                out->status = AgentQPolicyStoreStatus::invalid;
                return out->status;
            }
        }
        const AgentQPolicyStoreStatus slot_status =
            read_policy_slot(out->slot, g_policy_record_buffer, sizeof(g_policy_record_buffer), &out->record_size, log_failures);
        if (slot_status == AgentQPolicyStoreStatus::storage_error ||
            slot_status == AgentQPolicyStoreStatus::invalid) {
            out->status = slot_status;
            return out->status;
        }
        if (slot_status != AgentQPolicyStoreStatus::active) {
            out->status = AgentQPolicyStoreStatus::invalid;
            return out->status;
        }
        out->status = AgentQPolicyStoreStatus::active;
        return out->status;
    }

    bool policy_material_present = pending.present;
    bool slot_present[2] = {};
    for (uint8_t index = 0; index < 2; ++index) {
        policy_material_present = policy_material_present || commits[index].present;
        size_t slot_size = 0;
        const AgentQPolicyStoreStatus slot_status =
            read_blob(kPolicySlotKeys[index], g_policy_record_buffer, sizeof(g_policy_record_buffer), &slot_size, false);
        if (slot_status == AgentQPolicyStoreStatus::storage_error) {
            out->status = AgentQPolicyStoreStatus::storage_error;
            return out->status;
        }
        slot_present[index] = slot_status != AgentQPolicyStoreStatus::missing;
        policy_material_present = policy_material_present || slot_present[index];
    }

    out->status = policy_material_present ? AgentQPolicyStoreStatus::invalid : AgentQPolicyStoreStatus::missing;
    return out->status;
}

bool load_active_policy(AgentQPolicyDocument* out, void* context)
{
    (void)context;
    if (out == nullptr) {
        return false;
    }
    ActivePolicySelection selection = {};
    if (select_active_policy(&selection, true) != AgentQPolicyStoreStatus::active ||
        decode_agent_q_policy_v0_canonical_record(
            g_policy_record_buffer,
            selection.record_size,
            &g_policy_document) != AgentQPolicyCanonicalStatus::ok ||
        !agent_q_policy_canonical_to_runtime_view(g_policy_document, &g_policy_runtime_view)) {
        return false;
    }
    *out = g_policy_runtime_view.document;
    return true;
}

}  // namespace

bool store_default_policy()
{
    uint8_t record[kDefaultPolicyRecordBytes] = {};
    size_t record_size = 0;
    if (!default_policy_record(record, sizeof(record), &record_size)) {
        ESP_LOGW(kTag, "Could not build default policy record");
        return false;
    }
    if (store_active_policy_record(record, record_size) != AgentQPolicyStoreWriteResult::applied) {
        ESP_LOGW(kTag, "Could not store active default-reject policy");
        return false;
    }

    ESP_LOGI(kTag, "Stored active default-reject policy");
    return true;
}

bool policy_store_digest_for_record(const uint8_t* record, size_t record_size, uint8_t* output, size_t output_size)
{
    return sha256_for_record(record, record_size, output, output_size);
}

bool policy_store_policy_id_for_record(const uint8_t* record, size_t record_size, char* output, size_t output_size)
{
    return policy_id_for_record(record, record_size, output, output_size);
}

AgentQPolicyStoreWriteResult store_active_policy_record(const uint8_t* record, size_t record_size)
{
    if (!validate_policy_record(record, record_size)) {
        ESP_LOGW(kTag, "Refusing to store invalid active policy record");
        return AgentQPolicyStoreWriteResult::invalid_record;
    }

    ActivePolicySelection current = {};
    const AgentQPolicyStoreStatus current_status = select_active_policy(&current, true);
    if (current_status == AgentQPolicyStoreStatus::storage_error ||
        current_status == AgentQPolicyStoreStatus::invalid) {
        return AgentQPolicyStoreWriteResult::consistency_error;
    }

    const uint8_t next_slot =
        current_status == AgentQPolicyStoreStatus::active && current.slot == 0 ? 1 : 0;
    const uint64_t next_sequence =
        current_status == AgentQPolicyStoreStatus::active ? current.sequence + 1 : 1;
    if (next_sequence == 0) {
        return AgentQPolicyStoreWriteResult::consistency_error;
    }

    const uint8_t commit_index = static_cast<uint8_t>(next_sequence % 2);
    if (!erase_policy_key(kPolicyCommitKeys[commit_index])) {
        return AgentQPolicyStoreWriteResult::unchanged_failure;
    }

    uint8_t pending[kPendingRecordBytes] = {};
    build_pending_record(commit_index, next_slot, next_sequence, pending);
    if (!write_blob(kPolicyPendingKey, pending, sizeof(pending))) {
        return classify_pending_write_failure_terminal_state(
            current_status,
            current,
            next_slot,
            commit_index,
            next_sequence,
            record,
            record_size);
    }

    if (!write_blob(kPolicySlotKeys[next_slot], record, record_size)) {
        erase_interrupted_policy_write(PolicyPendingWrite{true, true, commit_index, next_slot, next_sequence});
        return classify_policy_write_terminal_state(
            current_status,
            current,
            next_slot,
            commit_index,
            next_sequence,
            record,
            record_size,
            false);
    }

    size_t readback_size = 0;
    if (read_policy_slot(next_slot, g_policy_scratch_buffer, sizeof(g_policy_scratch_buffer), &readback_size, true) !=
            AgentQPolicyStoreStatus::active ||
        readback_size != record_size ||
        memcmp(g_policy_scratch_buffer, record, record_size) != 0) {
        ESP_LOGW(kTag, "Active policy slot validation failed after write");
        erase_interrupted_policy_write(PolicyPendingWrite{true, true, commit_index, next_slot, next_sequence});
        return classify_policy_write_terminal_state(
            current_status,
            current,
            next_slot,
            commit_index,
            next_sequence,
            record,
            record_size,
            false);
    }

    uint8_t digest[32] = {};
    if (!sha256_for_record(record, record_size, digest, sizeof(digest))) {
        erase_interrupted_policy_write(PolicyPendingWrite{true, true, commit_index, next_slot, next_sequence});
        return classify_policy_write_terminal_state(
            current_status,
            current,
            next_slot,
            commit_index,
            next_sequence,
            record,
            record_size,
            false);
    }

    uint8_t commit[kCommitRecordBytes] = {};
    build_commit_record(next_slot, next_sequence, digest, commit);
    if (!write_blob(kPolicyCommitKeys[commit_index], commit, sizeof(commit))) {
        return classify_policy_write_terminal_state(
            current_status,
            current,
            next_slot,
            commit_index,
            next_sequence,
            record,
            record_size,
            true);
    }

    ActivePolicySelection after = {};
    if (select_active_policy(&after, true) != AgentQPolicyStoreStatus::active ||
        after.slot != next_slot ||
        after.sequence != next_sequence ||
        after.record_size != record_size ||
        memcmp(g_policy_record_buffer, record, record_size) != 0) {
        ESP_LOGW(kTag, "Committed active policy could not be selected after metadata flip");
        erase_policy_write_target(commit_index, next_slot);
        erase_policy_key(kPolicyPendingKey);
        return classify_policy_write_terminal_state(
            current_status,
            current,
            next_slot,
            commit_index,
            next_sequence,
            record,
            record_size,
            false);
    }

    if (!erase_policy_key(kPolicyPendingKey)) {
        ESP_LOGW(kTag, "Active policy pending marker cleanup failed after metadata flip; active policy is already committed");
    }

    return AgentQPolicyStoreWriteResult::applied;
}

bool wipe_policy()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while wiping policy: %s", esp_err_to_name(result));
        return false;
    }

    bool erased = true;
    for (const char* key : kPolicySlotKeys) {
        erased = erase_key_if_present(nvs, key) && erased;
    }
    for (const char* key : kPolicyCommitKeys) {
        erased = erase_key_if_present(nvs, key) && erased;
    }
    erased = erase_key_if_present(nvs, kPolicyPendingKey) && erased;
    if (erased) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (!erased || result != ESP_OK) {
        ESP_LOGW(kTag, "NVS erase failed for policy: %s", esp_err_to_name(result));
        return false;
    }

    ESP_LOGI(kTag, "Active policy wiped");
    return true;
}

AgentQPolicyStoreStatus active_policy_status()
{
    ActivePolicySelection selection = {};
    return select_active_policy(&selection, false);
}

AgentQPolicyProvider active_policy_provider()
{
    return AgentQPolicyProvider{load_active_policy, nullptr};
}

bool read_active_policy_summary(AgentQStoredPolicySummary* out)
{
    if (out == nullptr) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    ActivePolicySelection selection = {};
    if (select_active_policy(&selection, true) != AgentQPolicyStoreStatus::active ||
        decode_agent_q_policy_v0_canonical_record(
            g_policy_record_buffer,
            selection.record_size,
            &g_policy_document) != AgentQPolicyCanonicalStatus::ok ||
        !policy_id_for_record(g_policy_record_buffer, selection.record_size, out->policy_id, sizeof(out->policy_id))) {
        return false;
    }

    out->schema = kAgentQStoredPolicySchema;
    out->default_action = agent_q_policy_action_name(g_policy_document.default_action);
    out->rule_count = g_policy_document.rule_count;
    return true;
}

bool read_active_policy_document(AgentQStoredPolicyDocument* out)
{
    if (out == nullptr) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    ActivePolicySelection selection = {};
    if (select_active_policy(&selection, true) != AgentQPolicyStoreStatus::active ||
        decode_agent_q_policy_v0_canonical_record(
            g_policy_record_buffer,
            selection.record_size,
            &g_policy_document) != AgentQPolicyCanonicalStatus::ok ||
        !policy_id_for_record(g_policy_record_buffer, selection.record_size, out->policy_id, sizeof(out->policy_id)) ||
        !agent_q_policy_canonical_to_runtime_view(g_policy_document, &g_policy_runtime_view)) {
        return false;
    }

    out->schema = kAgentQStoredPolicySchema;
    out->default_action = agent_q_policy_action_name(g_policy_document.default_action);
    out->rule_count = g_policy_document.rule_count;
    out->document = &g_policy_runtime_view.document;
    return true;
}

}  // namespace agent_q
