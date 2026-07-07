#include "protocol/approval_history.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "nvs.h"
#include "protocol/persistent_storage_names.h"

namespace signing {
namespace {

constexpr const char* kTag = "ApprovalHist";
constexpr const char* kNvsNamespace = kMutableSettingsNvsNamespace;
constexpr const char* kApprovalHistoryKey = "approval_hist";
// Current-only storage layout. Format version 1 is the only accepted blob shape;
// unsupported blobs fail closed through the normal invalid-history path.
constexpr uint8_t kStoredApprovalHistoryFormatVersion = 1;
constexpr uint8_t kStoredConfirmationNone = 0;
constexpr uint8_t kStoredConfirmationPolicy = 1;
constexpr uint8_t kStoredConfirmationLocalPin = 2;
constexpr uint8_t kStoredConfirmationPhysicalConfirm = 3;
constexpr uint8_t kStoredDigestPayload = 1 << 0;
constexpr uint8_t kStoredDigestPolicy = 1 << 1;
constexpr uint8_t kStoredEventPolicyUpdate = 1;
constexpr uint8_t kStoredEventSigning = 2;
constexpr uint8_t kStoredSigningRecordNone = 0;
constexpr uint8_t kStoredSigningRecordConfirmation = 1;
constexpr uint8_t kStoredSigningRecordTerminal = 2;
constexpr uint8_t kStoredSigningTerminalNone = 0;
constexpr uint8_t kStoredSigningTerminalSigned = 1;
constexpr uint8_t kStoredSigningTerminalUserRejected = 2;
constexpr uint8_t kStoredSigningTerminalUserTimedOut = 3;
constexpr uint8_t kStoredSigningTerminalSigningFailed = 4;
constexpr uint8_t kStoredSigningTerminalPolicyRejected = 5;

struct StoredApprovalHistoryRecord {
    uint64_t sequence;
    uint64_t uptime_ms;
    uint8_t confirmation_kind;
    uint8_t flags;
    uint8_t event_kind;
    uint16_t policy_count;
    uint8_t signing_record_kind;
    uint8_t signing_terminal_result;
    char chain[kApprovalHistoryChainSize];
    char method[kApprovalHistoryMethodSize];
    char reason_code[kApprovalHistoryReasonCodeSize];
    char rule_ref[kApprovalHistoryRuleRefSize];
    char policy_result[kApprovalHistoryPolicyResultSize];
    char highest_action[kApprovalHistoryHighestActionSize];
    uint8_t payload_digest[32];
    uint8_t policy_hash[32];
};

struct StoredApprovalHistory {
    uint8_t magic[4];
    uint8_t format_version;
    uint8_t reserved0;
    uint16_t start;
    uint16_t count;
    uint16_t reserved1;
    uint64_t next_sequence;
    StoredApprovalHistoryRecord records[kApprovalHistoryCapacity];
};

StoredApprovalHistory g_history_workspace;
bool g_write_budget_active = false;
uint64_t g_write_budget_window_start_ms = 0;
size_t g_write_budget_used = 0;

static_assert(sizeof(StoredApprovalHistoryRecord) <= 256,
              "Approval history record must stay bounded for NVS storage");
static_assert(sizeof(StoredApprovalHistory) <= 8192,
              "Approval history blob must fit alongside Agent-Q material records in NVS");

void init_history(StoredApprovalHistory* history)
{
    if (history == nullptr) {
        return;
    }
    memset(history, 0, sizeof(*history));
    history->magic[0] = 'A';
    history->magic[1] = 'Q';
    history->magic[2] = 'A';
    history->magic[3] = 'H';
    history->format_version = kStoredApprovalHistoryFormatVersion;
    history->next_sequence = 1;
}

bool stored_event_kind_valid(uint8_t value)
{
    return value == kStoredEventPolicyUpdate ||
           value == kStoredEventSigning;
}

bool stored_signing_record_kind_valid(uint8_t value)
{
    return value == kStoredSigningRecordConfirmation ||
           value == kStoredSigningRecordTerminal;
}

bool stored_signing_terminal_result_valid(uint8_t value)
{
    return value == kStoredSigningTerminalSigned ||
           value == kStoredSigningTerminalUserRejected ||
           value == kStoredSigningTerminalUserTimedOut ||
           value == kStoredSigningTerminalSigningFailed ||
           value == kStoredSigningTerminalPolicyRejected;
}

bool stored_terminal_result_allowed_for_confirmation(uint8_t confirmation_kind, uint8_t terminal_result)
{
    if (confirmation_kind == kStoredConfirmationNone) {
        return terminal_result == kStoredSigningTerminalSigned ||
               terminal_result == kStoredSigningTerminalUserRejected ||
               terminal_result == kStoredSigningTerminalUserTimedOut ||
               terminal_result == kStoredSigningTerminalSigningFailed;
    }
    if (confirmation_kind == kStoredConfirmationPolicy) {
        return terminal_result == kStoredSigningTerminalSigned ||
               terminal_result == kStoredSigningTerminalPolicyRejected ||
               terminal_result == kStoredSigningTerminalSigningFailed;
    }
    return false;
}

bool history_chain_or_method_char(char value, bool first);
bool history_reason_char(char value, bool first);
bool history_rule_ref_char(char value, bool first);
bool history_policy_result_char(char value, bool first);
bool history_highest_action_char(char value, bool first);
bool policy_update_result_supported(const char* value);
bool highest_action_supported(const char* value);
bool materialize_record(const StoredApprovalHistoryRecord& stored, ApprovalHistoryRecord* output);

bool stored_history_token_valid(
    const char* value,
    size_t value_size,
    bool required,
    bool (*valid_char)(char, bool));

bool stored_has_policy_metadata(const StoredApprovalHistoryRecord& record)
{
    return (record.flags & kStoredDigestPolicy) != 0 &&
           record.rule_ref[0] != '\0';
}

bool stored_record_metadata_valid(const StoredApprovalHistoryRecord& record)
{
    if (!stored_event_kind_valid(record.event_kind) ||
        (record.flags & ~(kStoredDigestPayload | kStoredDigestPolicy)) != 0 ||
        record.policy_count > kCurrentPolicyMaxTotalPolicies) {
        return false;
    }
    if (record.event_kind == kStoredEventPolicyUpdate) {
        return record.confirmation_kind == kStoredConfirmationPolicy &&
               record.signing_record_kind == kStoredSigningRecordNone &&
               record.signing_terminal_result == kStoredSigningTerminalNone &&
               (record.flags & kStoredDigestPolicy) != 0 &&
               stored_history_token_valid(
                   record.reason_code,
                   sizeof(record.reason_code),
                   true,
                   history_reason_char) &&
               stored_history_token_valid(
                   record.policy_result,
                   sizeof(record.policy_result),
                   true,
                   history_policy_result_char) &&
               stored_history_token_valid(
                   record.highest_action,
                   sizeof(record.highest_action),
                   true,
                   history_highest_action_char) &&
               policy_update_result_supported(record.policy_result) &&
               highest_action_supported(record.highest_action);
    }
    if (!stored_signing_record_kind_valid(record.signing_record_kind) ||
        (record.flags & kStoredDigestPayload) == 0 ||
        !stored_history_token_valid(
            record.chain,
            sizeof(record.chain),
            true,
            history_chain_or_method_char) ||
        !stored_history_token_valid(
            record.method,
            sizeof(record.method),
            true,
            history_chain_or_method_char) ||
        !stored_history_token_valid(
            record.reason_code,
            sizeof(record.reason_code),
            true,
            history_reason_char)) {
        return false;
    }
    if (record.signing_record_kind == kStoredSigningRecordConfirmation) {
        if (record.confirmation_kind == kStoredConfirmationLocalPin ||
            record.confirmation_kind == kStoredConfirmationPhysicalConfirm) {
            return record.signing_terminal_result == kStoredSigningTerminalNone &&
                   (record.flags & kStoredDigestPolicy) == 0 &&
                   record.rule_ref[0] == '\0';
        }
        if (record.confirmation_kind == kStoredConfirmationPolicy) {
            return record.signing_terminal_result == kStoredSigningTerminalNone &&
                   stored_has_policy_metadata(record) &&
                   stored_history_token_valid(
                       record.rule_ref,
                       sizeof(record.rule_ref),
                       true,
                       history_rule_ref_char);
        }
        return false;
    }
    if (!stored_signing_terminal_result_valid(record.signing_terminal_result) ||
        !stored_terminal_result_allowed_for_confirmation(record.confirmation_kind, record.signing_terminal_result)) {
        return false;
    }
    if (record.confirmation_kind == kStoredConfirmationPolicy) {
        return stored_has_policy_metadata(record) &&
               stored_history_token_valid(
                   record.rule_ref,
                   sizeof(record.rule_ref),
                   true,
                   history_rule_ref_char);
    }
    return (record.flags & kStoredDigestPolicy) == 0 &&
           record.rule_ref[0] == '\0';
}

bool valid_history_header(const StoredApprovalHistory& history)
{
    if (history.magic[0] != 'A' ||
        history.magic[1] != 'Q' ||
        history.magic[2] != 'A' ||
        history.magic[3] != 'H' ||
        history.format_version != kStoredApprovalHistoryFormatVersion ||
        history.start >= kApprovalHistoryCapacity ||
        history.count > kApprovalHistoryCapacity ||
        history.next_sequence == 0) {
        return false;
    }
    for (size_t offset = 0; offset < history.count; ++offset) {
        const size_t index = (history.start + offset) % kApprovalHistoryCapacity;
        if (!stored_record_metadata_valid(history.records[index])) {
            return false;
        }
    }
    return true;
}

bool stored_history_records_materialize(const StoredApprovalHistory& history)
{
    ApprovalHistoryRecord scratch = {};
    for (size_t offset = 0; offset < history.count; ++offset) {
        const size_t index = (history.start + offset) % kApprovalHistoryCapacity;
        if (!materialize_record(history.records[index], &scratch)) {
            memset(&scratch, 0, sizeof(scratch));
            return false;
        }
        memset(&scratch, 0, sizeof(scratch));
    }
    return true;
}

ApprovalHistoryEventKind public_event_kind(uint8_t value)
{
    if (value == kStoredEventPolicyUpdate) {
        return ApprovalHistoryEventKind::policy_update;
    }
    if (value == kStoredEventSigning) {
        return ApprovalHistoryEventKind::signing;
    }
    return ApprovalHistoryEventKind::policy_update;
}

void reset_write_budget()
{
    g_write_budget_active = false;
    g_write_budget_window_start_ms = 0;
    g_write_budget_used = 0;
}

bool consume_write_budget(uint64_t uptime_ms)
{
    if (!g_write_budget_active ||
        uptime_ms < g_write_budget_window_start_ms ||
        uptime_ms - g_write_budget_window_start_ms >= kApprovalHistoryWriteBudgetWindowMs) {
        g_write_budget_active = true;
        g_write_budget_window_start_ms = uptime_ms;
        g_write_budget_used = 0;
    }
    if (g_write_budget_used >= kApprovalHistoryWriteBudgetMax) {
        ESP_LOGW(kTag, "Approval history write budget exhausted");
        return false;
    }
    ++g_write_budget_used;
    return true;
}

bool lowercase_letter(char value)
{
    return value >= 'a' && value <= 'z';
}

bool digit(char value)
{
    return value >= '0' && value <= '9';
}

bool history_chain_or_method_char(char value, bool first)
{
    if (first) {
        return lowercase_letter(value);
    }
    return lowercase_letter(value) ||
           digit(value) ||
           value == '_' ||
           value == '.' ||
           value == '-';
}

bool history_reason_char(char value, bool first)
{
    if (first) {
        return lowercase_letter(value);
    }
    return lowercase_letter(value) ||
           digit(value) ||
           value == '_';
}

bool history_rule_ref_char(char value, bool first)
{
    if (first) {
        return lowercase_letter(value);
    }
    return lowercase_letter(value) ||
           digit(value) ||
           value == '_' ||
           value == '.' ||
           value == ':' ||
           value == '/' ||
           value == '-';
}

bool history_policy_result_char(char value, bool first)
{
    return history_reason_char(value, first);
}

bool history_highest_action_char(char value, bool first)
{
    return history_reason_char(value, first);
}

bool stored_history_token_valid(
    const char* value,
    size_t value_size,
    bool required,
    bool (*valid_char)(char, bool))
{
    if (value == nullptr || value_size == 0 || valid_char == nullptr) {
        return false;
    }

    size_t index = 0;
    while (index < value_size && value[index] != '\0') {
        if (!valid_char(value[index], index == 0)) {
            return false;
        }
        ++index;
    }
    if (index == value_size) {
        return false;
    }
    return !required || index != 0;
}

bool policy_update_result_supported(const char* value)
{
    return value != nullptr &&
           (strcmp(value, "applied") == 0 ||
            strcmp(value, "rejected") == 0 ||
            strcmp(value, "timed_out") == 0 ||
            strcmp(value, "storage_error") == 0);
}

bool highest_action_supported(const char* value)
{
    return value != nullptr &&
           (strcmp(value, "reject") == 0 ||
            strcmp(value, "sign") == 0);
}

bool store_history_token(
    char* output,
    size_t output_size,
    const char* value,
    bool required,
    bool (*valid_char)(char, bool))
{
    if (output == nullptr || output_size == 0 || valid_char == nullptr) {
        return false;
    }
    memset(output, 0, output_size);
    if (value == nullptr) {
        return !required;
    }

    size_t index = 0;
    while (value[index] != '\0') {
        if (index + 1 >= output_size || !valid_char(value[index], index == 0)) {
            memset(output, 0, output_size);
            return false;
        }
        output[index] = value[index];
        ++index;
    }
    if (required && index == 0) {
        memset(output, 0, output_size);
        return false;
    }
    output[index] = '\0';
    return true;
}

bool copy_stored_history_token(
    char* output,
    size_t output_size,
    const char* value,
    size_t value_size,
    bool required,
    bool (*valid_char)(char, bool))
{
    if (output == nullptr || output_size == 0 || value == nullptr ||
        value_size == 0 || output_size < value_size || valid_char == nullptr) {
        return false;
    }
    memset(output, 0, output_size);

    size_t index = 0;
    while (index < value_size && value[index] != '\0') {
        if (!valid_char(value[index], index == 0)) {
            memset(output, 0, output_size);
            return false;
        }
        output[index] = value[index];
        ++index;
    }
    if (index == value_size || (required && index == 0)) {
        memset(output, 0, output_size);
        return false;
    }
    output[index] = '\0';
    return true;
}

void write_hex_byte(uint8_t value, char* output)
{
    constexpr char kHex[] = "0123456789abcdef";
    output[0] = kHex[(value >> 4) & 0x0F];
    output[1] = kHex[value & 0x0F];
}

int hex_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    return -1;
}

bool digest_from_string(const char* value, uint8_t output[32])
{
    if (value == nullptr || output == nullptr) {
        return false;
    }
    constexpr char kPrefix[] = "sha256:";
    if (strncmp(value, kPrefix, sizeof(kPrefix) - 1) != 0) {
        return false;
    }
    const char* hex = value + sizeof(kPrefix) - 1;
    for (size_t index = 0; index < 64; ++index) {
        if (hex[index] == '\0') {
            return false;
        }
    }
    if (hex[64] != '\0') {
        return false;
    }
    for (size_t index = 0; index < 32; ++index) {
        const int high = hex_nibble(hex[index * 2]);
        const int low = hex_nibble(hex[index * 2 + 1]);
        if (high < 0 || low < 0) {
            memset(output, 0, 32);
            return false;
        }
        output[index] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
}

bool digest_to_string(const uint8_t digest[32], char* output, size_t output_size)
{
    if (digest == nullptr || output == nullptr ||
        output_size != kApprovalHistoryDigestSize) {
        return false;
    }
    memset(output, 0, output_size);
    constexpr char kPrefix[] = "sha256:";
    memcpy(output, kPrefix, sizeof(kPrefix) - 1);
    char* cursor = output + sizeof(kPrefix) - 1;
    for (size_t index = 0; index < 32; ++index) {
        write_hex_byte(digest[index], cursor);
        cursor += 2;
    }
    *cursor = '\0';
    return true;
}

uint8_t stored_confirmation(ApprovalHistoryConfirmationKind value)
{
    switch (value) {
        case ApprovalHistoryConfirmationKind::policy:
            return kStoredConfirmationPolicy;
        case ApprovalHistoryConfirmationKind::local_pin:
            return kStoredConfirmationLocalPin;
        case ApprovalHistoryConfirmationKind::physical_confirm:
            return kStoredConfirmationPhysicalConfirm;
        case ApprovalHistoryConfirmationKind::none:
        default:
            return kStoredConfirmationNone;
    }
}

ApprovalHistoryConfirmationKind public_confirmation(uint8_t value)
{
    switch (value) {
        case kStoredConfirmationPolicy:
            return ApprovalHistoryConfirmationKind::policy;
        case kStoredConfirmationLocalPin:
            return ApprovalHistoryConfirmationKind::local_pin;
        case kStoredConfirmationPhysicalConfirm:
            return ApprovalHistoryConfirmationKind::physical_confirm;
        case kStoredConfirmationNone:
        default:
            return ApprovalHistoryConfirmationKind::none;
    }
}

uint8_t stored_signing_record_kind(HistoryRecordKind value)
{
    switch (value) {
        case HistoryRecordKind::confirmation:
            return kStoredSigningRecordConfirmation;
        case HistoryRecordKind::terminal:
            return kStoredSigningRecordTerminal;
        case HistoryRecordKind::none:
        default:
            return kStoredSigningRecordNone;
    }
}

HistoryRecordKind public_signing_record_kind(uint8_t value)
{
    switch (value) {
        case kStoredSigningRecordConfirmation:
            return HistoryRecordKind::confirmation;
        case kStoredSigningRecordTerminal:
            return HistoryRecordKind::terminal;
        case kStoredSigningRecordNone:
        default:
            return HistoryRecordKind::none;
    }
}

uint8_t stored_signing_terminal_result(HistoryTerminalResult value)
{
    switch (value) {
        case HistoryTerminalResult::signed_success:
            return kStoredSigningTerminalSigned;
        case HistoryTerminalResult::user_rejected:
            return kStoredSigningTerminalUserRejected;
        case HistoryTerminalResult::user_timed_out:
            return kStoredSigningTerminalUserTimedOut;
        case HistoryTerminalResult::policy_rejected:
            return kStoredSigningTerminalPolicyRejected;
        case HistoryTerminalResult::signing_failed:
            return kStoredSigningTerminalSigningFailed;
        case HistoryTerminalResult::none:
        default:
            return kStoredSigningTerminalNone;
    }
}

HistoryTerminalResult public_signing_terminal_result(uint8_t value)
{
    switch (value) {
        case kStoredSigningTerminalSigned:
            return HistoryTerminalResult::signed_success;
        case kStoredSigningTerminalUserRejected:
            return HistoryTerminalResult::user_rejected;
        case kStoredSigningTerminalUserTimedOut:
            return HistoryTerminalResult::user_timed_out;
        case kStoredSigningTerminalPolicyRejected:
            return HistoryTerminalResult::policy_rejected;
        case kStoredSigningTerminalSigningFailed:
            return HistoryTerminalResult::signing_failed;
        case kStoredSigningTerminalNone:
        default:
            return HistoryTerminalResult::none;
    }
}

ApprovalHistoryReadResult load_history(StoredApprovalHistory* history, bool missing_is_empty)
{
    if (history == nullptr) {
        return ApprovalHistoryReadResult::storage_error;
    }
    memset(history, 0, sizeof(*history));

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result != ESP_OK) {
        if (result == ESP_ERR_NVS_NOT_FOUND && missing_is_empty) {
            init_history(history);
            return ApprovalHistoryReadResult::ok;
        }
        ESP_LOGW(kTag, "NVS open failed while reading approval history: %s", esp_err_to_name(result));
        return ApprovalHistoryReadResult::storage_error;
    }

    size_t history_size = 0;
    result = nvs_get_blob(nvs, kApprovalHistoryKey, nullptr, &history_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        if (missing_is_empty) {
            init_history(history);
            return ApprovalHistoryReadResult::ok;
        }
        return ApprovalHistoryReadResult::storage_error;
    }
    if (result != ESP_OK) {
        nvs_close(nvs);
        ESP_LOGW(kTag, "Approval history size read failed: %s", esp_err_to_name(result));
        return ApprovalHistoryReadResult::storage_error;
    }
    if (history_size != sizeof(*history)) {
        nvs_close(nvs);
        ESP_LOGW(kTag, "Approval history has invalid size: %u",
                 static_cast<unsigned>(history_size));
        return ApprovalHistoryReadResult::invalid;
    }

    result = nvs_get_blob(nvs, kApprovalHistoryKey, history, &history_size);
    nvs_close(nvs);
    if (result != ESP_OK || history_size != sizeof(*history)) {
        ESP_LOGW(kTag, "Approval history read failed: %s size=%u",
                 esp_err_to_name(result),
                 static_cast<unsigned>(history_size));
        memset(history, 0, sizeof(*history));
        return ApprovalHistoryReadResult::storage_error;
    }
    if (!valid_history_header(*history)) {
        memset(history, 0, sizeof(*history));
        ESP_LOGW(kTag, "Approval history validation failed");
        return ApprovalHistoryReadResult::invalid;
    }
    return ApprovalHistoryReadResult::ok;
}

bool store_history(const StoredApprovalHistory& history)
{
    if (!valid_history_header(history)) {
        ESP_LOGW(kTag, "Refusing to store invalid approval history");
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing approval history: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_set_blob(nvs, kApprovalHistoryKey, &history, sizeof(history));
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Approval history write failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

bool materialize_record(const StoredApprovalHistoryRecord& stored, ApprovalHistoryRecord* output)
{
    if (output == nullptr) {
        return false;
    }
    memset(output, 0, sizeof(*output));
    output->sequence = stored.sequence;
    output->uptime_ms = stored.uptime_ms;
    output->event_kind = public_event_kind(stored.event_kind);
    output->confirmation_kind = public_confirmation(stored.confirmation_kind);
    output->signing_record_kind =
        public_signing_record_kind(stored.signing_record_kind);
    output->signing_terminal_result =
        public_signing_terminal_result(stored.signing_terminal_result);
    if (!copy_stored_history_token(output->reason_code, sizeof(output->reason_code), stored.reason_code, sizeof(stored.reason_code), true, history_reason_char)) {
        memset(output, 0, sizeof(*output));
        return false;
    }
    if (output->event_kind == ApprovalHistoryEventKind::signing) {
        if (!copy_stored_history_token(output->chain, sizeof(output->chain), stored.chain, sizeof(stored.chain), true, history_chain_or_method_char) ||
            !copy_stored_history_token(output->method, sizeof(output->method), stored.method, sizeof(stored.method), true, history_chain_or_method_char)) {
            memset(output, 0, sizeof(*output));
            return false;
        }
        if (!copy_stored_history_token(output->rule_ref, sizeof(output->rule_ref), stored.rule_ref, sizeof(stored.rule_ref), false, history_rule_ref_char)) {
            memset(output, 0, sizeof(*output));
            return false;
        }
        if ((stored.flags & kStoredDigestPayload) != 0) {
            digest_to_string(stored.payload_digest, output->payload_digest, sizeof(output->payload_digest));
        }
        if ((stored.flags & kStoredDigestPolicy) != 0) {
            digest_to_string(stored.policy_hash, output->policy_hash, sizeof(output->policy_hash));
        }
        if (output->event_kind == ApprovalHistoryEventKind::signing &&
            (stored.flags & kStoredDigestPayload) == 0) {
            memset(output, 0, sizeof(*output));
            return false;
        }
        return true;
    }
    if (!copy_stored_history_token(output->policy_result, sizeof(output->policy_result), stored.policy_result, sizeof(stored.policy_result), true, history_policy_result_char) ||
        !copy_stored_history_token(output->highest_action, sizeof(output->highest_action), stored.highest_action, sizeof(stored.highest_action), true, history_highest_action_char) ||
        !policy_update_result_supported(output->policy_result) ||
        !highest_action_supported(output->highest_action)) {
        memset(output, 0, sizeof(*output));
        return false;
    }
    if ((stored.flags & kStoredDigestPolicy) == 0 ||
        !digest_to_string(stored.policy_hash, output->policy_hash, sizeof(output->policy_hash)) ||
        stored.policy_count > kCurrentPolicyMaxTotalPolicies) {
        memset(output, 0, sizeof(*output));
        return false;
    }
    output->policy_count = stored.policy_count;
    return true;
}

}  // namespace

bool approval_history_digest_payload(
    const uint8_t* payload,
    size_t payload_size,
    char* output,
    size_t output_size)
{
    if (payload == nullptr || payload_size == 0 || output == nullptr ||
        output_size != kApprovalHistoryDigestSize) {
        return false;
    }
    uint8_t digest[32] = {};
    if (mbedtls_sha256(payload, payload_size, digest, 0) != 0) {
        return false;
    }
    const bool formatted = digest_to_string(digest, output, output_size);
    memset(digest, 0, sizeof(digest));
    return formatted;
}

bool append_record(StoredApprovalHistory* history, StoredApprovalHistoryRecord** record)
{
    if (history == nullptr || record == nullptr) {
        return false;
    }

    size_t slot = 0;
    if (history->count < kApprovalHistoryCapacity) {
        slot = (history->start + history->count) % kApprovalHistoryCapacity;
        ++history->count;
    } else {
        slot = history->start;
        history->start = (history->start + 1) % kApprovalHistoryCapacity;
    }

    StoredApprovalHistoryRecord* next = &history->records[slot];
    memset(next, 0, sizeof(*next));
    next->sequence = history->next_sequence++;
    if (history->next_sequence == 0) {
        history->next_sequence = 1;
    }
    *record = next;
    return true;
}

bool approval_history_parse_sequence(const char* value, uint64_t* output)
{
    if (value == nullptr || value[0] == '\0' || output == nullptr) {
        return false;
    }
    if (value[0] == '0' && value[1] != '\0') {
        return false;
    }

    uint64_t result = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
        const uint64_t digit_value = static_cast<uint64_t>(*cursor - '0');
        if (result > (UINT64_MAX - digit_value) / 10U) {
            return false;
        }
        result = result * 10U + digit_value;
    }
    *output = result;
    return true;
}

bool approval_history_append_required_policy_update(
    const PolicyUpdateHistoryAppendInput& input,
    uint64_t uptime_ms)
{
    StoredApprovalHistory& history = g_history_workspace;
    const ApprovalHistoryReadResult load_result = load_history(&history, true);
    if (load_result != ApprovalHistoryReadResult::ok) {
        return false;
    }

    StoredApprovalHistoryRecord* record = nullptr;
    if (!append_record(&history, &record)) {
        return false;
    }
    record->uptime_ms = uptime_ms;
    record->event_kind = kStoredEventPolicyUpdate;
    record->confirmation_kind = kStoredConfirmationPolicy;
    if (input.policy_count > kCurrentPolicyMaxTotalPolicies ||
        !policy_update_result_supported(input.result) ||
        !highest_action_supported(input.highest_action) ||
        !store_history_token(record->policy_result, sizeof(record->policy_result), input.result, true, history_policy_result_char) ||
        !store_history_token(record->reason_code, sizeof(record->reason_code), input.reason_code, true, history_reason_char) ||
        !store_history_token(record->highest_action, sizeof(record->highest_action), input.highest_action, true, history_highest_action_char) ||
        !digest_from_string(input.policy_hash, record->policy_hash)) {
        ESP_LOGW(kTag, "Refusing policy update history record with invalid metadata");
        return false;
    }
    record->policy_count = static_cast<uint16_t>(input.policy_count);
    record->flags |= kStoredDigestPolicy;
    return store_history(history);
}

static bool append_signing_history(
    const HistoryAppendInput& input,
    uint64_t uptime_ms,
    bool enforce_write_budget);

bool approval_history_append_required_signing(
    const HistoryAppendInput& input,
    uint64_t uptime_ms)
{
    return append_signing_history(input, uptime_ms, false);
}

bool approval_history_append_budgeted_signing(
    const HistoryAppendInput& input,
    uint64_t uptime_ms)
{
    return append_signing_history(input, uptime_ms, true);
}

static bool append_signing_history(
    const HistoryAppendInput& input,
    uint64_t uptime_ms,
    bool enforce_write_budget)
{
    const bool confirmation_record =
        input.record_kind == HistoryRecordKind::confirmation &&
        input.terminal_result == HistoryTerminalResult::none &&
        (((input.confirmation_kind == ApprovalHistoryConfirmationKind::local_pin ||
           input.confirmation_kind == ApprovalHistoryConfirmationKind::physical_confirm) &&
          input.policy_hash == nullptr &&
          input.rule_ref == nullptr) ||
         (input.confirmation_kind == ApprovalHistoryConfirmationKind::policy &&
          input.policy_hash != nullptr &&
          input.rule_ref != nullptr));
    const bool terminal_record =
        input.record_kind == HistoryRecordKind::terminal &&
        ((input.confirmation_kind == ApprovalHistoryConfirmationKind::none &&
          (input.terminal_result == HistoryTerminalResult::signed_success ||
           input.terminal_result == HistoryTerminalResult::user_rejected ||
           input.terminal_result == HistoryTerminalResult::user_timed_out ||
           input.terminal_result == HistoryTerminalResult::signing_failed) &&
          input.policy_hash == nullptr &&
          input.rule_ref == nullptr) ||
         (input.confirmation_kind == ApprovalHistoryConfirmationKind::policy &&
          (input.terminal_result == HistoryTerminalResult::signed_success ||
           input.terminal_result == HistoryTerminalResult::policy_rejected ||
           input.terminal_result == HistoryTerminalResult::signing_failed) &&
          input.policy_hash != nullptr &&
          input.rule_ref != nullptr));
    if (!confirmation_record && !terminal_record) {
        ESP_LOGW(kTag, "Refusing signing history record with invalid kind");
        return false;
    }

    StoredApprovalHistory& history = g_history_workspace;
    const ApprovalHistoryReadResult load_result = load_history(&history, true);
    if (load_result != ApprovalHistoryReadResult::ok) {
        return false;
    }

    StoredApprovalHistoryRecord* record = nullptr;
    if (!append_record(&history, &record)) {
        return false;
    }
    record->uptime_ms = uptime_ms;
    record->event_kind = kStoredEventSigning;
    record->confirmation_kind = stored_confirmation(input.confirmation_kind);
    record->signing_record_kind = stored_signing_record_kind(input.record_kind);
    record->signing_terminal_result =
        stored_signing_terminal_result(input.terminal_result);
    if (!store_history_token(record->chain, sizeof(record->chain), input.chain, true, history_chain_or_method_char) ||
        !store_history_token(record->method, sizeof(record->method), input.method, true, history_chain_or_method_char) ||
        !store_history_token(record->reason_code, sizeof(record->reason_code), input.reason_code, true, history_reason_char) ||
        !digest_from_string(input.payload_digest, record->payload_digest)) {
        ESP_LOGW(kTag, "Refusing signing history record with invalid metadata");
        return false;
    }
    record->flags |= kStoredDigestPayload;
    if (input.confirmation_kind == ApprovalHistoryConfirmationKind::policy) {
        if (!digest_from_string(input.policy_hash, record->policy_hash) ||
            !store_history_token(record->rule_ref, sizeof(record->rule_ref), input.rule_ref, true, history_rule_ref_char)) {
            ESP_LOGW(kTag, "Refusing policy signing history record with invalid metadata");
            return false;
        }
        record->flags |= kStoredDigestPolicy;
    }
    if (enforce_write_budget && !consume_write_budget(uptime_ms)) {
        return false;
    }
    return store_history(history);
}

ApprovalHistoryReadResult approval_history_read_page(
    uint64_t before_sequence,
    size_t limit,
    ApprovalHistoryPage* output)
{
    if (output == nullptr || limit == 0 || limit > kApprovalHistoryPageMax) {
        return ApprovalHistoryReadResult::storage_error;
    }
    memset(output, 0, sizeof(*output));

    StoredApprovalHistory& history = g_history_workspace;
    const ApprovalHistoryReadResult load_result = load_history(&history, true);
    if (load_result != ApprovalHistoryReadResult::ok) {
        return load_result;
    }

    for (size_t offset = 0; offset < history.count; ++offset) {
        const size_t newest_offset = history.count - 1 - offset;
        const size_t slot = (history.start + newest_offset) % kApprovalHistoryCapacity;
        const StoredApprovalHistoryRecord& stored = history.records[slot];
        if (stored.sequence == 0 ||
            (before_sequence != 0 && stored.sequence >= before_sequence)) {
            continue;
        }
        if (output->count < limit) {
            if (!materialize_record(stored, &output->records[output->count])) {
                memset(output, 0, sizeof(*output));
                return ApprovalHistoryReadResult::invalid;
            }
            ++output->count;
        } else {
            output->has_more = true;
            break;
        }
    }
    return ApprovalHistoryReadResult::ok;
}

ApprovalHistoryStorageStatus approval_history_status()
{
    StoredApprovalHistory& history = g_history_workspace;
    memset(&history, 0, sizeof(history));

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return ApprovalHistoryStorageStatus::missing;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while checking approval history: %s", esp_err_to_name(result));
        return ApprovalHistoryStorageStatus::storage_error;
    }

    size_t history_size = 0;
    result = nvs_get_blob(nvs, kApprovalHistoryKey, nullptr, &history_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return ApprovalHistoryStorageStatus::missing;
    }
    if (result != ESP_OK) {
        nvs_close(nvs);
        ESP_LOGW(kTag, "Approval history status size read failed: %s", esp_err_to_name(result));
        return ApprovalHistoryStorageStatus::storage_error;
    }
    if (history_size != sizeof(history)) {
        nvs_close(nvs);
        memset(&history, 0, sizeof(history));
        return ApprovalHistoryStorageStatus::invalid;
    }

    result = nvs_get_blob(nvs, kApprovalHistoryKey, &history, &history_size);
    nvs_close(nvs);
    if (result != ESP_OK || history_size != sizeof(history)) {
        memset(&history, 0, sizeof(history));
        ESP_LOGW(kTag, "Approval history status read failed: %s size=%u",
                 esp_err_to_name(result),
                 static_cast<unsigned>(history_size));
        return ApprovalHistoryStorageStatus::storage_error;
    }
    if (!valid_history_header(history) ||
        !stored_history_records_materialize(history)) {
        memset(&history, 0, sizeof(history));
        return ApprovalHistoryStorageStatus::invalid;
    }
    return ApprovalHistoryStorageStatus::active;
}

bool approval_history_wipe()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        reset_write_budget();
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while wiping approval history: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kApprovalHistoryKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        reset_write_budget();
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Approval history erase failed: %s", esp_err_to_name(result));
        return false;
    }
    reset_write_budget();
    return true;
}

const char* approval_history_confirmation_kind_to_string(ApprovalHistoryConfirmationKind value)
{
    switch (value) {
        case ApprovalHistoryConfirmationKind::policy:
            return "policy";
        case ApprovalHistoryConfirmationKind::local_pin:
            return "local_pin";
        case ApprovalHistoryConfirmationKind::physical_confirm:
            return "physical_confirm";
        case ApprovalHistoryConfirmationKind::none:
        default:
            return "none";
    }
}

const char* approval_history_signing_record_kind_to_string(
    HistoryRecordKind value)
{
    switch (value) {
        case HistoryRecordKind::confirmation:
            return "confirmation";
        case HistoryRecordKind::terminal:
            return "terminal";
        case HistoryRecordKind::none:
        default:
            return "none";
    }
}

const char* approval_history_signing_terminal_result_to_string(
    HistoryTerminalResult value)
{
    switch (value) {
        case HistoryTerminalResult::signed_success:
            return "signed";
        case HistoryTerminalResult::user_rejected:
            return "user_rejected";
        case HistoryTerminalResult::user_timed_out:
            return "user_timed_out";
        case HistoryTerminalResult::policy_rejected:
            return "policy_rejected";
        case HistoryTerminalResult::signing_failed:
            return "signing_failed";
        case HistoryTerminalResult::none:
        default:
            return "none";
    }
}

}  // namespace signing
