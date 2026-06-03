#include "agent_q_approval_history.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "nvs.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQApprovalHist";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kApprovalHistoryKey = "approval_hist";
constexpr uint8_t kStoredApprovalHistoryFormatVersion = 3;
constexpr uint8_t kStoredDecisionPolicyApproved = 0;
constexpr uint8_t kStoredDecisionPolicyRejected = 1;
constexpr uint8_t kStoredDecisionUserApproved = 2;
constexpr uint8_t kStoredDecisionUserRejected = 3;
constexpr uint8_t kStoredDecisionUserTimeout = 4;
constexpr uint8_t kStoredDecisionMethodError = 5;
constexpr uint8_t kStoredConfirmationNone = 0;
constexpr uint8_t kStoredConfirmationPolicy = 1;
constexpr uint8_t kStoredConfirmationPhysicalConfirm = 2;
constexpr uint8_t kStoredConfirmationLocalPin = 3;
constexpr uint8_t kStoredDigestPayload = 1 << 0;
constexpr uint8_t kStoredDigestPolicy = 1 << 1;
constexpr uint8_t kStoredEventMethodDecision = 0;
constexpr uint8_t kStoredEventPolicyUpdate = 1;

bool g_write_budget_active = false;
uint64_t g_write_budget_window_start_ms = 0;
size_t g_write_budget_used = 0;

struct StoredApprovalHistoryRecord {
    uint64_t sequence;
    uint64_t uptime_ms;
    uint8_t decision;
    uint8_t confirmation_kind;
    uint8_t flags;
    uint8_t event_kind;
    uint16_t rule_count;
    uint8_t reserved[2];
    char chain[kAgentQApprovalHistoryChainSize];
    char method[kAgentQApprovalHistoryMethodSize];
    char reason_code[kAgentQApprovalHistoryReasonCodeSize];
    char rule_ref[kAgentQApprovalHistoryRuleRefSize];
    char policy_result[kAgentQApprovalHistoryPolicyResultSize];
    char highest_action[kAgentQApprovalHistoryHighestActionSize];
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
    StoredApprovalHistoryRecord records[kAgentQApprovalHistoryCapacity];
};

StoredApprovalHistory g_history_workspace;

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
    return value == kStoredEventMethodDecision ||
           value == kStoredEventPolicyUpdate;
}

bool stored_decision_valid(uint8_t value)
{
    return value == kStoredDecisionPolicyApproved ||
           value == kStoredDecisionPolicyRejected ||
           value == kStoredDecisionUserApproved ||
           value == kStoredDecisionUserRejected ||
           value == kStoredDecisionUserTimeout ||
           value == kStoredDecisionMethodError;
}

bool stored_confirmation_valid(uint8_t value)
{
    return value == kStoredConfirmationNone ||
           value == kStoredConfirmationPolicy ||
           value == kStoredConfirmationPhysicalConfirm ||
           value == kStoredConfirmationLocalPin;
}

bool valid_history_header(const StoredApprovalHistory& history)
{
    if (history.magic[0] != 'A' ||
        history.magic[1] != 'Q' ||
        history.magic[2] != 'A' ||
        history.magic[3] != 'H' ||
        history.format_version != kStoredApprovalHistoryFormatVersion ||
        history.start >= kAgentQApprovalHistoryCapacity ||
        history.count > kAgentQApprovalHistoryCapacity ||
        history.next_sequence == 0) {
        return false;
    }
    for (size_t index = 0; index < kAgentQApprovalHistoryCapacity; ++index) {
        if (!stored_event_kind_valid(history.records[index].event_kind) ||
            !stored_decision_valid(history.records[index].decision) ||
            !stored_confirmation_valid(history.records[index].confirmation_kind) ||
            history.records[index].rule_count > kAgentQPolicyMaxRules) {
            return false;
        }
    }
    return true;
}

AgentQApprovalHistoryEventKind public_event_kind(uint8_t value)
{
    return value == kStoredEventPolicyUpdate
               ? AgentQApprovalHistoryEventKind::policy_update
               : AgentQApprovalHistoryEventKind::method_decision;
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
        uptime_ms - g_write_budget_window_start_ms >= kAgentQApprovalHistoryWriteBudgetWindowMs) {
        g_write_budget_active = true;
        g_write_budget_window_start_ms = uptime_ms;
        g_write_budget_used = 0;
    }
    if (g_write_budget_used >= kAgentQApprovalHistoryWriteBudgetMax) {
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
            strcmp(value, "ask") == 0 ||
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
        output_size != kAgentQApprovalHistoryDigestSize) {
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

uint8_t stored_decision(AgentQApprovalHistoryDecision value)
{
    switch (value) {
        case AgentQApprovalHistoryDecision::policy_approved:
            return kStoredDecisionPolicyApproved;
        case AgentQApprovalHistoryDecision::policy_rejected:
            return kStoredDecisionPolicyRejected;
        case AgentQApprovalHistoryDecision::user_approved:
            return kStoredDecisionUserApproved;
        case AgentQApprovalHistoryDecision::user_rejected:
            return kStoredDecisionUserRejected;
        case AgentQApprovalHistoryDecision::user_timeout:
            return kStoredDecisionUserTimeout;
        case AgentQApprovalHistoryDecision::method_error:
        default:
            return kStoredDecisionMethodError;
    }
}

AgentQApprovalHistoryDecision public_decision(uint8_t value)
{
    switch (value) {
        case kStoredDecisionPolicyApproved:
            return AgentQApprovalHistoryDecision::policy_approved;
        case kStoredDecisionPolicyRejected:
            return AgentQApprovalHistoryDecision::policy_rejected;
        case kStoredDecisionUserApproved:
            return AgentQApprovalHistoryDecision::user_approved;
        case kStoredDecisionUserRejected:
            return AgentQApprovalHistoryDecision::user_rejected;
        case kStoredDecisionUserTimeout:
            return AgentQApprovalHistoryDecision::user_timeout;
        case kStoredDecisionMethodError:
        default:
            return AgentQApprovalHistoryDecision::method_error;
    }
}

uint8_t stored_confirmation(AgentQApprovalHistoryConfirmationKind value)
{
    switch (value) {
        case AgentQApprovalHistoryConfirmationKind::policy:
            return kStoredConfirmationPolicy;
        case AgentQApprovalHistoryConfirmationKind::physical_confirm:
            return kStoredConfirmationPhysicalConfirm;
        case AgentQApprovalHistoryConfirmationKind::local_pin:
            return kStoredConfirmationLocalPin;
        case AgentQApprovalHistoryConfirmationKind::none:
        default:
            return kStoredConfirmationNone;
    }
}

AgentQApprovalHistoryConfirmationKind public_confirmation(uint8_t value)
{
    switch (value) {
        case kStoredConfirmationPolicy:
            return AgentQApprovalHistoryConfirmationKind::policy;
        case kStoredConfirmationPhysicalConfirm:
            return AgentQApprovalHistoryConfirmationKind::physical_confirm;
        case kStoredConfirmationLocalPin:
            return AgentQApprovalHistoryConfirmationKind::local_pin;
        case kStoredConfirmationNone:
        default:
            return AgentQApprovalHistoryConfirmationKind::none;
    }
}

AgentQApprovalHistoryReadResult load_history(StoredApprovalHistory* history, bool missing_is_empty)
{
    if (history == nullptr) {
        return AgentQApprovalHistoryReadResult::storage_error;
    }
    memset(history, 0, sizeof(*history));

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result != ESP_OK) {
        if (result == ESP_ERR_NVS_NOT_FOUND && missing_is_empty) {
            init_history(history);
            return AgentQApprovalHistoryReadResult::ok;
        }
        ESP_LOGW(kTag, "NVS open failed while reading approval history: %s", esp_err_to_name(result));
        return AgentQApprovalHistoryReadResult::storage_error;
    }

    size_t history_size = 0;
    result = nvs_get_blob(nvs, kApprovalHistoryKey, nullptr, &history_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        if (missing_is_empty) {
            init_history(history);
            return AgentQApprovalHistoryReadResult::ok;
        }
        return AgentQApprovalHistoryReadResult::storage_error;
    }
    if (result != ESP_OK) {
        nvs_close(nvs);
        ESP_LOGW(kTag, "Approval history size read failed: %s", esp_err_to_name(result));
        return AgentQApprovalHistoryReadResult::storage_error;
    }
    if (history_size != sizeof(*history)) {
        nvs_close(nvs);
        ESP_LOGW(kTag, "Approval history has invalid size: %u",
                 static_cast<unsigned>(history_size));
        return AgentQApprovalHistoryReadResult::invalid;
    }

    result = nvs_get_blob(nvs, kApprovalHistoryKey, history, &history_size);
    nvs_close(nvs);
    if (result != ESP_OK || history_size != sizeof(*history)) {
        ESP_LOGW(kTag, "Approval history read failed: %s size=%u",
                 esp_err_to_name(result),
                 static_cast<unsigned>(history_size));
        memset(history, 0, sizeof(*history));
        return AgentQApprovalHistoryReadResult::storage_error;
    }
    if (!valid_history_header(*history)) {
        memset(history, 0, sizeof(*history));
        ESP_LOGW(kTag, "Approval history validation failed");
        return AgentQApprovalHistoryReadResult::invalid;
    }
    return AgentQApprovalHistoryReadResult::ok;
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

bool materialize_record(const StoredApprovalHistoryRecord& stored, AgentQApprovalHistoryRecord* output)
{
    if (output == nullptr) {
        return false;
    }
    memset(output, 0, sizeof(*output));
    output->sequence = stored.sequence;
    output->uptime_ms = stored.uptime_ms;
    output->event_kind = public_event_kind(stored.event_kind);
    output->decision = public_decision(stored.decision);
    output->confirmation_kind = public_confirmation(stored.confirmation_kind);
    if (!copy_stored_history_token(output->reason_code, sizeof(output->reason_code), stored.reason_code, sizeof(stored.reason_code), true, history_reason_char)) {
        memset(output, 0, sizeof(*output));
        return false;
    }
    if (output->event_kind == AgentQApprovalHistoryEventKind::method_decision) {
        if (!copy_stored_history_token(output->chain, sizeof(output->chain), stored.chain, sizeof(stored.chain), true, history_chain_or_method_char) ||
            !copy_stored_history_token(output->method, sizeof(output->method), stored.method, sizeof(stored.method), true, history_chain_or_method_char) ||
            !copy_stored_history_token(output->rule_ref, sizeof(output->rule_ref), stored.rule_ref, sizeof(stored.rule_ref), false, history_rule_ref_char)) {
            memset(output, 0, sizeof(*output));
            return false;
        }
        if ((stored.flags & kStoredDigestPayload) != 0) {
            digest_to_string(stored.payload_digest, output->payload_digest, sizeof(output->payload_digest));
        }
        if ((stored.flags & kStoredDigestPolicy) != 0) {
            digest_to_string(stored.policy_hash, output->policy_hash, sizeof(output->policy_hash));
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
        stored.rule_count > kAgentQPolicyMaxRules) {
        memset(output, 0, sizeof(*output));
        return false;
    }
    output->rule_count = stored.rule_count;
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
        output_size != kAgentQApprovalHistoryDigestSize) {
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
    if (history->count < kAgentQApprovalHistoryCapacity) {
        slot = (history->start + history->count) % kAgentQApprovalHistoryCapacity;
        ++history->count;
    } else {
        slot = history->start;
        history->start = (history->start + 1) % kAgentQApprovalHistoryCapacity;
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

bool append_method_decision_history(
    const AgentQApprovalHistoryAppendInput& input,
    uint64_t uptime_ms,
    bool enforce_write_budget)
{
    StoredApprovalHistory& history = g_history_workspace;
    const AgentQApprovalHistoryReadResult load_result = load_history(&history, true);
    if (load_result != AgentQApprovalHistoryReadResult::ok) {
        return false;
    }

    StoredApprovalHistoryRecord* record = nullptr;
    if (!append_record(&history, &record)) {
        return false;
    }
    record->uptime_ms = uptime_ms;
    record->event_kind = kStoredEventMethodDecision;
    record->decision = stored_decision(input.decision);
    record->confirmation_kind = stored_confirmation(input.confirmation_kind);
    if (!store_history_token(record->chain, sizeof(record->chain), input.chain, true, history_chain_or_method_char) ||
        !store_history_token(record->method, sizeof(record->method), input.method, true, history_chain_or_method_char) ||
        !store_history_token(record->reason_code, sizeof(record->reason_code), input.reason_code, true, history_reason_char) ||
        !store_history_token(record->rule_ref, sizeof(record->rule_ref), input.rule_ref, false, history_rule_ref_char)) {
        ESP_LOGW(kTag, "Refusing approval history record with invalid or overlong token");
        return false;
    }
    if (digest_from_string(input.payload_digest, record->payload_digest)) {
        record->flags |= kStoredDigestPayload;
    }
    if (digest_from_string(input.policy_hash, record->policy_hash)) {
        record->flags |= kStoredDigestPolicy;
    }

    if (enforce_write_budget && !consume_write_budget(uptime_ms)) {
        return false;
    }

    return store_history(history);
}

static bool method_terminal_history_supported(const AgentQApprovalHistoryAppendInput& input)
{
    switch (input.decision) {
        case AgentQApprovalHistoryDecision::policy_approved:
            return input.confirmation_kind == AgentQApprovalHistoryConfirmationKind::policy;
        case AgentQApprovalHistoryDecision::user_approved:
        case AgentQApprovalHistoryDecision::user_rejected:
        case AgentQApprovalHistoryDecision::user_timeout:
            return input.confirmation_kind == AgentQApprovalHistoryConfirmationKind::local_pin ||
                   input.confirmation_kind == AgentQApprovalHistoryConfirmationKind::physical_confirm;
        case AgentQApprovalHistoryDecision::method_error:
            return input.confirmation_kind == AgentQApprovalHistoryConfirmationKind::policy ||
                   input.confirmation_kind == AgentQApprovalHistoryConfirmationKind::local_pin ||
                   input.confirmation_kind == AgentQApprovalHistoryConfirmationKind::physical_confirm;
        case AgentQApprovalHistoryDecision::policy_rejected:
        default:
            return false;
    }
}

bool approval_history_append(
    const AgentQApprovalHistoryAppendInput& input,
    uint64_t uptime_ms)
{
    return append_method_decision_history(input, uptime_ms, true);
}

bool approval_history_append_required_method_terminal(
    const AgentQApprovalHistoryAppendInput& input,
    uint64_t uptime_ms)
{
    if (!method_terminal_history_supported(input)) {
        ESP_LOGW(kTag, "Refusing unsupported required method terminal history record");
        return false;
    }
    return append_method_decision_history(input, uptime_ms, false);
}

bool approval_history_append_required_policy_update(
    const AgentQPolicyUpdateHistoryAppendInput& input,
    uint64_t uptime_ms)
{
    StoredApprovalHistory& history = g_history_workspace;
    const AgentQApprovalHistoryReadResult load_result = load_history(&history, true);
    if (load_result != AgentQApprovalHistoryReadResult::ok) {
        return false;
    }

    StoredApprovalHistoryRecord* record = nullptr;
    if (!append_record(&history, &record)) {
        return false;
    }
    record->uptime_ms = uptime_ms;
    record->event_kind = kStoredEventPolicyUpdate;
    record->decision = kStoredDecisionMethodError;
    record->confirmation_kind = kStoredConfirmationPolicy;
    if (input.rule_count > kAgentQPolicyMaxRules ||
        !policy_update_result_supported(input.result) ||
        !highest_action_supported(input.highest_action) ||
        !store_history_token(record->policy_result, sizeof(record->policy_result), input.result, true, history_policy_result_char) ||
        !store_history_token(record->reason_code, sizeof(record->reason_code), input.reason_code, true, history_reason_char) ||
        !store_history_token(record->highest_action, sizeof(record->highest_action), input.highest_action, true, history_highest_action_char) ||
        !digest_from_string(input.policy_hash, record->policy_hash)) {
        ESP_LOGW(kTag, "Refusing policy update history record with invalid metadata");
        return false;
    }
    record->rule_count = static_cast<uint16_t>(input.rule_count);
    record->flags |= kStoredDigestPolicy;
    return store_history(history);
}

AgentQApprovalHistoryReadResult approval_history_read_page(
    uint64_t before_sequence,
    size_t limit,
    AgentQApprovalHistoryPage* output)
{
    if (output == nullptr || limit == 0 || limit > kAgentQApprovalHistoryPageMax) {
        return AgentQApprovalHistoryReadResult::storage_error;
    }
    memset(output, 0, sizeof(*output));

    StoredApprovalHistory& history = g_history_workspace;
    const AgentQApprovalHistoryReadResult load_result = load_history(&history, true);
    if (load_result != AgentQApprovalHistoryReadResult::ok) {
        return load_result;
    }

    for (size_t offset = 0; offset < history.count; ++offset) {
        const size_t newest_offset = history.count - 1 - offset;
        const size_t slot = (history.start + newest_offset) % kAgentQApprovalHistoryCapacity;
        const StoredApprovalHistoryRecord& stored = history.records[slot];
        if (stored.sequence == 0 ||
            (before_sequence != 0 && stored.sequence >= before_sequence)) {
            continue;
        }
        if (output->count < limit) {
            if (!materialize_record(stored, &output->records[output->count])) {
                memset(output, 0, sizeof(*output));
                return AgentQApprovalHistoryReadResult::invalid;
            }
            ++output->count;
        } else {
            output->has_more = true;
            break;
        }
    }
    return AgentQApprovalHistoryReadResult::ok;
}

bool approval_history_wipe()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
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

const char* approval_history_decision_to_string(AgentQApprovalHistoryDecision value)
{
    switch (value) {
        case AgentQApprovalHistoryDecision::policy_approved:
            return "policy_approved";
        case AgentQApprovalHistoryDecision::policy_rejected:
            return "policy_rejected";
        case AgentQApprovalHistoryDecision::user_approved:
            return "user_approved";
        case AgentQApprovalHistoryDecision::user_rejected:
            return "user_rejected";
        case AgentQApprovalHistoryDecision::user_timeout:
            return "user_timeout";
        case AgentQApprovalHistoryDecision::method_error:
        default:
            return "method_error";
    }
}

const char* approval_history_confirmation_kind_to_string(AgentQApprovalHistoryConfirmationKind value)
{
    switch (value) {
        case AgentQApprovalHistoryConfirmationKind::policy:
            return "policy";
        case AgentQApprovalHistoryConfirmationKind::physical_confirm:
            return "physical_confirm";
        case AgentQApprovalHistoryConfirmationKind::local_pin:
            return "local_pin";
        case AgentQApprovalHistoryConfirmationKind::none:
        default:
            return "none";
    }
}

}  // namespace agent_q
