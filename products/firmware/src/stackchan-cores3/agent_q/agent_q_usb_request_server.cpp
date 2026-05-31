#include "agent_q_usb_request_server.h"

#include <stdio.h>
#include <string.h>

#include <ArduinoJson.h>
#include <memory>
#include "agent_q_bip39.h"
#include "agent_q_bip39_wordlist.h"
#include "agent_q_call_method_validation.h"
#include "agent_q_connect_settings.h"
#include "agent_q_display_power.h"
#include "agent_q_entropy.h"
#include "agent_q_local_auth.h"
#include "agent_q_local_reset.h"
#include "agent_q_motion_state.h"
#include "agent_q_pin_attempt.h"
#include "agent_q_policy_store.h"
#include "agent_q_root_material.h"
#include "agent_q_speech_bubble.h"
#include "agent_q_sui_account.h"
#include "agent_q_sui_account_store.h"
#include "agent_q_common/policy/agent_q_policy_runtime.h"
#include "agent_q_common/sui/agent_q_sui_policy_adapter.h"
#include "agent_q_common/sui/agent_q_sui_transaction_facts.h"
#include "driver/usb_serial_jtag.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "hal/board/hal_bridge.h"
#include "hal/hal.h"
#include "lvgl.h"
#include "nvs.h"

extern "C" {
#include "byte_conversions.h"
}

#include "stackchan/stackchan.h"

namespace {

constexpr const char* kTag = "UsbRequestServer";
constexpr int kProtocolVersion = 1;
constexpr const char* kFirmwareName = "Agent-Q Firmware";
constexpr const char* kHardwareId = "stackchan-cores3";
constexpr const char* kFirmwareVersion = "0.0.0";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kDeviceIdKey = "device_id";
constexpr const char* kProvisioningStateKey = "prov_state";
constexpr const char* kProvisioningStateUnprovisioned = "unprovisioned";
constexpr const char* kProvisioningStateProvisioning = "provisioning";
constexpr const char* kProvisioningStateProvisioned = "provisioned";
constexpr const char* kProvisioningStateError = "error";
constexpr uint32_t kIdentifyDisplayDefaultMs = 10000;
constexpr uint32_t kIdentifyDisplayMaxMs = 30000;
constexpr uint32_t kConnectApprovalDefaultMs = 30000;
constexpr uint32_t kConnectApprovalMaxMs = 60000;
constexpr uint32_t kProvisioningApprovalMaxMs = 60000;
constexpr uint32_t kRecoveryPhraseDisplayMs = kProvisioningApprovalMaxMs;
constexpr uint32_t kLocalPinSetupMs = kProvisioningApprovalMaxMs;
constexpr uint32_t kLocalProcessingRenderDelayMs = 250;
constexpr uint32_t kLocalProcessingDisplayMs = 900;
constexpr uint32_t kSettingsTouchEntryMs = 900;
constexpr uint32_t kSessionTtlMs = 1800000;
constexpr uint32_t kSessionExpiryCheckMs = 5000;
constexpr uint32_t kUsbHostLinkCheckMs = 250;
constexpr size_t kLineBufferSize = 1024;
constexpr size_t kResponseBufferSize = 512;
constexpr size_t kMaxRequestIdSize = 80;
constexpr size_t kDeviceIdSize = 37;
constexpr size_t kProvisioningStateSize = 16;
constexpr size_t kIdentifyCodeSize = 5;
constexpr size_t kSessionIdSize = 26;
constexpr size_t kGatewayNameSize = 65;
constexpr size_t kConnectDisplayMessageSize = 96;
constexpr size_t kRecoveryPhrasePrefixCellCount = 12;
constexpr size_t kRecoveryPhrasePrefixCellSize = 8;
constexpr size_t kRecoverWordsPerPage = 3;
constexpr size_t kRecoverPageCount = agent_q::kBip39MnemonicWordCount / kRecoverWordsPerPage;
constexpr size_t kRecoverPrefixMaxChars = 4;
constexpr size_t kRecoverPrefixBufferSize = kRecoverPrefixMaxChars + 1;
constexpr int kScreenHeight = 240;
constexpr int kScreenWidth = 320;
constexpr int kDecisionStripHeight = 34;
constexpr int kDecisionPanelHeight = kDecisionStripHeight;
constexpr int kDecisionButtonWidth = kScreenWidth / 2;
constexpr int kDecisionCornerRadius = 10;
constexpr int kRecoveryPhraseButtonHeight = 28;
constexpr int kRecoveryPhraseButtonRadius = 7;
constexpr int kRecoveryPhraseButtonWidth = 142;
constexpr int kRecoveryPhraseButtonLeftX = 8;
constexpr int kRecoveryPhraseButtonRightX = 154;
constexpr int kRecoveryPhraseButtonBottomMargin = 8;
constexpr int kRecoveryPhraseTopMargin = kRecoveryPhraseButtonBottomMargin;
constexpr int kSetupActionButtonY =
    kScreenHeight - 16 - kRecoveryPhraseButtonHeight - kRecoveryPhraseButtonBottomMargin;
constexpr int kPinPanelButtonRadius = 6;
constexpr int kPinPanelButtonHeight = 22;
constexpr int kPinKeypadButtonWidth = 90;
constexpr int kPinKeypadGridLeft = 17;
constexpr int kPinKeypadGridTop = 78;
constexpr int kPinKeypadRowHeight = 25;
constexpr int kSettingsMenuButtonCenterX = (kScreenWidth - 16 - kRecoveryPhraseButtonWidth) / 2;
constexpr int kSettingsMenuRowLabelX = 24;
constexpr int kSettingsMenuRowControlX = 218;
constexpr int kSettingsMenuRowOneY = 62;
constexpr int kSettingsMenuRowTwoY = 100;
constexpr int kSettingsMenuActionButtonWidth = 72;
constexpr int kSettingsMenuActionButtonHeight = 26;
constexpr int kSetupMenuGenerateButtonY = 78;
constexpr int kSetupMenuRecoverButtonY = 114;
constexpr int kMnemonicWordCellWidth = 90;
constexpr int kMnemonicWordCellHeight = 22;
constexpr int kMnemonicWordCellLeft = 17;
constexpr int kMnemonicWordIndexWidth = 22;
constexpr int kMnemonicWordPrefixLeft = 30;
constexpr int kMnemonicWordPrefixWidth = 54;
constexpr int kRecoverWordCellTop = 42;
constexpr int kRecoverAlphabetButtonWidth = 22;
constexpr int kRecoverAlphabetButtonHeight = 18;
constexpr int kRecoverAlphabetLeft = 9;
constexpr int kRecoverAlphabetTop = 82;
constexpr int kRecoverCandidateLeft = 17;
constexpr int kRecoverCandidateTop = 124;
constexpr int kRecoverCandidateWidth = 270;
constexpr int kRecoverCandidateHeight = 58;
constexpr int kRecoverCandidateButtonWidth = 84;
constexpr int kRecoverCandidateButtonHeight = 22;
constexpr int kRecoverNavigationButtonWidth = 68;
constexpr int kPinProcessingOverlaySize = 50;
constexpr int kPinProcessingOverlayX =
    (kScreenWidth - 16 - kPinProcessingOverlaySize) / 2;
constexpr int kPinProcessingOverlayY =
    (kScreenHeight - 16 - kPinProcessingOverlaySize) / 2;
constexpr int kPinProcessingSpinnerSize = 34;
constexpr int kPinProcessingArcDegrees = 112;
constexpr int kPinProcessingSpinMs = 650;
constexpr int kSettingsTouchEntryWidth = 64;
constexpr int kSettingsTouchEntryHeight = 56;
constexpr uint32_t kSetupCellBorderColor = 0xB7E4C7;
constexpr uint32_t kSetupInputPressedColor = 0x1D4ED8;
constexpr uint32_t kDisabledControlTextColor = 0x98A2B3;
constexpr uint32_t kDisabledActionTextColor = 0xEAECF0;
constexpr uint32_t kAgentQResultDisplayMs = 1800;

enum class AgentQUiPanelKind {
    none,
    decision_strip,
    setup_choice,
    recovery_phrase_display,
    recovery_word_entry,
    pin_entry,
    settings_menu,
    reset_pin_entry,
    local_pin_auth,
};

enum class AgentQUiMode {
    none,
    decision,
    result,
    identification,
};

enum class AgentQMessageKind {
    info,
    approval,
    success,
    rejected,
    timeout,
    error,
};

enum class SetupButtonKind {
    solid_action,
    outlined_keypad,
};

enum class PendingChoice {
    none,
    yes,
    no,
};

enum class AgentQUiEventKind {
    panel_deleted,
    setup_requested,
    setup_generate_requested,
    setup_recover_requested,
    setup_cancel_requested,
    provisioning_welcome_requested,
    settings_requested,
    settings_cancel_requested,
    settings_connect_pin_requested,
    settings_reset_requested,
    reset_cancel_requested,
    recovery_phrase_cancel_requested,
    recovery_phrase_confirm_requested,
    pin_digit_requested,
    pin_clear_requested,
    pin_backspace_requested,
    pin_submit_requested,
    pin_cancel_requested,
    recover_slot_requested,
    recover_letter_requested,
    recover_clear_requested,
    recover_candidate_requested,
    recover_previous_requested,
    recover_next_requested,
    recover_cancel_requested,
};

struct AgentQUiEvent {
    AgentQUiEventKind kind = AgentQUiEventKind::panel_deleted;
    AgentQUiPanelKind panel_kind = AgentQUiPanelKind::none;
    char digit = '\0';
    char letter = '\0';
    uint8_t slot = 0;
    uint16_t word_index = 0;
};

enum class PendingKind {
    none,
    connect,
    connect_pin,
};

enum class LocalPinAuthPurpose {
    none,
    connect,
    settings_connect_pin,
};

enum class LocalPinAuthStage {
    none,
    pin_entry,
    pin_verifying,
    committing_setting,
};

enum class ProvisioningRuntimeState {
    unprovisioned,
    provisioning,
    provisioned,
};

// Firmware-owned state is kept separate from StackChan-owned avatar/app state.
// Agent-Q records protocol/UI ownership here and only stores StackChan
// references for temporary objects it created and must remove.
struct PendingApprovalState {
    char id[kMaxRequestIdSize] = {};
    char gateway_name[kGatewayNameSize] = {};
    bool active = false;
    bool touch_armed = false;
    TickType_t deadline = 0;
    PendingChoice choice = PendingChoice::none;
    PendingKind kind = PendingKind::none;

    bool awaiting_choice() const
    {
        return active && kind == PendingKind::connect && choice == PendingChoice::none;
    }

    void clear()
    {
        id[0] = '\0';
        gateway_name[0] = '\0';
        active = false;
        touch_armed = false;
        deadline = 0;
        choice = PendingChoice::none;
        kind = PendingKind::none;
    }

    void begin_connect(const char* request_id, const char* request_gateway_name, uint32_t timeout_ms)
    {
        clear();
        strlcpy(id, request_id, sizeof(id));
        strlcpy(gateway_name, request_gateway_name, sizeof(gateway_name));
        active = true;
        kind = PendingKind::connect;
        deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    }

    void begin_connect_pin(const char* request_id, const char* request_gateway_name, uint32_t timeout_ms)
    {
        begin_connect(request_id, request_gateway_name, timeout_ms);
        kind = PendingKind::connect_pin;
    }
};

struct IdentificationState {
    char code[kIdentifyCodeSize] = {};
    bool active = false;
    TickType_t deadline = 0;

    void clear()
    {
        code[0] = '\0';
        active = false;
        deadline = 0;
    }

    void begin(const char* value, uint32_t duration_ms)
    {
        strlcpy(code, value, sizeof(code));
        active = true;
        deadline = xTaskGetTickCount() + pdMS_TO_TICKS(duration_ms);
    }
};

struct SessionState {
    char id[kSessionIdSize] = {};
    TickType_t expiry = 0;
    TickType_t next_expiry_check = 0;

    void clear()
    {
        id[0] = '\0';
        expiry = 0;
    }

    bool active() const
    {
        return id[0] != '\0' && expiry != 0;
    }
};

struct AgentQUiState {
    lv_obj_t* panel = nullptr;
    AgentQUiPanelKind panel_kind = AgentQUiPanelKind::none;
    stackchan::avatar::Avatar* speech_avatar = nullptr;
    int speech_decorator_id = -1;
    AgentQUiMode speech_mode = AgentQUiMode::none;
    stackchan::avatar::Emotion previous_emotion = stackchan::avatar::Emotion::Neutral;
    bool owns_emotion = false;
    TickType_t message_deadline = 0;
};

struct LocalPinAuthState {
    char pin_entry[agent_q::kLocalPinBufferSize] = {};
    size_t pin_entry_length = 0;
    LocalPinAuthPurpose purpose = LocalPinAuthPurpose::none;
    LocalPinAuthStage stage = LocalPinAuthStage::none;
    bool target_require_pin_on_connect = true;
    TickType_t deadline = 0;
    TickType_t verify_ready_at = 0;
    TickType_t commit_ready_at = 0;
    agent_q::AgentQPinAttemptState pin_attempt;

    bool flow_active() const
    {
        return purpose != LocalPinAuthPurpose::none && stage != LocalPinAuthStage::none;
    }

    void clear_flow()
    {
        agent_q::wipe_sensitive_buffer(pin_entry, sizeof(pin_entry));
        pin_entry_length = 0;
        purpose = LocalPinAuthPurpose::none;
        stage = LocalPinAuthStage::none;
        target_require_pin_on_connect = true;
        deadline = 0;
        verify_ready_at = 0;
        commit_ready_at = 0;
    }

    void clear_pin_only()
    {
        agent_q::wipe_sensitive_buffer(pin_entry, sizeof(pin_entry));
        pin_entry_length = 0;
        verify_ready_at = 0;
        commit_ready_at = 0;
    }

    void clear_attempts()
    {
        agent_q::pin_attempt_clear(&pin_attempt);
    }
};

enum class SetupScratchStage {
    none,
    setup_choice,
    recovery_phrase_displayed,
    recover_word_entry,
    pin_first_entry,
    pin_repeat_entry,
    pin_committing,
};

enum class RecoveryPhraseGenerationResult {
    ok,
    rng_error,
    generation_error,
};

struct ProvisioningScratchState {
    uint8_t root_material[agent_q::kRootMaterialBytes] = {};
    char recovery_phrase[agent_q::kBip39MnemonicMaxChars] = {};
    char recovery_phrase_prefix_cells[kRecoveryPhrasePrefixCellCount][kRecoveryPhrasePrefixCellSize] = {};
    uint16_t recover_word_indices[agent_q::kBip39MnemonicWordCount] = {};
    bool recover_word_selected[agent_q::kBip39MnemonicWordCount] = {};
    char recover_prefixes[agent_q::kBip39MnemonicWordCount][kRecoverPrefixBufferSize] = {};
    char pin_first[agent_q::kLocalPinBufferSize] = {};
    char pin_entry[agent_q::kLocalPinBufferSize] = {};
    size_t pin_entry_length = 0;
    uint8_t recover_page = 0;
    uint8_t recover_active_slot = 0;
    SetupScratchStage setup_stage = SetupScratchStage::none;
    TickType_t setup_choice_deadline = 0;
    TickType_t recovery_phrase_deadline = 0;
    TickType_t recover_word_deadline = 0;
    TickType_t pin_deadline = 0;
    TickType_t pin_commit_ready_at = 0;

    void wipe()
    {
        agent_q::wipe_sensitive_buffer(root_material, sizeof(root_material));
        agent_q::wipe_sensitive_buffer(recovery_phrase, sizeof(recovery_phrase));
        agent_q::wipe_sensitive_buffer(
            recovery_phrase_prefix_cells,
            kRecoveryPhrasePrefixCellCount * kRecoveryPhrasePrefixCellSize);
        agent_q::wipe_sensitive_buffer(recover_word_indices, sizeof(recover_word_indices));
        agent_q::wipe_sensitive_buffer(recover_word_selected, sizeof(recover_word_selected));
        agent_q::wipe_sensitive_buffer(recover_prefixes, sizeof(recover_prefixes));
        wipe_pin_only();
        recover_page = 0;
        recover_active_slot = 0;
        setup_stage = SetupScratchStage::none;
        setup_choice_deadline = 0;
        recovery_phrase_deadline = 0;
        recover_word_deadline = 0;
        pin_commit_ready_at = 0;
    }

    void wipe_pin_only()
    {
        agent_q::wipe_sensitive_buffer(pin_first, sizeof(pin_first));
        agent_q::wipe_sensitive_buffer(pin_entry, sizeof(pin_entry));
        pin_entry_length = 0;
        pin_deadline = 0;
        pin_commit_ready_at = 0;
    }

    void wipe_displayed_phrase_text()
    {
        agent_q::wipe_sensitive_buffer(recovery_phrase, sizeof(recovery_phrase));
        agent_q::wipe_sensitive_buffer(
            recovery_phrase_prefix_cells,
            kRecoveryPhrasePrefixCellCount * kRecoveryPhrasePrefixCellSize);
    }

    bool setup_flow_active() const
    {
        return setup_stage != SetupScratchStage::none;
    }
};

struct LocalSettingsTouchState {
    bool active = false;
    TickType_t started_at = 0;

    void clear()
    {
        active = false;
        started_at = 0;
    }
};

char g_line_buffer[kLineBufferSize];
size_t g_line_size = 0;
char g_device_id[kDeviceIdSize];
ProvisioningRuntimeState g_provisioning_state = ProvisioningRuntimeState::unprovisioned;
bool g_persistent_material_consistency_error = false;
PendingApprovalState g_pending;
IdentificationState g_identification;
SessionState g_session;
AgentQUiState g_ui;
ProvisioningScratchState g_provisioning_scratch;
LocalPinAuthState g_local_pin_auth;
LocalSettingsTouchState g_settings_touch;
bool g_usb_ready = false;
bool g_usb_host_connected_known = false;
bool g_usb_host_connected = false;
TickType_t g_next_usb_host_check = 0;
TaskHandle_t g_usb_task = nullptr;
QueueHandle_t g_pending_choice_queue = nullptr;
QueueHandle_t g_ui_event_queue = nullptr;
uint16_t g_recover_candidate_event_indices[agent_q::kBip39WordCount] = {};

bool refresh_persistent_material_consistency();
bool persist_provisioning_state(ProvisioningRuntimeState next_state);
agent_q::AgentQLocalResetPersistenceOps local_reset_persistence_ops();
void clear_agent_q_panel();
void clear_pending_state();

void wipe_setup_scratch(const char* reason)
{
    const bool had_setup_scratch = g_provisioning_scratch.setup_flow_active();
    g_provisioning_scratch.wipe();
    if (had_setup_scratch) {
        ESP_LOGW(kTag, "Setup scratch wiped: %s", reason != nullptr ? reason : "unspecified");
    }
}

void wipe_local_reset_scratch(const char* reason)
{
    const bool had_reset_scratch =
        agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active;
    agent_q::local_reset_wipe();
    g_settings_touch.clear();
    if (had_reset_scratch) {
        ESP_LOGW(kTag, "Local reset scratch wiped: %s", reason != nullptr ? reason : "unspecified");
    }
}

void wipe_local_pin_auth_scratch(const char* reason)
{
    const bool had_pin_auth = g_local_pin_auth.flow_active();
    g_local_pin_auth.clear_flow();
    if (had_pin_auth) {
        ESP_LOGW(kTag, "Local PIN authorization scratch wiped: %s", reason != nullptr ? reason : "unspecified");
    }
}

bool is_decision_panel_kind(AgentQUiPanelKind kind)
{
    return kind == AgentQUiPanelKind::decision_strip;
}

bool local_pin_auth_panel_matches_stage(AgentQUiPanelKind kind)
{
    return kind == AgentQUiPanelKind::local_pin_auth &&
           g_local_pin_auth.flow_active();
}

bool local_reset_panel_matches_stage(AgentQUiPanelKind kind)
{
    const agent_q::AgentQLocalResetStage stage =
        agent_q::local_reset_snapshot(xTaskGetTickCount()).stage;
    return (kind == AgentQUiPanelKind::settings_menu &&
            stage == agent_q::AgentQLocalResetStage::settings_menu) ||
           (kind == AgentQUiPanelKind::reset_pin_entry &&
            stage == agent_q::AgentQLocalResetStage::pin_entry);
}

bool tick_reached(TickType_t deadline)
{
    return static_cast<int32_t>(xTaskGetTickCount() - deadline) >= 0;
}

bool is_safe_id(const char* value)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }

    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (++length >= kMaxRequestIdSize) {
            return false;
        }
        const char c = *cursor;
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) {
            return false;
        }
    }
    return true;
}

bool is_safe_identification_code(const char* value)
{
    if (value == nullptr) {
        return false;
    }
    for (size_t index = 0; index < 4; ++index) {
        if (value[index] < '0' || value[index] > '9') {
            return false;
        }
    }
    return value[4] == '\0';
}

bool is_printable_ascii_gateway_name(const char* value)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }
    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (++length >= kGatewayNameSize) {
            return false;
        }
        const unsigned char c = static_cast<unsigned char>(*cursor);
        if (c < 0x20 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

void wipe_recovery_phrase_prefix_cells(char cells[kRecoveryPhrasePrefixCellCount][kRecoveryPhrasePrefixCellSize])
{
    agent_q::wipe_sensitive_buffer(
        cells, kRecoveryPhrasePrefixCellCount * kRecoveryPhrasePrefixCellSize);
}

bool format_recovery_phrase_prefix_cells(
    const char* phrase,
    char cells[kRecoveryPhrasePrefixCellCount][kRecoveryPhrasePrefixCellSize])
{
    if (phrase == nullptr || cells == nullptr) {
        return false;
    }

    wipe_recovery_phrase_prefix_cells(cells);
    size_t word_count = 0;
    const char* cursor = phrase;
    while (*cursor != '\0') {
        while (*cursor == ' ') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }

        char prefix[5] = {};
        size_t prefix_length = 0;
        while (*cursor != '\0' && *cursor != ' ') {
            if (prefix_length < 4) {
                prefix[prefix_length++] = *cursor;
            }
            cursor++;
        }
        word_count++;
        if (word_count > 12) {
            wipe_recovery_phrase_prefix_cells(cells);
            return false;
        }

        const int written = snprintf(
            cells[word_count - 1],
            kRecoveryPhrasePrefixCellSize,
            "%s",
            prefix);
        if (written <= 0 || static_cast<size_t>(written) >= kRecoveryPhrasePrefixCellSize) {
            wipe_recovery_phrase_prefix_cells(cells);
            return false;
        }
    }

    if (word_count != 12) {
        wipe_recovery_phrase_prefix_cells(cells);
        return false;
    }
    return true;
}

size_t recover_global_word_slot()
{
    return static_cast<size_t>(g_provisioning_scratch.recover_page) * kRecoverWordsPerPage +
           g_provisioning_scratch.recover_active_slot;
}

size_t recover_global_word_slot_for(uint8_t page, uint8_t slot)
{
    return static_cast<size_t>(page) * kRecoverWordsPerPage + slot;
}

bool recover_current_page_complete()
{
    if (g_provisioning_scratch.recover_page >= kRecoverPageCount) {
        return false;
    }
    for (size_t slot = 0; slot < kRecoverWordsPerPage; ++slot) {
        const size_t global_slot = recover_global_word_slot_for(g_provisioning_scratch.recover_page, slot);
        if (global_slot >= agent_q::kBip39MnemonicWordCount ||
            !g_provisioning_scratch.recover_word_selected[global_slot]) {
            return false;
        }
    }
    return true;
}

bool recover_all_words_complete()
{
    for (size_t index = 0; index < agent_q::kBip39MnemonicWordCount; ++index) {
        if (!g_provisioning_scratch.recover_word_selected[index]) {
            return false;
        }
    }
    return true;
}

bool word_starts_with_prefix(const char* word, const char* prefix)
{
    if (word == nullptr || prefix == nullptr || prefix[0] == '\0') {
        return false;
    }
    for (size_t index = 0; prefix[index] != '\0'; ++index) {
        if (word[index] != prefix[index]) {
            return false;
        }
    }
    return true;
}

void write_selected_word_prefix(size_t global_slot, uint16_t word_index)
{
    if (global_slot >= agent_q::kBip39MnemonicWordCount) {
        return;
    }
    char* prefix = g_provisioning_scratch.recover_prefixes[global_slot];
    agent_q::wipe_sensitive_buffer(prefix, kRecoverPrefixBufferSize);
    const char* word = agent_q::bip39_english_word(word_index);
    if (word == nullptr) {
        return;
    }
    size_t index = 0;
    while (index < kRecoverPrefixMaxChars && word[index] != '\0') {
        prefix[index] = word[index];
        ++index;
    }
    prefix[index] = '\0';
}

void wipe_recover_word_entry_scratch()
{
    agent_q::wipe_sensitive_buffer(
        g_provisioning_scratch.recover_word_indices,
        sizeof(g_provisioning_scratch.recover_word_indices));
    agent_q::wipe_sensitive_buffer(
        g_provisioning_scratch.recover_word_selected,
        sizeof(g_provisioning_scratch.recover_word_selected));
    agent_q::wipe_sensitive_buffer(
        g_provisioning_scratch.recover_prefixes,
        sizeof(g_provisioning_scratch.recover_prefixes));
    g_provisioning_scratch.recover_page = 0;
    g_provisioning_scratch.recover_active_slot = 0;
    g_provisioning_scratch.recover_word_deadline = 0;
}

bool is_safe_session_id(const char* value)
{
    if (value == nullptr) {
        return false;
    }
    const char* expected_prefix = "session_";
    const size_t prefix_length = 8;
    for (size_t index = 0; index < prefix_length; ++index) {
        if (value[index] != expected_prefix[index]) {
            return false;
        }
    }
    size_t length = prefix_length;
    for (const char* cursor = value + prefix_length; *cursor != '\0'; ++cursor) {
        if (++length >= kSessionIdSize) {
            return false;
        }
        const char c = *cursor;
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) {
            return false;
        }
    }
    return length > prefix_length;
}

void write_json_document(JsonDocument& response)
{
    char buffer[kResponseBufferSize];
    size_t len = serializeJson(response, buffer, sizeof(buffer) - 2);
    buffer[len++] = '\n';
    buffer[len] = '\0';
    usb_serial_jtag_write_bytes(buffer, len, pdMS_TO_TICKS(20));
    usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(50));
}

void write_error_response(const char* id, const char* code, const char* message)
{
    JsonDocument response;
    if (id != nullptr && id[0] != '\0') {
        response["id"] = id;
    }
    response["version"] = kProtocolVersion;
    response["type"] = "error";
    response["error"]["code"] = code;
    response["error"]["message"] = message;
    write_json_document(response);
}

const char* current_device_state()
{
    if (g_persistent_material_consistency_error) {
        return "error";
    }
    if (g_pending.active) {
        return "awaiting_approval";
    }
    if (g_provisioning_scratch.setup_flow_active() ||
        agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active ||
        g_local_pin_auth.flow_active()) {
        return "busy";
    }
    return "idle";
}

const char* provisioning_state_to_string(ProvisioningRuntimeState state)
{
    switch (state) {
        case ProvisioningRuntimeState::provisioned:
            return kProvisioningStateProvisioned;
        case ProvisioningRuntimeState::provisioning:
            return kProvisioningStateProvisioning;
        case ProvisioningRuntimeState::unprovisioned:
        default:
            return kProvisioningStateUnprovisioned;
    }
}

const char* reported_provisioning_state()
{
    if (g_persistent_material_consistency_error) {
        return kProvisioningStateError;
    }
    return provisioning_state_to_string(g_provisioning_state);
}

bool parse_provisioning_state(const char* value, ProvisioningRuntimeState* output)
{
    if (value == nullptr || output == nullptr) {
        return false;
    }
    if (strcmp(value, kProvisioningStateUnprovisioned) == 0) {
        *output = ProvisioningRuntimeState::unprovisioned;
        return true;
    }
    if (strcmp(value, kProvisioningStateProvisioning) == 0) {
        *output = ProvisioningRuntimeState::provisioning;
        return true;
    }
    if (strcmp(value, kProvisioningStateProvisioned) == 0) {
        *output = ProvisioningRuntimeState::provisioned;
        return true;
    }
    return false;
}

void write_status_response(const char* id)
{
    refresh_persistent_material_consistency();

    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "status";
    response["device"]["deviceId"] = g_device_id;
    response["device"]["state"] = current_device_state();
    response["device"]["firmwareName"] = kFirmwareName;
    response["device"]["hardware"] = kHardwareId;
    response["device"]["firmwareVersion"] = kFirmwareVersion;
    response["provisioning"]["state"] = reported_provisioning_state();
    write_json_document(response);
}

void write_identify_device_result(const char* id, const char* code)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "identify_device_result";
    response["status"] = "displayed";
    response["code"] = code;
    response["device"]["deviceId"] = g_device_id;
    response["device"]["state"] = current_device_state();
    response["device"]["firmwareName"] = kFirmwareName;
    response["device"]["hardware"] = kHardwareId;
    response["device"]["firmwareVersion"] = kFirmwareVersion;
    write_json_document(response);
}

void write_connect_approved_response(const char* id)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "connect_result";
    response["status"] = "approved";
    response["sessionId"] = g_session.id;
    response["sessionTtlMs"] = kSessionTtlMs;
    response["device"]["deviceId"] = g_device_id;
    response["device"]["state"] = "idle";
    response["device"]["firmwareName"] = kFirmwareName;
    response["device"]["hardware"] = kHardwareId;
    response["device"]["firmwareVersion"] = kFirmwareVersion;
    write_json_document(response);
}

void write_connect_rejected_response(const char* id, const char* error_code, const char* error_message)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "connect_result";
    response["status"] = "rejected";
    response["error"]["code"] = error_code;
    response["error"]["message"] = error_message;
    write_json_document(response);
}

void write_disconnect_result(const char* id)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "disconnect_result";
    response["status"] = "disconnected";
    write_json_document(response);
}

void write_rejected_method_result(const char* id, const char* code, const char* message)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "method_result";
    response["status"] = "rejected";
    response["error"]["code"] = code;
    response["error"]["message"] = message;
    write_json_document(response);
}

void write_capabilities_response(const char* id)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "capabilities";
    JsonArray chains = response["chains"].to<JsonArray>();
    JsonObject sui = chains.add<JsonObject>();
    sui["id"] = "sui";
    JsonArray accounts = sui["accounts"].to<JsonArray>();
    JsonObject account = accounts.add<JsonObject>();
    account["keyScheme"] = "ed25519";
    account["derivationPath"] = "m/44'/784'/0'/0'/0'";
    sui["methods"].to<JsonArray>();
    write_json_document(response);
}

bool write_policy_response(const char* id)
{
    agent_q::AgentQStoredPolicySummary policy = {};
    if (!agent_q::read_active_policy_summary(&policy)) {
        return false;
    }

    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "policy";
    JsonObject policy_json = response["policy"].to<JsonObject>();
    policy_json["schema"] = policy.schema;
    policy_json["policyId"] = policy.policy_id;
    policy_json["defaultAction"] = policy.default_action;
    policy_json["ruleCount"] = policy.rule_count;
    write_json_document(response);
    return true;
}

void write_sui_sign_transaction_policy_decision(const char* id, JsonDocument& request)
{
    JsonVariant params = request["params"];
    size_t decoded_tx_size = 0;
    if (!agent_q::validate_sui_sign_transaction_params(params, &decoded_tx_size)) {
        write_error_response(id, "invalid_params", "Invalid sui/sign_transaction params.");
        return;
    }

    const char* network = params["network"].as<const char*>();
    const char* tx_bytes_base64 = params["txBytes"].as<const char*>();
    uint8_t tx_bytes[agent_q::kSuiSignTransactionTxBytesMaxBytes] = {};
    if (base64_to_bytes(tx_bytes_base64, strlen(tx_bytes_base64), tx_bytes, sizeof(tx_bytes)) != 0) {
        write_error_response(id, "invalid_params", "Invalid sui/sign_transaction txBytes.");
        return;
    }

    agent_q::SuiTransferFacts sui_facts = {};
    const agent_q::SuiTransactionFactsResult parse_result =
        agent_q::parse_sui_transfer_facts(tx_bytes, decoded_tx_size, &sui_facts);
    memset(tx_bytes, 0, sizeof(tx_bytes));

    if (parse_result == agent_q::SuiTransactionFactsResult::malformed) {
        write_rejected_method_result(id, "malformed_transaction", "Transaction bytes are malformed.");
        ESP_LOGI(kTag, "sui/sign_transaction malformed txBytes: id=%s", id);
        return;
    }
    if (parse_result != agent_q::SuiTransactionFactsResult::ok) {
        write_rejected_method_result(id, "unsupported_transaction", "Transaction shape is not supported.");
        ESP_LOGI(kTag, "sui/sign_transaction unsupported tx shape: id=%s result=%s",
                 id, agent_q::sui_transaction_facts_result_name(parse_result));
        return;
    }

    agent_q::AgentQTransactionFacts policy_facts = {};
    if (!agent_q::make_sui_transfer_policy_facts(sui_facts, network, &policy_facts)) {
        write_rejected_method_result(id, "unsupported_transaction", "Transaction shape is not supported.");
        ESP_LOGI(kTag, "sui/sign_transaction facts adapter rejected tx: id=%s", id);
        return;
    }

    const agent_q::AgentQPolicyProvider policy_provider = agent_q::active_policy_provider();
    const agent_q::AgentQPolicyDecision decision =
        agent_q::evaluate_agent_q_policy_runtime(policy_provider, policy_facts);
    if (decision.reason == agent_q::AgentQPolicyDecisionReason::invalid_policy) {
        write_rejected_method_result(id, "policy_error", "Active policy is unavailable.");
        ESP_LOGW(kTag, "sui/sign_transaction active policy unavailable: id=%s", id);
        return;
    }
    if (decision.action == agent_q::AgentQPolicyAction::reject) {
        write_rejected_method_result(id, "policy_rejected", "The request was rejected by device policy.");
        ESP_LOGI(kTag, "sui/sign_transaction policy rejected: id=%s reason=%s",
                 id, agent_q::agent_q_policy_decision_reason_name(decision.reason));
        return;
    }

    write_rejected_method_result(id, "policy_action_not_implemented", "Policy action is not implemented.");
    ESP_LOGW(kTag, "sui/sign_transaction policy action not implemented: id=%s action=%s reason=%s",
             id,
             agent_q::agent_q_policy_action_name(decision.action),
             agent_q::agent_q_policy_decision_reason_name(decision.reason));
}

void clear_active_session()
{
    g_session.clear();
}

bool persist_unprovisioned_state_for_local_reset()
{
    return persist_provisioning_state(ProvisioningRuntimeState::unprovisioned);
}

void enter_persistent_material_consistency_error(const char* message)
{
    g_persistent_material_consistency_error = true;
    clear_active_session();
    ESP_LOGE(kTag, "%s", message != nullptr ? message : "Persistent material consistency error; failing closed");
}

agent_q::AgentQLocalResetPersistenceOps local_reset_persistence_ops()
{
    return agent_q::AgentQLocalResetPersistenceOps{
        clear_active_session,
        persist_unprovisioned_state_for_local_reset,
        enter_persistent_material_consistency_error,
    };
}

void enter_persistent_material_consistency_error_if_material_remains(const char* message)
{
    if (agent_q::local_reset_persistent_material_exists()) {
        enter_persistent_material_consistency_error(message);
    }
}

bool ensure_active_policy_for_legacy_provisioned_state(agent_q::AgentQPolicyStoreStatus* policy_status)
{
    if (policy_status == nullptr) {
        return false;
    }
    if (*policy_status == agent_q::AgentQPolicyStoreStatus::active) {
        return true;
    }
    if (*policy_status != agent_q::AgentQPolicyStoreStatus::missing) {
        enter_persistent_material_consistency_error(
            "Existing provisioned material has invalid or unreadable active policy; failing closed");
        return false;
    }

    ESP_LOGW(kTag, "Provisioned state has root material but no active policy; installing default-reject policy");
    if (!agent_q::store_default_policy()) {
        enter_persistent_material_consistency_error(
            "Could not initialize active policy for existing provisioned material; failing closed");
        return false;
    }

    *policy_status = agent_q::active_policy_status();
    if (*policy_status != agent_q::AgentQPolicyStoreStatus::active) {
        enter_persistent_material_consistency_error(
            "Initialized active policy is unreadable for existing provisioned material; failing closed");
        return false;
    }
    return true;
}

// Writes the Sui Ed25519 account (index 0, m/44'/784'/0'/0'/0') response after
// account derivation has completed inside the account module. Returns false
// without writing when stored root material is unavailable or derivation fails,
// so the caller emits a single error response (no partial account).
bool write_accounts_response(const char* id)
{
    uint8_t public_key[agent_q::kSuiEd25519PublicKeyBytes] = {};
    char address[agent_q::kSuiAddressBufferSize] = {};
    const agent_q::SuiAccountDerivationResult account_result =
        agent_q::derive_sui_ed25519_account_from_stored_root(public_key, address, sizeof(address));
    if (account_result == agent_q::SuiAccountDerivationResult::root_material_unavailable) {
        // A provisioned device whose stored root material is no longer readable
        // is inconsistent. Fail closed so get_status reports "error" and
        // connect/get_accounts stop treating it as provisioned until a local
        // recovery/reset flow exists, instead of silently staying provisioned
        // until reboot.
        enter_persistent_material_consistency_error("Root material unreadable while provisioned; failing closed");
        return false;
    }
    if (account_result != agent_q::SuiAccountDerivationResult::ok) {
        return false;
    }

    // Raw 32-byte Ed25519 public key as base64 (44 chars + NUL). The scheme is
    // reported separately as keyScheme, matching Sui SDK getPublicKey().toBase64().
    char public_key_base64[48] = {};
    if (bytes_to_base64(public_key, sizeof(public_key), public_key_base64, sizeof(public_key_base64)) != 0) {
        return false;
    }

    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "accounts";
    JsonArray accounts = response["accounts"].to<JsonArray>();
    JsonObject account = accounts.add<JsonObject>();
    account["chain"] = "sui";
    account["address"] = address;
    account["publicKey"] = public_key_base64;
    account["keyScheme"] = "ed25519";
    account["derivationPath"] = "m/44'/784'/0'/0'/0'";
    write_json_document(response);
    return true;
}

bool fill_protocol_random(void* output, size_t size, const char* purpose)
{
    if (agent_q::fill_secure_random(output, size)) {
        return true;
    }

    ESP_LOGE(kTag, "Secure RNG unavailable for %s", purpose != nullptr ? purpose : "protocol random");
    return false;
}

bool format_session_id(char* output, size_t output_size)
{
    uint8_t bytes[8] = {};
    if (!fill_protocol_random(bytes, sizeof(bytes), "session id")) {
        return false;
    }
    snprintf(output,
             output_size,
             "session_%02x%02x%02x%02x%02x%02x%02x%02x",
             bytes[0],
             bytes[1],
             bytes[2],
             bytes[3],
             bytes[4],
             bytes[5],
             bytes[6],
             bytes[7]);
    agent_q::wipe_sensitive_buffer(bytes, sizeof(bytes));
    return true;
}

bool replace_active_session()
{
    char next_id[kSessionIdSize] = {};
    if (!format_session_id(next_id, sizeof(next_id))) {
        return false;
    }
    snprintf(g_session.id, sizeof(g_session.id), "%s", next_id);
    g_session.expiry = xTaskGetTickCount() + pdMS_TO_TICKS(kSessionTtlMs);
    return true;
}

void expire_session_if_needed()
{
    if (!tick_reached(g_session.next_expiry_check)) {
        return;
    }
    g_session.next_expiry_check = xTaskGetTickCount() + pdMS_TO_TICKS(kSessionExpiryCheckMs);

    if (!g_session.active()) {
        return;
    }
    if (tick_reached(g_session.expiry)) {
        clear_active_session();
    }
}

void poll_usb_host_connection()
{
    if (!tick_reached(g_next_usb_host_check)) {
        return;
    }
    g_next_usb_host_check = xTaskGetTickCount() + pdMS_TO_TICKS(kUsbHostLinkCheckMs);

    const bool connected = usb_serial_jtag_is_connected();
    if (!g_usb_host_connected_known) {
        g_usb_host_connected_known = true;
        g_usb_host_connected = connected;
        return;
    }
    if (connected == g_usb_host_connected) {
        return;
    }

    const bool was_connected = g_usb_host_connected;
    g_usb_host_connected = connected;
    if (!was_connected || connected) {
        return;
    }

    const bool had_session = g_session.active();
    const bool had_pending_connect = g_pending.active &&
                                     (g_pending.kind == PendingKind::connect ||
                                      g_pending.kind == PendingKind::connect_pin);
    const bool had_connect_pin =
        g_local_pin_auth.flow_active() &&
        g_local_pin_auth.purpose == LocalPinAuthPurpose::connect;

    clear_active_session();
    g_line_size = 0;
    if (had_pending_connect) {
        clear_pending_state();
    }
    if (had_connect_pin) {
        wipe_local_pin_auth_scratch("USB host link lost during connect PIN authorization");
    }

    bool clear_connect_panel = false;
    {
        LvglLockGuard lock;
        clear_connect_panel =
            g_ui.panel != nullptr &&
            (g_ui.panel_kind == AgentQUiPanelKind::decision_strip ||
             (had_connect_pin && g_ui.panel_kind == AgentQUiPanelKind::local_pin_auth));
    }
    if (clear_connect_panel) {
        clear_agent_q_panel();
    }

    if (had_session || had_pending_connect || had_connect_pin) {
        ESP_LOGW(kTag, "USB host SOF lost; active session and connect flow cleared");
    }
}

bool format_uuid_v4(char* output, size_t output_size)
{
    uint8_t bytes[16] = {};
    if (!fill_protocol_random(bytes, sizeof(bytes), "device id")) {
        return false;
    }
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    snprintf(output,
             output_size,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0],
             bytes[1],
             bytes[2],
             bytes[3],
             bytes[4],
             bytes[5],
             bytes[6],
             bytes[7],
             bytes[8],
             bytes[9],
             bytes[10],
             bytes[11],
             bytes[12],
             bytes[13],
             bytes[14],
             bytes[15]);
    agent_q::wipe_sensitive_buffer(bytes, sizeof(bytes));
    return true;
}

void load_or_create_device_id()
{
    g_device_id[0] = '\0';

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed for device id: %s", esp_err_to_name(result));
        if (!format_uuid_v4(g_device_id, sizeof(g_device_id))) {
            ESP_LOGE(kTag, "Could not create volatile device id");
        }
        return;
    }

    size_t length = sizeof(g_device_id);
    result = nvs_get_str(nvs, kDeviceIdKey, g_device_id, &length);
    if (result == ESP_OK && g_device_id[0] != '\0') {
        nvs_close(nvs);
        ESP_LOGI(kTag, "Loaded device id from NVS");
        return;
    }

    if (!format_uuid_v4(g_device_id, sizeof(g_device_id))) {
        ESP_LOGE(kTag, "Could not create device id");
        nvs_close(nvs);
        return;
    }
    result = nvs_set_str(nvs, kDeviceIdKey, g_device_id);
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS write failed for device id: %s", esp_err_to_name(result));
    } else {
        ESP_LOGI(kTag, "Created device id in NVS");
    }
    nvs_close(nvs);
}

void load_provisioning_state()
{
    g_provisioning_state = ProvisioningRuntimeState::unprovisioned;
    g_persistent_material_consistency_error = false;

    bool reset_marker_present = false;
    const agent_q::AgentQLocalResetCommitResult reset_result =
        agent_q::local_reset_resume_pending_if_needed(
            local_reset_persistence_ops(),
            &reset_marker_present);
    if (reset_marker_present) {
        ESP_LOGW(kTag, "Found pending local reset marker; resuming material wipe before loading state");
        if (reset_result == agent_q::AgentQLocalResetCommitResult::ok) {
            ESP_LOGW(kTag, "Pending local reset completed during boot");
        } else {
            enter_persistent_material_consistency_error(
                "Pending local reset could not be completed during boot; failing closed");
        }
        return;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed for provisioning state: %s", esp_err_to_name(result));
        enter_persistent_material_consistency_error("Provisioning state could not be opened; failing closed");
        return;
    }

    char stored_state[kProvisioningStateSize] = {};
    size_t length = sizeof(stored_state);
    result = nvs_get_str(nvs, kProvisioningStateKey, stored_state, &length);
    nvs_close(nvs);

    if (result == ESP_ERR_NVS_NOT_FOUND) {
        enter_persistent_material_consistency_error_if_material_remains(
            "Persistent setup material exists without provisioning state; failing closed");
        ESP_LOGI(kTag, "Provisioning state not found in NVS; using unprovisioned");
        return;
    }
    if (result != ESP_OK) {
        enter_persistent_material_consistency_error("Provisioning state could not be read; failing closed");
        ESP_LOGW(kTag, "NVS read failed for provisioning state: %s", esp_err_to_name(result));
        return;
    }

    ProvisioningRuntimeState parsed = ProvisioningRuntimeState::unprovisioned;
    if (!parse_provisioning_state(stored_state, &parsed)) {
        if (agent_q::local_reset_persistent_material_exists()) {
            enter_persistent_material_consistency_error(
                "Unknown provisioning state with persistent setup material present; failing closed");
        } else {
            ESP_LOGW(kTag, "Unknown provisioning state in NVS; resetting to unprovisioned");
            persist_provisioning_state(ProvisioningRuntimeState::unprovisioned);
        }
        return;
    }

    const bool has_root = agent_q::has_root_material();
    agent_q::AgentQPolicyStoreStatus policy_status = agent_q::active_policy_status();
    const agent_q::AgentQLocalAuthStatus local_auth_status = agent_q::local_auth_status();
    if (parsed == ProvisioningRuntimeState::provisioned) {
        if (has_root &&
            ensure_active_policy_for_legacy_provisioned_state(&policy_status) &&
            local_auth_status == agent_q::AgentQLocalAuthStatus::active) {
            g_provisioning_state = ProvisioningRuntimeState::provisioned;
        } else {
            g_provisioning_state = ProvisioningRuntimeState::unprovisioned;
            enter_persistent_material_consistency_error(
                "Stored provisioned state is missing root material, active policy, or local PIN verifier; failing closed");
        }
    } else if (has_root ||
               policy_status != agent_q::AgentQPolicyStoreStatus::missing ||
               local_auth_status != agent_q::AgentQLocalAuthStatus::missing) {
        g_provisioning_state = ProvisioningRuntimeState::unprovisioned;
        enter_persistent_material_consistency_error(
            "Persistent setup material exists without provisioned state; failing closed");
    } else if (parsed == ProvisioningRuntimeState::provisioning) {
        g_provisioning_state = ProvisioningRuntimeState::unprovisioned;
        ESP_LOGW(kTag, "Resetting legacy provisioning state for persistent root material flow");
        persist_provisioning_state(ProvisioningRuntimeState::unprovisioned);
    } else {
        g_provisioning_state = parsed;
    }
    ESP_LOGI(kTag, "Loaded provisioning state from NVS: %s", provisioning_state_to_string(g_provisioning_state));
}

bool persist_provisioning_state(ProvisioningRuntimeState next_state)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while saving provisioning state: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_set_str(nvs, kProvisioningStateKey, provisioning_state_to_string(next_state));
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS write failed for provisioning state: %s", esp_err_to_name(result));
        return false;
    }

    g_provisioning_state = next_state;
    ESP_LOGI(kTag, "Stored provisioning state: %s", provisioning_state_to_string(g_provisioning_state));
    return true;
}

bool local_setup_start_allowed()
{
    if (!refresh_persistent_material_consistency()) {
        return false;
    }

    return g_provisioning_state == ProvisioningRuntimeState::unprovisioned &&
           !g_persistent_material_consistency_error &&
           !g_provisioning_scratch.setup_flow_active() &&
           !g_local_pin_auth.flow_active() &&
           !g_pending.active;
}

bool agent_q_panel_active(AgentQUiPanelKind kind)
{
    LvglLockGuard lock;
    return g_ui.panel != nullptr &&
           g_ui.panel_kind == kind;
}

bool refresh_persistent_material_consistency()
{
    if (g_persistent_material_consistency_error) {
        return false;
    }

    const bool has_root = agent_q::has_root_material();
    const agent_q::AgentQPolicyStoreStatus policy_status = agent_q::active_policy_status();
    const agent_q::AgentQLocalAuthStatus local_auth_status = agent_q::local_auth_status();
    if (g_provisioning_state == ProvisioningRuntimeState::provisioned) {
        if (has_root &&
            policy_status == agent_q::AgentQPolicyStoreStatus::active &&
            local_auth_status == agent_q::AgentQLocalAuthStatus::active) {
            return true;
        }
        enter_persistent_material_consistency_error(
            "Provisioned state lost root material, active policy, or local PIN verifier; failing closed");
        return false;
    }

    if (has_root ||
        policy_status != agent_q::AgentQPolicyStoreStatus::missing ||
        local_auth_status != agent_q::AgentQLocalAuthStatus::missing) {
        enter_persistent_material_consistency_error(
            "Persistent setup material exists outside provisioned state; failing closed");
        return false;
    }
    return true;
}

bool provisioned_material_ready()
{
    return g_provisioning_state == ProvisioningRuntimeState::provisioned &&
           refresh_persistent_material_consistency();
}

bool agent_q_ui_idle_for_local_settings()
{
    LvglLockGuard lock;
    return g_ui.panel == nullptr && g_ui.speech_mode == AgentQUiMode::none;
}

bool local_settings_touch_entry_candidate_allowed()
{
    return g_provisioning_state == ProvisioningRuntimeState::provisioned &&
           !g_persistent_material_consistency_error &&
           !g_pending.active &&
           !g_identification.active &&
           !g_provisioning_scratch.setup_flow_active() &&
           !g_local_pin_auth.flow_active() &&
           !agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active &&
           agent_q_ui_idle_for_local_settings();
}

bool write_busy_if_pending_or_local_flow_active(const char* id)
{
    if (g_pending.active) {
        write_error_response(id, "busy", "Device is awaiting local input.");
        return true;
    }
    if (g_provisioning_scratch.setup_flow_active()) {
        write_error_response(id, "busy", "Device is showing setup material.");
        return true;
    }
    if (agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active) {
        write_error_response(id, "busy", "Device is showing local reset UI.");
        return true;
    }
    if (g_local_pin_auth.flow_active()) {
        write_error_response(id, "busy", "Device is showing local PIN UI.");
        return true;
    }
    return false;
}

bool require_active_matching_session(const char* id, const char* session_id)
{
    if (!is_safe_session_id(session_id)) {
        write_error_response(id, "invalid_session", "Invalid sessionId.");
        return false;
    }
    if (!g_session.active()) {
        clear_active_session();
        write_error_response(id, "invalid_session", "Session is unknown or already ended.");
        return false;
    }
    if (tick_reached(g_session.expiry)) {
        clear_active_session();
        write_error_response(id, "invalid_session", "Session is unknown or already ended.");
        return false;
    }
    if (strcmp(session_id, g_session.id) != 0) {
        write_error_response(id, "invalid_session", "Session is unknown or already ended.");
        return false;
    }
    return true;
}

bool recovery_phrase_backup_confirmation_ready()
{
    return g_provisioning_scratch.setup_stage == SetupScratchStage::recovery_phrase_displayed;
}

void enqueue_pending_choice(PendingChoice choice)
{
    if (choice == PendingChoice::none || g_pending_choice_queue == nullptr) {
        return;
    }
    if (xQueueSend(g_pending_choice_queue, &choice, 0) != pdTRUE) {
        ESP_LOGW(kTag, "Pending choice queue is full");
    }
}

void enqueue_ui_event(AgentQUiEventKind kind, AgentQUiPanelKind panel_kind = AgentQUiPanelKind::none)
{
    if (g_ui_event_queue == nullptr) {
        return;
    }

    AgentQUiEvent event;
    event.kind = kind;
    event.panel_kind = panel_kind;
    if (xQueueSend(g_ui_event_queue, &event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_yes_clicked(lv_event_t*)
{
    enqueue_pending_choice(PendingChoice::yes);
}

void on_no_clicked(lv_event_t*)
{
    enqueue_pending_choice(PendingChoice::no);
}

void on_setup_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::setup_requested);
}

void on_setup_generate_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::setup_generate_requested);
}

void on_setup_recover_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::setup_recover_requested);
}

void on_setup_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::setup_cancel_requested);
}

void on_settings_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::settings_cancel_requested);
}

void on_settings_reset_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::settings_reset_requested);
}

void on_settings_connect_pin_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::settings_connect_pin_requested);
}

void on_reset_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::reset_cancel_requested);
}

void on_recovery_phrase_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::recovery_phrase_cancel_requested);
}

void on_recovery_phrase_confirm_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::recovery_phrase_confirm_requested);
}

void on_pin_digit_clicked(lv_event_t* event)
{
    const char* digit = static_cast<const char*>(lv_event_get_user_data(event));
    if (digit == nullptr || digit[0] < '0' || digit[0] > '9') {
        return;
    }
    if (g_ui_event_queue == nullptr) {
        return;
    }

    AgentQUiEvent ui_event;
    ui_event.kind = AgentQUiEventKind::pin_digit_requested;
    ui_event.digit = digit[0];
    if (xQueueSend(g_ui_event_queue, &ui_event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_pin_clear_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::pin_clear_requested);
}

void on_pin_backspace_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::pin_backspace_requested);
}

void on_pin_submit_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::pin_submit_requested);
}

void on_pin_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::pin_cancel_requested);
}

void on_recover_slot_clicked(lv_event_t* event)
{
    const uint8_t* slot = static_cast<const uint8_t*>(lv_event_get_user_data(event));
    if (slot == nullptr || *slot >= kRecoverWordsPerPage || g_ui_event_queue == nullptr) {
        return;
    }

    AgentQUiEvent ui_event;
    ui_event.kind = AgentQUiEventKind::recover_slot_requested;
    ui_event.slot = *slot;
    if (xQueueSend(g_ui_event_queue, &ui_event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_recover_letter_clicked(lv_event_t* event)
{
    const char* letter = static_cast<const char*>(lv_event_get_user_data(event));
    if (letter == nullptr || letter[0] < 'a' || letter[0] > 'z' || g_ui_event_queue == nullptr) {
        return;
    }

    AgentQUiEvent ui_event;
    ui_event.kind = AgentQUiEventKind::recover_letter_requested;
    ui_event.letter = letter[0];
    if (xQueueSend(g_ui_event_queue, &ui_event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_recover_candidate_clicked(lv_event_t* event)
{
    const uint16_t* word_index = static_cast<const uint16_t*>(lv_event_get_user_data(event));
    if (word_index == nullptr || *word_index >= agent_q::kBip39WordCount ||
        g_ui_event_queue == nullptr) {
        return;
    }

    AgentQUiEvent ui_event;
    ui_event.kind = AgentQUiEventKind::recover_candidate_requested;
    ui_event.word_index = *word_index;
    if (xQueueSend(g_ui_event_queue, &ui_event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_recover_clear_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::recover_clear_requested);
}

void on_recover_previous_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::recover_previous_requested);
}

void on_recover_next_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::recover_next_requested);
}

void on_recover_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::recover_cancel_requested);
}

void clear_agent_q_avatar_ui();

bool make_button_label_with_font(
    lv_obj_t* button,
    const char* text,
    const lv_font_t* font,
    lv_event_cb_t callback,
    void* user_data = nullptr)
{
    lv_obj_t* label = lv_label_create(button);
    if (label == nullptr) {
        return false;
    }
    lv_obj_remove_style_all(label);
    lv_label_set_text(label, text);
    lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_CLIP);
    lv_obj_remove_flag(label, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(label, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_text_font(label, font, 0);
    lv_obj_set_style_text_color(label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
    lv_obj_center(label);
    lv_obj_add_flag(label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(label, callback, LV_EVENT_CLICKED, user_data);
    return true;
}

void make_decision_button_corner_fill(lv_obj_t* button, lv_align_t align, lv_color_t color, lv_event_cb_t callback)
{
    lv_obj_t* fill = lv_obj_create(button);
    lv_obj_remove_style_all(fill);
    lv_obj_set_size(fill, kDecisionCornerRadius, kDecisionCornerRadius);
    lv_obj_align(fill, align, 0, 0);
    lv_obj_set_style_bg_color(fill, color, 0);
    lv_obj_set_style_bg_opa(fill, LV_OPA_COVER, 0);
    lv_obj_add_flag(fill, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(fill, callback, LV_EVENT_CLICKED, nullptr);
}

void make_decision_button(lv_obj_t* parent, const char* text, int x, lv_color_t color, lv_event_cb_t callback)
{
    // A plain clickable object avoids themed button shadows/scrollbars that can
    // show up as stray vertical lines over the avatar.
    lv_obj_t* button = lv_obj_create(parent);
    lv_obj_remove_style_all(button);
    lv_obj_set_size(button, kDecisionButtonWidth, kDecisionStripHeight);
    lv_obj_align(button, LV_ALIGN_TOP_LEFT, x, 0);
    lv_obj_add_flag(button, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_remove_flag(button, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(button, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_radius(button, kDecisionCornerRadius, 0);
    lv_obj_set_style_border_width(button, 0, 0);
    lv_obj_set_style_outline_width(button, 0, 0);
    lv_obj_set_style_shadow_width(button, 0, 0);
    lv_obj_set_style_pad_all(button, 0, 0);
    lv_obj_set_style_bg_color(button, color, 0);
    lv_obj_set_style_bg_opa(button, LV_OPA_COVER, 0);
    lv_obj_add_event_cb(button, callback, LV_EVENT_CLICKED, nullptr);
    if (x == 0) {
        make_decision_button_corner_fill(button, LV_ALIGN_TOP_RIGHT, color, callback);
        make_decision_button_corner_fill(button, LV_ALIGN_BOTTOM_LEFT, color, callback);
        make_decision_button_corner_fill(button, LV_ALIGN_BOTTOM_RIGHT, color, callback);
    } else {
        make_decision_button_corner_fill(button, LV_ALIGN_TOP_LEFT, color, callback);
        make_decision_button_corner_fill(button, LV_ALIGN_BOTTOM_LEFT, color, callback);
        make_decision_button_corner_fill(button, LV_ALIGN_BOTTOM_RIGHT, color, callback);
    }
    make_button_label_with_font(button, text, &lv_font_montserrat_14, callback);
}

bool make_setup_button(
    lv_obj_t* parent,
    const char* text,
    int x,
    int y,
    int width,
    int height,
    SetupButtonKind kind,
    lv_color_t color,
    lv_event_cb_t callback,
    const void* user_data = nullptr,
    bool enabled = true)
{
    lv_obj_t* button = lv_obj_create(parent);
    if (button == nullptr) {
        return false;
    }

    lv_obj_remove_style_all(button);
    lv_obj_set_size(button, width, height);
    lv_obj_align(button, LV_ALIGN_TOP_LEFT, x, y);
    lv_obj_remove_flag(button, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(button, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_outline_width(button, 0, 0);
    lv_obj_set_style_shadow_width(button, 0, 0);
    lv_obj_set_style_pad_all(button, 0, 0);
    lv_obj_set_style_bg_color(button, color, 0);

    lv_color_t label_color = color;
    if (kind == SetupButtonKind::solid_action) {
        lv_obj_set_style_radius(button, kRecoveryPhraseButtonRadius, 0);
        lv_obj_set_style_border_width(button, 0, 0);
        lv_obj_set_style_bg_opa(button, enabled ? LV_OPA_COVER : LV_OPA_40, 0);
        label_color = lv_color_hex(enabled ? 0xFFFFFF : kDisabledActionTextColor);
        if (enabled) {
            lv_obj_set_style_bg_opa(button, LV_OPA_80, LV_STATE_PRESSED);
        }
    } else {
        lv_obj_set_style_radius(button, kPinPanelButtonRadius, 0);
        lv_obj_set_style_border_width(button, 1, 0);
        lv_obj_set_style_border_color(button, lv_color_hex(kSetupCellBorderColor), 0);
        lv_obj_set_style_bg_opa(button, LV_OPA_TRANSP, 0);
        label_color = enabled ? color : lv_color_hex(kDisabledControlTextColor);
        if (enabled) {
            lv_obj_set_style_bg_color(button, color, LV_STATE_PRESSED);
            lv_obj_set_style_bg_opa(button, LV_OPA_30, LV_STATE_PRESSED);
        }
    }

    void* callback_data = const_cast<void*>(user_data);
    if (enabled) {
        lv_obj_add_flag(button, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(button, callback, LV_EVENT_CLICKED, callback_data);
    }

    lv_obj_t* label = lv_label_create(button);
    if (label == nullptr) {
        return false;
    }
    lv_obj_remove_style_all(label);
    lv_label_set_text(label, text);
    lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_CLIP);
    lv_obj_remove_flag(label, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(label, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_width(label, width);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(label, label_color, 0);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
    if (enabled && kind == SetupButtonKind::outlined_keypad) {
        lv_obj_set_style_radius(label, kPinPanelButtonRadius, LV_STATE_PRESSED);
        lv_obj_set_style_bg_color(label, color, LV_STATE_PRESSED);
        lv_obj_set_style_bg_opa(label, LV_OPA_30, LV_STATE_PRESSED);
    }
    lv_obj_center(label);
    if (enabled) {
        lv_obj_add_flag(label, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(label, callback, LV_EVENT_CLICKED, callback_data);
    }
    return true;
}

bool make_pin_keypad_buttons(lv_obj_t* parent, bool buttons_enabled)
{
    static const char* const kDigits[10] = {
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    };

    for (int digit = 1; digit <= 9; ++digit) {
        const int index = digit - 1;
        const int column = index % 3;
        const int row = index / 3;
        if (!make_setup_button(
                parent,
                kDigits[digit],
                kPinKeypadGridLeft + column * kPinKeypadButtonWidth,
                kPinKeypadGridTop + row * kPinKeypadRowHeight,
                kPinKeypadButtonWidth,
                kPinPanelButtonHeight,
                SetupButtonKind::outlined_keypad,
                lv_color_hex(kSetupInputPressedColor),
                on_pin_digit_clicked,
                kDigits[digit],
                buttons_enabled)) {
            return false;
        }
    }

    return make_setup_button(
               parent,
               "Clear",
               kPinKeypadGridLeft,
               kPinKeypadGridTop + 3 * kPinKeypadRowHeight,
               kPinKeypadButtonWidth,
               kPinPanelButtonHeight,
               SetupButtonKind::outlined_keypad,
               lv_color_hex(0x667085),
               on_pin_clear_clicked,
               nullptr,
               buttons_enabled) &&
           make_setup_button(
               parent,
               kDigits[0],
               kPinKeypadGridLeft + kPinKeypadButtonWidth,
               kPinKeypadGridTop + 3 * kPinKeypadRowHeight,
               kPinKeypadButtonWidth,
               kPinPanelButtonHeight,
               SetupButtonKind::outlined_keypad,
               lv_color_hex(kSetupInputPressedColor),
               on_pin_digit_clicked,
               kDigits[0],
               buttons_enabled) &&
           make_setup_button(
               parent,
               LV_SYMBOL_BACKSPACE,
               kPinKeypadGridLeft + 2 * kPinKeypadButtonWidth,
               kPinKeypadGridTop + 3 * kPinKeypadRowHeight,
               kPinKeypadButtonWidth,
               kPinPanelButtonHeight,
               SetupButtonKind::outlined_keypad,
               lv_color_hex(0x667085),
               on_pin_backspace_clicked,
               nullptr,
               buttons_enabled);
}

bool make_settings_row_label(lv_obj_t* parent, const char* text, int y)
{
    lv_obj_t* label = lv_label_create(parent);
    if (label == nullptr) {
        return false;
    }
    lv_label_set_text(label, text);
    lv_label_set_long_mode(label, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(label, kSettingsMenuRowControlX - kSettingsMenuRowLabelX - 8);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(label, lv_color_hex(0x063A1D), 0);
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, kSettingsMenuRowLabelX, y + 4);
    return true;
}

void rotate_processing_arc(void* obj, int32_t rotation)
{
    lv_arc_set_rotation(static_cast<lv_obj_t*>(obj), rotation);
}

bool make_pin_processing_overlay(lv_obj_t* parent)
{
    lv_obj_t* blocker = lv_obj_create(parent);
    if (blocker == nullptr) {
        return false;
    }

    lv_obj_remove_style_all(blocker);
    lv_obj_set_size(blocker, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(blocker, LV_ALIGN_TOP_LEFT, 0, 0);
    lv_obj_remove_flag(blocker, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(blocker, LV_SCROLLBAR_MODE_OFF);
    lv_obj_add_flag(blocker, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_bg_opa(blocker, LV_OPA_TRANSP, 0);

    lv_obj_t* card = lv_obj_create(blocker);
    if (card == nullptr) {
        lv_obj_delete(blocker);
        return false;
    }

    lv_obj_remove_style_all(card);
    lv_obj_set_size(card, kPinProcessingOverlaySize, kPinProcessingOverlaySize);
    lv_obj_align(card, LV_ALIGN_TOP_LEFT, kPinProcessingOverlayX, kPinProcessingOverlayY);
    lv_obj_remove_flag(card, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(card, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_radius(card, kPinPanelButtonRadius, 0);
    lv_obj_set_style_border_width(card, 0, 0);
    lv_obj_set_style_bg_color(card, lv_color_hex(0x667085), 0);
    lv_obj_set_style_bg_opa(card, LV_OPA_40, 0);

#if LV_USE_ARC
    lv_obj_t* spinner = lv_arc_create(card);
    if (spinner == nullptr) {
        lv_obj_delete(blocker);
        return false;
    }

    lv_obj_remove_style(spinner, nullptr, LV_PART_KNOB);
    lv_obj_remove_flag(spinner, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_size(spinner, kPinProcessingSpinnerSize, kPinProcessingSpinnerSize);
    lv_arc_set_bg_angles(spinner, 0, 360);
    lv_arc_set_angles(spinner, 0, kPinProcessingArcDegrees);
    lv_arc_set_rotation(spinner, 270);
    lv_obj_set_style_arc_width(spinner, 4, LV_PART_MAIN);
    lv_obj_set_style_arc_width(spinner, 4, LV_PART_INDICATOR);
    lv_obj_set_style_arc_color(spinner, lv_color_hex(0xD0D5DD), LV_PART_MAIN);
    lv_obj_set_style_arc_color(spinner, lv_color_hex(0x24875A), LV_PART_INDICATOR);
    lv_obj_center(spinner);

    lv_anim_t animation;
    lv_anim_init(&animation);
    lv_anim_set_var(&animation, spinner);
    lv_anim_set_values(&animation, 0, 360);
    lv_anim_set_duration(&animation, kPinProcessingSpinMs);
    lv_anim_set_repeat_count(&animation, LV_ANIM_REPEAT_INFINITE);
    lv_anim_set_path_cb(&animation, lv_anim_path_linear);
    lv_anim_set_exec_cb(&animation, rotate_processing_arc);
    lv_anim_start(&animation);
#else
    lv_obj_t* loading = lv_label_create(card);
    if (loading != nullptr) {
        lv_label_set_text(loading, "...");
        lv_obj_set_style_text_font(loading, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(loading, lv_color_hex(0xFFFFFF), 0);
        lv_obj_center(loading);
    }
#endif

    lv_obj_move_foreground(blocker);
    return true;
}

bool make_pin_processing_overlay_on_current_panel(AgentQUiPanelKind expected_kind)
{
    LvglLockGuard lock;
    if (g_ui.panel == nullptr || g_ui.panel_kind != expected_kind) {
        return false;
    }
    return make_pin_processing_overlay(g_ui.panel);
}

void on_agent_q_panel_deleted(lv_event_t* event)
{
    lv_obj_t* target = static_cast<lv_obj_t*>(lv_event_get_target(event));
    if (g_ui.panel == target) {
        const AgentQUiPanelKind deleted_kind = g_ui.panel_kind;
        ESP_LOGW(kTag, "Agent-Q panel was deleted by external UI state");
        g_ui.panel = nullptr;
        g_ui.panel_kind = AgentQUiPanelKind::none;
        enqueue_ui_event(AgentQUiEventKind::panel_deleted, deleted_kind);
    }
}

void register_agent_q_panel_locked(AgentQUiPanelKind kind)
{
    g_ui.panel_kind = kind;
    lv_obj_add_flag(g_ui.panel, LV_OBJ_FLAG_FLOATING);
    lv_obj_add_event_cb(g_ui.panel, on_agent_q_panel_deleted, LV_EVENT_DELETE, nullptr);
}

enum class SensitiveUiClearPolicy {
    wipe,
    preserve,
};

void clear_panel_locked(SensitiveUiClearPolicy policy)
{
    if (g_ui.panel != nullptr) {
        lv_obj_t* panel = g_ui.panel;
        const AgentQUiPanelKind panel_kind = g_ui.panel_kind;
        g_ui.panel = nullptr;
        g_ui.panel_kind = AgentQUiPanelKind::none;
        const bool wipe_setup_after_delete =
            policy == SensitiveUiClearPolicy::wipe &&
            (panel_kind == AgentQUiPanelKind::setup_choice ||
             panel_kind == AgentQUiPanelKind::recovery_phrase_display ||
             panel_kind == AgentQUiPanelKind::recovery_word_entry ||
             panel_kind == AgentQUiPanelKind::pin_entry);
        const bool wipe_reset_after_delete =
            policy == SensitiveUiClearPolicy::wipe &&
            local_reset_panel_matches_stage(panel_kind);
        const bool wipe_local_pin_auth_after_delete =
            policy == SensitiveUiClearPolicy::wipe &&
            local_pin_auth_panel_matches_stage(panel_kind);
        lv_obj_delete(panel);
        if (wipe_setup_after_delete) {
            wipe_setup_scratch("sensitive setup panel cleared");
        }
        if (wipe_reset_after_delete) {
            wipe_local_reset_scratch("local reset panel cleared");
        }
        if (wipe_local_pin_auth_after_delete) {
            wipe_local_pin_auth_scratch("local PIN authorization panel cleared");
        }
    } else {
        g_ui.panel_kind = AgentQUiPanelKind::none;
    }
}

struct AgentQMessagePresentation {
    lv_color_t background;
    lv_color_t foreground;
    stackchan::avatar::Emotion emotion;
    bool lift_head;
};

AgentQMessagePresentation agent_q_message_presentation(AgentQMessageKind kind)
{
    switch (kind) {
        case AgentQMessageKind::approval:
            return {
                lv_color_hex(0xFFD166), lv_color_hex(0x3A2B00), stackchan::avatar::Emotion::Neutral, true};
        case AgentQMessageKind::success:
            return {
                lv_color_hex(0x7DE2A6), lv_color_hex(0x063A1D), stackchan::avatar::Emotion::Happy, true};
        case AgentQMessageKind::rejected:
            return {
                lv_color_hex(0xF28B82), lv_color_hex(0x3C0505), stackchan::avatar::Emotion::Sad, false};
        case AgentQMessageKind::timeout:
            return {
                lv_color_hex(0xD0D5DD), lv_color_hex(0x2B2D33), stackchan::avatar::Emotion::Sleepy, false};
        case AgentQMessageKind::error:
            return {
                lv_color_hex(0xE25B5B), lv_color_hex(0xFFFFFF), stackchan::avatar::Emotion::Angry, false};
        case AgentQMessageKind::info:
        default:
            return {
                lv_color_hex(0x91D8FF), lv_color_hex(0x05324A), stackchan::avatar::Emotion::Doubt, true};
    }
}

void clear_agent_q_avatar_ui()
{
    if (g_ui.speech_avatar == nullptr) {
        g_ui.speech_mode = AgentQUiMode::none;
        g_ui.speech_decorator_id = -1;
        g_ui.message_deadline = 0;
        return;
    }

    auto* speech_avatar = g_ui.speech_avatar;
    LvglLockGuard lock;
    if (GetStackChan().hasAvatar()) {
        auto& current_avatar = GetStackChan().avatar();
        if (&current_avatar == speech_avatar) {
            if (g_ui.speech_decorator_id >= 0) {
                current_avatar.removeDecorator(g_ui.speech_decorator_id);
            }
            if (g_ui.owns_emotion) {
                current_avatar.setEmotion(g_ui.previous_emotion);
            }
        } else {
            ESP_LOGI(kTag, "Agent-Q avatar owner changed; dropping stale UI owner");
        }
    }
    g_ui.speech_avatar = nullptr;
    g_ui.speech_decorator_id = -1;
    g_ui.speech_mode = AgentQUiMode::none;
    g_ui.owns_emotion = false;
    g_ui.message_deadline = 0;
}

bool show_agent_q_message(
    const char* message,
    AgentQMessageKind kind,
    AgentQUiMode mode,
    uint32_t duration_ms,
    lv_event_cb_t click_callback = nullptr)
{
    clear_agent_q_avatar_ui();
    const AgentQMessagePresentation presentation = agent_q_message_presentation(kind);

    LvglLockGuard lock;
    agent_q::request_display_power_wake();
    if (!GetStackChan().hasAvatar()) {
        return false;
    }
    auto& avatar = GetStackChan().avatar();
    g_ui.previous_emotion = avatar.getEmotion();
    g_ui.owns_emotion = true;
    avatar.setEmotion(presentation.emotion);
    g_ui.speech_decorator_id = avatar.addDecorator(std::make_unique<agent_q::AgentQSpeechBubbleDecorator>(
        lv_screen_active(),
        message != nullptr && message[0] != '\0' ? message : "Agent-Q",
        presentation.background,
        presentation.foreground,
        click_callback));
    if (presentation.lift_head) {
        agent_q::play_motion_feedback(agent_q::AgentQMotionFeedbackState::head_lift);
    }
    g_ui.speech_avatar = &avatar;
    g_ui.speech_mode = mode;
    g_ui.message_deadline = duration_ms > 0 ? xTaskGetTickCount() + pdMS_TO_TICKS(duration_ms) : 0;
    return g_ui.speech_decorator_id >= 0;
}

bool provisioning_welcome_available()
{
    bool ui_display_idle = false;
    {
        LvglLockGuard lock;
        ui_display_idle = g_ui.panel == nullptr && g_ui.speech_mode == AgentQUiMode::none;
    }

    return g_provisioning_state == ProvisioningRuntimeState::unprovisioned &&
           !g_persistent_material_consistency_error &&
           !g_pending.active &&
           !g_identification.active &&
           !g_provisioning_scratch.setup_flow_active() &&
           !g_local_pin_auth.flow_active() &&
           !agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active &&
           ui_display_idle;
}

void show_provisioning_welcome_if_available()
{
    if (!provisioning_welcome_available()) {
        return;
    }

    show_agent_q_message(
        "Set up Agent-Q", AgentQMessageKind::info, AgentQUiMode::identification, 0, on_setup_clicked);
}

void clear_agent_q_panel()
{
    LvglLockGuard lock;
    clear_panel_locked(SensitiveUiClearPolicy::wipe);
}

void clear_agent_q_request_ui()
{
    clear_agent_q_avatar_ui();
    clear_agent_q_panel();
}

void show_decision_panel()
{
    g_identification.clear();

    {
        LvglLockGuard lock;
        clear_panel_locked(SensitiveUiClearPolicy::wipe);

        g_ui.panel = lv_obj_create(lv_screen_active());
        register_agent_q_panel_locked(AgentQUiPanelKind::decision_strip);
        lv_obj_remove_style_all(g_ui.panel);
        lv_obj_set_size(g_ui.panel, kScreenWidth, kDecisionPanelHeight);
        lv_obj_align(g_ui.panel, LV_ALIGN_BOTTOM_MID, 0, 0);
        lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
        lv_obj_set_scrollbar_mode(g_ui.panel, LV_SCROLLBAR_MODE_OFF);
        lv_obj_set_style_radius(g_ui.panel, 0, 0);
        lv_obj_set_style_clip_corner(g_ui.panel, true, 0);
        lv_obj_set_style_border_width(g_ui.panel, 0, 0);
        lv_obj_set_style_outline_width(g_ui.panel, 0, 0);
        lv_obj_set_style_shadow_width(g_ui.panel, 0, 0);
        lv_obj_set_style_bg_opa(g_ui.panel, LV_OPA_TRANSP, 0);
        lv_obj_set_style_pad_all(g_ui.panel, 0, 0);

        make_decision_button(g_ui.panel, "Cancel", 0, lv_color_hex(0xA53B3B), on_no_clicked);
        make_decision_button(g_ui.panel, "Confirm", kDecisionButtonWidth, lv_color_hex(0x24875A), on_yes_clicked);

        lv_obj_move_foreground(g_ui.panel);
    }
}

void show_identification_code(const char* code, uint32_t duration_ms)
{
    clear_agent_q_request_ui();
    g_identification.begin(code, duration_ms);

    char message[40];
    snprintf(message, sizeof(message), "Device code: %s", code);
    if (!show_agent_q_message(message, AgentQMessageKind::info, AgentQUiMode::identification, duration_ms)) {
        ESP_LOGW(kTag, "identify_device could not show Agent-Q speech bubble");
    }
}

void clear_identification_if_needed()
{
    if (!g_identification.active || g_identification.deadline == 0 ||
        !tick_reached(g_identification.deadline)) {
        return;
    }

    clear_agent_q_request_ui();
    g_identification.clear();
    show_provisioning_welcome_if_available();
}

void clear_agent_q_message_if_needed()
{
    if (g_ui.message_deadline == 0 || !tick_reached(g_ui.message_deadline)) {
        return;
    }
    clear_agent_q_avatar_ui();
    show_provisioning_welcome_if_available();
}

bool show_avatar_decision(const char* message)
{
    if (!show_agent_q_message(message, AgentQMessageKind::approval, AgentQUiMode::decision, 0)) {
        return false;
    }
    show_decision_panel();
    return true;
}

void clear_pending_state()
{
    g_pending.clear();
    g_identification.clear();
}

void show_result_and_clear_pending(const char* message, AgentQMessageKind kind)
{
    clear_agent_q_panel();
    show_agent_q_message(message, kind, AgentQUiMode::result, kAgentQResultDisplayMs);
    clear_pending_state();
}

void format_connect_message(const char* gateway_name, char* output, size_t output_size)
{
    if (gateway_name == nullptr || gateway_name[0] == '\0') {
        gateway_name = "Agent-Q Gateway";
    }
    snprintf(output, output_size, "Connect %s?", gateway_name);
}

void show_connect_decision(const char* gateway_name)
{
    char message[kConnectDisplayMessageSize];
    format_connect_message(gateway_name, message, sizeof(message));
    if (show_avatar_decision(message)) {
        return;
    }
    ESP_LOGW(kTag, "connect could not show Agent-Q avatar decision UI");
}

enum class SetupCommitResult {
    ok,
    missing_scratch,
    root_storage_error,
    policy_storage_error,
    local_auth_storage_error,
    state_storage_error,
};

void rollback_persistent_setup_material_after_failed_commit()
{
    agent_q::wipe_local_auth();
    agent_q::wipe_policy();
    agent_q::wipe_root_material();
}

SetupCommitResult commit_setup_material_after_pin_match(const char* pin, const char* reason)
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::pin_committing ||
        !agent_q::is_valid_local_pin(pin)) {
        return SetupCommitResult::missing_scratch;
    }

    if (!agent_q::store_root_material(
            g_provisioning_scratch.root_material,
            sizeof(g_provisioning_scratch.root_material))) {
        rollback_persistent_setup_material_after_failed_commit();
        enter_persistent_material_consistency_error_if_material_remains(
            "Root material storage left partial persistent setup material; failing closed");
        wipe_setup_scratch(reason);
        return SetupCommitResult::root_storage_error;
    }

    if (!agent_q::store_default_policy()) {
        rollback_persistent_setup_material_after_failed_commit();
        enter_persistent_material_consistency_error_if_material_remains(
            "Policy storage failed with persistent setup material present; failing closed");
        wipe_setup_scratch(reason);
        return SetupCommitResult::policy_storage_error;
    }

    if (!agent_q::store_local_pin_verifier(pin)) {
        rollback_persistent_setup_material_after_failed_commit();
        enter_persistent_material_consistency_error_if_material_remains(
            "Local PIN verifier storage failed with persistent setup material present; failing closed");
        wipe_setup_scratch(reason);
        return SetupCommitResult::local_auth_storage_error;
    }

    if (!persist_provisioning_state(ProvisioningRuntimeState::provisioned)) {
        rollback_persistent_setup_material_after_failed_commit();
        enter_persistent_material_consistency_error_if_material_remains(
            "Provisioning state storage failed with persistent setup material present; failing closed");
        wipe_setup_scratch(reason);
        return SetupCommitResult::state_storage_error;
    }

    g_persistent_material_consistency_error = false;
    wipe_setup_scratch(reason);
    return SetupCommitResult::ok;
}

bool show_setup_choice_panel()
{
    clear_agent_q_avatar_ui();

    LvglLockGuard lock;
    agent_q::request_display_power_wake();
    clear_panel_locked(SensitiveUiClearPolicy::preserve);

    g_ui.panel = lv_obj_create(lv_screen_active());
    if (g_ui.panel == nullptr) {
        g_ui.panel_kind = AgentQUiPanelKind::none;
        return false;
    }
    register_agent_q_panel_locked(AgentQUiPanelKind::setup_choice);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(g_ui.panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(g_ui.panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(g_ui.panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(g_ui.panel, 8, 0);
    lv_obj_set_style_border_width(g_ui.panel, 0, 0);
    lv_obj_set_style_bg_color(g_ui.panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(g_ui.panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(g_ui.panel, 0, 0);

    lv_obj_t* title = lv_label_create(g_ui.panel);
    if (title == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(title, "Set up Agent-Q");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 24);

    if (!make_setup_button(
            g_ui.panel,
            "Generate",
            kSettingsMenuButtonCenterX,
            kSetupMenuGenerateButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x24875A),
            on_setup_generate_clicked) ||
        !make_setup_button(
            g_ui.panel,
            "Recover",
            kSettingsMenuButtonCenterX,
            kSetupMenuRecoverButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x1D4ED8),
            on_setup_recover_clicked) ||
        !make_setup_button(
            g_ui.panel,
            "Cancel",
            kSettingsMenuButtonCenterX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x667085),
            on_setup_cancel_clicked)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    lv_obj_move_foreground(g_ui.panel);
    return true;
}

bool make_recover_word_cell(lv_obj_t* parent, uint8_t slot)
{
    static const uint8_t kSlotUserData[kRecoverWordsPerPage] = {0, 1, 2};
    if (slot >= kRecoverWordsPerPage) {
        return false;
    }

    const size_t global_slot =
        recover_global_word_slot_for(g_provisioning_scratch.recover_page, slot);
    if (global_slot >= agent_q::kBip39MnemonicWordCount) {
        return false;
    }

    lv_obj_t* cell = lv_obj_create(parent);
    if (cell == nullptr) {
        return false;
    }
    lv_obj_remove_flag(cell, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_size(cell, kMnemonicWordCellWidth, kMnemonicWordCellHeight);
    lv_obj_align(
        cell,
        LV_ALIGN_TOP_LEFT,
        kMnemonicWordCellLeft + static_cast<int>(slot) * kMnemonicWordCellWidth,
        kRecoverWordCellTop);
    lv_obj_set_style_radius(cell, 4, 0);
    lv_obj_set_style_border_width(cell, 1, 0);
    lv_obj_set_style_border_color(cell, lv_color_hex(kSetupCellBorderColor), 0);
    lv_obj_set_style_bg_color(cell, lv_color_hex(
        slot == g_provisioning_scratch.recover_active_slot ? 0xE9F8EF : 0xFFFFFF), 0);
    lv_obj_set_style_bg_opa(cell, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_color(cell, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
    lv_obj_set_style_bg_opa(cell, LV_OPA_30, LV_STATE_PRESSED);
    lv_obj_set_style_pad_all(cell, 0, 0);
    lv_obj_add_flag(cell, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(
        cell,
        on_recover_slot_clicked,
        LV_EVENT_CLICKED,
        const_cast<uint8_t*>(&kSlotUserData[slot]));

    lv_obj_t* index_label = lv_label_create(cell);
    if (index_label == nullptr) {
        return false;
    }
    char index_text[3] = {};
    snprintf(index_text, sizeof(index_text), "%02u", static_cast<unsigned>(global_slot + 1));
    lv_label_set_text(index_label, index_text);
    lv_label_set_long_mode(index_label, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(index_label, kMnemonicWordIndexWidth);
    lv_obj_set_style_text_align(index_label, LV_TEXT_ALIGN_RIGHT, 0);
    lv_obj_set_style_text_font(index_label, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_color(index_label, lv_color_hex(0x475467), 0);
    lv_obj_set_style_bg_opa(index_label, LV_OPA_TRANSP, 0);
    lv_obj_set_style_radius(index_label, 4, LV_STATE_PRESSED);
    lv_obj_set_style_bg_color(index_label, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
    lv_obj_set_style_bg_opa(index_label, LV_OPA_30, LV_STATE_PRESSED);
    lv_obj_align(index_label, LV_ALIGN_LEFT_MID, 4, 0);
    lv_obj_add_flag(index_label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(
        index_label,
        on_recover_slot_clicked,
        LV_EVENT_CLICKED,
        const_cast<uint8_t*>(&kSlotUserData[slot]));

    lv_obj_t* prefix_label = lv_label_create(cell);
    if (prefix_label == nullptr) {
        return false;
    }
    const char* prefix = g_provisioning_scratch.recover_prefixes[global_slot];
    lv_label_set_text(prefix_label, prefix[0] != '\0' ? prefix : "____");
    lv_label_set_long_mode(prefix_label, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(prefix_label, kMnemonicWordPrefixWidth);
    lv_obj_set_style_text_align(prefix_label, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_style_text_font(prefix_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(prefix_label, lv_color_hex(0x111827), 0);
    lv_obj_set_style_bg_opa(prefix_label, LV_OPA_TRANSP, 0);
    lv_obj_set_style_radius(prefix_label, 4, LV_STATE_PRESSED);
    lv_obj_set_style_bg_color(prefix_label, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
    lv_obj_set_style_bg_opa(prefix_label, LV_OPA_30, LV_STATE_PRESSED);
    lv_obj_align(prefix_label, LV_ALIGN_LEFT_MID, kMnemonicWordPrefixLeft, 0);
    lv_obj_add_flag(prefix_label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(
        prefix_label,
        on_recover_slot_clicked,
        LV_EVENT_CLICKED,
        const_cast<uint8_t*>(&kSlotUserData[slot]));
    return true;
}

bool make_recover_alphabet_buttons(lv_obj_t* parent)
{
    static const char* const kLetters[26] = {
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
        "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    };

    for (int index = 0; index < 26; ++index) {
        char label[2] = {};
        label[0] = static_cast<char>('A' + index);
        const int column = index % 13;
        const int row = index / 13;
        if (!make_setup_button(
                parent,
                label,
                kRecoverAlphabetLeft + column * kRecoverAlphabetButtonWidth,
                kRecoverAlphabetTop + row * (kRecoverAlphabetButtonHeight + 4),
                kRecoverAlphabetButtonWidth,
                kRecoverAlphabetButtonHeight,
                SetupButtonKind::outlined_keypad,
                lv_color_hex(kSetupInputPressedColor),
                on_recover_letter_clicked,
                kLetters[index])) {
            return false;
        }
    }
    return true;
}

bool make_recover_candidate_area(lv_obj_t* parent)
{
    lv_obj_t* area = lv_obj_create(parent);
    if (area == nullptr) {
        return false;
    }
    lv_obj_remove_style_all(area);
    lv_obj_set_size(area, kRecoverCandidateWidth, kRecoverCandidateHeight);
    lv_obj_align(area, LV_ALIGN_TOP_LEFT, kRecoverCandidateLeft, kRecoverCandidateTop);
    lv_obj_set_scroll_dir(area, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(area, LV_SCROLLBAR_MODE_AUTO);
    lv_obj_set_style_pad_all(area, 0, 0);
    lv_obj_set_style_bg_opa(area, LV_OPA_TRANSP, 0);

    const size_t global_slot = recover_global_word_slot();
    const char* prefix = global_slot < agent_q::kBip39MnemonicWordCount
        ? g_provisioning_scratch.recover_prefixes[global_slot]
        : "";
    if (prefix[0] == '\0') {
        lv_obj_t* label = lv_label_create(area);
        if (label == nullptr) {
            return false;
        }
        lv_label_set_text(label, "Tap a letter to list BIP-39 words.");
        lv_obj_set_width(label, kRecoverCandidateWidth - 8);
        lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(label, lv_color_hex(0x475467), 0);
        lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 16);
        return true;
    }

    size_t candidate_count = 0;
    for (uint16_t word_index = 0; word_index < agent_q::kBip39WordCount; ++word_index) {
        const char* word = agent_q::bip39_english_word(word_index);
        if (!word_starts_with_prefix(word, prefix)) {
            continue;
        }
        if (candidate_count >= agent_q::kBip39WordCount) {
            break;
        }
        g_recover_candidate_event_indices[candidate_count] = word_index;

        lv_obj_t* button = lv_obj_create(area);
        if (button == nullptr) {
            return false;
        }
        const int column = static_cast<int>(candidate_count % 3);
        const int row = static_cast<int>(candidate_count / 3);
        lv_obj_remove_style_all(button);
        lv_obj_set_size(button, kRecoverCandidateButtonWidth, kRecoverCandidateButtonHeight);
        lv_obj_align(
            button,
            LV_ALIGN_TOP_LEFT,
            column * (kRecoverCandidateButtonWidth + 6),
            row * (kRecoverCandidateButtonHeight + 4));
        lv_obj_set_style_radius(button, kPinPanelButtonRadius, 0);
        lv_obj_set_style_border_width(button, 1, 0);
        lv_obj_set_style_border_color(button, lv_color_hex(kSetupCellBorderColor), 0);
        lv_obj_set_style_bg_opa(button, LV_OPA_TRANSP, 0);
        lv_obj_set_style_bg_color(button, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
        lv_obj_set_style_bg_opa(button, LV_OPA_30, LV_STATE_PRESSED);
        lv_obj_add_flag(button, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(
            button,
            on_recover_candidate_clicked,
            LV_EVENT_CLICKED,
            &g_recover_candidate_event_indices[candidate_count]);

        lv_obj_t* label = lv_label_create(button);
        if (label == nullptr) {
            return false;
        }
        lv_obj_remove_style_all(label);
        lv_label_set_text_static(label, word);
        lv_label_set_long_mode(label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(label, kRecoverCandidateButtonWidth - 6);
        lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(label, &lv_font_unscii_8, 0);
        lv_obj_set_style_text_color(label, lv_color_hex(0x111827), 0);
        lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
        lv_obj_set_style_radius(label, kPinPanelButtonRadius, LV_STATE_PRESSED);
        lv_obj_set_style_bg_color(label, lv_color_hex(kSetupInputPressedColor), LV_STATE_PRESSED);
        lv_obj_set_style_bg_opa(label, LV_OPA_30, LV_STATE_PRESSED);
        lv_obj_center(label);
        lv_obj_add_flag(label, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(
            label,
            on_recover_candidate_clicked,
            LV_EVENT_CLICKED,
            &g_recover_candidate_event_indices[candidate_count]);
        ++candidate_count;
    }

    if (candidate_count == 0) {
        lv_obj_t* label = lv_label_create(area);
        if (label == nullptr) {
            return false;
        }
        lv_label_set_text(label, "No matching BIP-39 words.");
        lv_obj_set_width(label, kRecoverCandidateWidth - 8);
        lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(label, lv_color_hex(0xA53B3B), 0);
        lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 16);
    }

    return true;
}

bool show_recover_word_entry_panel(const char* notice = nullptr)
{
    clear_agent_q_avatar_ui();

    LvglLockGuard lock;
    agent_q::request_display_power_wake();
    clear_panel_locked(SensitiveUiClearPolicy::preserve);

    g_ui.panel = lv_obj_create(lv_screen_active());
    if (g_ui.panel == nullptr) {
        g_ui.panel_kind = AgentQUiPanelKind::none;
        return false;
    }
    register_agent_q_panel_locked(AgentQUiPanelKind::recovery_word_entry);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(g_ui.panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(g_ui.panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(g_ui.panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(g_ui.panel, 8, 0);
    lv_obj_set_style_border_width(g_ui.panel, 0, 0);
    lv_obj_set_style_bg_color(g_ui.panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(g_ui.panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(g_ui.panel, 0, 0);

    char title_text[32] = {};
    snprintf(title_text, sizeof(title_text), "Recover words %u-%u",
             static_cast<unsigned>(g_provisioning_scratch.recover_page * kRecoverWordsPerPage + 1),
             static_cast<unsigned>((g_provisioning_scratch.recover_page + 1) * kRecoverWordsPerPage));
    lv_obj_t* title = lv_label_create(g_ui.panel);
    if (title == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(title, title_text);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 8);

    if (notice != nullptr && notice[0] != '\0') {
        lv_obj_t* notice_label = lv_label_create(g_ui.panel);
        if (notice_label == nullptr) {
            clear_panel_locked(SensitiveUiClearPolicy::wipe);
            return false;
        }
        lv_label_set_text(notice_label, notice);
        lv_obj_set_width(notice_label, kScreenWidth - 44);
        lv_obj_set_style_text_align(notice_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_font(notice_label, &lv_font_unscii_8, 0);
        lv_obj_set_style_text_color(notice_label, lv_color_hex(0xA53B3B), 0);
        lv_obj_align(notice_label, LV_ALIGN_TOP_MID, 0, 26);
    }

    for (uint8_t slot = 0; slot < kRecoverWordsPerPage; ++slot) {
        if (!make_recover_word_cell(g_ui.panel, slot)) {
            clear_panel_locked(SensitiveUiClearPolicy::wipe);
            return false;
        }
    }

    if (!make_recover_alphabet_buttons(g_ui.panel) ||
        !make_recover_candidate_area(g_ui.panel)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    if (!make_setup_button(
            g_ui.panel,
            "Cancel",
            kRecoveryPhraseButtonLeftX,
            kSetupActionButtonY,
            kRecoverNavigationButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0xA53B3B),
            on_recover_cancel_clicked) ||
        !make_setup_button(
            g_ui.panel,
            "Clear",
            kRecoveryPhraseButtonLeftX + kRecoverNavigationButtonWidth + 8,
            kSetupActionButtonY,
            kRecoverNavigationButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(0x667085),
            on_recover_clear_clicked) ||
        !make_setup_button(
            g_ui.panel,
            "Prev",
            kRecoveryPhraseButtonLeftX + 2 * (kRecoverNavigationButtonWidth + 8),
            kSetupActionButtonY,
            kRecoverNavigationButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x667085),
            on_recover_previous_clicked,
            nullptr,
            g_provisioning_scratch.recover_page > 0) ||
        !make_setup_button(
            g_ui.panel,
            g_provisioning_scratch.recover_page + 1 >= kRecoverPageCount ? "Verify" : "Next",
            kRecoveryPhraseButtonLeftX + 3 * (kRecoverNavigationButtonWidth + 8),
            kSetupActionButtonY,
            kRecoverNavigationButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x24875A),
            on_recover_next_clicked,
            nullptr,
            recover_current_page_complete())) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    lv_obj_move_foreground(g_ui.panel);
    return true;
}

bool show_recovery_phrase_display(const char* recovery_phrase)
{
    if (!format_recovery_phrase_prefix_cells(
            recovery_phrase, g_provisioning_scratch.recovery_phrase_prefix_cells)) {
        return false;
    }

    clear_agent_q_avatar_ui();

    LvglLockGuard lock;
    clear_panel_locked(SensitiveUiClearPolicy::preserve);

    g_ui.panel = lv_obj_create(lv_screen_active());
    if (g_ui.panel == nullptr) {
        g_ui.panel_kind = AgentQUiPanelKind::none;
        return false;
    }
    register_agent_q_panel_locked(AgentQUiPanelKind::recovery_phrase_display);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(g_ui.panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(g_ui.panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(g_ui.panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(g_ui.panel, 8, 0);
    lv_obj_set_style_border_width(g_ui.panel, 0, 0);
    lv_obj_set_style_bg_color(g_ui.panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(g_ui.panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(g_ui.panel, 0, 0);

    lv_obj_t* title = lv_label_create(g_ui.panel);
    if (title == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(title, "BIP-39 prefixes (DEV)");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kRecoveryPhraseTopMargin);

    lv_obj_t* warning = lv_label_create(g_ui.panel);
    if (warning == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(warning, "Write up-to-4-letter prefixes. Host cannot read them.");
    lv_label_set_long_mode(warning, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(warning, kScreenWidth - 44);
    lv_obj_set_style_text_align(warning, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(warning, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(warning, lv_color_hex(0x3A2B00), 0);
    lv_obj_align(warning, LV_ALIGN_TOP_MID, 0, 22 + kRecoveryPhraseTopMargin);

    constexpr int kGridTop = 58 + kRecoveryPhraseTopMargin;
    constexpr int kGridRowHeight = 25;
    for (size_t index = 0; index < kRecoveryPhrasePrefixCellCount; ++index) {
        lv_obj_t* cell = lv_obj_create(g_ui.panel);
        if (cell == nullptr) {
            clear_panel_locked(SensitiveUiClearPolicy::wipe);
            return false;
        }
        lv_obj_remove_flag(cell, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_size(cell, kMnemonicWordCellWidth, kMnemonicWordCellHeight);
        lv_obj_set_style_radius(cell, 4, 0);
        lv_obj_set_style_border_width(cell, 1, 0);
        lv_obj_set_style_border_color(cell, lv_color_hex(0xB7E4C7), 0);
        lv_obj_set_style_bg_color(cell, lv_color_hex(0xFFFFFF), 0);
        lv_obj_set_style_bg_opa(cell, LV_OPA_COVER, 0);
        lv_obj_set_style_pad_all(cell, 0, 0);
        const int column = static_cast<int>(index % 3);
        const int row = static_cast<int>(index / 3);
        lv_obj_align(
            cell,
            LV_ALIGN_TOP_LEFT,
            kMnemonicWordCellLeft + column * kMnemonicWordCellWidth,
            kGridTop + row * kGridRowHeight);

        lv_obj_t* index_label = lv_label_create(cell);
        if (index_label == nullptr) {
            clear_panel_locked(SensitiveUiClearPolicy::wipe);
            return false;
        }
        char index_text[3] = {};
        snprintf(index_text, sizeof(index_text), "%02u", static_cast<unsigned>(index + 1));
        lv_label_set_text(index_label, index_text);
        lv_label_set_long_mode(index_label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(index_label, kMnemonicWordIndexWidth);
        lv_obj_set_style_text_align(index_label, LV_TEXT_ALIGN_RIGHT, 0);
        lv_obj_set_style_text_font(index_label, &lv_font_unscii_8, 0);
        lv_obj_set_style_text_color(index_label, lv_color_hex(0x475467), 0);
        lv_obj_align(index_label, LV_ALIGN_LEFT_MID, 4, 0);

        lv_obj_t* prefix_label = lv_label_create(cell);
        if (prefix_label == nullptr) {
            clear_panel_locked(SensitiveUiClearPolicy::wipe);
            return false;
        }
        lv_label_set_text_static(prefix_label, g_provisioning_scratch.recovery_phrase_prefix_cells[index]);
        lv_label_set_long_mode(prefix_label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(prefix_label, kMnemonicWordPrefixWidth);
        lv_obj_set_style_text_align(prefix_label, LV_TEXT_ALIGN_LEFT, 0);
        lv_obj_set_style_text_font(prefix_label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(prefix_label, lv_color_hex(0x111827), 0);
        lv_obj_align(prefix_label, LV_ALIGN_LEFT_MID, kMnemonicWordPrefixLeft, 0);
    }
    if (!make_setup_button(
            g_ui.panel,
            "Cancel",
            kRecoveryPhraseButtonLeftX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0xA53B3B),
            on_recovery_phrase_cancel_clicked) ||
        !make_setup_button(
            g_ui.panel,
            "Confirm",
            kRecoveryPhraseButtonRightX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x24875A),
            on_recovery_phrase_confirm_clicked)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    lv_obj_move_foreground(g_ui.panel);
    return true;
}

bool show_pin_setup_panel(const char* notice = nullptr)
{
    clear_agent_q_avatar_ui();

    LvglLockGuard lock;
    clear_panel_locked(SensitiveUiClearPolicy::preserve);

    g_ui.panel = lv_obj_create(lv_screen_active());
    if (g_ui.panel == nullptr) {
        g_ui.panel_kind = AgentQUiPanelKind::none;
        return false;
    }
    register_agent_q_panel_locked(AgentQUiPanelKind::pin_entry);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(g_ui.panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(g_ui.panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(g_ui.panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(g_ui.panel, 8, 0);
    lv_obj_set_style_border_width(g_ui.panel, 0, 0);
    lv_obj_set_style_bg_color(g_ui.panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(g_ui.panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(g_ui.panel, 0, 0);

    const bool repeat_stage = g_provisioning_scratch.setup_stage == SetupScratchStage::pin_repeat_entry;
    const bool committing_stage = g_provisioning_scratch.setup_stage == SetupScratchStage::pin_committing;
    const bool buttons_enabled = !committing_stage;
    lv_obj_t* title = lv_label_create(g_ui.panel);
    if (title == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(title, committing_stage ? "Saving setup" : (repeat_stage ? "Repeat 6-digit PIN" : "Set 6-digit PIN"));
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 8);

    lv_obj_t* message = lv_label_create(g_ui.panel);
    if (message == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(
        message,
        notice != nullptr && notice[0] != '\0'
            ? notice
            : (committing_stage ? "Processing. Please wait." : "Choose a local setup PIN."));
    lv_label_set_long_mode(message, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(message, kScreenWidth - 44);
    lv_obj_set_style_text_align(message, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(message, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(message, lv_color_hex(0x3A2B00), 0);
    lv_obj_align(message, LV_ALIGN_TOP_MID, 0, 30);

    char pin_mask[agent_q::kLocalPinDigits + 1] = {};
    for (size_t index = 0; index < agent_q::kLocalPinDigits; ++index) {
        pin_mask[index] = index < g_provisioning_scratch.pin_entry_length ? '*' : '_';
    }
    char pin_text[16] = {};
    snprintf(pin_text, sizeof(pin_text), "PIN: %s", pin_mask);
    lv_obj_t* pin_label = lv_label_create(g_ui.panel);
    if (pin_label == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(pin_label, pin_text);
    lv_obj_set_style_text_font(pin_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(pin_label, lv_color_hex(0x111827), 0);
    lv_obj_align(pin_label, LV_ALIGN_TOP_MID, 0, 58);

    if (!make_pin_keypad_buttons(g_ui.panel, buttons_enabled)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    if (!make_setup_button(
            g_ui.panel,
            "Cancel",
            kRecoveryPhraseButtonLeftX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0xA53B3B),
            on_pin_cancel_clicked,
            nullptr,
            buttons_enabled) ||
        !make_setup_button(
            g_ui.panel,
            "Confirm",
            kRecoveryPhraseButtonRightX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x24875A),
            on_pin_submit_clicked,
            nullptr,
            buttons_enabled)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    if (committing_stage && !make_pin_processing_overlay(g_ui.panel)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    lv_obj_move_foreground(g_ui.panel);
    return true;
}

bool show_settings_menu_panel()
{
    clear_agent_q_avatar_ui();

    LvglLockGuard lock;
    agent_q::request_display_power_wake();
    clear_panel_locked(SensitiveUiClearPolicy::preserve);

    g_ui.panel = lv_obj_create(lv_screen_active());
    if (g_ui.panel == nullptr) {
        g_ui.panel_kind = AgentQUiPanelKind::none;
        return false;
    }
    register_agent_q_panel_locked(AgentQUiPanelKind::settings_menu);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(g_ui.panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(g_ui.panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(g_ui.panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(g_ui.panel, 8, 0);
    lv_obj_set_style_border_width(g_ui.panel, 0, 0);
    lv_obj_set_style_bg_color(g_ui.panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(g_ui.panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(g_ui.panel, 0, 0);

    lv_obj_t* title = lv_label_create(g_ui.panel);
    if (title == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(title, "Settings");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 24);

    bool require_pin_on_connect = true;
    const bool connect_setting_read_ok =
        agent_q::read_require_pin_on_connect(&require_pin_on_connect);

    // Settings are fixed rows: add future settings by appending the same
    // label/control pair, not by adding explanatory text blocks.
    if (!make_settings_row_label(g_ui.panel, "PIN on connect", kSettingsMenuRowOneY) ||
        !make_setup_button(
            g_ui.panel,
            require_pin_on_connect ? "ON" : "OFF",
            kSettingsMenuRowControlX,
            kSettingsMenuRowOneY,
            kSettingsMenuActionButtonWidth,
            kSettingsMenuActionButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(require_pin_on_connect ? 0x24875A : 0x667085),
            connect_setting_read_ok ? on_settings_connect_pin_clicked : nullptr,
            nullptr,
            connect_setting_read_ok) ||
        !make_settings_row_label(g_ui.panel, "Reset device", kSettingsMenuRowTwoY) ||
        !make_setup_button(
            g_ui.panel,
            "RESET",
            kSettingsMenuRowControlX,
            kSettingsMenuRowTwoY,
            kSettingsMenuActionButtonWidth,
            kSettingsMenuActionButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0xA53B3B),
            on_settings_reset_clicked) ||
        !make_setup_button(
            g_ui.panel,
            "Close",
            kSettingsMenuButtonCenterX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x667085),
            on_settings_cancel_clicked)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    lv_obj_move_foreground(g_ui.panel);
    return true;
}

bool show_reset_pin_panel(const char* notice = nullptr)
{
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    clear_agent_q_avatar_ui();

    LvglLockGuard lock;
    agent_q::request_display_power_wake();
    clear_panel_locked(SensitiveUiClearPolicy::preserve);

    g_ui.panel = lv_obj_create(lv_screen_active());
    if (g_ui.panel == nullptr) {
        g_ui.panel_kind = AgentQUiPanelKind::none;
        return false;
    }
    register_agent_q_panel_locked(AgentQUiPanelKind::reset_pin_entry);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(g_ui.panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(g_ui.panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(g_ui.panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(g_ui.panel, 8, 0);
    lv_obj_set_style_border_width(g_ui.panel, 0, 0);
    lv_obj_set_style_bg_color(g_ui.panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(g_ui.panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(g_ui.panel, 0, 0);

    const bool processing_stage =
        reset.stage == agent_q::AgentQLocalResetStage::pin_verifying ||
        reset.stage == agent_q::AgentQLocalResetStage::wiping;
    const bool locked_stage = reset.lockout_active;
    const bool buttons_enabled = !processing_stage && !locked_stage;

    lv_obj_t* title = lv_label_create(g_ui.panel);
    if (title == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(title, processing_stage ? "Processing reset" : "Enter reset PIN");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 8);

    lv_obj_t* message = lv_label_create(g_ui.panel);
    if (message == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(
        message,
        notice != nullptr && notice[0] != '\0'
            ? notice
            : (processing_stage ? "Processing. Please wait." : "Confirm reset with local PIN."));
    lv_label_set_long_mode(message, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(message, kScreenWidth - 44);
    lv_obj_set_style_text_align(message, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(message, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(message, lv_color_hex(0x3A2B00), 0);
    lv_obj_align(message, LV_ALIGN_TOP_MID, 0, 30);

    char pin_mask[agent_q::kLocalPinDigits + 1] = {};
    for (size_t index = 0; index < agent_q::kLocalPinDigits; ++index) {
        pin_mask[index] = index < reset.pin_entry_length ? '*' : '_';
    }
    char pin_text[16] = {};
    snprintf(pin_text, sizeof(pin_text), "PIN: %s", pin_mask);
    lv_obj_t* pin_label = lv_label_create(g_ui.panel);
    if (pin_label == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(pin_label, pin_text);
    lv_obj_set_style_text_font(pin_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(pin_label, lv_color_hex(0x111827), 0);
    lv_obj_align(pin_label, LV_ALIGN_TOP_MID, 0, 58);

    if (!make_pin_keypad_buttons(g_ui.panel, buttons_enabled)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    if (!make_setup_button(
            g_ui.panel,
            "Cancel",
            kRecoveryPhraseButtonLeftX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x667085),
            on_reset_cancel_clicked,
            nullptr,
            !processing_stage) ||
        !make_setup_button(
            g_ui.panel,
            "Reset",
            kRecoveryPhraseButtonRightX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0xA53B3B),
            on_pin_submit_clicked,
            nullptr,
            buttons_enabled)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    if (processing_stage && !make_pin_processing_overlay(g_ui.panel)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    lv_obj_move_foreground(g_ui.panel);
    return true;
}

const char* local_pin_auth_default_message(bool processing_stage, bool locked_stage)
{
    if (locked_stage) {
        return "Too many wrong PINs. Wait 30s.";
    }
    if (processing_stage) {
        return "Processing. Please wait.";
    }
    if (g_local_pin_auth.purpose == LocalPinAuthPurpose::connect) {
        return "Enter local PIN to connect.";
    }
    return "Enter PIN to change setting.";
}

bool show_local_pin_auth_panel(const char* notice = nullptr)
{
    if (!g_local_pin_auth.flow_active()) {
        return false;
    }

    clear_agent_q_avatar_ui();

    LvglLockGuard lock;
    agent_q::request_display_power_wake();
    clear_panel_locked(SensitiveUiClearPolicy::preserve);

    g_ui.panel = lv_obj_create(lv_screen_active());
    if (g_ui.panel == nullptr) {
        g_ui.panel_kind = AgentQUiPanelKind::none;
        return false;
    }
    register_agent_q_panel_locked(AgentQUiPanelKind::local_pin_auth);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_remove_flag(g_ui.panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
    lv_obj_set_scrollbar_mode(g_ui.panel, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_size(g_ui.panel, kScreenWidth - 16, kScreenHeight - 16);
    lv_obj_align(g_ui.panel, LV_ALIGN_TOP_MID, 0, 8);
    lv_obj_set_style_radius(g_ui.panel, 8, 0);
    lv_obj_set_style_border_width(g_ui.panel, 0, 0);
    lv_obj_set_style_bg_color(g_ui.panel, lv_color_hex(0xF7FFF9), 0);
    lv_obj_set_style_bg_opa(g_ui.panel, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(g_ui.panel, 0, 0);

    const bool processing_stage =
        g_local_pin_auth.stage == LocalPinAuthStage::pin_verifying ||
        g_local_pin_auth.stage == LocalPinAuthStage::committing_setting;
    const TickType_t now = xTaskGetTickCount();
    agent_q::pin_attempt_release_if_elapsed(&g_local_pin_auth.pin_attempt, now);
    const bool locked_stage =
        agent_q::pin_attempt_locked_at(g_local_pin_auth.pin_attempt, now);
    const bool buttons_enabled = !processing_stage && !locked_stage;

    lv_obj_t* title = lv_label_create(g_ui.panel);
    if (title == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(
        title,
        processing_stage
            ? "Processing PIN"
            : (g_local_pin_auth.purpose == LocalPinAuthPurpose::connect ? "Connect PIN" : "Settings PIN"));
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 8);

    lv_obj_t* message = lv_label_create(g_ui.panel);
    if (message == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(
        message,
        notice != nullptr && notice[0] != '\0'
            ? notice
            : local_pin_auth_default_message(processing_stage, locked_stage));
    lv_label_set_long_mode(message, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(message, kScreenWidth - 44);
    lv_obj_set_style_text_align(message, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(message, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(message, lv_color_hex(0x3A2B00), 0);
    lv_obj_align(message, LV_ALIGN_TOP_MID, 0, 30);

    char pin_mask[agent_q::kLocalPinDigits + 1] = {};
    for (size_t index = 0; index < agent_q::kLocalPinDigits; ++index) {
        pin_mask[index] = index < g_local_pin_auth.pin_entry_length ? '*' : '_';
    }
    char pin_text[16] = {};
    snprintf(pin_text, sizeof(pin_text), "PIN: %s", pin_mask);
    lv_obj_t* pin_label = lv_label_create(g_ui.panel);
    if (pin_label == nullptr) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }
    lv_label_set_text(pin_label, pin_text);
    lv_obj_set_style_text_font(pin_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(pin_label, lv_color_hex(0x111827), 0);
    lv_obj_align(pin_label, LV_ALIGN_TOP_MID, 0, 58);

    if (!make_pin_keypad_buttons(g_ui.panel, buttons_enabled)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    if (!make_setup_button(
            g_ui.panel,
            "Cancel",
            kRecoveryPhraseButtonLeftX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x667085),
            on_pin_cancel_clicked,
            nullptr,
            !processing_stage) ||
        !make_setup_button(
            g_ui.panel,
            "Confirm",
            kRecoveryPhraseButtonRightX,
            kSetupActionButtonY,
            kRecoveryPhraseButtonWidth,
            kRecoveryPhraseButtonHeight,
            SetupButtonKind::solid_action,
            lv_color_hex(0x24875A),
            on_pin_submit_clicked,
            nullptr,
            buttons_enabled)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    if (processing_stage && !make_pin_processing_overlay(g_ui.panel)) {
        clear_panel_locked(SensitiveUiClearPolicy::wipe);
        return false;
    }

    lv_obj_move_foreground(g_ui.panel);
    return true;
}

RecoveryPhraseGenerationResult generate_recovery_phrase_scratch()
{
    wipe_setup_scratch("recovery phrase generation reset");

    if (!agent_q::fill_secure_random(
            g_provisioning_scratch.root_material,
            sizeof(g_provisioning_scratch.root_material))) {
        wipe_setup_scratch("recovery phrase entropy failure");
        return RecoveryPhraseGenerationResult::rng_error;
    }
    const bool generated = agent_q::make_bip39_mnemonic_12_words(
        g_provisioning_scratch.root_material,
        g_provisioning_scratch.recovery_phrase,
        sizeof(g_provisioning_scratch.recovery_phrase));
    if (!generated) {
        wipe_setup_scratch("recovery phrase generation failure");
        return RecoveryPhraseGenerationResult::generation_error;
    }

    g_provisioning_scratch.setup_stage = SetupScratchStage::recovery_phrase_displayed;
    g_provisioning_scratch.recovery_phrase_deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(kRecoveryPhraseDisplayMs);
    return RecoveryPhraseGenerationResult::ok;
}

void begin_recovery_word_entry_scratch()
{
    wipe_setup_scratch("recovery import reset");
    g_provisioning_scratch.setup_stage = SetupScratchStage::recover_word_entry;
    g_provisioning_scratch.recover_page = 0;
    g_provisioning_scratch.recover_active_slot = 0;
    g_provisioning_scratch.recover_word_deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs);
}

bool setup_choice_action_allowed()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::setup_choice ||
        g_provisioning_scratch.setup_choice_deadline == 0 ||
        tick_reached(g_provisioning_scratch.setup_choice_deadline) ||
        g_pending.active ||
        agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active) {
        return false;
    }
    if (!refresh_persistent_material_consistency()) {
        return false;
    }
    return g_provisioning_state == ProvisioningRuntimeState::unprovisioned &&
           !g_persistent_material_consistency_error;
}

void clear_setup_choice_if_needed()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::setup_choice) {
        return;
    }

    const bool panel_active = agent_q_panel_active(AgentQUiPanelKind::setup_choice);
    const bool expired = g_provisioning_scratch.setup_choice_deadline != 0 &&
                         tick_reached(g_provisioning_scratch.setup_choice_deadline);
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel();
    } else {
        wipe_setup_scratch("setup choice panel lost");
    }

    if (expired) {
        show_agent_q_message("Setup expired", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void clear_recovery_word_entry_if_needed()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::recover_word_entry) {
        return;
    }

    const bool panel_active = agent_q_panel_active(AgentQUiPanelKind::recovery_word_entry);
    const bool expired = g_provisioning_scratch.recover_word_deadline != 0 &&
                         tick_reached(g_provisioning_scratch.recover_word_deadline);
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel();
    } else {
        wipe_setup_scratch("recovery word entry panel lost");
    }

    if (expired) {
        show_agent_q_message("Recovery expired", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void clear_recovery_phrase_if_needed()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::recovery_phrase_displayed) {
        return;
    }

    const bool panel_active = agent_q_panel_active(AgentQUiPanelKind::recovery_phrase_display);
    const bool expired = g_provisioning_scratch.recovery_phrase_deadline != 0 &&
                         tick_reached(g_provisioning_scratch.recovery_phrase_deadline);
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel();
    } else {
        wipe_setup_scratch("recovery phrase display lost");
    }

    if (expired) {
        show_agent_q_message("Phrase expired", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void clear_pin_setup_if_needed()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::pin_first_entry &&
        g_provisioning_scratch.setup_stage != SetupScratchStage::pin_repeat_entry) {
        return;
    }

    const bool panel_active = agent_q_panel_active(AgentQUiPanelKind::pin_entry);
    const bool expired = g_provisioning_scratch.pin_deadline != 0 &&
                         tick_reached(g_provisioning_scratch.pin_deadline);
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel();
    } else {
        wipe_setup_scratch("local PIN setup panel lost");
    }

    if (expired) {
        show_agent_q_message("Setup expired", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_pin_digit_from_local_ui(char digit)
{
    if ((g_provisioning_scratch.setup_stage != SetupScratchStage::pin_first_entry &&
         g_provisioning_scratch.setup_stage != SetupScratchStage::pin_repeat_entry) ||
        digit < '0' || digit > '9') {
        return;
    }
    if (g_provisioning_scratch.pin_entry_length >= agent_q::kLocalPinDigits) {
        g_provisioning_scratch.pin_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs);
        if (!show_pin_setup_panel()) {
            wipe_setup_scratch("local PIN setup display allocation failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    g_provisioning_scratch.pin_entry[g_provisioning_scratch.pin_entry_length++] = digit;
    g_provisioning_scratch.pin_entry[g_provisioning_scratch.pin_entry_length] = '\0';
    g_provisioning_scratch.pin_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs);
    if (!show_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_pin_clear_from_local_ui()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::pin_first_entry &&
        g_provisioning_scratch.setup_stage != SetupScratchStage::pin_repeat_entry) {
        return;
    }
    agent_q::wipe_sensitive_buffer(g_provisioning_scratch.pin_entry, sizeof(g_provisioning_scratch.pin_entry));
    g_provisioning_scratch.pin_entry_length = 0;
    g_provisioning_scratch.pin_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs);
    if (!show_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_pin_backspace_from_local_ui()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::pin_first_entry &&
        g_provisioning_scratch.setup_stage != SetupScratchStage::pin_repeat_entry) {
        return;
    }
    if (g_provisioning_scratch.pin_entry_length > 0) {
        g_provisioning_scratch.pin_entry[--g_provisioning_scratch.pin_entry_length] = '\0';
    }
    g_provisioning_scratch.pin_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs);
    if (!show_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_pin_submit_from_local_ui()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::pin_first_entry &&
        g_provisioning_scratch.setup_stage != SetupScratchStage::pin_repeat_entry) {
        ESP_LOGW(kTag, "Stale local PIN submit ignored");
        return;
    }
    if (g_provisioning_scratch.pin_entry_length != agent_q::kLocalPinDigits ||
        !agent_q::is_valid_local_pin(g_provisioning_scratch.pin_entry)) {
        g_provisioning_scratch.pin_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs);
        if (!show_pin_setup_panel("Enter exactly 6 digits.")) {
            wipe_setup_scratch("local PIN setup display allocation failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    if (g_provisioning_scratch.setup_stage == SetupScratchStage::pin_first_entry) {
        strlcpy(g_provisioning_scratch.pin_first,
                g_provisioning_scratch.pin_entry,
                sizeof(g_provisioning_scratch.pin_first));
        agent_q::wipe_sensitive_buffer(g_provisioning_scratch.pin_entry, sizeof(g_provisioning_scratch.pin_entry));
        g_provisioning_scratch.pin_entry_length = 0;
        g_provisioning_scratch.setup_stage = SetupScratchStage::pin_repeat_entry;
        g_provisioning_scratch.pin_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs);
        if (!show_pin_setup_panel()) {
            wipe_setup_scratch("local PIN setup display allocation failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    if (strcmp(g_provisioning_scratch.pin_first, g_provisioning_scratch.pin_entry) != 0) {
        agent_q::wipe_sensitive_buffer(g_provisioning_scratch.pin_first, sizeof(g_provisioning_scratch.pin_first));
        agent_q::wipe_sensitive_buffer(g_provisioning_scratch.pin_entry, sizeof(g_provisioning_scratch.pin_entry));
        g_provisioning_scratch.pin_entry_length = 0;
        g_provisioning_scratch.setup_stage = SetupScratchStage::pin_first_entry;
        g_provisioning_scratch.pin_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs);
        if (!show_pin_setup_panel("PINs did not match.")) {
            wipe_setup_scratch("local PIN setup display allocation failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    g_provisioning_scratch.setup_stage = SetupScratchStage::pin_committing;
    g_provisioning_scratch.pin_commit_ready_at =
        xTaskGetTickCount() + pdMS_TO_TICKS(kLocalProcessingDisplayMs);
    agent_q::wipe_sensitive_buffer(g_provisioning_scratch.pin_first, sizeof(g_provisioning_scratch.pin_first));
    if (!make_pin_processing_overlay_on_current_panel(AgentQUiPanelKind::pin_entry) &&
        !show_pin_setup_panel()) {
        ESP_LOGW(kTag, "Local setup committing panel could not be shown");
        wipe_setup_scratch("local PIN setup committing display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void commit_local_setup_if_ready()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::pin_committing ||
        g_provisioning_scratch.pin_commit_ready_at == 0 ||
        !tick_reached(g_provisioning_scratch.pin_commit_ready_at)) {
        return;
    }

    const SetupCommitResult result =
        commit_setup_material_after_pin_match(
            g_provisioning_scratch.pin_entry,
            "local recovery phrase backup and PIN committed");
    clear_agent_q_panel();
    switch (result) {
        case SetupCommitResult::ok:
            ESP_LOGI(kTag, "Local setup PIN confirmed and provisioned");
            show_agent_q_message("Provisioned", AgentQMessageKind::success, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
        case SetupCommitResult::missing_scratch:
            ESP_LOGW(kTag, "Local PIN confirmation missing scratch");
            show_agent_q_message("Setup unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
        case SetupCommitResult::root_storage_error:
        case SetupCommitResult::policy_storage_error:
        case SetupCommitResult::local_auth_storage_error:
        case SetupCommitResult::state_storage_error:
            ESP_LOGW(kTag, "Local PIN confirmation storage error");
            show_agent_q_message("Storage error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
    }
}

void clear_local_reset_if_needed()
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalResetSnapshot reset = agent_q::local_reset_snapshot(now);
    if (reset.stage == agent_q::AgentQLocalResetStage::none ||
        reset.stage == agent_q::AgentQLocalResetStage::pin_verifying ||
        reset.stage == agent_q::AgentQLocalResetStage::wiping) {
        return;
    }

    if (agent_q::local_reset_release_lockout_if_elapsed(now)) {
        if (!show_reset_pin_panel("Try again.")) {
            wipe_local_reset_scratch("local reset PIN panel allocation failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    bool panel_active = false;
    {
        LvglLockGuard lock;
        panel_active = g_ui.panel != nullptr &&
                       local_reset_panel_matches_stage(g_ui.panel_kind);
    }
    const bool expired = agent_q::local_reset_deadline_expired(now);
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel();
    } else {
        wipe_local_reset_scratch("local reset panel lost");
    }

    if (expired) {
        show_agent_q_message("Reset canceled", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void commit_local_reset_if_ready()
{
    if (!agent_q::local_reset_wipe_ready(xTaskGetTickCount())) {
        return;
    }

    const agent_q::AgentQLocalResetCommitResult result =
        agent_q::local_reset_commit_material(local_reset_persistence_ops());
    clear_agent_q_panel();
    wipe_local_reset_scratch("local reset completed");
    switch (result) {
        case agent_q::AgentQLocalResetCommitResult::ok:
            g_persistent_material_consistency_error = false;
            ESP_LOGW(kTag, "Local reset completed; device returned to unprovisioned");
            show_agent_q_message("Device reset", AgentQMessageKind::success, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
        case agent_q::AgentQLocalResetCommitResult::missing_state:
            ESP_LOGW(kTag, "Local reset commit missing state");
            show_agent_q_message("Reset unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
        case agent_q::AgentQLocalResetCommitResult::reset_marker_storage_error:
            ESP_LOGW(kTag, "Local reset aborted before wiping material because the reset marker could not be stored");
            show_agent_q_message("Reset error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
        case agent_q::AgentQLocalResetCommitResult::root_wipe_error:
        case agent_q::AgentQLocalResetCommitResult::policy_wipe_error:
        case agent_q::AgentQLocalResetCommitResult::local_auth_wipe_error:
        case agent_q::AgentQLocalResetCommitResult::connect_setting_wipe_error:
        case agent_q::AgentQLocalResetCommitResult::material_remaining_error:
        case agent_q::AgentQLocalResetCommitResult::state_storage_error:
            ESP_LOGE(kTag, "Local reset failed and device entered consistency error");
            show_agent_q_message("Reset error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
    }
}

void start_local_settings_from_touch()
{
    if (!provisioned_material_ready() ||
        g_pending.active ||
        g_identification.active ||
        g_provisioning_scratch.setup_flow_active() ||
        agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active ||
        !agent_q_ui_idle_for_local_settings()) {
        ESP_LOGW(kTag, "Local settings touch ignored because settings are unavailable");
        g_settings_touch.clear();
        return;
    }

    agent_q::local_reset_begin_settings(
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));
    if (!show_settings_menu_panel()) {
        wipe_local_reset_scratch("local settings display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void cancel_local_reset_from_ui(const char* message)
{
    if (agent_q::local_reset_snapshot(xTaskGetTickCount()).stage !=
        agent_q::AgentQLocalResetStage::pin_entry) {
        ESP_LOGW(kTag, "Stale local reset cancel ignored");
        return;
    }

    clear_agent_q_panel();
    agent_q::local_reset_begin_settings(
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));
    if (!show_settings_menu_panel()) {
        wipe_local_reset_scratch("local settings display allocation failed after reset cancel");
        show_agent_q_message(
            message != nullptr && message[0] != '\0' ? message : "Reset canceled",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
    }
}

void close_local_settings_from_ui()
{
    if (agent_q::local_reset_snapshot(xTaskGetTickCount()).stage !=
        agent_q::AgentQLocalResetStage::settings_menu) {
        ESP_LOGW(kTag, "Stale local settings close ignored");
        return;
    }

    clear_agent_q_panel();
    wipe_local_reset_scratch("local settings closed");
}

void start_reset_pin_from_settings_menu()
{
    if (!provisioned_material_ready() ||
        !agent_q::local_reset_begin_pin_entry(
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs))) {
        ESP_LOGW(kTag, "Stale local reset menu action ignored");
        return;
    }

    if (!show_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void begin_connect_pin_auth(const char* id, const char* gateway_name, uint32_t approval_timeout_ms)
{
    g_pending.begin_connect_pin(id, gateway_name, approval_timeout_ms);
    g_local_pin_auth.clear_flow();
    g_local_pin_auth.purpose = LocalPinAuthPurpose::connect;
    g_local_pin_auth.stage = LocalPinAuthStage::pin_entry;
    g_local_pin_auth.deadline = g_pending.deadline;

    if (!show_local_pin_auth_panel()) {
        write_connect_rejected_response(g_pending.id, "ui_error", "Could not show local PIN UI.");
        wipe_local_pin_auth_scratch("connect PIN display allocation failed");
        clear_pending_state();
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void start_settings_connect_pin_from_settings_menu()
{
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    if (!provisioned_material_ready() ||
        reset.stage != agent_q::AgentQLocalResetStage::settings_menu ||
        g_local_pin_auth.flow_active()) {
        ESP_LOGW(kTag, "Stale settings connect PIN action ignored");
        return;
    }

    bool current_require_pin = true;
    if (!agent_q::read_require_pin_on_connect(&current_require_pin)) {
        agent_q::local_reset_wipe();
        clear_agent_q_panel();
        show_agent_q_message(
            "Settings error",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
        return;
    }
    agent_q::local_reset_wipe();
    g_local_pin_auth.clear_flow();
    g_local_pin_auth.purpose = LocalPinAuthPurpose::settings_connect_pin;
    g_local_pin_auth.stage = LocalPinAuthStage::pin_entry;
    g_local_pin_auth.target_require_pin_on_connect = !current_require_pin;
    g_local_pin_auth.deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs);

    if (!show_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("settings connect PIN display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void cancel_local_pin_auth_from_ui(const char* message)
{
    if (!g_local_pin_auth.flow_active() ||
        g_local_pin_auth.stage != LocalPinAuthStage::pin_entry) {
        ESP_LOGW(kTag, "Stale local PIN authorization cancel ignored");
        return;
    }

    const LocalPinAuthPurpose purpose = g_local_pin_auth.purpose;
    char request_id[kMaxRequestIdSize] = {};
    if (purpose == LocalPinAuthPurpose::connect && g_pending.kind == PendingKind::connect_pin) {
        strlcpy(request_id, g_pending.id, sizeof(request_id));
    }

    clear_agent_q_panel();
    if (purpose == LocalPinAuthPurpose::connect && request_id[0] != '\0') {
        write_connect_rejected_response(request_id, "rejected", "Connection rejected.");
        clear_pending_state();
        show_agent_q_message("Connection rejected", AgentQMessageKind::rejected, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }
    if (purpose == LocalPinAuthPurpose::settings_connect_pin) {
        agent_q::local_reset_begin_settings(
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));
        if (!show_settings_menu_panel()) {
            wipe_local_reset_scratch("local settings display allocation failed after PIN cancel");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    show_agent_q_message(
        message != nullptr && message[0] != '\0' ? message : "Settings canceled",
        AgentQMessageKind::rejected,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void handle_local_pin_auth_digit_from_ui(char digit)
{
    const TickType_t now = xTaskGetTickCount();
    agent_q::pin_attempt_release_if_elapsed(&g_local_pin_auth.pin_attempt, now);
    if (!g_local_pin_auth.flow_active() ||
        g_local_pin_auth.stage != LocalPinAuthStage::pin_entry ||
        agent_q::pin_attempt_locked_at(g_local_pin_auth.pin_attempt, now) ||
        digit < '0' || digit > '9') {
        return;
    }
    if (g_local_pin_auth.pin_entry_length >= agent_q::kLocalPinDigits) {
        g_local_pin_auth.deadline =
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs);
        if (!show_local_pin_auth_panel()) {
            wipe_local_pin_auth_scratch("local PIN authorization display allocation failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    g_local_pin_auth.pin_entry[g_local_pin_auth.pin_entry_length++] = digit;
    g_local_pin_auth.pin_entry[g_local_pin_auth.pin_entry_length] = '\0';
    g_local_pin_auth.deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs);
    if (!show_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("local PIN authorization display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_local_pin_auth_clear_from_ui()
{
    const TickType_t now = xTaskGetTickCount();
    agent_q::pin_attempt_release_if_elapsed(&g_local_pin_auth.pin_attempt, now);
    if (!g_local_pin_auth.flow_active() ||
        g_local_pin_auth.stage != LocalPinAuthStage::pin_entry ||
        agent_q::pin_attempt_locked_at(g_local_pin_auth.pin_attempt, now)) {
        return;
    }
    g_local_pin_auth.clear_pin_only();
    g_local_pin_auth.deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs);
    if (!show_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("local PIN authorization display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_local_pin_auth_backspace_from_ui()
{
    const TickType_t now = xTaskGetTickCount();
    agent_q::pin_attempt_release_if_elapsed(&g_local_pin_auth.pin_attempt, now);
    if (!g_local_pin_auth.flow_active() ||
        g_local_pin_auth.stage != LocalPinAuthStage::pin_entry ||
        agent_q::pin_attempt_locked_at(g_local_pin_auth.pin_attempt, now)) {
        return;
    }
    if (g_local_pin_auth.pin_entry_length > 0) {
        g_local_pin_auth.pin_entry[--g_local_pin_auth.pin_entry_length] = '\0';
    }
    g_local_pin_auth.deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs);
    if (!show_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("local PIN authorization display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_local_pin_auth_submit_from_ui()
{
    const TickType_t now = xTaskGetTickCount();
    agent_q::pin_attempt_release_if_elapsed(&g_local_pin_auth.pin_attempt, now);
    if (!g_local_pin_auth.flow_active() ||
        g_local_pin_auth.stage != LocalPinAuthStage::pin_entry) {
        ESP_LOGW(kTag, "Stale local PIN authorization submit ignored");
        return;
    }
    if (agent_q::pin_attempt_locked_at(g_local_pin_auth.pin_attempt, now)) {
        return;
    }
    if (g_local_pin_auth.pin_entry_length != agent_q::kLocalPinDigits ||
        !agent_q::is_valid_local_pin(g_local_pin_auth.pin_entry)) {
        g_local_pin_auth.deadline =
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs);
        if (!show_local_pin_auth_panel("Enter exactly 6 digits.")) {
            wipe_local_pin_auth_scratch("local PIN authorization display allocation failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    g_local_pin_auth.stage = LocalPinAuthStage::pin_verifying;
    g_local_pin_auth.verify_ready_at =
        xTaskGetTickCount() + pdMS_TO_TICKS(kLocalProcessingRenderDelayMs);
    g_local_pin_auth.deadline = 0;
    if (!make_pin_processing_overlay_on_current_panel(AgentQUiPanelKind::local_pin_auth) &&
        !show_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("local PIN authorization verification display allocation failed");
        clear_agent_q_panel();
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_reset_pin_digit_from_local_ui(char digit)
{
    if (!agent_q::local_reset_add_pin_digit(
            digit,
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs))) {
        return;
    }

    if (!show_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_reset_pin_clear_from_local_ui()
{
    if (!agent_q::local_reset_clear_pin(
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs))) {
        return;
    }
    if (!show_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_reset_pin_backspace_from_local_ui()
{
    if (!agent_q::local_reset_backspace_pin(
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs))) {
        return;
    }
    if (!show_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_reset_pin_submit_from_local_ui()
{
    if (!provisioned_material_ready()) {
        wipe_local_reset_scratch("local reset material state unavailable");
        clear_agent_q_panel();
        show_agent_q_message("Reset unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    const agent_q::AgentQLocalResetPinSubmitResult submit_result =
        agent_q::local_reset_submit_pin_for_verification(
            xTaskGetTickCount() + pdMS_TO_TICKS(kLocalProcessingRenderDelayMs),
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));
    if (submit_result == agent_q::AgentQLocalResetPinSubmitResult::unavailable_stage) {
        ESP_LOGW(kTag, "Stale local reset PIN submit ignored");
        return;
    }
    if (submit_result == agent_q::AgentQLocalResetPinSubmitResult::locked) {
        return;
    }
    if (submit_result == agent_q::AgentQLocalResetPinSubmitResult::invalid_pin) {
        if (!show_reset_pin_panel("Enter exactly 6 digits.")) {
            wipe_local_reset_scratch("local reset PIN display allocation failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    if (!make_pin_processing_overlay_on_current_panel(AgentQUiPanelKind::reset_pin_entry) &&
        !show_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN verification display allocation failed");
        clear_agent_q_panel();
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void verify_local_reset_pin_if_ready()
{
    if (!provisioned_material_ready()) {
        const agent_q::AgentQLocalResetSnapshot reset =
            agent_q::local_reset_snapshot(xTaskGetTickCount());
        if (reset.stage != agent_q::AgentQLocalResetStage::pin_verifying) {
            return;
        }
        wipe_local_reset_scratch("local reset material state unavailable during PIN verification");
        clear_agent_q_panel();
        show_agent_q_message("Reset unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalResetPinVerifyResult verify_result =
        agent_q::local_reset_verify_pin_if_ready(
            now,
            now + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs),
            now + pdMS_TO_TICKS(agent_q::kAgentQLocalResetPinLockoutMs),
            now + pdMS_TO_TICKS(kLocalProcessingDisplayMs));
    switch (verify_result) {
        case agent_q::AgentQLocalResetPinVerifyResult::not_ready:
            return;
        case agent_q::AgentQLocalResetPinVerifyResult::auth_unavailable:
            enter_persistent_material_consistency_error("Local reset could not verify stored PIN; failing closed");
            wipe_local_reset_scratch("local reset PIN verifier unavailable");
            clear_agent_q_panel();
            show_agent_q_message("Auth error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            return;
        case agent_q::AgentQLocalResetPinVerifyResult::locked:
            if (!show_reset_pin_panel("Too many wrong PINs. Wait 30s.")) {
                wipe_local_reset_scratch("local reset PIN lockout display allocation failed");
                show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            }
            return;
        case agent_q::AgentQLocalResetPinVerifyResult::wrong_pin:
            if (!show_reset_pin_panel("Wrong PIN.")) {
                wipe_local_reset_scratch("local reset PIN display allocation failed");
                show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            }
            return;
        case agent_q::AgentQLocalResetPinVerifyResult::verified:
            break;
    }

    bool reset_panel_active = false;
    {
        LvglLockGuard lock;
        reset_panel_active = g_ui.panel != nullptr &&
                             g_ui.panel_kind == AgentQUiPanelKind::reset_pin_entry;
    }
    if (!reset_panel_active) {
        if (!show_reset_pin_panel()) {
            ESP_LOGW(kTag, "Local reset wiping panel could not be shown");
            commit_local_reset_if_ready();
        }
    }
}

void verify_local_pin_auth_if_ready()
{
    if (!g_local_pin_auth.flow_active() ||
        g_local_pin_auth.stage != LocalPinAuthStage::pin_verifying ||
        g_local_pin_auth.verify_ready_at == 0 ||
        !tick_reached(g_local_pin_auth.verify_ready_at)) {
        return;
    }

    const LocalPinAuthPurpose purpose = g_local_pin_auth.purpose;
    if (!provisioned_material_ready()) {
        char request_id[kMaxRequestIdSize] = {};
        if (purpose == LocalPinAuthPurpose::connect && g_pending.kind == PendingKind::connect_pin) {
            strlcpy(request_id, g_pending.id, sizeof(request_id));
        }
        wipe_local_pin_auth_scratch("local PIN authorization material state unavailable");
        clear_agent_q_panel();
        if (request_id[0] != '\0') {
            write_connect_rejected_response(request_id, "invalid_state", "Connect is unavailable.");
            clear_pending_state();
        }
        show_agent_q_message("PIN unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    bool verified = false;
    if (!agent_q::verify_local_pin(g_local_pin_auth.pin_entry, &verified)) {
        char request_id[kMaxRequestIdSize] = {};
        if (purpose == LocalPinAuthPurpose::connect && g_pending.kind == PendingKind::connect_pin) {
            strlcpy(request_id, g_pending.id, sizeof(request_id));
        }
        enter_persistent_material_consistency_error("Local PIN verifier unavailable during PIN authorization; failing closed");
        wipe_local_pin_auth_scratch("local PIN authorization verifier unavailable");
        clear_agent_q_panel();
        if (request_id[0] != '\0') {
            write_connect_rejected_response(request_id, "auth_unavailable", "Local PIN verifier unavailable.");
            clear_pending_state();
        }
        show_agent_q_message("Auth error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    const TickType_t now = xTaskGetTickCount();
    if (!verified) {
        g_local_pin_auth.clear_pin_only();
        g_local_pin_auth.stage = LocalPinAuthStage::pin_entry;
        g_local_pin_auth.deadline = now + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs);
        const bool locked = agent_q::pin_attempt_record_failure(
            &g_local_pin_auth.pin_attempt,
            now + pdMS_TO_TICKS(agent_q::kAgentQLocalResetPinLockoutMs));
        if (!show_local_pin_auth_panel(locked ? "Too many wrong PINs. Wait 30s." : "Wrong PIN.")) {
            wipe_local_pin_auth_scratch("local PIN authorization display allocation failed after wrong PIN");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    agent_q::wipe_sensitive_buffer(g_local_pin_auth.pin_entry, sizeof(g_local_pin_auth.pin_entry));
    g_local_pin_auth.pin_entry_length = 0;
    g_local_pin_auth.verify_ready_at = 0;
    g_local_pin_auth.clear_attempts();

    if (purpose == LocalPinAuthPurpose::connect) {
        char request_id[kMaxRequestIdSize] = {};
        if (g_pending.kind == PendingKind::connect_pin) {
            strlcpy(request_id, g_pending.id, sizeof(request_id));
        }
        g_pending.active = false;
        if (!replace_active_session()) {
            if (request_id[0] != '\0') {
                write_error_response(request_id, "rng_error", "Could not create session id.");
            }
            ESP_LOGE(kTag, "connect PIN could not create session id: id=%s", request_id);
            clear_agent_q_panel();
            clear_pending_state();
            show_agent_q_message("RNG error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            return;
        }
        clear_agent_q_panel();
        if (request_id[0] != '\0') {
            write_connect_approved_response(request_id);
        }
        clear_pending_state();
        ESP_LOGI(kTag, "connect PIN approved: id=%s", request_id);
        show_agent_q_message("Connected", AgentQMessageKind::success, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    g_local_pin_auth.stage = LocalPinAuthStage::committing_setting;
    g_local_pin_auth.commit_ready_at = now + pdMS_TO_TICKS(kLocalProcessingDisplayMs);
    if (!make_pin_processing_overlay_on_current_panel(AgentQUiPanelKind::local_pin_auth) &&
        !show_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("settings PIN commit display allocation failed");
        clear_agent_q_panel();
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void commit_local_pin_setting_if_ready()
{
    if (!g_local_pin_auth.flow_active() ||
        g_local_pin_auth.stage != LocalPinAuthStage::committing_setting ||
        g_local_pin_auth.commit_ready_at == 0 ||
        !tick_reached(g_local_pin_auth.commit_ready_at)) {
        return;
    }

    const bool next_value = g_local_pin_auth.target_require_pin_on_connect;
    const bool stored = agent_q::store_require_pin_on_connect(next_value);
    clear_agent_q_panel();
    if (!stored) {
        show_agent_q_message("Settings error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    agent_q::local_reset_begin_settings(
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));
    if (!show_settings_menu_panel()) {
        wipe_local_reset_scratch("local settings display allocation failed after PIN setting commit");
        show_agent_q_message("Settings saved", AgentQMessageKind::success, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void clear_local_pin_auth_if_needed()
{
    if (!g_local_pin_auth.flow_active() ||
        g_local_pin_auth.stage == LocalPinAuthStage::pin_verifying ||
        g_local_pin_auth.stage == LocalPinAuthStage::committing_setting) {
        return;
    }

    const TickType_t now = xTaskGetTickCount();
    if (agent_q::pin_attempt_release_if_elapsed(&g_local_pin_auth.pin_attempt, now)) {
        g_local_pin_auth.deadline = now + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs);
        if (!show_local_pin_auth_panel("Try again.")) {
            wipe_local_pin_auth_scratch("local PIN authorization lockout display allocation failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    bool panel_active = false;
    {
        LvglLockGuard lock;
        panel_active = g_ui.panel != nullptr &&
                       local_pin_auth_panel_matches_stage(g_ui.panel_kind);
    }
    const bool expired = g_local_pin_auth.deadline != 0 &&
                         tick_reached(g_local_pin_auth.deadline);
    if (panel_active && !expired) {
        return;
    }

    const LocalPinAuthPurpose purpose = g_local_pin_auth.purpose;
    char request_id[kMaxRequestIdSize] = {};
    if (purpose == LocalPinAuthPurpose::connect && g_pending.kind == PendingKind::connect_pin) {
        strlcpy(request_id, g_pending.id, sizeof(request_id));
    }

    if (panel_active) {
        clear_agent_q_panel();
    } else {
        wipe_local_pin_auth_scratch("local PIN authorization panel lost");
    }

    if (request_id[0] != '\0') {
        write_connect_rejected_response(request_id,
                                        expired ? "timeout" : "rejected",
                                        expired ? "Connection PIN timed out." : "Connection PIN UI closed.");
        clear_pending_state();
        show_agent_q_message(expired ? "Connection timed out" : "Connection canceled",
                             expired ? AgentQMessageKind::timeout : AgentQMessageKind::info,
                             AgentQUiMode::result,
                             kAgentQResultDisplayMs);
        return;
    }

    if (expired) {
        show_agent_q_message("Settings timed out", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void poll_touch_fallback()
{
    if (!g_pending.awaiting_choice()) {
        return;
    }

    const auto touch = hal_bridge::get_touch_point();
    if (touch.num == 0) {
        g_pending.touch_armed = true;
        return;
    }
    if (!g_pending.touch_armed) {
        return;
    }

    lv_area_t panel_area;
    {
        LvglLockGuard lock;
        if (g_ui.panel == nullptr || !is_decision_panel_kind(g_ui.panel_kind)) {
            return;
        }
        lv_obj_get_coords(g_ui.panel, &panel_area);
    }

    const int panel_width = panel_area.x2 - panel_area.x1 + 1;
    const int panel_height = panel_area.y2 - panel_area.y1 + 1;
    const int relative_x = touch.x - panel_area.x1;
    const int relative_y = touch.y - panel_area.y1;
    const bool inside_panel = relative_x >= 0 && relative_y >= 0 &&
                              relative_x < panel_width && relative_y < panel_height;
    if (!inside_panel) {
        return;
    }

    g_pending.choice = relative_x < panel_width / 2 ? PendingChoice::no : PendingChoice::yes;
    g_pending.touch_armed = false;
}

void poll_local_settings_touch_entry()
{
    if (!local_settings_touch_entry_candidate_allowed()) {
        g_settings_touch.clear();
        return;
    }

    const auto touch = hal_bridge::get_touch_point();
    const bool inside_entry_corner = touch.num > 0 &&
                                     touch.x >= kScreenWidth - kSettingsTouchEntryWidth &&
                                     touch.y >= 0 &&
                                     touch.y < kSettingsTouchEntryHeight;
    if (!inside_entry_corner) {
        g_settings_touch.clear();
        return;
    }

    const TickType_t now = xTaskGetTickCount();
    if (!g_settings_touch.active) {
        g_settings_touch.active = true;
        g_settings_touch.started_at = now;
        return;
    }
    if (static_cast<int32_t>(now - g_settings_touch.started_at) <
        static_cast<int32_t>(pdMS_TO_TICKS(kSettingsTouchEntryMs))) {
        return;
    }

    g_settings_touch.clear();
    enqueue_ui_event(AgentQUiEventKind::settings_requested);
}

void drain_pending_choice_events()
{
    if (g_pending_choice_queue == nullptr) {
        return;
    }

    PendingChoice choice = PendingChoice::none;
    while (xQueueReceive(g_pending_choice_queue, &choice, 0) == pdTRUE) {
        if (g_pending.awaiting_choice()) {
            g_pending.choice = choice;
            g_pending.touch_armed = false;
        }
    }
}

void start_local_provisioning_from_setup_touch()
{
    if (!setup_choice_action_allowed()) {
        ESP_LOGW(kTag, "Stale local setup generate action ignored");
        return;
    }

    const RecoveryPhraseGenerationResult generation_result = generate_recovery_phrase_scratch();
    if (generation_result == RecoveryPhraseGenerationResult::ok) {
        if (show_recovery_phrase_display(g_provisioning_scratch.recovery_phrase)) {
            ESP_LOGI(kTag, "Local setup recovery phrase displayed");
        } else {
            wipe_setup_scratch("local setup recovery phrase display allocation failed");
            ESP_LOGW(kTag, "Local setup display failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    if (generation_result == RecoveryPhraseGenerationResult::rng_error) {
        ESP_LOGW(kTag, "Local setup RNG failed");
        show_agent_q_message("RNG error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    ESP_LOGW(kTag, "Local setup phrase generation failed");
    show_agent_q_message("Generation error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
}

void show_setup_choice_from_setup_touch()
{
    if (!local_setup_start_allowed()) {
        ESP_LOGW(kTag, "Local setup touch ignored because setup is unavailable");
        clear_agent_q_request_ui();
        show_agent_q_message("Setup unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    wipe_setup_scratch("setup choice reset");
    g_provisioning_scratch.setup_stage = SetupScratchStage::setup_choice;
    g_provisioning_scratch.setup_choice_deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs);
    if (!show_setup_choice_panel()) {
        wipe_setup_scratch("setup choice display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void start_local_recovery_from_setup_choice()
{
    if (!setup_choice_action_allowed()) {
        ESP_LOGW(kTag, "Stale local recover action ignored");
        return;
    }

    begin_recovery_word_entry_scratch();
    if (!show_recover_word_entry_panel()) {
        wipe_setup_scratch("recovery word entry display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void cancel_setup_from_local_ui()
{
    if (g_provisioning_scratch.setup_stage == SetupScratchStage::none ||
        g_provisioning_scratch.setup_stage == SetupScratchStage::pin_committing) {
        ESP_LOGW(kTag, "Stale local setup cancel ignored");
        return;
    }

    clear_agent_q_panel();
    wipe_setup_scratch("provisioning scratch wipe");
    ESP_LOGI(kTag, "Local setup canceled from recovery phrase UI");
    show_agent_q_message("Setup canceled", AgentQMessageKind::rejected, AgentQUiMode::result, kAgentQResultDisplayMs);
}

void confirm_recovery_phrase_from_local_ui()
{
    if (!recovery_phrase_backup_confirmation_ready()) {
        ESP_LOGW(kTag, "Stale local backup confirmation ignored");
        return;
    }

    g_provisioning_scratch.setup_stage = SetupScratchStage::pin_first_entry;
    agent_q::wipe_sensitive_buffer(g_provisioning_scratch.pin_first, sizeof(g_provisioning_scratch.pin_first));
    agent_q::wipe_sensitive_buffer(g_provisioning_scratch.pin_entry, sizeof(g_provisioning_scratch.pin_entry));
    g_provisioning_scratch.pin_entry_length = 0;
    g_provisioning_scratch.pin_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs);

    if (!show_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed");
        ESP_LOGW(kTag, "Local backup confirmation could not start setup PIN entry");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    g_provisioning_scratch.wipe_displayed_phrase_text();
    ESP_LOGI(kTag, "Local backup confirmed; setup PIN entry started");
}

void handle_recover_slot_from_local_ui(uint8_t slot)
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::recover_word_entry ||
        slot >= kRecoverWordsPerPage) {
        return;
    }
    g_provisioning_scratch.recover_active_slot = slot;
    g_provisioning_scratch.recover_word_deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs);
    if (!show_recover_word_entry_panel()) {
        wipe_setup_scratch("recovery word entry display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_recover_letter_from_local_ui(char letter)
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::recover_word_entry ||
        letter < 'a' || letter > 'z') {
        return;
    }
    const size_t global_slot = recover_global_word_slot();
    if (global_slot >= agent_q::kBip39MnemonicWordCount) {
        return;
    }
    char* prefix = g_provisioning_scratch.recover_prefixes[global_slot];
    size_t length = strlen(prefix);
    if (length >= kRecoverPrefixMaxChars) {
        g_provisioning_scratch.recover_word_deadline =
            xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs);
        if (!show_recover_word_entry_panel()) {
            wipe_setup_scratch("recovery word entry display allocation failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }
    prefix[length++] = letter;
    prefix[length] = '\0';
    g_provisioning_scratch.recover_word_selected[global_slot] = false;
    g_provisioning_scratch.recover_word_indices[global_slot] = 0;
    g_provisioning_scratch.recover_word_deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs);
    if (!show_recover_word_entry_panel()) {
        wipe_setup_scratch("recovery word entry display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_recover_clear_from_local_ui()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::recover_word_entry) {
        return;
    }
    const size_t global_slot = recover_global_word_slot();
    if (global_slot >= agent_q::kBip39MnemonicWordCount) {
        return;
    }
    agent_q::wipe_sensitive_buffer(
        g_provisioning_scratch.recover_prefixes[global_slot],
        kRecoverPrefixBufferSize);
    g_provisioning_scratch.recover_word_selected[global_slot] = false;
    g_provisioning_scratch.recover_word_indices[global_slot] = 0;
    g_provisioning_scratch.recover_word_deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs);
    if (!show_recover_word_entry_panel()) {
        wipe_setup_scratch("recovery word entry display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_recover_candidate_from_local_ui(uint16_t word_index)
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::recover_word_entry ||
        word_index >= agent_q::kBip39WordCount ||
        agent_q::bip39_english_word(word_index) == nullptr) {
        return;
    }
    const size_t global_slot = recover_global_word_slot();
    if (global_slot >= agent_q::kBip39MnemonicWordCount) {
        return;
    }
    g_provisioning_scratch.recover_word_indices[global_slot] = word_index;
    g_provisioning_scratch.recover_word_selected[global_slot] = true;
    write_selected_word_prefix(global_slot, word_index);
    if (g_provisioning_scratch.recover_active_slot + 1 < kRecoverWordsPerPage) {
        ++g_provisioning_scratch.recover_active_slot;
    }
    g_provisioning_scratch.recover_word_deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs);
    if (!show_recover_word_entry_panel()) {
        wipe_setup_scratch("recovery word entry display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_recover_previous_from_local_ui()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::recover_word_entry ||
        g_provisioning_scratch.recover_page == 0) {
        return;
    }
    --g_provisioning_scratch.recover_page;
    g_provisioning_scratch.recover_active_slot = 0;
    g_provisioning_scratch.recover_word_deadline =
        xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs);
    if (!show_recover_word_entry_panel()) {
        wipe_setup_scratch("recovery word entry display allocation failed");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void start_pin_setup_after_recovered_entropy()
{
    g_provisioning_scratch.setup_stage = SetupScratchStage::pin_first_entry;
    wipe_recover_word_entry_scratch();
    agent_q::wipe_sensitive_buffer(g_provisioning_scratch.pin_first, sizeof(g_provisioning_scratch.pin_first));
    agent_q::wipe_sensitive_buffer(g_provisioning_scratch.pin_entry, sizeof(g_provisioning_scratch.pin_entry));
    g_provisioning_scratch.pin_entry_length = 0;
    g_provisioning_scratch.pin_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs);

    if (!show_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed after recovery");
        show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_recover_next_from_local_ui()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::recover_word_entry ||
        !recover_current_page_complete()) {
        return;
    }

    if (g_provisioning_scratch.recover_page + 1 < kRecoverPageCount) {
        ++g_provisioning_scratch.recover_page;
        g_provisioning_scratch.recover_active_slot = 0;
        g_provisioning_scratch.recover_word_deadline =
            xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs);
        if (!show_recover_word_entry_panel()) {
            wipe_setup_scratch("recovery word entry display allocation failed");
            show_agent_q_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    if (!recover_all_words_complete()) {
        return;
    }

    const agent_q::Bip39EntropyRecoveryResult result =
        agent_q::recover_bip39_entropy_12_words(
            g_provisioning_scratch.recover_word_indices,
            agent_q::kBip39MnemonicWordCount,
            g_provisioning_scratch.root_material,
            sizeof(g_provisioning_scratch.root_material));
    if (result != agent_q::Bip39EntropyRecoveryResult::ok) {
        agent_q::wipe_sensitive_buffer(
            g_provisioning_scratch.root_material,
            sizeof(g_provisioning_scratch.root_material));
        g_provisioning_scratch.recover_word_deadline =
            xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs);
        if (!show_recover_word_entry_panel("Checksum failed. Recheck words.")) {
            wipe_setup_scratch("recovery checksum failure display allocation failed");
            show_agent_q_message("Recovery error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    start_pin_setup_after_recovered_entropy();
}

void drain_ui_events()
{
    if (g_ui_event_queue == nullptr) {
        return;
    }

    AgentQUiEvent event;
    while (xQueueReceive(g_ui_event_queue, &event, 0) == pdTRUE) {
        if (event.kind == AgentQUiEventKind::setup_requested) {
            show_setup_choice_from_setup_touch();
            continue;
        }

        if (event.kind == AgentQUiEventKind::setup_generate_requested) {
            start_local_provisioning_from_setup_touch();
            continue;
        }

        if (event.kind == AgentQUiEventKind::setup_recover_requested) {
            start_local_recovery_from_setup_choice();
            continue;
        }

        if (event.kind == AgentQUiEventKind::setup_cancel_requested) {
            cancel_setup_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::provisioning_welcome_requested) {
            show_provisioning_welcome_if_available();
            continue;
        }

        if (event.kind == AgentQUiEventKind::settings_requested) {
            start_local_settings_from_touch();
            continue;
        }

        if (event.kind == AgentQUiEventKind::settings_cancel_requested) {
            close_local_settings_from_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::settings_connect_pin_requested) {
            start_settings_connect_pin_from_settings_menu();
            continue;
        }

        if (event.kind == AgentQUiEventKind::settings_reset_requested) {
            start_reset_pin_from_settings_menu();
            continue;
        }

        if (event.kind == AgentQUiEventKind::reset_cancel_requested) {
            cancel_local_reset_from_ui("Reset canceled");
            continue;
        }

        if (event.kind == AgentQUiEventKind::recovery_phrase_cancel_requested) {
            cancel_setup_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::recovery_phrase_confirm_requested) {
            confirm_recovery_phrase_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::recover_slot_requested) {
            handle_recover_slot_from_local_ui(event.slot);
            continue;
        }

        if (event.kind == AgentQUiEventKind::recover_letter_requested) {
            handle_recover_letter_from_local_ui(event.letter);
            continue;
        }

        if (event.kind == AgentQUiEventKind::recover_clear_requested) {
            handle_recover_clear_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::recover_candidate_requested) {
            handle_recover_candidate_from_local_ui(event.word_index);
            continue;
        }

        if (event.kind == AgentQUiEventKind::recover_previous_requested) {
            handle_recover_previous_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::recover_next_requested) {
            handle_recover_next_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::recover_cancel_requested) {
            cancel_setup_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_digit_requested) {
            const agent_q::AgentQLocalResetStage reset_stage =
                agent_q::local_reset_snapshot(xTaskGetTickCount()).stage;
            if (g_provisioning_scratch.setup_stage == SetupScratchStage::pin_first_entry ||
                g_provisioning_scratch.setup_stage == SetupScratchStage::pin_repeat_entry) {
                handle_pin_digit_from_local_ui(event.digit);
            } else if (reset_stage == agent_q::AgentQLocalResetStage::pin_entry) {
                handle_reset_pin_digit_from_local_ui(event.digit);
            } else if (g_local_pin_auth.stage == LocalPinAuthStage::pin_entry) {
                handle_local_pin_auth_digit_from_ui(event.digit);
            }
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_clear_requested) {
            const agent_q::AgentQLocalResetStage reset_stage =
                agent_q::local_reset_snapshot(xTaskGetTickCount()).stage;
            if (g_provisioning_scratch.setup_stage == SetupScratchStage::pin_first_entry ||
                g_provisioning_scratch.setup_stage == SetupScratchStage::pin_repeat_entry) {
                handle_pin_clear_from_local_ui();
            } else if (reset_stage == agent_q::AgentQLocalResetStage::pin_entry) {
                handle_reset_pin_clear_from_local_ui();
            } else if (g_local_pin_auth.stage == LocalPinAuthStage::pin_entry) {
                handle_local_pin_auth_clear_from_ui();
            }
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_backspace_requested) {
            const agent_q::AgentQLocalResetStage reset_stage =
                agent_q::local_reset_snapshot(xTaskGetTickCount()).stage;
            if (g_provisioning_scratch.setup_stage == SetupScratchStage::pin_first_entry ||
                g_provisioning_scratch.setup_stage == SetupScratchStage::pin_repeat_entry) {
                handle_pin_backspace_from_local_ui();
            } else if (reset_stage == agent_q::AgentQLocalResetStage::pin_entry) {
                handle_reset_pin_backspace_from_local_ui();
            } else if (g_local_pin_auth.stage == LocalPinAuthStage::pin_entry) {
                handle_local_pin_auth_backspace_from_ui();
            }
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_submit_requested) {
            const agent_q::AgentQLocalResetStage reset_stage =
                agent_q::local_reset_snapshot(xTaskGetTickCount()).stage;
            if (g_provisioning_scratch.setup_stage == SetupScratchStage::pin_first_entry ||
                g_provisioning_scratch.setup_stage == SetupScratchStage::pin_repeat_entry) {
                handle_pin_submit_from_local_ui();
            } else if (reset_stage == agent_q::AgentQLocalResetStage::pin_entry) {
                handle_reset_pin_submit_from_local_ui();
            } else if (g_local_pin_auth.stage == LocalPinAuthStage::pin_entry) {
                handle_local_pin_auth_submit_from_ui();
            }
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_cancel_requested) {
            const agent_q::AgentQLocalResetStage reset_stage =
                agent_q::local_reset_snapshot(xTaskGetTickCount()).stage;
            if (g_provisioning_scratch.setup_stage == SetupScratchStage::pin_first_entry ||
                g_provisioning_scratch.setup_stage == SetupScratchStage::pin_repeat_entry) {
                cancel_setup_from_local_ui();
            } else if (reset_stage == agent_q::AgentQLocalResetStage::pin_entry) {
                cancel_local_reset_from_ui("Reset canceled");
            } else if (g_local_pin_auth.stage == LocalPinAuthStage::pin_entry) {
                cancel_local_pin_auth_from_ui("Settings canceled");
            }
            continue;
        }

        if (event.kind != AgentQUiEventKind::panel_deleted) {
            continue;
        }
        if (event.panel_kind == AgentQUiPanelKind::recovery_phrase_display &&
            g_provisioning_scratch.setup_stage == SetupScratchStage::recovery_phrase_displayed) {
            wipe_setup_scratch("recovery phrase panel deleted");
        } else if (event.panel_kind == AgentQUiPanelKind::setup_choice &&
                   g_provisioning_scratch.setup_stage == SetupScratchStage::setup_choice) {
            wipe_setup_scratch("setup choice panel deleted");
        } else if (event.panel_kind == AgentQUiPanelKind::recovery_word_entry &&
                   g_provisioning_scratch.setup_stage == SetupScratchStage::recover_word_entry) {
            wipe_setup_scratch("recovery word entry panel deleted");
        } else if (event.panel_kind == AgentQUiPanelKind::pin_entry &&
                   (g_provisioning_scratch.setup_stage == SetupScratchStage::pin_first_entry ||
                    g_provisioning_scratch.setup_stage == SetupScratchStage::pin_repeat_entry)) {
            wipe_setup_scratch("local PIN setup panel deleted");
        } else if (local_reset_panel_matches_stage(event.panel_kind)) {
            wipe_local_reset_scratch("local reset panel deleted");
        } else if (local_pin_auth_panel_matches_stage(event.panel_kind)) {
            char request_id[kMaxRequestIdSize] = {};
            if (g_local_pin_auth.purpose == LocalPinAuthPurpose::connect &&
                g_pending.kind == PendingKind::connect_pin) {
                strlcpy(request_id, g_pending.id, sizeof(request_id));
            }
            wipe_local_pin_auth_scratch("local PIN authorization panel deleted");
            if (request_id[0] != '\0') {
                write_connect_rejected_response(request_id, "rejected", "Connection PIN UI closed.");
                clear_pending_state();
            }
        }
    }
}

void ensure_pending_request_ui()
{
    if (!g_pending.awaiting_choice()) {
        return;
    }
    if (g_pending.kind != PendingKind::connect) {
        clear_pending_state();
        return;
    }

    bool needs_decision_panel = false;
    {
        LvglLockGuard lock;
        needs_decision_panel = g_ui.panel == nullptr || !is_decision_panel_kind(g_ui.panel_kind);
    }
    if (!needs_decision_panel) {
        return;
    }

    show_connect_decision(g_pending.gateway_name);
    ESP_LOGW(kTag, "connect decision UI recovered: id=%s", g_pending.id);
}

void send_choice_response_if_needed()
{
    drain_pending_choice_events();
    poll_touch_fallback();

    if (g_pending.active && g_pending.kind == PendingKind::connect_pin) {
        return;
    }

    if (!g_pending.active || g_pending.choice == PendingChoice::none) {
        if (g_pending.active && g_pending.deadline != 0 &&
            tick_reached(g_pending.deadline)) {
            // Device leaves awaiting_approval before reporting the result.
            g_pending.active = false;
            if (g_pending.kind == PendingKind::connect) {
                write_connect_rejected_response(g_pending.id, "timeout", "Connection approval timed out.");
                ESP_LOGI(kTag, "connect timed out: id=%s", g_pending.id);
                show_result_and_clear_pending("Connection timed out", AgentQMessageKind::timeout);
            } else {
                clear_pending_state();
            }
        }
        return;
    }

    const bool approved = g_pending.choice == PendingChoice::yes;
    g_pending.active = false;
    if (g_pending.kind != PendingKind::connect) {
        clear_pending_state();
        return;
    }

    if (approved) {
        if (!replace_active_session()) {
            write_error_response(g_pending.id, "rng_error", "Could not create session id.");
            ESP_LOGE(kTag, "connect could not create session id: id=%s", g_pending.id);
            show_result_and_clear_pending("RNG error", AgentQMessageKind::error);
            return;
        }
        write_connect_approved_response(g_pending.id);
        ESP_LOGI(kTag, "connect approved: id=%s", g_pending.id);
        show_result_and_clear_pending("Connected", AgentQMessageKind::success);
    } else {
        write_connect_rejected_response(g_pending.id, "rejected", "Connection rejected.");
        ESP_LOGI(kTag, "connect rejected: id=%s", g_pending.id);
        show_result_and_clear_pending("Connection rejected", AgentQMessageKind::rejected);
    }
}

void handle_line(const char* line)
{
    JsonDocument request;
    const DeserializationError error = deserializeJson(request, line);
    if (error) {
        write_error_response(nullptr, "invalid_json", "Invalid JSON.");
        return;
    }

    const char* id = request["id"] | "";
    if (!is_safe_id(id)) {
        write_error_response(nullptr, "invalid_id", "Invalid request id.");
        return;
    }

    const int version = request["version"] | 0;
    if (version != kProtocolVersion) {
        write_error_response(id, "unsupported_version", "Unsupported protocol version.");
        return;
    }

    const char* type = request["type"] | "";
    if (strcmp(type, "get_status") == 0) {
        write_status_response(id);
        return;
    }

    if (strcmp(type, "identify_device") == 0) {
        if (write_busy_if_pending_or_local_flow_active(id)) {
            return;
        }

        const char* code = request["params"]["code"] | "";
        if (!is_safe_identification_code(code)) {
            write_error_response(id, "invalid_code", "Invalid identification code.");
            return;
        }

        const uint32_t duration_ms = request["params"]["durationMs"] | kIdentifyDisplayDefaultMs;
        if (duration_ms == 0 || duration_ms > kIdentifyDisplayMaxMs) {
            write_error_response(id, "invalid_duration", "Invalid identification duration.");
            return;
        }

        show_identification_code(code, duration_ms);
        write_identify_device_result(id, code);
        ESP_LOGI(kTag, "identify_device displayed: id=%s code=%s", id, code);
        return;
    }

    if (strcmp(type, "connect") == 0) {
        if (!provisioned_material_ready()) {
            write_error_response(id, "invalid_state", "Connect is available only after provisioning is complete.");
            return;
        }
        if (write_busy_if_pending_or_local_flow_active(id)) {
            return;
        }

        const char* gateway_name = request["params"]["gatewayName"] | "";
        if (!is_printable_ascii_gateway_name(gateway_name)) {
            write_error_response(id, "invalid_gateway_name", "gatewayName must be 1-64 printable ASCII characters.");
            return;
        }

        uint32_t approval_timeout_ms = request["params"]["approvalTimeoutMs"] | kConnectApprovalDefaultMs;
        if (approval_timeout_ms == 0 || approval_timeout_ms > kConnectApprovalMaxMs) {
            write_error_response(id, "invalid_approval_timeout", "Invalid approval timeout.");
            return;
        }

        if (agent_q::connect_requires_pin()) {
            begin_connect_pin_auth(id, gateway_name, approval_timeout_ms);
            ESP_LOGI(kTag, "connect waiting for local PIN: id=%s gateway=%s", id, g_pending.gateway_name);
            return;
        }

        g_pending.begin_connect(id, gateway_name, approval_timeout_ms);
        show_connect_decision(g_pending.gateway_name);
        ESP_LOGI(kTag, "connect waiting for YES/NO: id=%s gateway=%s", id, g_pending.gateway_name);
        return;
    }

    if (strcmp(type, "disconnect") == 0) {
        if (write_busy_if_pending_or_local_flow_active(id)) {
            return;
        }

        const char* session_id = request["sessionId"] | "";
        if (!require_active_matching_session(id, session_id)) {
            return;
        }
        clear_active_session();
        write_disconnect_result(id);
        ESP_LOGI(kTag, "disconnect: id=%s", id);
        return;
    }

    if (strcmp(type, "get_capabilities") == 0) {
        // get_capabilities is read-only and session-scoped. Firmware is the
        // capability authority; Gateway must not infer or extend this response.
        if (!provisioned_material_ready()) {
            write_error_response(id, "invalid_state", "Capabilities are available only after provisioning is complete.");
            return;
        }
        if (write_busy_if_pending_or_local_flow_active(id)) {
            return;
        }

        const char* session_id = request["sessionId"] | "";
        if (!require_active_matching_session(id, session_id)) {
            return;
        }

        write_capabilities_response(id);
        ESP_LOGI(kTag, "get_capabilities: id=%s", id);
        return;
    }

    if (strcmp(type, "get_accounts") == 0) {
        // get_accounts is a session-scoped read-only request. State and session
        // guards are checked before deriving; no approval UI and no pending
        // state are involved.
        if (!provisioned_material_ready()) {
            write_error_response(id, "invalid_state", "Accounts are available only after provisioning is complete.");
            return;
        }
        if (write_busy_if_pending_or_local_flow_active(id)) {
            return;
        }

        const char* session_id = request["sessionId"] | "";
        if (!require_active_matching_session(id, session_id)) {
            return;
        }

        if (!write_accounts_response(id)) {
            write_error_response(id, "account_error", "Could not derive accounts.");
            ESP_LOGW(kTag, "get_accounts derivation failed: id=%s", id);
            return;
        }
        ESP_LOGI(kTag, "get_accounts: id=%s", id);
        return;
    }

    if (strcmp(type, "get_policy") == 0) {
        // get_policy is a session-scoped read-only request. Firmware returns
        // metadata for the active policy document it will use for method
        // decisions; Gateway must not infer policy state from local defaults.
        if (!provisioned_material_ready()) {
            write_error_response(id, "invalid_state", "Policy is available only after provisioning is complete.");
            return;
        }
        if (write_busy_if_pending_or_local_flow_active(id)) {
            return;
        }

        const char* session_id = request["sessionId"] | "";
        if (!require_active_matching_session(id, session_id)) {
            return;
        }

        if (!write_policy_response(id)) {
            write_error_response(id, "policy_error", "Active policy is unavailable.");
            ESP_LOGW(kTag, "get_policy active policy unavailable: id=%s", id);
            return;
        }
        ESP_LOGI(kTag, "get_policy: id=%s", id);
        return;
    }

    if (strcmp(type, "call_method") == 0) {
        // Runtime skeleton only: Firmware enforces state/session gates, recognizes
        // Sui sign_transaction for rejected policy-decision smoke, and does not
        // sign or advertise callable methods yet.
        if (!provisioned_material_ready()) {
            write_error_response(id, "invalid_state", "call_method is available only after provisioning is complete.");
            return;
        }
        if (write_busy_if_pending_or_local_flow_active(id)) {
            return;
        }

        const char* session_id = request["sessionId"] | "";
        if (!require_active_matching_session(id, session_id)) {
            return;
        }

        switch (agent_q::validate_call_method_request_fields(request)) {
            case agent_q::CallMethodFieldValidation::valid:
                break;
            case agent_q::CallMethodFieldValidation::invalid_method:
                write_error_response(id, "invalid_method", "Invalid call_method chain or method.");
                return;
            case agent_q::CallMethodFieldValidation::invalid_params_shape:
                write_error_response(id, "invalid_params", "call_method params must be an object.");
                return;
            case agent_q::CallMethodFieldValidation::invalid_params_size:
                write_error_response(id, "invalid_params", "call_method params are too large for the runtime.");
                return;
        }

        const char* chain = request["chain"] | "";
        const char* method = request["method"] | "";
        if (strcmp(chain, "sui") == 0 && strcmp(method, "sign_transaction") == 0) {
            write_sui_sign_transaction_policy_decision(id, request);
            return;
        }

        write_rejected_method_result(id, "unsupported_method", "Method is not supported.");
        ESP_LOGI(kTag, "call_method unsupported: id=%s", id);
        return;
    }

    write_error_response(id, "unsupported_type", "Unsupported request type.");
}

void poll_usb_input()
{
    uint8_t buffer[64];
    const int read_count = usb_serial_jtag_read_bytes(buffer, sizeof(buffer), 0);
    if (read_count <= 0) {
        return;
    }

    for (int index = 0; index < read_count; ++index) {
        const char c = static_cast<char>(buffer[index]);
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            g_line_buffer[g_line_size] = '\0';
            if (g_line_size > 0) {
                handle_line(g_line_buffer);
            }
            g_line_size = 0;
            continue;
        }

        if (g_line_size + 1 >= sizeof(g_line_buffer)) {
            g_line_size = 0;
            write_error_response(nullptr, "invalid_json", "JSON line is too long.");
            continue;
        }

        g_line_buffer[g_line_size++] = c;
    }
}

void usb_request_task(void*)
{
    // Ordering matters: any pending YES/NO choice is resolved and its response is
    // sent (send_choice_response_if_needed) before new input is read
    // (poll_usb_input). A new request therefore cannot be handled until the
    // in-flight approval response has been written in the same loop pass.
    while (true) {
        clear_identification_if_needed();
        clear_agent_q_message_if_needed();
        clear_setup_choice_if_needed();
        clear_recovery_phrase_if_needed();
        clear_recovery_word_entry_if_needed();
        clear_pin_setup_if_needed();
        clear_local_reset_if_needed();
        clear_local_pin_auth_if_needed();
        drain_ui_events();
        commit_local_setup_if_ready();
        verify_local_reset_pin_if_ready();
        commit_local_reset_if_ready();
        verify_local_pin_auth_if_ready();
        commit_local_pin_setting_if_ready();
        expire_session_if_needed();
        poll_local_settings_touch_entry();
        send_choice_response_if_needed();
        ensure_pending_request_ui();
        if (g_usb_ready) {
            poll_usb_host_connection();
            poll_usb_input();
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

}  // namespace

namespace agent_q {

void init_usb_request_server()
{
    load_or_create_device_id();
    load_provisioning_state();
    g_session.clear();
    g_session.next_expiry_check = 0;
    g_pending.clear();
    g_identification.clear();
    wipe_setup_scratch("usb request server init");
    wipe_local_reset_scratch("usb request server init");
    if (g_pending_choice_queue == nullptr) {
        g_pending_choice_queue = xQueueCreate(4, sizeof(PendingChoice));
        if (g_pending_choice_queue == nullptr) {
            ESP_LOGE(kTag, "Pending choice queue create failed");
        }
    } else {
        xQueueReset(g_pending_choice_queue);
    }
    if (g_ui_event_queue == nullptr) {
        g_ui_event_queue = xQueueCreate(4, sizeof(AgentQUiEvent));
        if (g_ui_event_queue == nullptr) {
            ESP_LOGE(kTag, "UI event queue create failed");
        }
    } else {
        xQueueReset(g_ui_event_queue);
    }
    g_ui = AgentQUiState{};

    if (!usb_serial_jtag_is_driver_installed()) {
        usb_serial_jtag_driver_config_t config = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
        config.tx_buffer_size = 1024;
        config.rx_buffer_size = 1024;
        const esp_err_t result = usb_serial_jtag_driver_install(&config);
        if (result != ESP_OK) {
            ESP_LOGE(kTag, "USB serial driver install failed: %s", esp_err_to_name(result));
            return;
        }
    }

    g_usb_ready = true;
    if (g_usb_task == nullptr) {
        BaseType_t task_created = xTaskCreatePinnedToCore(
            usb_request_task, "agent_q_usb", 4096, nullptr, 4, &g_usb_task, 1);
        if (task_created != pdPASS) {
            ESP_LOGE(kTag, "USB request task start failed");
            g_usb_ready = false;
            g_usb_task = nullptr;
            return;
        }
    }
    ESP_LOGI(kTag, "USB request server ready");
}

void show_provisioning_welcome_if_needed()
{
    enqueue_ui_event(AgentQUiEventKind::provisioning_welcome_requested);
}

}  // namespace agent_q
