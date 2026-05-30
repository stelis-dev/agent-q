#include "agent_q_usb_request_server.h"

#include <stdio.h>
#include <string.h>

#include <ArduinoJson.h>
#include <memory>
#include "agent_q_bip39.h"
#include "agent_q_call_method_validation.h"
#include "agent_q_display_power.h"
#include "agent_q_entropy.h"
#include "agent_q_local_auth.h"
#include "agent_q_motion_state.h"
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
constexpr uint32_t kIdentifyDisplayDefaultMs = 10000;
constexpr uint32_t kIdentifyDisplayMaxMs = 30000;
constexpr uint32_t kConnectApprovalDefaultMs = 30000;
constexpr uint32_t kConnectApprovalMaxMs = 60000;
constexpr uint32_t kProvisioningApprovalMaxMs = 60000;
constexpr uint32_t kRecoveryPhraseDisplayMs = kProvisioningApprovalMaxMs;
constexpr uint32_t kLocalPinSetupMs = kProvisioningApprovalMaxMs;
constexpr uint32_t kSessionTtlMs = 1800000;
constexpr uint32_t kSessionExpiryCheckMs = 5000;
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
constexpr uint32_t kSetupCellBorderColor = 0xB7E4C7;
constexpr uint32_t kDisabledControlTextColor = 0x98A2B3;
constexpr uint32_t kDisabledActionTextColor = 0xEAECF0;
constexpr uint32_t kLocalSetupCommitDisplayDelayMs = 120;
constexpr uint32_t kAgentQResultDisplayMs = 1800;

enum class AgentQUiPanelKind {
    none,
    decision_strip,
    recovery_phrase_display,
    pin_entry,
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
    provisioning_welcome_requested,
    recovery_phrase_cancel_requested,
    recovery_phrase_confirm_requested,
    pin_digit_requested,
    pin_clear_requested,
    pin_backspace_requested,
    pin_submit_requested,
    pin_cancel_requested,
};

struct AgentQUiEvent {
    AgentQUiEventKind kind = AgentQUiEventKind::panel_deleted;
    AgentQUiPanelKind panel_kind = AgentQUiPanelKind::none;
    char digit = '\0';
};

enum class PendingKind {
    none,
    connect,
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
        return active && choice == PendingChoice::none;
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

enum class SetupScratchStage {
    none,
    recovery_phrase_displayed,
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
    char pin_first[agent_q::kLocalPinBufferSize] = {};
    char pin_entry[agent_q::kLocalPinBufferSize] = {};
    size_t pin_entry_length = 0;
    SetupScratchStage setup_stage = SetupScratchStage::none;
    TickType_t recovery_phrase_deadline = 0;
    TickType_t pin_deadline = 0;
    TickType_t pin_commit_ready_at = 0;

    void wipe()
    {
        agent_q::wipe_sensitive_buffer(root_material, sizeof(root_material));
        agent_q::wipe_sensitive_buffer(recovery_phrase, sizeof(recovery_phrase));
        agent_q::wipe_sensitive_buffer(
            recovery_phrase_prefix_cells,
            kRecoveryPhrasePrefixCellCount * kRecoveryPhrasePrefixCellSize);
        wipe_pin_only();
        setup_stage = SetupScratchStage::none;
        recovery_phrase_deadline = 0;
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
bool g_usb_ready = false;
TaskHandle_t g_usb_task = nullptr;
QueueHandle_t g_pending_choice_queue = nullptr;
QueueHandle_t g_ui_event_queue = nullptr;

bool recovery_phrase_display_panel_active();
bool refresh_persistent_material_consistency();
bool persist_provisioning_state(ProvisioningRuntimeState next_state);

void wipe_setup_scratch(const char* reason)
{
    const bool had_setup_scratch = g_provisioning_scratch.setup_flow_active();
    g_provisioning_scratch.wipe();
    if (had_setup_scratch) {
        ESP_LOGW(kTag, "Setup scratch wiped: %s", reason != nullptr ? reason : "unspecified");
    }
}

bool is_decision_panel_kind(AgentQUiPanelKind kind)
{
    return kind == AgentQUiPanelKind::decision_strip;
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
    if (g_provisioning_scratch.setup_flow_active()) {
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
    response["provisioning"]["state"] = provisioning_state_to_string(g_provisioning_state);
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

bool persistent_setup_material_exists()
{
    return agent_q::has_root_material() ||
           agent_q::active_policy_status() != agent_q::AgentQPolicyStoreStatus::missing ||
           agent_q::local_auth_status() != agent_q::AgentQLocalAuthStatus::missing;
}

void enter_persistent_material_consistency_error(const char* message)
{
    g_persistent_material_consistency_error = true;
    clear_active_session();
    ESP_LOGE(kTag, "%s", message != nullptr ? message : "Persistent material consistency error; failing closed");
}

void enter_persistent_material_consistency_error_if_material_remains(const char* message)
{
    if (persistent_setup_material_exists()) {
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
        if (persistent_setup_material_exists()) {
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
           !g_pending.active;
}

bool recovery_phrase_display_panel_active()
{
    LvglLockGuard lock;
    return g_ui.panel != nullptr &&
           g_ui.panel_kind == AgentQUiPanelKind::recovery_phrase_display;
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

bool write_busy_if_pending_or_setup_flow_active(const char* id)
{
    if (g_pending.active) {
        write_error_response(id, "busy", "Device is awaiting physical input.");
        return true;
    }
    if (g_provisioning_scratch.setup_flow_active()) {
        write_error_response(id, "busy", "Device is showing setup material.");
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
    lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(label, label_color, 0);
    lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
    lv_obj_center(label);
    return true;
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
    lv_obj_add_event_cb(g_ui.panel, on_agent_q_panel_deleted, LV_EVENT_DELETE, nullptr);
}

enum class SensitiveSetupClearPolicy {
    wipe,
    preserve,
};

void clear_panel_locked(SensitiveSetupClearPolicy policy = SensitiveSetupClearPolicy::wipe)
{
    if (g_ui.panel != nullptr) {
        lv_obj_t* panel = g_ui.panel;
        const AgentQUiPanelKind panel_kind = g_ui.panel_kind;
        g_ui.panel = nullptr;
        g_ui.panel_kind = AgentQUiPanelKind::none;
        const bool wipe_setup_after_delete =
            policy == SensitiveSetupClearPolicy::wipe &&
            (panel_kind == AgentQUiPanelKind::recovery_phrase_display ||
             panel_kind == AgentQUiPanelKind::pin_entry);
        lv_obj_delete(panel);
        if (wipe_setup_after_delete) {
            wipe_setup_scratch("sensitive setup panel cleared");
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
    clear_panel_locked();
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
        clear_panel_locked();

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

bool show_recovery_phrase_display(const char* recovery_phrase)
{
    if (!format_recovery_phrase_prefix_cells(
            recovery_phrase, g_provisioning_scratch.recovery_phrase_prefix_cells)) {
        return false;
    }

    clear_agent_q_request_ui();

    LvglLockGuard lock;
    clear_panel_locked();

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
        clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, "BIP-39 prefixes (DEV)");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, kRecoveryPhraseTopMargin);

    lv_obj_t* warning = lv_label_create(g_ui.panel);
    if (warning == nullptr) {
        clear_panel_locked();
        return false;
    }
    lv_label_set_text(warning, "Write up-to-4-letter prefixes. Host cannot read them.");
    lv_label_set_long_mode(warning, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(warning, kScreenWidth - 44);
    lv_obj_set_style_text_align(warning, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(warning, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(warning, lv_color_hex(0x3A2B00), 0);
    lv_obj_align(warning, LV_ALIGN_TOP_MID, 0, 22 + kRecoveryPhraseTopMargin);

    constexpr int kGridLeft = 17;
    constexpr int kGridTop = 58 + kRecoveryPhraseTopMargin;
    constexpr int kGridCellWidth = 90;
    constexpr int kGridCellHeight = 22;
    constexpr int kGridRowHeight = 25;
    constexpr int kIndexWidth = 22;
    constexpr int kPrefixLeft = 30;
    constexpr int kPrefixWidth = 54;
    for (size_t index = 0; index < kRecoveryPhrasePrefixCellCount; ++index) {
        lv_obj_t* cell = lv_obj_create(g_ui.panel);
        if (cell == nullptr) {
            clear_panel_locked();
            return false;
        }
        lv_obj_remove_flag(cell, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_size(cell, kGridCellWidth, kGridCellHeight);
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
            kGridLeft + column * kGridCellWidth,
            kGridTop + row * kGridRowHeight);

        lv_obj_t* index_label = lv_label_create(cell);
        if (index_label == nullptr) {
            clear_panel_locked();
            return false;
        }
        char index_text[3] = {};
        snprintf(index_text, sizeof(index_text), "%02u", static_cast<unsigned>(index + 1));
        lv_label_set_text(index_label, index_text);
        lv_label_set_long_mode(index_label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(index_label, kIndexWidth);
        lv_obj_set_style_text_align(index_label, LV_TEXT_ALIGN_RIGHT, 0);
        lv_obj_set_style_text_font(index_label, &lv_font_unscii_8, 0);
        lv_obj_set_style_text_color(index_label, lv_color_hex(0x475467), 0);
        lv_obj_align(index_label, LV_ALIGN_LEFT_MID, 4, 0);

        lv_obj_t* prefix_label = lv_label_create(cell);
        if (prefix_label == nullptr) {
            clear_panel_locked();
            return false;
        }
        lv_label_set_text_static(prefix_label, g_provisioning_scratch.recovery_phrase_prefix_cells[index]);
        lv_label_set_long_mode(prefix_label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(prefix_label, kPrefixWidth);
        lv_obj_set_style_text_align(prefix_label, LV_TEXT_ALIGN_LEFT, 0);
        lv_obj_set_style_text_font(prefix_label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(prefix_label, lv_color_hex(0x111827), 0);
        lv_obj_align(prefix_label, LV_ALIGN_LEFT_MID, kPrefixLeft, 0);
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
        clear_panel_locked();
        return false;
    }

    lv_obj_move_foreground(g_ui.panel);
    return true;
}

bool show_pin_setup_panel(const char* notice = nullptr)
{
    clear_agent_q_avatar_ui();

    LvglLockGuard lock;
    clear_panel_locked(SensitiveSetupClearPolicy::preserve);

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
        clear_panel_locked();
        return false;
    }
    lv_label_set_text(title, committing_stage ? "Saving setup" : (repeat_stage ? "Repeat 6-digit PIN" : "Set 6-digit PIN"));
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0x063A1D), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 8);

    lv_obj_t* message = lv_label_create(g_ui.panel);
    if (message == nullptr) {
        clear_panel_locked();
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
        clear_panel_locked();
        return false;
    }
    lv_label_set_text(pin_label, pin_text);
    lv_obj_set_style_text_font(pin_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(pin_label, lv_color_hex(0x111827), 0);
    lv_obj_align(pin_label, LV_ALIGN_TOP_MID, 0, 58);

    static const char* const kDigits[10] = {
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    };
    constexpr int kButtonWidth = 90;
    constexpr int kGridLeft = 17;
    constexpr int kGridTop = 78;
    constexpr int kRowHeight = 25;
    for (int digit = 1; digit <= 9; ++digit) {
        const int index = digit - 1;
        const int column = index % 3;
        const int row = index / 3;
        if (!make_setup_button(
                g_ui.panel,
                kDigits[digit],
                kGridLeft + column * kButtonWidth,
                kGridTop + row * kRowHeight,
                kButtonWidth,
                kPinPanelButtonHeight,
                SetupButtonKind::outlined_keypad,
                lv_color_hex(0x1D4ED8),
                on_pin_digit_clicked,
                kDigits[digit],
                buttons_enabled)) {
            clear_panel_locked();
            return false;
        }
    }

    if (!make_setup_button(
            g_ui.panel,
            "Clear",
            kGridLeft,
            kGridTop + 3 * kRowHeight,
            kButtonWidth,
            kPinPanelButtonHeight,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(0x667085),
            on_pin_clear_clicked,
            nullptr,
            buttons_enabled) ||
        !make_setup_button(
            g_ui.panel,
            kDigits[0],
            kGridLeft + kButtonWidth,
            kGridTop + 3 * kRowHeight,
            kButtonWidth,
            kPinPanelButtonHeight,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(0x1D4ED8),
            on_pin_digit_clicked,
            kDigits[0],
            buttons_enabled) ||
        !make_setup_button(
            g_ui.panel,
            LV_SYMBOL_BACKSPACE,
            kGridLeft + 2 * kButtonWidth,
            kGridTop + 3 * kRowHeight,
            kButtonWidth,
            kPinPanelButtonHeight,
            SetupButtonKind::outlined_keypad,
            lv_color_hex(0x667085),
            on_pin_backspace_clicked,
            nullptr,
            buttons_enabled)) {
        clear_panel_locked();
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
        clear_panel_locked();
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

void clear_recovery_phrase_if_needed()
{
    if (g_provisioning_scratch.setup_stage != SetupScratchStage::recovery_phrase_displayed) {
        return;
    }

    const bool panel_active = recovery_phrase_display_panel_active();
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

    bool panel_active = false;
    {
        LvglLockGuard lock;
        panel_active = g_ui.panel != nullptr &&
                       g_ui.panel_kind == AgentQUiPanelKind::pin_entry;
    }
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
        xTaskGetTickCount() + pdMS_TO_TICKS(kLocalSetupCommitDisplayDelayMs);
    agent_q::wipe_sensitive_buffer(g_provisioning_scratch.pin_first, sizeof(g_provisioning_scratch.pin_first));
    if (!show_pin_setup_panel()) {
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
    if (!local_setup_start_allowed()) {
        ESP_LOGW(kTag, "Local setup touch ignored because setup is unavailable");
        clear_agent_q_request_ui();
        show_agent_q_message("Setup unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    clear_agent_q_request_ui();
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

void drain_ui_events()
{
    if (g_ui_event_queue == nullptr) {
        return;
    }

    AgentQUiEvent event;
    while (xQueueReceive(g_ui_event_queue, &event, 0) == pdTRUE) {
        if (event.kind == AgentQUiEventKind::setup_requested) {
            start_local_provisioning_from_setup_touch();
            continue;
        }

        if (event.kind == AgentQUiEventKind::provisioning_welcome_requested) {
            show_provisioning_welcome_if_available();
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

        if (event.kind == AgentQUiEventKind::pin_digit_requested) {
            handle_pin_digit_from_local_ui(event.digit);
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_clear_requested) {
            handle_pin_clear_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_backspace_requested) {
            handle_pin_backspace_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_submit_requested) {
            handle_pin_submit_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_cancel_requested) {
            cancel_setup_from_local_ui();
            continue;
        }

        if (event.kind != AgentQUiEventKind::panel_deleted) {
            continue;
        }
        if (event.panel_kind == AgentQUiPanelKind::recovery_phrase_display &&
            g_provisioning_scratch.setup_stage == SetupScratchStage::recovery_phrase_displayed) {
            wipe_setup_scratch("recovery phrase panel deleted");
        } else if (event.panel_kind == AgentQUiPanelKind::pin_entry &&
                   (g_provisioning_scratch.setup_stage == SetupScratchStage::pin_first_entry ||
                    g_provisioning_scratch.setup_stage == SetupScratchStage::pin_repeat_entry)) {
            wipe_setup_scratch("local PIN setup panel deleted");
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
        if (write_busy_if_pending_or_setup_flow_active(id)) {
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
        if (write_busy_if_pending_or_setup_flow_active(id)) {
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

        g_pending.begin_connect(id, gateway_name, approval_timeout_ms);
        show_connect_decision(g_pending.gateway_name);
        ESP_LOGI(kTag, "connect waiting for YES/NO: id=%s gateway=%s", id, g_pending.gateway_name);
        return;
    }

    if (strcmp(type, "disconnect") == 0) {
        if (!provisioned_material_ready()) {
            write_error_response(id, "invalid_state", "Disconnect is available only after provisioning is complete.");
            return;
        }
        if (write_busy_if_pending_or_setup_flow_active(id)) {
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
        if (write_busy_if_pending_or_setup_flow_active(id)) {
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
        if (write_busy_if_pending_or_setup_flow_active(id)) {
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
        if (write_busy_if_pending_or_setup_flow_active(id)) {
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
        if (write_busy_if_pending_or_setup_flow_active(id)) {
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
        drain_ui_events();
        clear_identification_if_needed();
        clear_agent_q_message_if_needed();
        clear_recovery_phrase_if_needed();
        clear_pin_setup_if_needed();
        commit_local_setup_if_ready();
        expire_session_if_needed();
        send_choice_response_if_needed();
        ensure_pending_request_ui();
        if (g_usb_ready) {
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
