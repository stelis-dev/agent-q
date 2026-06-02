#include "agent_q_usb_request_server.h"

#include <stdio.h>
#include <string.h>

#include <ArduinoJson.h>
#include <memory>
#include "agent_q_u64_decimal.h"
#include "agent_q_avatar_overlay_drawing.h"
#include "agent_q_approval_history.h"
#include "agent_q_bip39.h"
#include "agent_q_bip39_wordlist.h"
#include "agent_q_call_method_validation.h"
#include "agent_q_connect_approval.h"
#include "agent_q_connect_settings.h"
#include "agent_q_drawing_surface.h"
#include "agent_q_entropy.h"
#include "agent_q_identification_display.h"
#include "agent_q_json_input.h"
#include "agent_q_local_auth.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_local_pin_auth.h"
#include "agent_q_local_settings_touch_entry.h"
#include "agent_q_local_reset.h"
#include "agent_q_method_runtime.h"
#include "agent_q_modal_drawing.h"
#include "agent_q_persistent_material.h"
#include "agent_q_policy_store.h"
#include "agent_q_protocol_pin_approval.h"
#include "agent_q_policy_update_flow.h"
#include "agent_q_provisioning_flow.h"
#include "agent_q_provisioning_state_store.h"
#include "agent_q_session.h"
#include "agent_q_sui_account.h"
#include "agent_q_sui_account_store.h"
#include "agent_q_usb_response_writer.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"
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

using AgentQUiPanelKind = agent_q::AgentQUiPanelKind;
using AgentQMessageKind = agent_q::AgentQMessageKind;
using AgentQUiMode = agent_q::AgentQUiMode;
using ConnectApprovalChoice = agent_q::AgentQConnectApprovalChoice;
using LocalPinAuthPurpose = agent_q::AgentQLocalPinAuthPurpose;
using LocalPinAuthStage = agent_q::AgentQLocalPinAuthStage;
using ProvisioningFlowGenerateResult = agent_q::AgentQProvisioningFlowGenerateResult;
using ProvisioningFlowPanel = agent_q::AgentQProvisioningFlowPanel;
using ProvisioningFlowPinSubmitResult = agent_q::AgentQProvisioningFlowPinSubmitResult;
using ProvisioningFlowStage = agent_q::AgentQProvisioningFlowStage;
using ProvisioningRuntimeState = agent_q::AgentQProvisioningRuntimeState;
using SensitiveUiClearPolicy = agent_q::SensitiveUiClearPolicy;

constexpr const char* kTag = "UsbRequestServer";
constexpr int kProtocolVersion = 1;
constexpr const char* kFirmwareName = "Agent-Q Firmware";
constexpr const char* kHardwareId = "stackchan-cores3";
constexpr const char* kFirmwareVersion = "0.0.0";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kDeviceIdKey = "device_id";
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
constexpr uint32_t kUsbHostLinkCheckMs = 10;
constexpr size_t kMaxRawJsonObjectBytes = 4096;
constexpr size_t kLineBufferSize = kMaxRawJsonObjectBytes + 1;
constexpr uint32_t kUsbRequestTaskStackBytes = 8192;
constexpr size_t kMaxRequestIdSize = 80;
constexpr size_t kDeviceIdSize = 37;
constexpr size_t kIdentifyCodeSize = 5;
constexpr size_t kGatewayNameSize = 65;
constexpr size_t kConnectDisplayMessageSize = 96;
constexpr size_t kRecoverWordsPerPage = agent_q::kProvisioningFlowRecoverWordsPerPage;
constexpr int kScreenWidth = 320;
constexpr int kSettingsTouchEntryWidth = 64;
constexpr int kSettingsTouchEntryHeight = 56;
constexpr uint32_t kAgentQResultDisplayMs = 1800;

enum class AgentQUiEventKind {
    panel_deleted,
    setup_requested,
    setup_generate_requested,
    setup_recover_requested,
    setup_cancel_requested,
    ui_surface_ready,
    settings_requested,
    settings_cancel_requested,
    settings_connect_pin_requested,
    settings_change_pin_requested,
    settings_reset_requested,
    error_recovery_erase_requested,
    error_recovery_cancel_requested,
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

char g_line_buffer[kLineBufferSize];
size_t g_line_size = 0;
bool g_discarding_invalid_line = false;
char g_device_id[kDeviceIdSize];
ProvisioningRuntimeState g_provisioning_state = ProvisioningRuntimeState::unprovisioned;
static_assert(
    kMaxRequestIdSize == agent_q::kAgentQProtocolPinRequestIdSize,
    "Protocol PIN approval request-id storage must match USB request-id storage.");
static_assert(
    kMaxRequestIdSize == agent_q::kAgentQConnectApprovalRequestIdSize,
    "Connect approval request-id storage must match USB request-id storage.");
static_assert(
    kGatewayNameSize == agent_q::kAgentQConnectApprovalGatewayNameSize,
    "Connect approval gateway-name storage must match USB gateway-name storage.");

bool g_connect_decision_touch_armed = false;
bool g_usb_ready = false;
bool g_usb_host_connected_known = false;
bool g_usb_host_connected = false;
TickType_t g_next_usb_host_check = 0;
TaskHandle_t g_usb_task = nullptr;
QueueHandle_t g_connect_decision_choice_queue = nullptr;
QueueHandle_t g_ui_event_queue = nullptr;

bool refresh_persistent_material_consistency();
bool persist_provisioning_state(ProvisioningRuntimeState next_state);
agent_q::AgentQPersistentMaterialOps persistent_material_ops();
agent_q::AgentQLocalResetPersistenceOps local_reset_persistence_ops();
bool clear_agent_q_panel_if_kind(
    AgentQUiPanelKind expected_kind,
    SensitiveUiClearPolicy policy = SensitiveUiClearPolicy::wipe);
bool clear_agent_q_panel_if_local_reset_stage(
    SensitiveUiClearPolicy policy = SensitiveUiClearPolicy::wipe);
bool clear_agent_q_panel_if_local_pin_auth_stage(
    SensitiveUiClearPolicy policy = SensitiveUiClearPolicy::wipe);
void clear_connect_decision_state();
void cancel_policy_update_after_session_loss(const char* log_reason);
void show_persistent_error_recovery_if_needed();

void wipe_setup_scratch(const char* reason)
{
    const bool had_setup_scratch = agent_q::provisioning_flow_active();
    agent_q::provisioning_flow_wipe();
    if (had_setup_scratch) {
        ESP_LOGW(kTag, "Setup scratch wiped: %s", reason != nullptr ? reason : "unspecified");
    }
}

void wipe_local_reset_scratch(const char* reason)
{
    const bool had_reset_scratch =
        agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active;
    agent_q::local_reset_wipe();
    agent_q::local_settings_touch_entry_clear();
    if (had_reset_scratch) {
        ESP_LOGW(kTag, "Local reset scratch wiped: %s", reason != nullptr ? reason : "unspecified");
    }
}

void wipe_local_pin_auth_scratch(const char* reason)
{
    const bool had_pin_auth = agent_q::local_pin_auth_flow_active();
    agent_q::local_pin_auth_clear_flow();
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
           agent_q::local_pin_auth_flow_active();
}

bool local_pin_auth_accepts_keypad_input()
{
    return agent_q::local_pin_auth_accepts_keypad_input();
}

bool local_reset_panel_matches_stage(AgentQUiPanelKind kind)
{
    const agent_q::AgentQLocalResetStage stage =
        agent_q::local_reset_snapshot(xTaskGetTickCount()).stage;
    return (kind == AgentQUiPanelKind::settings_menu &&
            stage == agent_q::AgentQLocalResetStage::settings_menu) ||
           (kind == AgentQUiPanelKind::reset_pin_entry &&
            stage == agent_q::AgentQLocalResetStage::pin_entry) ||
           (kind == AgentQUiPanelKind::error_recovery &&
            stage == agent_q::AgentQLocalResetStage::error_recovery_confirm);
}

bool provisioning_flow_panel_deleted(AgentQUiPanelKind kind, const char* reason)
{
    ProvisioningFlowPanel panel;
    switch (kind) {
        case AgentQUiPanelKind::setup_choice:
            panel = ProvisioningFlowPanel::setup_choice;
            break;
        case AgentQUiPanelKind::recovery_phrase_display:
            panel = ProvisioningFlowPanel::recovery_phrase_display;
            break;
        case AgentQUiPanelKind::recovery_word_entry:
            panel = ProvisioningFlowPanel::recovery_word_entry;
            break;
        case AgentQUiPanelKind::pin_entry:
            panel = ProvisioningFlowPanel::pin_entry;
            break;
        default:
            return false;
    }
    const bool wiped = agent_q::provisioning_flow_handle_panel_deleted(panel);
    if (wiped) {
        ESP_LOGW(kTag, "Setup scratch wiped: %s", reason != nullptr ? reason : "panel deleted");
    }
    return wiped;
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

bool write_error_response(const char* id, const char* code, const char* message)
{
    JsonDocument response;
    if (id != nullptr && id[0] != '\0') {
        response["id"] = id;
    }
    response["version"] = kProtocolVersion;
    response["type"] = "error";
    response["error"]["code"] = code;
    response["error"]["message"] = message;
    return agent_q::usb_response_write_json(response);
}

void log_response_write_failure(const char* response_type, const char* id)
{
    ESP_LOGW(kTag,
             "USB response write failed: type=%s id=%s",
             response_type != nullptr ? response_type : "",
             id != nullptr ? id : "");
}

const char* current_device_state()
{
    if (agent_q::persistent_material_consistency_error_active()) {
        return "error";
    }
    if (agent_q::connect_approval_active() || agent_q::protocol_pin_approval_active()) {
        return "awaiting_approval";
    }
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    if (agent_q::provisioning_flow_active() ||
        (reset.flow_active &&
         reset.stage != agent_q::AgentQLocalResetStage::settings_menu) ||
        agent_q::local_pin_auth_flow_active()) {
        return "busy";
    }
    return "idle";
}

const char* reported_provisioning_state()
{
    if (agent_q::persistent_material_consistency_error_active()) {
        return kProvisioningStateError;
    }
    return agent_q::provisioning_runtime_state_to_string(g_provisioning_state);
}

bool write_status_response(const char* id)
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
    return agent_q::usb_response_write_json(response);
}

bool write_identify_device_result(const char* id, const char* code)
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
    return agent_q::usb_response_write_json(response);
}

bool write_connect_approved_response(const char* id)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "connect_result";
    response["status"] = "approved";
    response["sessionId"] = agent_q::session_id();
    response["sessionTtlMs"] = agent_q::kAgentQSessionAdvertisedTtlMs;
    response["device"]["deviceId"] = g_device_id;
    response["device"]["state"] = "idle";
    response["device"]["firmwareName"] = kFirmwareName;
    response["device"]["hardware"] = kHardwareId;
    response["device"]["firmwareVersion"] = kFirmwareVersion;
    return agent_q::usb_response_write_json(response);
}

bool write_connect_rejected_response(const char* id, const char* error_code, const char* error_message)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "connect_result";
    response["status"] = "rejected";
    response["error"]["code"] = error_code;
    response["error"]["message"] = error_message;
    return agent_q::usb_response_write_json(response);
}

bool write_disconnect_result(const char* id)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "disconnect_result";
    response["status"] = "disconnected";
    return agent_q::usb_response_write_json(response);
}

bool write_rejected_method_result(const char* id, const char* code, const char* message)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "method_result";
    response["status"] = "rejected";
    response["error"]["code"] = code;
    response["error"]["message"] = message;
    return agent_q::usb_response_write_json(response);
}

bool write_capabilities_response(const char* id)
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
    return agent_q::usb_response_write_json(response);
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
    return agent_q::usb_response_write_json(response);
}

bool write_approval_history_response(const char* id, uint64_t before_sequence, size_t limit)
{
    agent_q::AgentQApprovalHistoryPage page = {};
    const agent_q::AgentQApprovalHistoryReadResult read_result =
        agent_q::approval_history_read_page(before_sequence, limit, &page);
    if (read_result != agent_q::AgentQApprovalHistoryReadResult::ok) {
        return false;
    }

    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "approval_history";
    response["hasMore"] = page.has_more;
    JsonArray records = response["records"].to<JsonArray>();
    for (size_t index = 0; index < page.count; ++index) {
        const agent_q::AgentQApprovalHistoryRecord& source = page.records[index];
        JsonObject record = records.add<JsonObject>();
        char sequence[agent_q::kAgentQU64DecimalBufferBytes] = {};
        char uptime_ms[agent_q::kAgentQU64DecimalBufferBytes] = {};
        if (!agent_q::format_u64_decimal(source.sequence, sequence, sizeof(sequence)) ||
            !agent_q::format_u64_decimal(source.uptime_ms, uptime_ms, sizeof(uptime_ms))) {
            return false;
        }
        record["seq"] = sequence;
        record["uptimeMs"] = uptime_ms;
        record["timeSource"] = "uptime";
        record["reasonCode"] = source.reason_code;
        if (source.event_kind == agent_q::AgentQApprovalHistoryEventKind::policy_update) {
            record["eventKind"] = "policy_update";
            record["result"] = source.policy_result;
            record["policyHash"] = source.policy_hash;
            record["ruleCount"] = source.rule_count;
            record["highestAction"] = source.highest_action;
        } else {
            record["eventKind"] = "method_decision";
            record["decisionKind"] = agent_q::approval_history_decision_to_string(source.decision);
            record["confirmationKind"] =
                agent_q::approval_history_confirmation_kind_to_string(source.confirmation_kind);
            record["chain"] = source.chain;
            record["method"] = source.method;
            if (source.payload_digest[0] != '\0') {
                record["payloadDigest"] = source.payload_digest;
            }
            if (source.policy_hash[0] != '\0') {
                record["policyHash"] = source.policy_hash;
            }
            if (source.rule_ref[0] != '\0') {
                record["ruleRef"] = source.rule_ref;
            }
        }
    }
    return agent_q::usb_response_write_json(response);
}

bool write_policy_update_result_response(
    const char* id,
    const char* status,
    const char* reason_code,
    bool include_policy)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "policy_update_result";
    response["status"] = status;
    response["reasonCode"] = reason_code;
    if (include_policy) {
        const agent_q::AgentQPolicyUpdateFlowSnapshot snapshot =
            agent_q::policy_update_flow_snapshot();
        JsonObject policy = response["policy"].to<JsonObject>();
        policy["policyHash"] = snapshot.policy_hash;
        policy["ruleCount"] = snapshot.rule_count;
        policy["highestAction"] = snapshot.highest_action;
    }
    return agent_q::usb_response_write_json(response);
}

bool parse_approval_history_params(JsonDocument& request, size_t* limit, uint64_t* before_sequence)
{
    if (limit == nullptr || before_sequence == nullptr) {
        return false;
    }
    *limit = agent_q::kAgentQApprovalHistoryPageMax;
    *before_sequence = 0;

    JsonVariant params = request["params"];
    if (params.isNull()) {
        return true;
    }
    if (!params.is<JsonObject>()) {
        return false;
    }

    JsonObject params_object = params.as<JsonObject>();
    for (JsonPair pair : params_object) {
        JsonVariant value = pair.value();
        if (agent_q::agent_q_json_string_equals(pair.key(), "limit")) {
            if (!value.is<unsigned int>()) {
                return false;
            }
            const unsigned int requested_limit = value.as<unsigned int>();
            if (requested_limit == 0 ||
                requested_limit > agent_q::kAgentQApprovalHistoryPageMax) {
                return false;
            }
            *limit = requested_limit;
            continue;
        }
        if (agent_q::agent_q_json_string_equals(pair.key(), "beforeSeq")) {
            const char* before_value = nullptr;
            if (!agent_q::agent_q_json_value_c_string(value, &before_value)) {
                return false;
            }
            if (!agent_q::approval_history_parse_sequence(before_value, before_sequence)) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

void clear_active_session()
{
    agent_q::session_clear();
}

bool persist_unprovisioned_state_for_local_reset()
{
    return persist_provisioning_state(ProvisioningRuntimeState::unprovisioned);
}

void handle_persistent_material_consistency_error(const char* message)
{
    clear_active_session();
    ESP_LOGE(kTag, "%s", message != nullptr ? message : "Persistent material consistency error; failing closed");
}

void record_local_reset_material_failure(agent_q::AgentQPersistentMaterialRuntimeFailure failure)
{
    agent_q::persistent_material_record_runtime_failure(
        failure,
        persistent_material_ops());
}

agent_q::AgentQLocalResetPersistenceOps local_reset_persistence_ops()
{
    return agent_q::AgentQLocalResetPersistenceOps{
        clear_active_session,
        persist_unprovisioned_state_for_local_reset,
        record_local_reset_material_failure,
    };
}

agent_q::AgentQPersistentMaterialOps persistent_material_ops()
{
    return agent_q::AgentQPersistentMaterialOps{
        persist_provisioning_state,
        handle_persistent_material_consistency_error,
    };
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
        agent_q::persistent_material_record_runtime_failure(
            agent_q::AgentQPersistentMaterialRuntimeFailure::root_material_unreadable,
            persistent_material_ops());
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
    return agent_q::usb_response_write_json(response);
}

bool fill_protocol_random(void* output, size_t size, const char* purpose)
{
    if (agent_q::fill_secure_random(output, size)) {
        return true;
    }

    ESP_LOGE(kTag, "Secure RNG unavailable for %s", purpose != nullptr ? purpose : "protocol random");
    return false;
}

bool fill_session_random(void* output, size_t size, void*)
{
    return fill_protocol_random(output, size, "session id");
}

bool replace_active_session()
{
    return agent_q::session_replace(fill_session_random, nullptr) ==
           agent_q::AgentQSessionStartResult::ok;
}

bool usb_host_loss_relevant()
{
    const agent_q::AgentQLocalPinAuthSnapshot pin_auth =
        agent_q::local_pin_auth_snapshot(xTaskGetTickCount());
    const agent_q::AgentQProtocolPinApprovalSnapshot protocol_pin =
        agent_q::protocol_pin_approval_snapshot();
    return agent_q::session_active() ||
           agent_q::connect_approval_active() ||
           protocol_pin.active ||
           (pin_auth.flow_active &&
            (pin_auth.purpose == LocalPinAuthPurpose::connect ||
             pin_auth.purpose == LocalPinAuthPurpose::policy_update));
}

void show_usb_disconnected_message()
{
    agent_q::avatar_overlay_show_message(
        "USB disconnected",
        AgentQMessageKind::usb_disconnected,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void clear_usb_session_state_for_host_loss(bool notify)
{
    const bool had_session = agent_q::session_active();
    const bool had_connect_decision = agent_q::connect_approval_active();
    const agent_q::AgentQProtocolPinApprovalSnapshot protocol_pin =
        agent_q::protocol_pin_approval_snapshot();
    const bool had_protocol_connect_pin =
        protocol_pin.active &&
        protocol_pin.purpose == agent_q::AgentQProtocolPinApprovalPurpose::connect;
    const bool had_protocol_policy_update_pin =
        protocol_pin.active &&
        protocol_pin.purpose == agent_q::AgentQProtocolPinApprovalPurpose::policy_update;
    const agent_q::AgentQLocalPinAuthSnapshot pin_auth =
        agent_q::local_pin_auth_snapshot(xTaskGetTickCount());
    const bool had_connect_pin =
        pin_auth.flow_active &&
        pin_auth.purpose == LocalPinAuthPurpose::connect;
    const bool had_policy_update_pin =
        pin_auth.flow_active &&
        pin_auth.purpose == LocalPinAuthPurpose::policy_update;

    clear_active_session();
    g_line_size = 0;
    if (had_connect_decision) {
        clear_connect_decision_state();
    }
    if (had_protocol_connect_pin || had_protocol_policy_update_pin) {
        agent_q::protocol_pin_approval_clear();
    }
    if (had_connect_pin || had_policy_update_pin) {
        wipe_local_pin_auth_scratch("USB host link lost during local PIN authorization");
    }
    if (had_protocol_policy_update_pin || had_policy_update_pin) {
        agent_q::policy_update_flow_clear();
    }

    clear_agent_q_panel_if_kind(AgentQUiPanelKind::decision_strip, SensitiveUiClearPolicy::preserve);
    if (had_connect_pin || had_policy_update_pin) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    }

    if (had_session || had_connect_decision || had_protocol_connect_pin ||
        had_connect_pin || had_protocol_policy_update_pin || had_policy_update_pin) {
        if (notify) {
            show_usb_disconnected_message();
        }
        ESP_LOGW(kTag, "USB host SOF lost; active session and connect flow cleared");
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
        if (!connected && usb_host_loss_relevant()) {
            clear_usb_session_state_for_host_loss(true);
        }
        return;
    }

    const bool was_connected = g_usb_host_connected;
    g_usb_host_connected = connected;
    if (!was_connected && connected) {
        agent_q::avatar_overlay_show_message(
            "USB connected", AgentQMessageKind::usb_connected, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }
    if (!was_connected) {
        return;
    }

    clear_usb_session_state_for_host_loss(false);
    show_usb_disconnected_message();
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
    agent_q::persistent_material_begin_load();

    bool reset_marker_present = false;
    const agent_q::AgentQLocalResetCommitResult reset_result =
        agent_q::local_reset_resume_pending_if_needed(
            local_reset_persistence_ops(),
            &reset_marker_present);
    if (reset_marker_present) {
        ESP_LOGW(kTag, "Found pending local reset marker; resuming material wipe before loading state");
        if (reset_result == agent_q::AgentQLocalResetCommitResult::ok) {
            ESP_LOGW(kTag, "Pending local reset completed during boot");
        } else if (!agent_q::persistent_material_consistency_error_active()) {
            agent_q::persistent_material_record_runtime_failure(
                agent_q::AgentQPersistentMaterialRuntimeFailure::pending_reset_resume_failed,
                persistent_material_ops());
        }
        return;
    }

    agent_q::AgentQProvisioningStateStoreRecord stored_state = {};
    if (!agent_q::provisioning_state_store_load(&stored_state)) {
        stored_state.status = agent_q::AgentQProvisioningStateStorageStatus::unreadable;
        stored_state.value[0] = '\0';
    }

    ProvisioningRuntimeState effective_state = ProvisioningRuntimeState::unprovisioned;
    const agent_q::AgentQPersistentMaterialConsistencyResult consistency_result =
        agent_q::persistent_material_validate_loaded_storage_state(
            stored_state.status,
            stored_state.value,
            &effective_state,
            persistent_material_ops());
    if (consistency_result == agent_q::AgentQPersistentMaterialConsistencyResult::provisioning_state_reset) {
        ESP_LOGW(kTag, "Resetting stale provisioning state for persistent root material flow");
    } else if (consistency_result == agent_q::AgentQPersistentMaterialConsistencyResult::unknown_state_reset) {
        ESP_LOGW(kTag, "Resetting unknown provisioning state without persistent material");
    } else if (stored_state.status == agent_q::AgentQProvisioningStateStorageStatus::missing &&
               consistency_result == agent_q::AgentQPersistentMaterialConsistencyResult::ok) {
        ESP_LOGI(kTag, "Provisioning state not found in NVS; using unprovisioned");
    }
    g_provisioning_state = effective_state;
    ESP_LOGI(kTag, "Loaded provisioning state from NVS: %s",
             agent_q::provisioning_runtime_state_to_string(g_provisioning_state));
}

bool persist_provisioning_state(ProvisioningRuntimeState next_state)
{
    if (!agent_q::provisioning_state_store_save(next_state)) {
        return false;
    }

    g_provisioning_state = next_state;
    ESP_LOGI(kTag, "Stored provisioning state: %s",
             agent_q::provisioning_runtime_state_to_string(g_provisioning_state));
    return true;
}

bool local_setup_start_allowed()
{
    if (!refresh_persistent_material_consistency()) {
        return false;
    }

    bool welcome_visible = false;
    {
        LvglLockGuard lock;
        welcome_visible =
            agent_q::drawing_surface_panel_locked() == nullptr &&
            agent_q::avatar_overlay_mode() == AgentQUiMode::identification;
    }

    return g_provisioning_state == ProvisioningRuntimeState::unprovisioned &&
           !agent_q::persistent_material_consistency_error_active() &&
           !agent_q::identification_display_active() &&
           !agent_q::provisioning_flow_active() &&
           !agent_q::local_pin_auth_flow_active() &&
           !agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active &&
           !agent_q::connect_approval_active() &&
           !agent_q::protocol_pin_approval_active() &&
           welcome_visible;
}

bool agent_q_panel_active(AgentQUiPanelKind kind)
{
    LvglLockGuard lock;
    return agent_q::drawing_surface_panel_active(kind);
}

bool refresh_persistent_material_consistency()
{
    if (agent_q::persistent_material_consistency_error_active()) {
        return false;
    }

    return agent_q::persistent_material_validate_runtime_state(
        g_provisioning_state,
        persistent_material_ops());
}

bool provisioned_material_ready()
{
    return g_provisioning_state == ProvisioningRuntimeState::provisioned &&
           refresh_persistent_material_consistency();
}

bool agent_q_ui_idle_for_local_settings()
{
    LvglLockGuard lock;
    return agent_q::drawing_surface_panel_locked() == nullptr &&
           agent_q::avatar_overlay_mode() == AgentQUiMode::none;
}

bool local_settings_touch_entry_candidate_allowed()
{
    return g_provisioning_state == ProvisioningRuntimeState::provisioned &&
           !agent_q::persistent_material_consistency_error_active() &&
           !agent_q::connect_approval_active() &&
           !agent_q::protocol_pin_approval_active() &&
           !agent_q::identification_display_active() &&
           !agent_q::provisioning_flow_active() &&
           !agent_q::local_pin_auth_flow_active() &&
           !agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active &&
           agent_q_ui_idle_for_local_settings();
}

bool write_busy_if_pending_or_local_flow_active(const char* id, bool allow_settings_menu = false)
{
    if (agent_q::connect_approval_active()) {
        write_error_response(id, "busy", "Device is awaiting local input.");
        return true;
    }
    if (agent_q::protocol_pin_approval_active()) {
        write_error_response(id, "busy", "Device is awaiting local PIN approval.");
        return true;
    }
    if (agent_q::policy_update_flow_active()) {
        write_error_response(id, "busy", "Device has a pending policy update.");
        return true;
    }
    if (agent_q::provisioning_flow_active()) {
        write_error_response(id, "busy", "Device is showing setup material.");
        return true;
    }
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    if (reset.flow_active) {
        if (allow_settings_menu &&
            reset.stage == agent_q::AgentQLocalResetStage::settings_menu) {
            return false;
        }
        write_error_response(
            id,
            "busy",
            reset.stage == agent_q::AgentQLocalResetStage::settings_menu
                ? "Device is showing local settings UI."
                : "Device is showing local reset UI.");
        return true;
    }
    if (agent_q::local_pin_auth_flow_active()) {
        write_error_response(id, "busy", "Device is showing local PIN UI.");
        return true;
    }
    return false;
}

bool require_active_matching_session(const char* id, const char* session_id)
{
    switch (agent_q::session_validate(session_id)) {
        case agent_q::AgentQSessionValidationResult::ok:
            return true;
        case agent_q::AgentQSessionValidationResult::invalid_format:
            write_error_response(id, "invalid_session", "Invalid sessionId.");
            return false;
        case agent_q::AgentQSessionValidationResult::missing:
            cancel_policy_update_after_session_loss("active session missing during request validation");
            write_error_response(id, "invalid_session", "Session is unknown or already ended.");
            return false;
        case agent_q::AgentQSessionValidationResult::mismatch:
        default:
            write_error_response(id, "invalid_session", "Session is unknown or already ended.");
            return false;
    }
}

void write_policy_update_invalid_session_and_clear(const char* request_id, const char* log_reason)
{
    if (request_id != nullptr && request_id[0] != '\0') {
        write_error_response(request_id, "invalid_session", "Policy update session is unknown or already ended.");
    }
    agent_q::policy_update_flow_clear();
    agent_q::protocol_pin_approval_clear();
    ESP_LOGW(kTag, "Policy update canceled: %s", log_reason != nullptr ? log_reason : "invalid session");
    agent_q::avatar_overlay_show_message(
        "Session ended",
        AgentQMessageKind::error,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void cancel_policy_update_after_session_loss(const char* log_reason)
{
    char request_id[kMaxRequestIdSize] = {};
    if (agent_q::protocol_pin_approval_policy_update_request_id(request_id, sizeof(request_id))) {
        const agent_q::AgentQLocalPinAuthSnapshot pin_auth =
            agent_q::local_pin_auth_snapshot(xTaskGetTickCount());
        if (pin_auth.flow_active &&
            pin_auth.purpose == LocalPinAuthPurpose::policy_update) {
            wipe_local_pin_auth_scratch("session loss canceled pending policy update");
            clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        }
        write_policy_update_invalid_session_and_clear(request_id, log_reason);
        return;
    }

    if (agent_q::policy_update_flow_active()) {
        agent_q::policy_update_flow_clear();
    }
}

bool require_pending_policy_update_session(const char* request_id)
{
    switch (agent_q::protocol_pin_approval_validate_policy_update_session()) {
        case agent_q::AgentQSessionValidationResult::ok:
            return true;
        case agent_q::AgentQSessionValidationResult::invalid_format:
        case agent_q::AgentQSessionValidationResult::missing:
        case agent_q::AgentQSessionValidationResult::mismatch:
        default:
            write_policy_update_invalid_session_and_clear(request_id, "pending policy update session invalid");
            return false;
    }
}

bool pending_request_id_for_local_pin_purpose(
    LocalPinAuthPurpose purpose,
    char* output,
    size_t output_size)
{
    return agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
        purpose,
        output,
        output_size);
}

TickType_t local_pin_auth_retry_deadline(
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    return agent_q::protocol_pin_approval_retry_deadline_for_local_pin_purpose(
        purpose,
        now + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));
}

bool protocol_local_pin_deadline_reached(LocalPinAuthPurpose purpose, TickType_t now)
{
    return agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
        purpose,
        now);
}

bool disconnect_pending_policy_update_for_session(const char* id, const char* session_id)
{
    if (!agent_q::protocol_pin_approval_policy_update_session_matches(session_id)) {
        return false;
    }

    char policy_request_id[kMaxRequestIdSize] = {};
    agent_q::protocol_pin_approval_policy_update_request_id(
        policy_request_id,
        sizeof(policy_request_id));
    const agent_q::AgentQLocalPinAuthSnapshot pin_auth =
        agent_q::local_pin_auth_snapshot(xTaskGetTickCount());
    if (pin_auth.flow_active &&
        pin_auth.purpose == LocalPinAuthPurpose::policy_update) {
        wipe_local_pin_auth_scratch("disconnect canceled pending policy update");
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    }
    if (policy_request_id[0] != '\0' &&
        (id == nullptr || strcmp(policy_request_id, id) != 0)) {
        write_error_response(
            policy_request_id,
            "invalid_session",
            "Policy update session is unknown or already ended.");
    }
    agent_q::policy_update_flow_clear();
    agent_q::protocol_pin_approval_clear();
    clear_active_session();
    if (write_disconnect_result(id)) {
        ESP_LOGI(kTag, "disconnect canceled pending policy update: id=%s", id);
    } else {
        log_response_write_failure("disconnect_result", id);
    }
    return true;
}

bool recovery_phrase_backup_confirmation_ready()
{
    return agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::recovery_phrase_displayed);
}

void enqueue_connect_decision_choice(ConnectApprovalChoice choice)
{
    if (choice == ConnectApprovalChoice::none || g_connect_decision_choice_queue == nullptr) {
        return;
    }
    if (xQueueSend(g_connect_decision_choice_queue, &choice, 0) != pdTRUE) {
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
    enqueue_connect_decision_choice(ConnectApprovalChoice::approved);
}

void on_no_clicked(lv_event_t*)
{
    enqueue_connect_decision_choice(ConnectApprovalChoice::rejected);
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

void on_settings_change_pin_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::settings_change_pin_requested);
}

void on_error_recovery_erase_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::error_recovery_erase_requested);
}

void on_error_recovery_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::error_recovery_cancel_requested);
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

void on_agent_q_panel_deleted(AgentQUiPanelKind deleted_kind)
{
    enqueue_ui_event(AgentQUiEventKind::panel_deleted, deleted_kind);
}

void clear_panel_locked(SensitiveUiClearPolicy policy)
{
    const AgentQUiPanelKind panel_kind = agent_q::drawing_surface_clear_panel_locked();
    if (panel_kind == AgentQUiPanelKind::none ||
        policy != SensitiveUiClearPolicy::wipe) {
        return;
    }

    const bool wipe_setup_after_delete =
        panel_kind == AgentQUiPanelKind::setup_choice ||
        panel_kind == AgentQUiPanelKind::recovery_phrase_display ||
        panel_kind == AgentQUiPanelKind::recovery_word_entry ||
        panel_kind == AgentQUiPanelKind::pin_entry;
    const bool wipe_reset_after_delete = local_reset_panel_matches_stage(panel_kind);
    const bool wipe_local_pin_auth_after_delete = local_pin_auth_panel_matches_stage(panel_kind);
    if (wipe_setup_after_delete) {
        if (!provisioning_flow_panel_deleted(panel_kind, "sensitive setup panel cleared")) {
            wipe_setup_scratch("sensitive setup panel cleared");
        }
    }
    if (wipe_reset_after_delete) {
        wipe_local_reset_scratch("local reset panel cleared");
    }
    if (wipe_local_pin_auth_after_delete) {
        wipe_local_pin_auth_scratch("local PIN authorization panel cleared");
    }
}

bool provisioning_welcome_available()
{
    bool ui_display_idle = false;
    {
        LvglLockGuard lock;
        ui_display_idle =
            agent_q::drawing_surface_ready() &&
            agent_q::drawing_surface_panel_locked() == nullptr &&
            agent_q::avatar_overlay_mode() == AgentQUiMode::none;
    }

    return g_provisioning_state == ProvisioningRuntimeState::unprovisioned &&
           !agent_q::persistent_material_consistency_error_active() &&
           !agent_q::connect_approval_active() &&
           !agent_q::protocol_pin_approval_active() &&
           !agent_q::identification_display_active() &&
           !agent_q::provisioning_flow_active() &&
           !agent_q::local_pin_auth_flow_active() &&
           !agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active &&
           ui_display_idle;
}

void show_provisioning_welcome_if_available()
{
    if (!provisioning_welcome_available()) {
        return;
    }

    agent_q::avatar_overlay_show_message(
        "Set up Agent-Q", AgentQMessageKind::info, AgentQUiMode::identification, 0, on_setup_clicked);
}

void show_idle_agent_q_ui_for_current_state()
{
    show_persistent_error_recovery_if_needed();
    show_provisioning_welcome_if_available();
}

bool clear_agent_q_panel_if_kind(AgentQUiPanelKind expected_kind, SensitiveUiClearPolicy policy)
{
    LvglLockGuard lock;
    if (!agent_q::drawing_surface_panel_active(expected_kind)) {
        return false;
    }
    clear_panel_locked(policy);
    return true;
}

bool clear_agent_q_panel_if_local_reset_stage(SensitiveUiClearPolicy policy)
{
    LvglLockGuard lock;
    const AgentQUiPanelKind panel_kind = agent_q::drawing_surface_panel_kind_locked();
    if (agent_q::drawing_surface_panel_locked() == nullptr ||
        !local_reset_panel_matches_stage(panel_kind)) {
        return false;
    }
    clear_panel_locked(policy);
    return true;
}

bool clear_agent_q_panel_if_local_pin_auth_stage(SensitiveUiClearPolicy policy)
{
    LvglLockGuard lock;
    const AgentQUiPanelKind panel_kind = agent_q::drawing_surface_panel_kind_locked();
    if (agent_q::drawing_surface_panel_locked() == nullptr ||
        !local_pin_auth_panel_matches_stage(panel_kind)) {
        return false;
    }
    clear_panel_locked(policy);
    return true;
}

void clear_request_ui_for_identification()
{
    agent_q::avatar_overlay_clear();
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::decision_strip, SensitiveUiClearPolicy::preserve);
}

void show_decision_panel()
{
    agent_q::identification_display_clear();
    if (!agent_q::modal_draw_decision_panel()) {
        ESP_LOGW(kTag, "connect decision panel could not be shown");
    }
}

void show_identification_code(const char* code, uint32_t duration_ms)
{
    clear_request_ui_for_identification();
    agent_q::identification_display_begin(
        xTaskGetTickCount() + pdMS_TO_TICKS(duration_ms));

    char message[40];
    snprintf(message, sizeof(message), "Device code: %s", code);
    if (!agent_q::avatar_overlay_show_message(message, AgentQMessageKind::info, AgentQUiMode::identification, duration_ms)) {
        ESP_LOGW(kTag, "identify_device could not show Agent-Q speech bubble");
    }
}

void clear_identification_if_needed()
{
    if (!agent_q::identification_display_deadline_reached(xTaskGetTickCount())) {
        return;
    }

    bool identification_visible = false;
    {
        LvglLockGuard lock;
        identification_visible =
            agent_q::avatar_overlay_mode() == AgentQUiMode::identification;
    }
    agent_q::identification_display_clear();
    if (identification_visible) {
        agent_q::avatar_overlay_clear();
        show_provisioning_welcome_if_available();
    }
}

void clear_agent_q_message_if_needed()
{
    if (!agent_q::avatar_overlay_message_deadline_reached(xTaskGetTickCount())) {
        return;
    }
    agent_q::avatar_overlay_clear();
    show_provisioning_welcome_if_available();
}

bool show_avatar_decision(const char* message)
{
    if (!agent_q::avatar_overlay_show_message(message, AgentQMessageKind::approval, AgentQUiMode::decision, 0)) {
        return false;
    }
    show_decision_panel();
    return true;
}

void clear_connect_decision_state()
{
    agent_q::connect_approval_clear();
    g_connect_decision_touch_armed = false;
    agent_q::identification_display_clear();
}

void show_result_and_clear_connect_decision(const char* message, AgentQMessageKind kind)
{
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::decision_strip, SensitiveUiClearPolicy::preserve);
    agent_q::avatar_overlay_show_message(message, kind, AgentQUiMode::result, kAgentQResultDisplayMs);
    clear_connect_decision_state();
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

using SetupCommitResult = agent_q::AgentQPersistentMaterialCommitResult;

bool setup_choice_action_allowed()
{
    if (!agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::setup_choice) ||
        !agent_q::provisioning_flow_setup_choice_action_allowed(xTaskGetTickCount()) ||
        agent_q::connect_approval_active() ||
        agent_q::protocol_pin_approval_active() ||
        agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active) {
        return false;
    }
    if (!refresh_persistent_material_consistency()) {
        return false;
    }
    return g_provisioning_state == ProvisioningRuntimeState::unprovisioned &&
           !agent_q::persistent_material_consistency_error_active();
}

void clear_setup_choice_if_needed()
{
    if (!agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::setup_choice)) {
        return;
    }

    const bool panel_active = agent_q_panel_active(AgentQUiPanelKind::setup_choice);
    const bool expired = agent_q::provisioning_flow_stage_expired(xTaskGetTickCount());
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::setup_choice);
    } else {
        wipe_setup_scratch("setup choice panel lost");
    }

    if (expired) {
        agent_q::avatar_overlay_show_message("Setup expired", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void clear_recovery_word_entry_if_needed()
{
    if (!agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::recover_word_entry)) {
        return;
    }

    const bool panel_active = agent_q_panel_active(AgentQUiPanelKind::recovery_word_entry);
    const bool expired = agent_q::provisioning_flow_stage_expired(xTaskGetTickCount());
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::recovery_word_entry);
    } else {
        wipe_setup_scratch("recovery word entry panel lost");
    }

    if (expired) {
        agent_q::avatar_overlay_show_message("Recovery expired", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void clear_recovery_phrase_if_needed()
{
    if (!agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::recovery_phrase_displayed)) {
        return;
    }

    const bool panel_active = agent_q_panel_active(AgentQUiPanelKind::recovery_phrase_display);
    const bool expired = agent_q::provisioning_flow_stage_expired(xTaskGetTickCount());
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::recovery_phrase_display);
    } else {
        wipe_setup_scratch("recovery phrase display lost");
    }

    if (expired) {
        agent_q::avatar_overlay_show_message("Phrase expired", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void clear_pin_setup_if_needed()
{
    const TickType_t now = xTaskGetTickCount();
    if (agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::pin_committing)) {
        if (!agent_q::provisioning_flow_fail_pin_commit_if_expired(now)) {
            return;
        }
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
        agent_q::avatar_overlay_show_message("Setup timed out", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    if (!agent_q::provisioning_flow_snapshot().accepts_setup_pin_input) {
        return;
    }

    const bool panel_active = agent_q_panel_active(AgentQUiPanelKind::pin_entry);
    const bool expired = agent_q::provisioning_flow_stage_expired(now);
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::pin_entry);
    } else {
        wipe_setup_scratch("local PIN setup panel lost");
    }

    if (expired) {
        agent_q::avatar_overlay_show_message("Setup expired", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_pin_digit_from_local_ui(char digit)
{
    if (!agent_q::provisioning_flow_add_pin_digit(
            digit,
            xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs))) {
        return;
    }
    if (!agent_q::modal_draw_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_pin_clear_from_local_ui()
{
    if (!agent_q::provisioning_flow_clear_pin_entry(
            xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs))) {
        return;
    }
    if (!agent_q::modal_draw_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_pin_backspace_from_local_ui()
{
    if (!agent_q::provisioning_flow_backspace_pin(
            xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs))) {
        return;
    }
    if (!agent_q::modal_draw_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_pin_submit_from_local_ui()
{
    if (!agent_q::provisioning_flow_snapshot().accepts_setup_pin_input) {
        ESP_LOGW(kTag, "Stale local PIN submit ignored");
        return;
    }
    const ProvisioningFlowPinSubmitResult result =
        agent_q::provisioning_flow_submit_pin(
            xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs),
            xTaskGetTickCount() + pdMS_TO_TICKS(kLocalProcessingDisplayMs),
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalAuthWorkerMaxMs));
    if (result == ProvisioningFlowPinSubmitResult::invalid_pin) {
        if (!agent_q::modal_draw_pin_setup_panel("Enter exactly 6 digits.")) {
            wipe_setup_scratch("local PIN setup display allocation failed");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }
    if (result == ProvisioningFlowPinSubmitResult::worker_unavailable) {
        if (!agent_q::modal_draw_pin_setup_panel("Auth worker busy. Try again.")) {
            wipe_setup_scratch("local PIN setup worker unavailable display allocation failed");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }
    if (result == ProvisioningFlowPinSubmitResult::advanced_to_repeat) {
        if (!agent_q::modal_draw_pin_setup_panel()) {
            wipe_setup_scratch("local PIN setup display allocation failed");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }
    if (result == ProvisioningFlowPinSubmitResult::mismatch_restart) {
        if (!agent_q::modal_draw_pin_setup_panel("PINs did not match.")) {
            wipe_setup_scratch("local PIN setup display allocation failed");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }
    if (result != ProvisioningFlowPinSubmitResult::commit_started) {
        ESP_LOGW(kTag, "Stale local PIN submit ignored");
        return;
    }

    if (!agent_q::modal_draw_processing_overlay_on_current_panel(AgentQUiPanelKind::pin_entry) &&
        !agent_q::modal_draw_pin_setup_panel()) {
        ESP_LOGW(kTag, "Local setup committing panel could not be shown");
        wipe_setup_scratch("local PIN setup committing display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void clear_local_reset_if_needed()
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalResetSnapshot reset = agent_q::local_reset_snapshot(now);
    if (reset.stage == agent_q::AgentQLocalResetStage::none) {
        return;
    }
    if (reset.stage == agent_q::AgentQLocalResetStage::pin_verifying) {
        if (!agent_q::local_reset_fail_pin_verification_if_expired(now)) {
            return;
        }
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::reset_pin_entry, SensitiveUiClearPolicy::preserve);
        agent_q::avatar_overlay_show_message("Auth timed out", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }
    if (reset.stage == agent_q::AgentQLocalResetStage::wiping) {
        return;
    }

    if (agent_q::local_reset_release_lockout_if_elapsed(now)) {
        if (!agent_q::modal_draw_reset_pin_panel("Try again.")) {
            wipe_local_reset_scratch("local reset PIN panel allocation failed");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    bool panel_active = false;
    {
        LvglLockGuard lock;
        panel_active =
            local_reset_panel_matches_stage(agent_q::drawing_surface_panel_kind_locked()) &&
            agent_q::drawing_surface_panel_locked() != nullptr;
    }
    const bool expired = agent_q::local_reset_deadline_expired(now);
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel_if_local_reset_stage();
    } else {
        wipe_local_reset_scratch("local reset panel lost");
    }

    if (expired) {
        const char* timeout_message = "Reset canceled";
        if (reset.stage == agent_q::AgentQLocalResetStage::settings_menu) {
            timeout_message = "Settings timed out";
        } else if (reset.stage == agent_q::AgentQLocalResetStage::error_recovery_confirm) {
            timeout_message = "Erase canceled";
        }
        agent_q::avatar_overlay_show_message(
            timeout_message,
            AgentQMessageKind::timeout,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
    }
}

void commit_local_reset_if_ready()
{
    if (!agent_q::local_reset_wipe_ready(xTaskGetTickCount())) {
        return;
    }

    const agent_q::AgentQLocalResetCommitResult result =
        agent_q::local_reset_commit_material(local_reset_persistence_ops());
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::reset_pin_entry, SensitiveUiClearPolicy::preserve);
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::error_recovery, SensitiveUiClearPolicy::preserve);
    wipe_local_reset_scratch("local reset completed");
    switch (result) {
        case agent_q::AgentQLocalResetCommitResult::ok:
            ESP_LOGW(kTag, "Local reset completed; device returned to unprovisioned");
            agent_q::avatar_overlay_show_message("Device reset", AgentQMessageKind::success, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
        case agent_q::AgentQLocalResetCommitResult::missing_state:
            ESP_LOGW(kTag, "Local reset commit missing state");
            agent_q::avatar_overlay_show_message("Reset unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
        case agent_q::AgentQLocalResetCommitResult::reset_marker_storage_error:
            ESP_LOGW(kTag, "Local reset aborted before wiping material because the reset marker could not be stored");
            agent_q::avatar_overlay_show_message("Reset error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
        case agent_q::AgentQLocalResetCommitResult::root_wipe_error:
        case agent_q::AgentQLocalResetCommitResult::policy_wipe_error:
        case agent_q::AgentQLocalResetCommitResult::local_auth_wipe_error:
        case agent_q::AgentQLocalResetCommitResult::connect_setting_wipe_error:
        case agent_q::AgentQLocalResetCommitResult::approval_history_wipe_error:
        case agent_q::AgentQLocalResetCommitResult::policy_update_marker_wipe_error:
        case agent_q::AgentQLocalResetCommitResult::material_remaining_error:
        case agent_q::AgentQLocalResetCommitResult::state_storage_error:
            ESP_LOGE(kTag, "Local reset failed and device entered consistency error");
            agent_q::avatar_overlay_show_message("Reset error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
    }
}

void start_local_settings_from_touch()
{
    if (!provisioned_material_ready() ||
        agent_q::connect_approval_active() ||
        agent_q::protocol_pin_approval_active() ||
        agent_q::identification_display_active() ||
        agent_q::provisioning_flow_active() ||
        agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active ||
        !agent_q_ui_idle_for_local_settings()) {
        ESP_LOGW(kTag, "Local settings touch ignored because settings are unavailable");
        agent_q::local_settings_touch_entry_clear();
        return;
    }

    agent_q::local_reset_begin_settings(
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));
    if (!agent_q::modal_draw_settings_menu_panel()) {
        wipe_local_reset_scratch("local settings display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void cancel_local_reset_from_ui(const char* message)
{
    if (agent_q::local_reset_snapshot(xTaskGetTickCount()).stage !=
        agent_q::AgentQLocalResetStage::pin_entry) {
        ESP_LOGW(kTag, "Stale local reset cancel ignored");
        return;
    }

    clear_agent_q_panel_if_kind(AgentQUiPanelKind::reset_pin_entry);
    agent_q::local_reset_begin_settings(
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));
    if (!agent_q::modal_draw_settings_menu_panel()) {
        wipe_local_reset_scratch("local settings display allocation failed after reset cancel");
        agent_q::avatar_overlay_show_message(
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

    clear_agent_q_panel_if_kind(AgentQUiPanelKind::settings_menu);
    wipe_local_reset_scratch("local settings closed");
}

void show_persistent_error_recovery_if_needed()
{
    if (!agent_q::persistent_material_consistency_error_active() ||
        agent_q::connect_approval_active() ||
        agent_q::protocol_pin_approval_active() ||
        agent_q::identification_display_active() ||
        agent_q::provisioning_flow_active() ||
        agent_q::local_pin_auth_flow_active() ||
        agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active) {
        return;
    }

    bool error_recovery_visible = false;
    {
        LvglLockGuard lock;
        if (!agent_q::drawing_surface_ready()) {
            return;
        }
        error_recovery_visible =
            agent_q::drawing_surface_panel_active(AgentQUiPanelKind::error_recovery);
    }
    if (error_recovery_visible) {
        return;
    }

    if (!agent_q::modal_draw_error_recovery_panel(false)) {
        ESP_LOGW(kTag, "Persistent error recovery panel could not be shown");
    }
}

void start_error_recovery_from_ui()
{
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    if (!agent_q::persistent_material_consistency_error_active() ||
        reset.flow_active ||
        agent_q::connect_approval_active() ||
        agent_q::protocol_pin_approval_active() ||
        agent_q::identification_display_active() ||
        agent_q::provisioning_flow_active() ||
        agent_q::local_pin_auth_flow_active()) {
        ESP_LOGW(kTag, "Stale error recovery action ignored");
        return;
    }

    agent_q::local_reset_begin_error_recovery_confirm(
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));
    if (!agent_q::modal_draw_error_recovery_panel(true)) {
        wipe_local_reset_scratch("error recovery confirmation display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void cancel_error_recovery_from_ui()
{
    if (agent_q::local_reset_snapshot(xTaskGetTickCount()).stage !=
        agent_q::AgentQLocalResetStage::error_recovery_confirm) {
        ESP_LOGW(kTag, "Stale error recovery cancel ignored");
        return;
    }

    clear_agent_q_panel_if_kind(AgentQUiPanelKind::error_recovery);
    wipe_local_reset_scratch("error recovery canceled");
    agent_q::avatar_overlay_show_message("Erase canceled", AgentQMessageKind::info, AgentQUiMode::result, kAgentQResultDisplayMs);
}

void confirm_error_recovery_from_ui()
{
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    if (reset.stage == agent_q::AgentQLocalResetStage::none) {
        start_error_recovery_from_ui();
        return;
    }
    if (reset.stage != agent_q::AgentQLocalResetStage::error_recovery_confirm ||
        !agent_q::persistent_material_consistency_error_active()) {
        ESP_LOGW(kTag, "Stale error recovery erase ignored");
        return;
    }

    if (!agent_q::local_reset_begin_error_recovery_wipe(
            xTaskGetTickCount() + pdMS_TO_TICKS(kLocalProcessingDisplayMs))) {
        ESP_LOGW(kTag, "Error recovery erase could not enter wiping state");
        return;
    }

    if (!agent_q::modal_draw_processing_overlay_on_current_panel(AgentQUiPanelKind::error_recovery) &&
        !agent_q::modal_draw_error_recovery_panel(true)) {
        wipe_local_reset_scratch("error recovery wiping display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void start_reset_pin_from_settings_menu()
{
    if (!provisioned_material_ready() ||
        !agent_q::local_reset_begin_pin_entry(
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs))) {
        ESP_LOGW(kTag, "Stale local reset menu action ignored");
        return;
    }

    if (!agent_q::modal_draw_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void begin_connect_pin_auth(const char* id, const char* gateway_name, uint32_t approval_timeout_ms)
{
    agent_q::identification_display_clear();
    const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(approval_timeout_ms);
    if (!agent_q::protocol_pin_approval_begin_connect(id, deadline)) {
        write_connect_rejected_response(id, "invalid_state", "Connect is unavailable.");
        agent_q::avatar_overlay_show_message("Connect unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }
    agent_q::local_pin_auth_begin_connect(deadline);

    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        write_connect_rejected_response(id, "ui_error", "Could not show local PIN UI.");
        wipe_local_pin_auth_scratch("connect PIN display allocation failed");
        agent_q::protocol_pin_approval_clear();
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void clear_policy_update_terminal_state()
{
    agent_q::policy_update_flow_clear();
    agent_q::protocol_pin_approval_clear();
}

void finish_policy_update_result_terminal(
    const char* request_id,
    agent_q::AgentQPolicyUpdateFlowTerminalResult result,
    const char* display_message,
    AgentQMessageKind display_kind,
    bool refresh_material_consistency = false)
{
    if (!write_policy_update_result_response(
            request_id,
            agent_q::policy_update_flow_terminal_status(result),
            agent_q::policy_update_flow_terminal_reason(result),
            true)) {
        log_response_write_failure("policy_update_result", request_id);
    }
    clear_policy_update_terminal_state();
    if (refresh_material_consistency) {
        refresh_persistent_material_consistency();
    }
    agent_q::avatar_overlay_show_message(
        display_message,
        display_kind,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void finish_policy_update_error_terminal(
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    write_error_response(request_id, error_code, error_message);
    clear_policy_update_terminal_state();
    agent_q::avatar_overlay_show_message(
        display_message,
        AgentQMessageKind::error,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void finish_policy_update_terminal(
    const char* request_id,
    agent_q::AgentQPolicyUpdateFlowTerminalResult result)
{
    if (request_id == nullptr || request_id[0] == '\0') {
        clear_policy_update_terminal_state();
        return;
    }

    switch (result) {
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::applied:
            finish_policy_update_result_terminal(
                request_id,
                result,
                "Policy updated",
                AgentQMessageKind::success);
            return;
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::rejected:
            finish_policy_update_result_terminal(
                request_id,
                result,
                "Policy rejected",
                AgentQMessageKind::rejected);
            return;
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::timed_out:
            finish_policy_update_result_terminal(
                request_id,
                result,
                "Policy timed out",
                AgentQMessageKind::timeout);
            return;
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::ui_error:
            finish_policy_update_result_terminal(
                request_id,
                result,
                "Display error",
                AgentQMessageKind::error);
            return;
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::storage_error:
            finish_policy_update_result_terminal(
                request_id,
                result,
                "Policy failed",
                AgentQMessageKind::error);
            return;
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::consistency_error:
            finish_policy_update_result_terminal(
                request_id,
                result,
                "Policy error",
                AgentQMessageKind::error,
                true);
            return;
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::history_error:
            finish_policy_update_error_terminal(
                request_id,
                "history_error",
                "Could not record policy update.",
                "History error");
            return;
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::invalid_state:
        default:
            finish_policy_update_error_terminal(
                request_id,
                "invalid_state",
                "Policy update is unavailable.",
                "Policy unavailable");
            return;
    }
}

void begin_policy_update_pin_auth(const char* id, const char* session_id, uint32_t approval_timeout_ms)
{
    agent_q::identification_display_clear();
    const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(approval_timeout_ms);
    if (!agent_q::protocol_pin_approval_begin_policy_update(id, session_id, deadline)) {
        finish_policy_update_error_terminal(
            id,
            "invalid_state",
            "Policy update is unavailable.",
            "Policy unavailable");
        return;
    }
    agent_q::local_pin_auth_begin_policy_update(deadline);

    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("policy update PIN display allocation failed");
        finish_policy_update_terminal(
            id,
            agent_q::policy_update_flow_record_ui_error());
    }
}

void handle_local_pin_auth_display_failure(const char* reason, bool clear_panel = false)
{
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(xTaskGetTickCount());
    char request_id[kMaxRequestIdSize] = {};
    if (snapshot.purpose == LocalPinAuthPurpose::policy_update &&
        agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
            LocalPinAuthPurpose::policy_update,
            request_id,
            sizeof(request_id))) {
        wipe_local_pin_auth_scratch(reason);
        if (clear_panel) {
            clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        }
        finish_policy_update_terminal(
            request_id,
            agent_q::policy_update_flow_record_ui_error());
        return;
    }

    wipe_local_pin_auth_scratch(reason);
    if (clear_panel) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    }
    agent_q::avatar_overlay_show_message(
        "Display error",
        AgentQMessageKind::error,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void start_settings_connect_pin_from_settings_menu()
{
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    if (!provisioned_material_ready() ||
        reset.stage != agent_q::AgentQLocalResetStage::settings_menu ||
        agent_q::local_pin_auth_flow_active()) {
        ESP_LOGW(kTag, "Stale settings connect PIN action ignored");
        return;
    }

    bool current_require_pin = true;
    if (!agent_q::read_require_pin_on_connect(&current_require_pin)) {
        agent_q::local_reset_wipe();
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::settings_menu, SensitiveUiClearPolicy::preserve);
        agent_q::avatar_overlay_show_message(
            "Settings error",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
        return;
    }
    agent_q::local_reset_wipe();
    agent_q::local_pin_auth_begin_connect_setting(
        !current_require_pin,
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));

    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("settings connect PIN display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void start_settings_change_pin_from_settings_menu()
{
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    if (!provisioned_material_ready() ||
        reset.stage != agent_q::AgentQLocalResetStage::settings_menu ||
        agent_q::local_pin_auth_flow_active()) {
        ESP_LOGW(kTag, "Stale settings Change PIN action ignored");
        return;
    }

    agent_q::local_reset_wipe();
    agent_q::local_pin_auth_begin_change_pin(
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));

    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("settings Change PIN display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void cancel_local_pin_auth_from_ui(const char* message)
{
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(xTaskGetTickCount());
    if (!snapshot.flow_active || !snapshot.accepts_keypad_input) {
        ESP_LOGW(kTag, "Stale local PIN authorization cancel ignored");
        return;
    }

    const LocalPinAuthPurpose purpose = snapshot.purpose;
    char request_id[kMaxRequestIdSize] = {};
    pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));

    clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    wipe_local_pin_auth_scratch("local PIN authorization canceled");
    if (purpose == LocalPinAuthPurpose::policy_update && request_id[0] != '\0') {
        finish_policy_update_terminal(
            request_id,
            agent_q::policy_update_flow_record_rejected(
                static_cast<uint64_t>(esp_timer_get_time() / 1000LL)));
        return;
    }
    if (purpose == LocalPinAuthPurpose::connect && request_id[0] != '\0') {
        write_connect_rejected_response(request_id, "rejected", "Connection rejected.");
        agent_q::protocol_pin_approval_clear();
        agent_q::avatar_overlay_show_message("Connection rejected", AgentQMessageKind::rejected, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }
    if (purpose == LocalPinAuthPurpose::settings_connect_pin ||
        purpose == LocalPinAuthPurpose::settings_change_pin) {
        agent_q::local_reset_begin_settings(
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));
        if (!agent_q::modal_draw_settings_menu_panel()) {
            wipe_local_reset_scratch("local settings display allocation failed after PIN cancel");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    agent_q::avatar_overlay_show_message(
        message != nullptr && message[0] != '\0' ? message : "Settings canceled",
        AgentQMessageKind::rejected,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void handle_local_pin_auth_digit_from_ui(char digit)
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(now);
    const agent_q::AgentQLocalPinAuthInputResult result =
        agent_q::local_pin_auth_add_digit(
            digit,
            local_pin_auth_retry_deadline(snapshot.purpose, now));
    if (result == agent_q::AgentQLocalPinAuthInputResult::inactive ||
        result == agent_q::AgentQLocalPinAuthInputResult::locked ||
        result == agent_q::AgentQLocalPinAuthInputResult::invalid_digit) {
        return;
    }
    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        handle_local_pin_auth_display_failure("local PIN authorization display allocation failed");
    }
}

void handle_local_pin_auth_clear_from_ui()
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(now);
    if (!agent_q::local_pin_auth_clear_pin(
            local_pin_auth_retry_deadline(snapshot.purpose, now))) {
        return;
    }
    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        handle_local_pin_auth_display_failure("local PIN authorization display allocation failed");
    }
}

void handle_local_pin_auth_backspace_from_ui()
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(now);
    if (!agent_q::local_pin_auth_backspace_pin(
            local_pin_auth_retry_deadline(snapshot.purpose, now))) {
        return;
    }
    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        handle_local_pin_auth_display_failure("local PIN authorization display allocation failed");
    }
}

void handle_local_pin_auth_submit_from_ui()
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(now);
    const TickType_t retry_deadline =
        local_pin_auth_retry_deadline(snapshot.purpose, now);
    const agent_q::AgentQLocalPinAuthSubmitResult result =
        agent_q::local_pin_auth_submit(
            now + pdMS_TO_TICKS(kLocalProcessingRenderDelayMs),
            now + pdMS_TO_TICKS(kLocalProcessingDisplayMs),
            retry_deadline,
            now + pdMS_TO_TICKS(agent_q::kAgentQLocalAuthWorkerMaxMs));
    switch (result) {
        case agent_q::AgentQLocalPinAuthSubmitResult::unavailable_stage:
            ESP_LOGW(kTag, "Stale local PIN authorization submit ignored");
            return;
        case agent_q::AgentQLocalPinAuthSubmitResult::locked:
            return;
        case agent_q::AgentQLocalPinAuthSubmitResult::worker_unavailable:
            if (!agent_q::modal_draw_local_pin_auth_panel("Auth worker busy. Try again.")) {
                handle_local_pin_auth_display_failure(
                    "local PIN worker unavailable display allocation failed",
                    true);
            }
            return;
        case agent_q::AgentQLocalPinAuthSubmitResult::invalid_pin:
            if (!agent_q::modal_draw_local_pin_auth_panel("Enter exactly 6 digits.")) {
                handle_local_pin_auth_display_failure("local PIN authorization display allocation failed");
            }
            return;
        case agent_q::AgentQLocalPinAuthSubmitResult::advanced_to_repeat_pin:
            if (!agent_q::modal_draw_local_pin_auth_panel()) {
                handle_local_pin_auth_display_failure("Change PIN repeat display allocation failed");
            }
            return;
        case agent_q::AgentQLocalPinAuthSubmitResult::mismatch_restart:
            if (!agent_q::modal_draw_local_pin_auth_panel("PINs did not match.")) {
                handle_local_pin_auth_display_failure("Change PIN mismatch display allocation failed");
            }
            return;
        case agent_q::AgentQLocalPinAuthSubmitResult::started_pin_change_commit:
            if (!agent_q::modal_draw_processing_overlay_on_current_panel(AgentQUiPanelKind::local_pin_auth) &&
                !agent_q::modal_draw_local_pin_auth_panel()) {
                handle_local_pin_auth_display_failure(
                    "Change PIN commit display allocation failed",
                    true);
            }
            return;
        case agent_q::AgentQLocalPinAuthSubmitResult::started_verification:
            if (!agent_q::modal_draw_processing_overlay_on_current_panel(AgentQUiPanelKind::local_pin_auth) &&
                !agent_q::modal_draw_local_pin_auth_panel()) {
                handle_local_pin_auth_display_failure(
                    "local PIN authorization verification display allocation failed",
                    true);
            }
            return;
    }
}

void handle_reset_pin_digit_from_local_ui(char digit)
{
    if (!agent_q::local_reset_add_pin_digit(
            digit,
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs))) {
        return;
    }

    if (!agent_q::modal_draw_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_reset_pin_clear_from_local_ui()
{
    if (!agent_q::local_reset_clear_pin(
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs))) {
        return;
    }
    if (!agent_q::modal_draw_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_reset_pin_backspace_from_local_ui()
{
    if (!agent_q::local_reset_backspace_pin(
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs))) {
        return;
    }
    if (!agent_q::modal_draw_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_reset_pin_submit_from_local_ui()
{
    if (!provisioned_material_ready()) {
        wipe_local_reset_scratch("local reset material state unavailable");
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::reset_pin_entry, SensitiveUiClearPolicy::preserve);
        agent_q::avatar_overlay_show_message("Reset unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    const agent_q::AgentQLocalResetPinSubmitResult submit_result =
        agent_q::local_reset_submit_pin_for_verification(
            xTaskGetTickCount() + pdMS_TO_TICKS(kLocalProcessingRenderDelayMs),
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs),
            xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalAuthWorkerMaxMs));
    if (submit_result == agent_q::AgentQLocalResetPinSubmitResult::unavailable_stage) {
        ESP_LOGW(kTag, "Stale local reset PIN submit ignored");
        return;
    }
    if (submit_result == agent_q::AgentQLocalResetPinSubmitResult::locked) {
        return;
    }
    if (submit_result == agent_q::AgentQLocalResetPinSubmitResult::worker_unavailable) {
        if (!agent_q::modal_draw_reset_pin_panel("Auth worker busy. Try again.")) {
            wipe_local_reset_scratch("local reset PIN worker unavailable display allocation failed");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }
    if (submit_result == agent_q::AgentQLocalResetPinSubmitResult::invalid_pin) {
        if (!agent_q::modal_draw_reset_pin_panel("Enter exactly 6 digits.")) {
            wipe_local_reset_scratch("local reset PIN display allocation failed");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    if (!agent_q::modal_draw_processing_overlay_on_current_panel(AgentQUiPanelKind::reset_pin_entry) &&
        !agent_q::modal_draw_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN verification display allocation failed");
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::reset_pin_entry, SensitiveUiClearPolicy::preserve);
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void commit_local_pin_setting_if_ready()
{
    const agent_q::AgentQLocalPinAuthCommitResult result =
        agent_q::local_pin_auth_commit_if_ready(xTaskGetTickCount());
    if (result == agent_q::AgentQLocalPinAuthCommitResult::not_ready) {
        return;
    }
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    if (result == agent_q::AgentQLocalPinAuthCommitResult::pin_change_auth_unavailable) {
        agent_q::persistent_material_record_runtime_failure(
            agent_q::AgentQPersistentMaterialRuntimeFailure::pin_change_auth_unavailable,
            persistent_material_ops());
        agent_q::avatar_overlay_show_message(
            "Auth error",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
        return;
    }
    if (result == agent_q::AgentQLocalPinAuthCommitResult::pin_change_storage_error) {
        agent_q::avatar_overlay_show_message(
            "PIN change failed",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
        return;
    }
    if (result == agent_q::AgentQLocalPinAuthCommitResult::storage_error) {
        agent_q::avatar_overlay_show_message(
            "Settings error",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
        return;
    }

    agent_q::local_reset_begin_settings(
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));
    if (!agent_q::modal_draw_settings_menu_panel()) {
        wipe_local_reset_scratch("local settings display allocation failed after PIN commit");
        agent_q::avatar_overlay_show_message(
            result == agent_q::AgentQLocalPinAuthCommitResult::pin_changed ? "PIN changed" : "Settings saved",
            AgentQMessageKind::success,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
    }
}

void handle_setup_auth_worker_result(agent_q::AgentQLocalAuthWorkerResult& worker_result)
{
    if (!agent_q::provisioning_flow_commit_job_active(worker_result.job_id)) {
        return;
    }

    const uint8_t* root_material = nullptr;
    size_t root_material_size = 0;
    const agent_q::AgentQLocalAuthPreparedRecord* prepared_auth = nullptr;
    if (!agent_q::provisioning_flow_commit_worker_result(
            worker_result,
            &root_material,
            &root_material_size,
            &prepared_auth)) {
        wipe_setup_scratch("local setup PIN verifier preparation failed");
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
        agent_q::avatar_overlay_show_message("Storage error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    const SetupCommitResult result =
        agent_q::persistent_material_commit_setup_with_prepared_auth(
            root_material,
            root_material_size,
            prepared_auth,
            persistent_material_ops());
    wipe_setup_scratch("local recovery phrase backup and PIN committed");
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
    switch (result) {
        case SetupCommitResult::ok:
            ESP_LOGI(kTag, "Local setup PIN confirmed and provisioned");
            agent_q::avatar_overlay_show_message("Provisioned", AgentQMessageKind::success, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
        case SetupCommitResult::missing_input:
            ESP_LOGW(kTag, "Local PIN confirmation missing scratch");
            agent_q::avatar_overlay_show_message("Setup unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
        case SetupCommitResult::root_storage_error:
        case SetupCommitResult::policy_storage_error:
        case SetupCommitResult::local_auth_storage_error:
        case SetupCommitResult::state_storage_error:
            ESP_LOGW(kTag, "Local PIN confirmation storage error");
            agent_q::avatar_overlay_show_message("Storage error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            break;
    }
}

void handle_local_reset_auth_worker_result(const agent_q::AgentQLocalAuthWorkerResult& worker_result)
{
    const TickType_t now = xTaskGetTickCount();
    if (!provisioned_material_ready()) {
        const agent_q::AgentQLocalResetSnapshot reset =
            agent_q::local_reset_snapshot(now);
        if (reset.stage != agent_q::AgentQLocalResetStage::pin_verifying) {
            return;
        }
        wipe_local_reset_scratch("local reset material state unavailable during PIN verification");
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::reset_pin_entry, SensitiveUiClearPolicy::preserve);
        agent_q::avatar_overlay_show_message("Reset unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    const agent_q::AgentQLocalResetPinVerifyResult verify_result =
        agent_q::local_reset_complete_pin_verify_job(
            worker_result,
            now + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs),
            now + pdMS_TO_TICKS(agent_q::kAgentQLocalResetPinLockoutMs),
            now + pdMS_TO_TICKS(kLocalProcessingDisplayMs));
    switch (verify_result) {
        case agent_q::AgentQLocalResetPinVerifyResult::not_ready:
            return;
        case agent_q::AgentQLocalResetPinVerifyResult::auth_unavailable:
            agent_q::persistent_material_record_runtime_failure(
                agent_q::AgentQPersistentMaterialRuntimeFailure::local_reset_auth_unavailable,
                persistent_material_ops());
            wipe_local_reset_scratch("local reset PIN verifier unavailable");
            clear_agent_q_panel_if_kind(AgentQUiPanelKind::reset_pin_entry, SensitiveUiClearPolicy::preserve);
            agent_q::avatar_overlay_show_message("Auth error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            return;
        case agent_q::AgentQLocalResetPinVerifyResult::locked:
            if (!agent_q::modal_draw_reset_pin_panel("Too many wrong PINs. Wait 30s.")) {
                wipe_local_reset_scratch("local reset PIN lockout display allocation failed");
                agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            }
            return;
        case agent_q::AgentQLocalResetPinVerifyResult::wrong_pin:
            if (!agent_q::modal_draw_reset_pin_panel("Wrong PIN.")) {
                wipe_local_reset_scratch("local reset PIN display allocation failed");
                agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            }
            return;
        case agent_q::AgentQLocalResetPinVerifyResult::verified:
            break;
    }

    bool reset_panel_active = false;
    {
        LvglLockGuard lock;
        reset_panel_active =
            agent_q::drawing_surface_panel_active(AgentQUiPanelKind::reset_pin_entry);
    }
    if (!reset_panel_active) {
        if (!agent_q::modal_draw_reset_pin_panel()) {
            ESP_LOGW(kTag, "Local reset wiping panel could not be shown");
            commit_local_reset_if_ready();
        }
    }
}

void handle_local_pin_auth_verify_worker_result(
    const agent_q::AgentQLocalAuthWorkerResult& worker_result)
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(now);
    if (!snapshot.flow_active || snapshot.stage != LocalPinAuthStage::pin_verifying) {
        return;
    }

    const LocalPinAuthPurpose purpose = snapshot.purpose;
    if (!provisioned_material_ready()) {
        char request_id[kMaxRequestIdSize] = {};
        pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
        wipe_local_pin_auth_scratch("local PIN authorization material state unavailable");
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        if (purpose == LocalPinAuthPurpose::policy_update && request_id[0] != '\0') {
            write_error_response(request_id, "invalid_state", "Policy update is unavailable.");
            agent_q::policy_update_flow_clear();
            agent_q::protocol_pin_approval_clear();
        }
        if (request_id[0] != '\0') {
            if (purpose == LocalPinAuthPurpose::policy_update) {
                agent_q::avatar_overlay_show_message("PIN unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
                return;
            }
            write_connect_rejected_response(request_id, "invalid_state", "Connect is unavailable.");
            agent_q::protocol_pin_approval_clear();
        }
        agent_q::avatar_overlay_show_message("PIN unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    const agent_q::AgentQLocalPinAuthVerifyResult result =
        agent_q::local_pin_auth_complete_verify_job(
            worker_result,
            local_pin_auth_retry_deadline(purpose, now),
            now + pdMS_TO_TICKS(agent_q::kAgentQLocalResetPinLockoutMs),
            now + pdMS_TO_TICKS(kLocalProcessingDisplayMs));
    switch (result) {
        case agent_q::AgentQLocalPinAuthVerifyResult::not_ready:
            return;
        case agent_q::AgentQLocalPinAuthVerifyResult::auth_unavailable: {
            char request_id[kMaxRequestIdSize] = {};
            pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
            agent_q::persistent_material_record_runtime_failure(
                agent_q::AgentQPersistentMaterialRuntimeFailure::local_pin_auth_unavailable,
                persistent_material_ops());
            wipe_local_pin_auth_scratch("local PIN authorization verifier unavailable");
            clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
            if (purpose == LocalPinAuthPurpose::policy_update && request_id[0] != '\0') {
                if (!write_policy_update_result_response(request_id, "consistency_error", "consistency_error", true)) {
                    log_response_write_failure("policy_update_result", request_id);
                }
                agent_q::policy_update_flow_clear();
                agent_q::protocol_pin_approval_clear();
                agent_q::avatar_overlay_show_message("Auth error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
                return;
            }
            if (request_id[0] != '\0') {
                write_connect_rejected_response(request_id, "auth_unavailable", "Local PIN verifier unavailable.");
                agent_q::protocol_pin_approval_clear();
            }
            agent_q::avatar_overlay_show_message("Auth error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            return;
        }
        case agent_q::AgentQLocalPinAuthVerifyResult::locked:
            if (!agent_q::modal_draw_local_pin_auth_panel("Too many wrong PINs. Wait 30s.")) {
                handle_local_pin_auth_display_failure("local PIN authorization display allocation failed after wrong PIN");
            }
            return;
        case agent_q::AgentQLocalPinAuthVerifyResult::wrong_pin:
            if (!agent_q::modal_draw_local_pin_auth_panel("Wrong PIN.")) {
                handle_local_pin_auth_display_failure("local PIN authorization display allocation failed after wrong PIN");
            }
            return;
        case agent_q::AgentQLocalPinAuthVerifyResult::advanced_to_change_pin:
            if (!agent_q::modal_draw_local_pin_auth_panel()) {
                handle_local_pin_auth_display_failure("Change PIN new PIN display allocation failed");
            }
            return;
        case agent_q::AgentQLocalPinAuthVerifyResult::verified_connect: {
            char request_id[kMaxRequestIdSize] = {};
            pending_request_id_for_local_pin_purpose(LocalPinAuthPurpose::connect, request_id, sizeof(request_id));
            if (!replace_active_session()) {
                if (request_id[0] != '\0') {
                    write_error_response(request_id, "rng_error", "Could not create session id.");
                }
                ESP_LOGE(kTag, "connect PIN could not create session id: id=%s", request_id);
                wipe_local_pin_auth_scratch("connect PIN session creation failed");
                clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
                agent_q::protocol_pin_approval_clear();
                agent_q::avatar_overlay_show_message("RNG error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
                return;
            }
            wipe_local_pin_auth_scratch("connect PIN approved");
            clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
            if (request_id[0] != '\0') {
                if (!write_connect_approved_response(request_id)) {
                    log_response_write_failure("connect_result", request_id);
                }
            }
            agent_q::protocol_pin_approval_clear();
            ESP_LOGI(kTag, "connect PIN approved: id=%s", request_id);
            agent_q::avatar_overlay_show_message("Connected", AgentQMessageKind::success, AgentQUiMode::result, kAgentQResultDisplayMs);
            return;
        }
        case agent_q::AgentQLocalPinAuthVerifyResult::verified_policy_update: {
            char request_id[kMaxRequestIdSize] = {};
            pending_request_id_for_local_pin_purpose(LocalPinAuthPurpose::policy_update, request_id, sizeof(request_id));
            clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
            wipe_local_pin_auth_scratch("policy update PIN approved");
            if (!require_pending_policy_update_session(request_id)) {
                return;
            }
            finish_policy_update_terminal(
                request_id,
                agent_q::policy_update_flow_commit(
                    static_cast<uint64_t>(esp_timer_get_time() / 1000LL)));
            return;
        }
        case agent_q::AgentQLocalPinAuthVerifyResult::started_setting_commit:
            if (!agent_q::modal_draw_processing_overlay_on_current_panel(AgentQUiPanelKind::local_pin_auth) &&
                !agent_q::modal_draw_local_pin_auth_panel()) {
                wipe_local_pin_auth_scratch("settings PIN commit display allocation failed");
                clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
                agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            }
            return;
    }
}

void handle_local_pin_auth_prepare_worker_result(
    const agent_q::AgentQLocalAuthWorkerResult& worker_result)
{
    const agent_q::AgentQLocalPinAuthCommitResult result =
        agent_q::local_pin_auth_complete_pin_change_job(worker_result);
    if (result == agent_q::AgentQLocalPinAuthCommitResult::not_ready) {
        return;
    }
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    if (result == agent_q::AgentQLocalPinAuthCommitResult::pin_change_auth_unavailable) {
        agent_q::persistent_material_record_runtime_failure(
            agent_q::AgentQPersistentMaterialRuntimeFailure::pin_change_auth_unavailable,
            persistent_material_ops());
        agent_q::avatar_overlay_show_message(
            "Auth error",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
        return;
    }
    if (result == agent_q::AgentQLocalPinAuthCommitResult::pin_change_storage_error) {
        agent_q::avatar_overlay_show_message(
            "PIN change failed",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
        return;
    }

    agent_q::local_reset_begin_settings(
        xTaskGetTickCount() + pdMS_TO_TICKS(agent_q::kAgentQLocalResetEntryMs));
    if (!agent_q::modal_draw_settings_menu_panel()) {
        wipe_local_reset_scratch("local settings display allocation failed after PIN commit");
        agent_q::avatar_overlay_show_message(
            "PIN changed",
            AgentQMessageKind::success,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
    }
}

void drain_local_auth_worker_results()
{
    agent_q::AgentQLocalAuthWorkerResult worker_result = {};
    while (agent_q::local_auth_worker_poll_result(&worker_result)) {
        switch (worker_result.owner) {
            case agent_q::AgentQLocalAuthWorkerOwner::provisioning_setup:
                handle_setup_auth_worker_result(worker_result);
                break;
            case agent_q::AgentQLocalAuthWorkerOwner::local_reset:
                handle_local_reset_auth_worker_result(worker_result);
                break;
            case agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth:
                if (worker_result.operation == agent_q::AgentQLocalAuthWorkerOperation::verify_pin) {
                    handle_local_pin_auth_verify_worker_result(worker_result);
                } else {
                    handle_local_pin_auth_prepare_worker_result(worker_result);
                }
                break;
        }
        agent_q::local_auth_worker_wipe_result(&worker_result);
    }
}

void clear_local_pin_auth_if_needed()
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(now);
    if (!snapshot.flow_active) {
        return;
    }
    if (snapshot.processing) {
        if (!agent_q::local_pin_auth_fail_processing_if_expired(now)) {
            return;
        }

        const LocalPinAuthPurpose purpose = snapshot.purpose;
        char request_id[kMaxRequestIdSize] = {};
        pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        if (purpose == LocalPinAuthPurpose::policy_update && request_id[0] != '\0') {
            finish_policy_update_terminal(
                request_id,
                agent_q::policy_update_flow_record_timed_out(
                    static_cast<uint64_t>(esp_timer_get_time() / 1000LL)));
            return;
        }
        if (request_id[0] != '\0') {
            write_connect_rejected_response(request_id, "timeout", "Connection PIN timed out.");
            agent_q::protocol_pin_approval_clear();
            agent_q::avatar_overlay_show_message("Connection timed out",
                                 AgentQMessageKind::timeout,
                                 AgentQUiMode::result,
                                 kAgentQResultDisplayMs);
            return;
        }
        agent_q::avatar_overlay_show_message("Auth timed out", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    const LocalPinAuthPurpose purpose = snapshot.purpose;
    char request_id[kMaxRequestIdSize] = {};
    pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
    if (request_id[0] != '\0' &&
        protocol_local_pin_deadline_reached(purpose, now)) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        wipe_local_pin_auth_scratch("protocol-backed local PIN authorization timed out");
        if (purpose == LocalPinAuthPurpose::policy_update) {
            finish_policy_update_terminal(
                request_id,
                agent_q::policy_update_flow_record_timed_out(
                    static_cast<uint64_t>(esp_timer_get_time() / 1000LL)));
            return;
        }
        write_connect_rejected_response(request_id, "timeout", "Connection PIN timed out.");
        agent_q::protocol_pin_approval_clear();
        agent_q::avatar_overlay_show_message("Connection timed out",
                             AgentQMessageKind::timeout,
                             AgentQUiMode::result,
                             kAgentQResultDisplayMs);
        return;
    }

    if (agent_q::local_pin_auth_release_lockout_if_elapsed(
            now,
            local_pin_auth_retry_deadline(purpose, now))) {
        if (!agent_q::modal_draw_local_pin_auth_panel("Try again.")) {
            handle_local_pin_auth_display_failure("local PIN authorization lockout display allocation failed");
        }
        return;
    }

    bool panel_active = false;
    {
        LvglLockGuard lock;
        panel_active =
            local_pin_auth_panel_matches_stage(agent_q::drawing_surface_panel_kind_locked()) &&
            agent_q::drawing_surface_panel_locked() != nullptr;
    }
    const bool expired = agent_q::local_pin_auth_deadline_expired(now);
    if (panel_active && !expired) {
        return;
    }

    if (!panel_active && !expired) {
        if (!agent_q::modal_draw_local_pin_auth_panel()) {
            if (purpose == LocalPinAuthPurpose::policy_update && request_id[0] != '\0') {
                wipe_local_pin_auth_scratch("policy update PIN UI recovery failed");
                finish_policy_update_terminal(
                    request_id,
                    agent_q::policy_update_flow_record_ui_error());
                return;
            }
            if (purpose == LocalPinAuthPurpose::connect && request_id[0] != '\0') {
                write_connect_rejected_response(request_id, "ui_error", "Could not restore local PIN UI.");
                agent_q::protocol_pin_approval_clear();
            }
            wipe_local_pin_auth_scratch("local PIN UI recovery failed");
            agent_q::avatar_overlay_show_message("Display error",
                                 AgentQMessageKind::error,
                                 AgentQUiMode::result,
                                 kAgentQResultDisplayMs);
        }
        return;
    }

    if (panel_active) {
        clear_agent_q_panel_if_local_pin_auth_stage();
    }
    wipe_local_pin_auth_scratch(
        expired ? "local PIN authorization timed out" : "local PIN authorization panel lost");

    if (request_id[0] != '\0') {
        if (purpose == LocalPinAuthPurpose::policy_update) {
            finish_policy_update_terminal(
                request_id,
                agent_q::policy_update_flow_record_timed_out(
                    static_cast<uint64_t>(esp_timer_get_time() / 1000LL)));
            return;
        }
        write_connect_rejected_response(request_id,
                                        expired ? "timeout" : "rejected",
                                        expired ? "Connection PIN timed out." : "Connection PIN UI closed.");
        agent_q::protocol_pin_approval_clear();
        agent_q::avatar_overlay_show_message(expired ? "Connection timed out" : "Connection canceled",
                             expired ? AgentQMessageKind::timeout : AgentQMessageKind::info,
                             AgentQUiMode::result,
                             kAgentQResultDisplayMs);
        return;
    }

    if (expired) {
        agent_q::avatar_overlay_show_message("Settings timed out", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void poll_touch_fallback()
{
    if (!agent_q::connect_approval_awaiting_choice()) {
        return;
    }

    const auto touch = hal_bridge::get_touch_point();
    if (touch.num == 0) {
        g_connect_decision_touch_armed = true;
        return;
    }
    if (!g_connect_decision_touch_armed) {
        return;
    }

    lv_area_t panel_area;
    {
        LvglLockGuard lock;
        const AgentQUiPanelKind panel_kind = agent_q::drawing_surface_panel_kind_locked();
        if (!is_decision_panel_kind(panel_kind) ||
            !agent_q::drawing_surface_get_panel_coords(panel_kind, &panel_area)) {
            return;
        }
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

    agent_q::connect_approval_choose(
        relative_x < panel_width / 2
            ? ConnectApprovalChoice::rejected
            : ConnectApprovalChoice::approved);
    g_connect_decision_touch_armed = false;
}

void poll_local_settings_touch_entry()
{
    if (!local_settings_touch_entry_candidate_allowed()) {
        agent_q::local_settings_touch_entry_clear();
        return;
    }

    const auto touch = hal_bridge::get_touch_point();
    const bool inside_entry_corner = touch.num > 0 &&
                                     touch.x >= kScreenWidth - kSettingsTouchEntryWidth &&
                                     touch.y >= 0 &&
                                     touch.y < kSettingsTouchEntryHeight;
    const TickType_t now = xTaskGetTickCount();
    if (agent_q::local_settings_touch_entry_update(
            inside_entry_corner,
            now,
            pdMS_TO_TICKS(kSettingsTouchEntryMs))) {
        enqueue_ui_event(AgentQUiEventKind::settings_requested);
    }
}

void drain_connect_decision_choice_events()
{
    if (g_connect_decision_choice_queue == nullptr) {
        return;
    }

    ConnectApprovalChoice choice = ConnectApprovalChoice::none;
    while (xQueueReceive(g_connect_decision_choice_queue, &choice, 0) == pdTRUE) {
        if (agent_q::connect_approval_awaiting_choice()) {
            agent_q::connect_approval_choose(choice);
            g_connect_decision_touch_armed = false;
        }
    }
}

void start_local_provisioning_from_setup_touch()
{
    if (!setup_choice_action_allowed()) {
        ESP_LOGW(kTag, "Stale local setup generate action ignored");
        return;
    }

    const ProvisioningFlowGenerateResult generation_result =
        agent_q::provisioning_flow_begin_generate(
            xTaskGetTickCount() + pdMS_TO_TICKS(kRecoveryPhraseDisplayMs));
    if (generation_result == ProvisioningFlowGenerateResult::ok) {
        if (agent_q::modal_draw_recovery_phrase_display(agent_q::provisioning_flow_recovery_phrase())) {
            ESP_LOGI(kTag, "Local setup recovery phrase displayed");
        } else {
            wipe_setup_scratch("local setup recovery phrase display allocation failed");
            ESP_LOGW(kTag, "Local setup display failed");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    if (generation_result == ProvisioningFlowGenerateResult::rng_error) {
        ESP_LOGW(kTag, "Local setup RNG failed");
        agent_q::avatar_overlay_show_message("RNG error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    ESP_LOGW(kTag, "Local setup phrase generation failed");
    agent_q::avatar_overlay_show_message("Generation error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
}

void show_setup_choice_from_setup_touch()
{
    if (!local_setup_start_allowed()) {
        ESP_LOGW(kTag, "Local setup touch ignored because setup is unavailable");
        agent_q::avatar_overlay_clear();
        agent_q::avatar_overlay_show_message("Setup unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    agent_q::provisioning_flow_begin_setup_choice(
        xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs));
    if (!agent_q::modal_draw_setup_choice_panel()) {
        wipe_setup_scratch("setup choice display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void start_local_recovery_from_setup_choice()
{
    if (!setup_choice_action_allowed()) {
        ESP_LOGW(kTag, "Stale local recover action ignored");
        return;
    }

    agent_q::provisioning_flow_begin_recover(
        xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs));
    if (!agent_q::modal_draw_recover_word_entry_panel()) {
        wipe_setup_scratch("recovery word entry display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void cancel_setup_from_local_ui()
{
    if (agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::none) ||
        agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::pin_committing)) {
        ESP_LOGW(kTag, "Stale local setup cancel ignored");
        return;
    }

    clear_agent_q_panel_if_kind(AgentQUiPanelKind::setup_choice, SensitiveUiClearPolicy::preserve);
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::recovery_phrase_display, SensitiveUiClearPolicy::preserve);
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::recovery_word_entry, SensitiveUiClearPolicy::preserve);
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
    wipe_setup_scratch("provisioning scratch wipe");
    ESP_LOGI(kTag, "Local setup canceled from recovery phrase UI");
    agent_q::avatar_overlay_show_message("Setup canceled", AgentQMessageKind::rejected, AgentQUiMode::result, kAgentQResultDisplayMs);
}

void confirm_recovery_phrase_from_local_ui()
{
    if (!recovery_phrase_backup_confirmation_ready()) {
        ESP_LOGW(kTag, "Stale local backup confirmation ignored");
        return;
    }

    if (!agent_q::provisioning_flow_begin_pin_setup_from_displayed_phrase(
            xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs))) {
        ESP_LOGW(kTag, "Local backup confirmation could not enter setup PIN state");
        return;
    }

    if (!agent_q::modal_draw_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed");
        ESP_LOGW(kTag, "Local backup confirmation could not start setup PIN entry");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    ESP_LOGI(kTag, "Local backup confirmed; setup PIN entry started");
}

void handle_recover_slot_from_local_ui(uint8_t slot)
{
    if (!agent_q::provisioning_flow_recover_select_slot(
            slot,
            xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs))) {
        return;
    }
    if (!agent_q::modal_draw_recover_word_entry_panel()) {
        wipe_setup_scratch("recovery word entry display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_recover_letter_from_local_ui(char letter)
{
    if (!agent_q::provisioning_flow_recover_add_letter(
            letter,
            xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs))) {
        return;
    }
    if (!agent_q::modal_draw_recover_word_entry_panel()) {
        wipe_setup_scratch("recovery word entry display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_recover_clear_from_local_ui()
{
    if (agent_q::provisioning_flow_recover_clear_active(
            xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs)) &&
        !agent_q::modal_draw_recover_word_entry_panel()) {
        wipe_setup_scratch("recovery word entry display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_recover_candidate_from_local_ui(uint16_t word_index)
{
    if (agent_q::provisioning_flow_recover_select_candidate(
            word_index,
            xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs)) &&
        !agent_q::modal_draw_recover_word_entry_panel()) {
        wipe_setup_scratch("recovery word entry display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_recover_previous_from_local_ui()
{
    if (agent_q::provisioning_flow_recover_previous_page(
            xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs)) &&
        !agent_q::modal_draw_recover_word_entry_panel()) {
        wipe_setup_scratch("recovery word entry display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void start_pin_setup_after_recovered_entropy()
{
    agent_q::provisioning_flow_begin_pin_setup_after_recovery(
        xTaskGetTickCount() + pdMS_TO_TICKS(kLocalPinSetupMs));

    if (!agent_q::modal_draw_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed after recovery");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_recover_next_from_local_ui()
{
    if (!agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::recover_word_entry) ||
        !agent_q::provisioning_flow_recover_current_page_complete()) {
        return;
    }

    if (agent_q::provisioning_flow_recover_next_page(
            xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs))) {
        if (!agent_q::modal_draw_recover_word_entry_panel()) {
            wipe_setup_scratch("recovery word entry display allocation failed");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    if (!agent_q::provisioning_flow_recover_all_words_complete()) {
        return;
    }

    const agent_q::Bip39EntropyRecoveryResult result =
        agent_q::provisioning_flow_recover_entropy_from_words();
    if (result != agent_q::Bip39EntropyRecoveryResult::ok) {
        agent_q::provisioning_flow_recover_refresh_deadline(
            xTaskGetTickCount() + pdMS_TO_TICKS(kProvisioningApprovalMaxMs));
        if (!agent_q::modal_draw_recover_word_entry_panel("Checksum failed. Recheck words.")) {
            wipe_setup_scratch("recovery checksum failure display allocation failed");
            agent_q::avatar_overlay_show_message("Recovery error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
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

        if (event.kind == AgentQUiEventKind::ui_surface_ready) {
            show_idle_agent_q_ui_for_current_state();
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

        if (event.kind == AgentQUiEventKind::settings_change_pin_requested) {
            start_settings_change_pin_from_settings_menu();
            continue;
        }

        if (event.kind == AgentQUiEventKind::settings_reset_requested) {
            start_reset_pin_from_settings_menu();
            continue;
        }

        if (event.kind == AgentQUiEventKind::error_recovery_erase_requested) {
            confirm_error_recovery_from_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::error_recovery_cancel_requested) {
            cancel_error_recovery_from_ui();
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
            if (agent_q::provisioning_flow_snapshot().accepts_setup_pin_input) {
                handle_pin_digit_from_local_ui(event.digit);
            } else if (reset_stage == agent_q::AgentQLocalResetStage::pin_entry) {
                handle_reset_pin_digit_from_local_ui(event.digit);
            } else if (local_pin_auth_accepts_keypad_input()) {
                handle_local_pin_auth_digit_from_ui(event.digit);
            }
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_clear_requested) {
            const agent_q::AgentQLocalResetStage reset_stage =
                agent_q::local_reset_snapshot(xTaskGetTickCount()).stage;
            if (agent_q::provisioning_flow_snapshot().accepts_setup_pin_input) {
                handle_pin_clear_from_local_ui();
            } else if (reset_stage == agent_q::AgentQLocalResetStage::pin_entry) {
                handle_reset_pin_clear_from_local_ui();
            } else if (local_pin_auth_accepts_keypad_input()) {
                handle_local_pin_auth_clear_from_ui();
            }
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_backspace_requested) {
            const agent_q::AgentQLocalResetStage reset_stage =
                agent_q::local_reset_snapshot(xTaskGetTickCount()).stage;
            if (agent_q::provisioning_flow_snapshot().accepts_setup_pin_input) {
                handle_pin_backspace_from_local_ui();
            } else if (reset_stage == agent_q::AgentQLocalResetStage::pin_entry) {
                handle_reset_pin_backspace_from_local_ui();
            } else if (local_pin_auth_accepts_keypad_input()) {
                handle_local_pin_auth_backspace_from_ui();
            }
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_submit_requested) {
            const agent_q::AgentQLocalResetStage reset_stage =
                agent_q::local_reset_snapshot(xTaskGetTickCount()).stage;
            if (agent_q::provisioning_flow_snapshot().accepts_setup_pin_input) {
                handle_pin_submit_from_local_ui();
            } else if (reset_stage == agent_q::AgentQLocalResetStage::pin_entry) {
                handle_reset_pin_submit_from_local_ui();
            } else if (local_pin_auth_accepts_keypad_input()) {
                handle_local_pin_auth_submit_from_ui();
            }
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_cancel_requested) {
            const agent_q::AgentQLocalResetStage reset_stage =
                agent_q::local_reset_snapshot(xTaskGetTickCount()).stage;
            if (agent_q::provisioning_flow_snapshot().accepts_setup_pin_input) {
                cancel_setup_from_local_ui();
            } else if (reset_stage == agent_q::AgentQLocalResetStage::pin_entry) {
                cancel_local_reset_from_ui("Reset canceled");
            } else if (local_pin_auth_accepts_keypad_input()) {
                cancel_local_pin_auth_from_ui("Settings canceled");
            }
            continue;
        }

        if (event.kind != AgentQUiEventKind::panel_deleted) {
            continue;
        }
        if (provisioning_flow_panel_deleted(event.panel_kind, "setup panel deleted")) {
            continue;
        } else if (local_reset_panel_matches_stage(event.panel_kind)) {
            wipe_local_reset_scratch("local reset panel deleted");
        } else if (event.panel_kind == AgentQUiPanelKind::local_pin_auth) {
            // LVGL may delete our transient panel when the underlying app redraws.
            // UI object lifetime is not the authority for PIN authorization state;
            // clear_local_pin_auth_if_needed() will either restore the panel or
            // time out the flow according to the explicit state deadline.
            ESP_LOGW(kTag, "Local PIN authorization panel deleted; state loop will recover if active");
        }
    }
}

void ensure_connect_decision_ui()
{
    if (!agent_q::connect_approval_awaiting_choice()) {
        return;
    }

    bool needs_decision_panel = false;
    {
        LvglLockGuard lock;
        needs_decision_panel = agent_q::drawing_surface_panel_locked() == nullptr ||
                               !is_decision_panel_kind(agent_q::drawing_surface_panel_kind_locked());
    }
    if (!needs_decision_panel) {
        return;
    }

    const agent_q::AgentQConnectApprovalSnapshot approval =
        agent_q::connect_approval_snapshot();
    show_connect_decision(approval.gateway_name);
    ESP_LOGW(kTag, "connect decision UI recovered: id=%s", approval.request_id);
}

void send_connect_decision_response_if_needed()
{
    drain_connect_decision_choice_events();
    poll_touch_fallback();

    agent_q::AgentQConnectApprovalSnapshot approval =
        agent_q::connect_approval_snapshot();
    if (!approval.active || approval.choice == ConnectApprovalChoice::none) {
        if (agent_q::connect_approval_deadline_reached(xTaskGetTickCount())) {
            char request_id[kMaxRequestIdSize] = {};
            agent_q::connect_approval_request_id(request_id, sizeof(request_id));
            // Device leaves awaiting_approval before reporting the result.
            agent_q::connect_approval_clear();
            write_connect_rejected_response(request_id, "timeout", "Connection approval timed out.");
            ESP_LOGI(kTag, "connect timed out: id=%s", request_id);
            show_result_and_clear_connect_decision("Connection timed out", AgentQMessageKind::timeout);
        }
        return;
    }

    const bool approved = approval.choice == ConnectApprovalChoice::approved;
    char request_id[kMaxRequestIdSize] = {};
    agent_q::connect_approval_request_id(request_id, sizeof(request_id));
    agent_q::connect_approval_clear();
    if (approved) {
        if (!replace_active_session()) {
            write_error_response(request_id, "rng_error", "Could not create session id.");
            ESP_LOGE(kTag, "connect could not create session id: id=%s", request_id);
            show_result_and_clear_connect_decision("RNG error", AgentQMessageKind::error);
            return;
        }
        if (write_connect_approved_response(request_id)) {
            ESP_LOGI(kTag, "connect approved: id=%s", request_id);
        } else {
            log_response_write_failure("connect_result", request_id);
        }
        show_result_and_clear_connect_decision("Connected", AgentQMessageKind::success);
    } else {
        if (write_connect_rejected_response(request_id, "rejected", "Connection rejected.")) {
            ESP_LOGI(kTag, "connect rejected: id=%s", request_id);
        } else {
            log_response_write_failure("connect_result", request_id);
        }
        show_result_and_clear_connect_decision("Connection rejected", AgentQMessageKind::rejected);
    }
}

void handle_line(const char* line)
{
    if (!agent_q::agent_q_json_line_is_single_object(line)) {
        write_error_response(nullptr, "invalid_json", "Invalid JSON.");
        return;
    }

    JsonDocument request;
    const DeserializationError error = deserializeJson(request, line);
    if (error) {
        write_error_response(nullptr, "invalid_json", "Invalid JSON.");
        return;
    }

    const char* id = nullptr;
    if (!agent_q::agent_q_json_value_c_string(request["id"], &id)) {
        write_error_response(nullptr, "invalid_id", "Invalid request id.");
        return;
    }
    if (!is_safe_id(id)) {
        write_error_response(nullptr, "invalid_id", "Invalid request id.");
        return;
    }

    const int version = request["version"] | 0;
    if (version != kProtocolVersion) {
        write_error_response(id, "unsupported_version", "Unsupported protocol version.");
        return;
    }

    const char* type = nullptr;
    if (!agent_q::agent_q_json_optional_c_string(request["type"], "", &type)) {
        write_error_response(id, "unsupported_type", "Unsupported request type.");
        return;
    }
    if (strcmp(type, "get_status") == 0) {
        if (!write_status_response(id)) {
            log_response_write_failure("status", id);
        }
        return;
    }

    if (strcmp(type, "identify_device") == 0) {
        if (write_busy_if_pending_or_local_flow_active(id)) {
            return;
        }

        const char* code = nullptr;
        if (!agent_q::agent_q_json_optional_c_string(request["params"]["code"], "", &code)) {
            write_error_response(id, "invalid_code", "Invalid identification code.");
            return;
        }
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
        if (write_identify_device_result(id, code)) {
            ESP_LOGI(kTag, "identify_device displayed: id=%s code=%s", id, code);
        } else {
            log_response_write_failure("identify_device_result", id);
        }
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

        const char* gateway_name = nullptr;
        if (!agent_q::agent_q_json_optional_c_string(request["params"]["gatewayName"], "", &gateway_name)) {
            write_error_response(id, "invalid_gateway_name", "gatewayName must be 1-64 printable ASCII characters.");
            return;
        }
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
            ESP_LOGI(kTag, "connect waiting for local PIN: id=%s gateway=%s", id, gateway_name);
            return;
        }

        const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(approval_timeout_ms);
        if (!agent_q::connect_approval_begin(id, gateway_name, deadline)) {
            write_connect_rejected_response(id, "invalid_state", "Connect is unavailable.");
            agent_q::avatar_overlay_show_message("Connect unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            return;
        }
        show_connect_decision(gateway_name);
        ESP_LOGI(kTag, "connect waiting for YES/NO: id=%s gateway=%s", id, gateway_name);
        return;
    }

    if (strcmp(type, "disconnect") == 0) {
        const char* session_id = nullptr;
        if (!agent_q::agent_q_json_optional_c_string(request["sessionId"], "", &session_id)) {
            write_error_response(id, "invalid_session", "Invalid session.");
            return;
        }
        if (!require_active_matching_session(id, session_id)) {
            return;
        }
        if (disconnect_pending_policy_update_for_session(id, session_id)) {
            return;
        }
        if (write_busy_if_pending_or_local_flow_active(id, true)) {
            return;
        }
        clear_active_session();
        if (write_disconnect_result(id)) {
            ESP_LOGI(kTag, "disconnect: id=%s", id);
        } else {
            log_response_write_failure("disconnect_result", id);
        }
        return;
    }

    if (strcmp(type, "get_capabilities") == 0) {
        // get_capabilities is read-only and session-scoped. Firmware is the
        // capability authority; Gateway must not infer or extend this response.
        if (!provisioned_material_ready()) {
            write_error_response(id, "invalid_state", "Capabilities are available only after provisioning is complete.");
            return;
        }
        if (write_busy_if_pending_or_local_flow_active(id, true)) {
            return;
        }

        const char* session_id = nullptr;
        if (!agent_q::agent_q_json_optional_c_string(request["sessionId"], "", &session_id)) {
            write_error_response(id, "invalid_session", "Invalid session.");
            return;
        }
        if (!require_active_matching_session(id, session_id)) {
            return;
        }

        if (write_capabilities_response(id)) {
            ESP_LOGI(kTag, "get_capabilities: id=%s", id);
        } else {
            log_response_write_failure("capabilities", id);
        }
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
        if (write_busy_if_pending_or_local_flow_active(id, true)) {
            return;
        }

        const char* session_id = nullptr;
        if (!agent_q::agent_q_json_optional_c_string(request["sessionId"], "", &session_id)) {
            write_error_response(id, "invalid_session", "Invalid session.");
            return;
        }
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
        if (write_busy_if_pending_or_local_flow_active(id, true)) {
            return;
        }

        const char* session_id = nullptr;
        if (!agent_q::agent_q_json_optional_c_string(request["sessionId"], "", &session_id)) {
            write_error_response(id, "invalid_session", "Invalid session.");
            return;
        }
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

    if (strcmp(type, "get_approval_history") == 0) {
        // get_approval_history is read-only and session-scoped. It returns
        // Firmware-authored approval-history metadata such as method decisions
        // and future policy-update terminal records; raw requests, session ids,
        // private material, PINs, and policy documents are never stored or
        // returned.
        if (!provisioned_material_ready()) {
            write_error_response(id, "invalid_state", "Approval history is available only after provisioning is complete.");
            return;
        }
        if (write_busy_if_pending_or_local_flow_active(id, true)) {
            return;
        }

        const char* session_id = nullptr;
        if (!agent_q::agent_q_json_optional_c_string(request["sessionId"], "", &session_id)) {
            write_error_response(id, "invalid_session", "Invalid session.");
            return;
        }
        if (!require_active_matching_session(id, session_id)) {
            return;
        }

        size_t limit = agent_q::kAgentQApprovalHistoryPageMax;
        uint64_t before_sequence = 0;
        if (!parse_approval_history_params(request, &limit, &before_sequence)) {
            write_error_response(id, "invalid_params", "Approval history params are invalid.");
            return;
        }

        if (!write_approval_history_response(id, before_sequence, limit)) {
            write_error_response(id, "history_error", "Approval history is unavailable.");
            ESP_LOGW(kTag, "get_approval_history unavailable: id=%s", id);
            return;
        }
        ESP_LOGI(kTag, "get_approval_history: id=%s", id);
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
        if (write_busy_if_pending_or_local_flow_active(id, true)) {
            return;
        }

        const char* session_id = nullptr;
        if (!agent_q::agent_q_json_optional_c_string(request["sessionId"], "", &session_id)) {
            write_error_response(id, "invalid_session", "Invalid session.");
            return;
        }
        if (!require_active_matching_session(id, session_id)) {
            return;
        }

        const agent_q::CallMethodNamespaceValidation namespace_validation =
            agent_q::classify_call_method_namespace(request);
        if (namespace_validation == agent_q::CallMethodNamespaceValidation::invalid_namespace) {
            write_error_response(id, "invalid_method", "Invalid call_method namespace fields.");
            return;
        }

        if (namespace_validation == agent_q::CallMethodNamespaceValidation::admin_scoped) {
            const char* method_namespace = nullptr;
            const char* method = nullptr;
            if (!agent_q::agent_q_json_value_c_string(request["methodNamespace"], &method_namespace) ||
                strcmp(method_namespace, "admin") != 0 ||
                !agent_q::agent_q_json_value_c_string(request["method"], &method) ||
                strcmp(method, "propose_policy_update") != 0) {
                write_error_response(id, "invalid_method", "Invalid admin method request.");
                return;
            }
            if (write_busy_if_pending_or_local_flow_active(id)) {
                return;
            }

            JsonVariant params = request["params"];
            if (!params.is<JsonObject>()) {
                write_error_response(id, "invalid_params", "Policy update params must be an object.");
                return;
            }
            JsonObject params_object = params.as<JsonObject>();
            bool saw_policy = false;
            for (JsonPair pair : params_object) {
                if (agent_q::agent_q_json_string_equals(pair.key(), "policy")) {
                    saw_policy = true;
                    continue;
                }
                write_error_response(id, "invalid_params", "Policy update params contain unsupported fields.");
                return;
            }
            if (!saw_policy) {
                write_error_response(id, "invalid_params", "Policy update params require policy.");
                return;
            }

            const agent_q::AgentQPolicyUpdateFlowBeginResult begin_result =
                agent_q::policy_update_flow_begin(params_object["policy"]);
            if (begin_result != agent_q::AgentQPolicyUpdateFlowBeginResult::ok) {
                if (!write_policy_update_result_response(
                        id,
                        "invalid_policy",
                        agent_q::policy_update_flow_begin_result_reason(begin_result),
                        false)) {
                    log_response_write_failure("policy_update_result", id);
                }
                return;
            }

            begin_policy_update_pin_auth(id, session_id, kProvisioningApprovalMaxMs);
            ESP_LOGI(kTag, "policy update waiting for local PIN: id=%s", id);
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

        const char* chain = nullptr;
        const char* method = nullptr;
        if (!agent_q::agent_q_json_value_c_string(request["chain"], &chain) ||
            !agent_q::agent_q_json_value_c_string(request["method"], &method)) {
            write_error_response(id, "invalid_method", "Invalid call_method chain or method.");
            return;
        }
        const agent_q::AgentQMethodRuntimeResult method_result =
            agent_q::evaluate_call_method(chain, method, request["params"]);
        if (method_result.has_approval_history) {
            const auto& history = method_result.approval_history;
            const agent_q::AgentQApprovalHistoryAppendInput append_input{
                history.decision,
                history.confirmation_kind,
                history.chain,
                history.method,
                history.reason_code,
                history.payload_digest[0] != '\0' ? history.payload_digest : nullptr,
                history.policy_hash[0] != '\0' ? history.policy_hash : nullptr,
                history.rule_ref[0] != '\0' ? history.rule_ref : nullptr,
            };
            if (!agent_q::approval_history_append(
                    append_input,
                    static_cast<uint64_t>(esp_timer_get_time() / 1000LL))) {
                ESP_LOGW(kTag, "Approval history append failed: id=%s chain=%s method=%s code=%s",
                         id,
                         chain,
                         method,
                         method_result.code);
                write_error_response(id, "history_error", "Could not record method decision.");
                return;
            }
        }
        if (method_result.status == agent_q::AgentQMethodRuntimeStatus::invalid_params) {
            write_error_response(id, method_result.code, method_result.message);
            return;
        }

        if (write_rejected_method_result(id, method_result.code, method_result.message)) {
            ESP_LOGI(kTag, "call_method rejected: id=%s chain=%s method=%s code=%s",
                     id,
                     chain,
                     method,
                     method_result.code);
        } else {
            log_response_write_failure("method_result", id);
        }
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
            if (g_discarding_invalid_line) {
                g_discarding_invalid_line = false;
                g_line_size = 0;
                continue;
            }
            g_line_buffer[g_line_size] = '\0';
            if (g_line_size > 0) {
                handle_line(g_line_buffer);
            }
            g_line_size = 0;
            continue;
        }

        if (g_discarding_invalid_line) {
            continue;
        }

        if (c == '\0') {
            g_line_size = 0;
            g_discarding_invalid_line = true;
            write_error_response(nullptr, "invalid_json", "JSON line contains a NUL byte.");
            continue;
        }

        if (g_line_size + 1 >= sizeof(g_line_buffer)) {
            g_line_size = 0;
            g_discarding_invalid_line = true;
            write_error_response(nullptr, "invalid_json", "JSON line is too long.");
            continue;
        }

        g_line_buffer[g_line_size++] = c;
    }
}

void usb_request_task(void*)
{
    // Ordering matters: any pending YES/NO choice is resolved and its response is
    // sent (send_connect_decision_response_if_needed) before new input is read
    // (poll_usb_input). A new request therefore cannot be handled until the
    // in-flight approval response has been written in the same loop pass.
    while (true) {
        drain_local_auth_worker_results();
        clear_identification_if_needed();
        clear_agent_q_message_if_needed();
        clear_setup_choice_if_needed();
        clear_recovery_phrase_if_needed();
        clear_recovery_word_entry_if_needed();
        clear_pin_setup_if_needed();
        clear_local_reset_if_needed();
        clear_local_pin_auth_if_needed();
        drain_ui_events();
        commit_local_reset_if_ready();
        commit_local_pin_setting_if_ready();
        poll_local_settings_touch_entry();
        show_persistent_error_recovery_if_needed();
        send_connect_decision_response_if_needed();
        ensure_connect_decision_ui();
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
    agent_q::session_init();
    if (!agent_q::local_auth_worker_init()) {
        ESP_LOGE(kTag, "Local auth worker init failed");
    }
    agent_q::connect_approval_clear();
    g_connect_decision_touch_armed = false;
    agent_q::identification_display_clear();
    wipe_setup_scratch("usb request server init");
    wipe_local_reset_scratch("usb request server init");
    if (g_connect_decision_choice_queue == nullptr) {
        g_connect_decision_choice_queue = xQueueCreate(4, sizeof(ConnectApprovalChoice));
        if (g_connect_decision_choice_queue == nullptr) {
            ESP_LOGE(kTag, "Pending choice queue create failed");
        }
    } else {
        xQueueReset(g_connect_decision_choice_queue);
    }
    if (g_ui_event_queue == nullptr) {
        g_ui_event_queue = xQueueCreate(4, sizeof(AgentQUiEvent));
        if (g_ui_event_queue == nullptr) {
            ESP_LOGE(kTag, "UI event queue create failed");
        }
    } else {
        xQueueReset(g_ui_event_queue);
    }
    agent_q::drawing_surface_set_panel_deleted_callback(on_agent_q_panel_deleted);
    agent_q::AgentQModalDrawingCallbacks modal_callbacks;
    modal_callbacks.on_yes_clicked = on_yes_clicked;
    modal_callbacks.on_no_clicked = on_no_clicked;
    modal_callbacks.on_setup_generate_clicked = on_setup_generate_clicked;
    modal_callbacks.on_setup_recover_clicked = on_setup_recover_clicked;
    modal_callbacks.on_setup_cancel_clicked = on_setup_cancel_clicked;
    modal_callbacks.on_settings_cancel_clicked = on_settings_cancel_clicked;
    modal_callbacks.on_settings_connect_pin_clicked = on_settings_connect_pin_clicked;
    modal_callbacks.on_settings_change_pin_clicked = on_settings_change_pin_clicked;
    modal_callbacks.on_settings_reset_clicked = on_settings_reset_clicked;
    modal_callbacks.on_error_recovery_erase_clicked = on_error_recovery_erase_clicked;
    modal_callbacks.on_error_recovery_cancel_clicked = on_error_recovery_cancel_clicked;
    modal_callbacks.on_reset_cancel_clicked = on_reset_cancel_clicked;
    modal_callbacks.on_recovery_phrase_cancel_clicked = on_recovery_phrase_cancel_clicked;
    modal_callbacks.on_recovery_phrase_confirm_clicked = on_recovery_phrase_confirm_clicked;
    modal_callbacks.on_pin_digit_clicked = on_pin_digit_clicked;
    modal_callbacks.on_pin_clear_clicked = on_pin_clear_clicked;
    modal_callbacks.on_pin_backspace_clicked = on_pin_backspace_clicked;
    modal_callbacks.on_pin_submit_clicked = on_pin_submit_clicked;
    modal_callbacks.on_pin_cancel_clicked = on_pin_cancel_clicked;
    modal_callbacks.on_recover_slot_clicked = on_recover_slot_clicked;
    modal_callbacks.on_recover_letter_clicked = on_recover_letter_clicked;
    modal_callbacks.on_recover_candidate_clicked = on_recover_candidate_clicked;
    modal_callbacks.on_recover_clear_clicked = on_recover_clear_clicked;
    modal_callbacks.on_recover_previous_clicked = on_recover_previous_clicked;
    modal_callbacks.on_recover_next_clicked = on_recover_next_clicked;
    modal_callbacks.on_recover_cancel_clicked = on_recover_cancel_clicked;
    agent_q::modal_drawing_set_callbacks(modal_callbacks);
    agent_q::avatar_overlay_clear();

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
    usb_serial_jtag_vfs_use_driver();

    g_usb_ready = true;
    if (g_usb_task == nullptr) {
        BaseType_t task_created = xTaskCreatePinnedToCore(
            usb_request_task, "agent_q_usb", kUsbRequestTaskStackBytes, nullptr, 4, &g_usb_task, 1);
        if (task_created != pdPASS) {
            ESP_LOGE(kTag, "USB request task start failed");
            g_usb_ready = false;
            g_usb_task = nullptr;
            return;
        }
    }
    ESP_LOGI(kTag, "USB request server ready");
}

void notify_agent_q_ui_surface_ready()
{
    {
        LvglLockGuard lock;
        agent_q::drawing_surface_mark_ready();
    }
    enqueue_ui_event(AgentQUiEventKind::ui_surface_ready);
}

}  // namespace agent_q
