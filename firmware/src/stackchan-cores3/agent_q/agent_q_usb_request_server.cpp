#include "agent_q_usb_request_server.h"

#include <stdio.h>
#include <string.h>

#include <ArduinoJson.h>
#include <memory>
#include "agent_q_sign_route.h"
#include "agent_q_u64_decimal.h"
#include "agent_q_avatar_overlay_drawing.h"
#include "agent_q_approval_history.h"
#include "agent_q_base64.h"
#include "agent_q_bip39.h"
#include "agent_q_bip39_wordlist.h"
#include "agent_q_connect_approval.h"
#include "agent_q_human_approval_settings.h"
#include "agent_q_drawing_surface.h"
#include "agent_q_entropy.h"
#include "agent_q_identification_display.h"
#include "agent_q_json_input.h"
#include "agent_q_local_auth.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_local_pin_auth.h"
#include "agent_q_local_settings_touch_entry.h"
#include "agent_q_local_reset.h"
#include "agent_q_modal_drawing.h"
#include "agent_q_persistent_material.h"
#include "agent_q_policy_proposal_parser.h"
#include "agent_q_policy_store.h"
#include "agent_q_policy_update_flow.h"
#include "agent_q_protocol_constants.h"
#include "agent_q_protocol_pin_approval.h"
#include "agent_q_provisioning_flow.h"
#include "agent_q_provisioning_runtime_state.h"
#include "agent_q_request_id.h"
#include "agent_q_session.h"
#include "agent_q_sign_personal_message_user_ingress.h"
#include "agent_q_sign_transaction_policy_runtime.h"
#include "agent_q_policy_signing_execution.h"
#include "agent_q_user_signing_confirmation.h"
#include "agent_q_user_signing_flow.h"
#include "agent_q_sign_transaction_user_ingress.h"
#include "agent_q_user_signing_review_view_model.h"
#include "agent_q_user_signing_critical_section.h"
#include "agent_q_signing_route.h"
#include "agent_q_signing_mode.h"
#include "agent_q_sui_account.h"
#include "agent_q_sui_account_store.h"
#include "agent_q_sui_signing_preparation.h"
#include "agent_q_sui_signing_service.h"
#include "agent_q_timeout_window.h"
#include "agent_q_usb_link_state.h"
#include "agent_q_usb_approval_history_handler.h"
#include "agent_q_usb_connect_handler.h"
#include "agent_q_usb_device_handlers.h"
#include "agent_q_usb_disconnect_handler.h"
#include "agent_q_usb_operation_dispatch.h"
#include "agent_q_usb_operation_response_writer.h"
#include "agent_q_usb_policy_propose_handler.h"
#include "agent_q_ui_panel_cleanup.h"
#include "agent_q_usb_operation_type.h"
#include "agent_q_usb_line_receiver.h"
#include "agent_q_usb_request_envelope.h"
#include "agent_q_usb_request_line_handler.h"
#include "agent_q_usb_retained_result_handlers.h"
#include "agent_q_usb_session_read_handlers.h"
#include "agent_q_usb_signing_handlers.h"
#include "agent_q_usb_signing_result_writer.h"
#include "agent_q_usb_response_writer.h"
#include "agent_q_ui_event_bridge.h"
#include "agent_q_signing_retry_delivery.h"
#include "agent_q_signing_retry_response.h"
#include "agent_q_signing_preflight.h"
#include "agent_q_signing_result_store.h"
#include "agent_q_usb_session_grace.h"
#include "agent_q_usb_session_loss.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
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
using AgentQUiEvent = agent_q::AgentQUiEvent;
using AgentQUiEventKind = agent_q::AgentQUiEventKind;
using AgentQMessageKind = agent_q::AgentQMessageKind;
using AgentQUiMode = agent_q::AgentQUiMode;
using ConnectApprovalChoice = agent_q::AgentQConnectApprovalChoice;
using LocalPinAuthPurpose = agent_q::AgentQLocalPinAuthPurpose;
using LocalPinAuthStage = agent_q::AgentQLocalPinAuthStage;
using AgentQUsbOperationResponseWriter = agent_q::AgentQUsbOperationResponseWriter;
using ProvisioningFlowGenerateResult = agent_q::AgentQProvisioningFlowGenerateResult;
using ProvisioningFlowPanel = agent_q::AgentQProvisioningFlowPanel;
using ProvisioningFlowPinSubmitResult = agent_q::AgentQProvisioningFlowPinSubmitResult;
using ProvisioningFlowStage = agent_q::AgentQProvisioningFlowStage;
using ProvisioningRuntimeState = agent_q::AgentQProvisioningRuntimeState;
using SensitiveUiClearPolicy = agent_q::SensitiveUiClearPolicy;

constexpr const char* kTag = "UsbRequestServer";
constexpr int kProtocolVersion = agent_q::kAgentQProtocolVersion;
constexpr const char* kFirmwareName = "Agent-Q Firmware";
constexpr const char* kHardwareId = "stackchan-cores3";
constexpr const char* kFirmwareVersion = "0.0.0";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kDeviceIdKey = "device_id";
constexpr uint32_t kIdentifyDisplayDefaultMs = 30000;
constexpr uint32_t kConnectApprovalDefaultMs = 30000;
constexpr uint32_t kProvisioningApprovalMaxMs = 30000;
constexpr uint32_t kLocalPinInputWindowMs = 30000;
constexpr uint32_t kBackupPhraseDisplayMs = kProvisioningApprovalMaxMs;
constexpr uint32_t kLocalPinSetupMs = kProvisioningApprovalMaxMs;
constexpr uint32_t kLocalProcessingRenderDelayMs = 250;
constexpr uint32_t kLocalProcessingDisplayMs = 900;
constexpr uint32_t kSettingsTouchEntryMs = 900;
constexpr uint32_t kUsbHostLinkCheckMs = 10;
constexpr uint32_t kUsbRequestTaskStackBytes = 8192;
constexpr size_t kPolicyReadbackEnvelopeReserveBytes = 1024;
constexpr size_t kMaxRequestIdSize = agent_q::kAgentQRequestIdSize;
constexpr size_t kDeviceIdSize = 37;
constexpr size_t kIdentifyCodeSize = 5;
constexpr size_t kClientNameSize = 65;
constexpr int kScreenWidth = 320;
constexpr int kSettingsTouchEntryWidth = 64;
constexpr int kSettingsTouchEntryHeight = 56;
constexpr uint32_t kAgentQResultDisplayMs = 1800;

static_assert(
    agent_q::kAgentQPolicyProposalMaxSerializedObjectBytes + kPolicyReadbackEnvelopeReserveBytes <=
        agent_q::kAgentQUsbResponseLineMaxBytes,
    "policy_get readback for accepted policy proposals must fit within the USB response line cap");

char g_device_id[kDeviceIdSize];
static_assert(
    kMaxRequestIdSize == agent_q::kAgentQProtocolPinRequestIdSize,
    "Protocol PIN approval request-id storage must match USB request-id storage.");
static_assert(
    kMaxRequestIdSize == agent_q::kAgentQConnectApprovalRequestIdSize,
    "Connect approval request-id storage must match USB request-id storage.");
static_assert(
    kClientNameSize == agent_q::kAgentQConnectApprovalClientNameSize,
    "Connect approval agent-q-name storage must match USB agent-q-name storage.");

bool g_usb_ready = false;
TaskHandle_t g_usb_task = nullptr;

bool refresh_persistent_material_consistency();
bool provisioned_material_ready();
agent_q::AgentQPersistentMaterialOps persistent_material_ops();
agent_q::AgentQLocalResetPersistenceOps local_reset_persistence_ops();
bool clear_agent_q_panel_if_kind(
    AgentQUiPanelKind expected_kind,
    SensitiveUiClearPolicy policy = SensitiveUiClearPolicy::wipe);
bool clear_agent_q_panel_if_local_reset_stage(
    SensitiveUiClearPolicy policy = SensitiveUiClearPolicy::wipe);
bool clear_agent_q_panel_if_local_pin_auth_stage(
    SensitiveUiClearPolicy policy = SensitiveUiClearPolicy::wipe);
void clear_connect_review_state();
void cancel_policy_update_after_session_loss(const char* log_reason);
void cancel_user_signing_after_session_loss(const char* log_reason);
bool pending_request_id_for_local_pin_purpose(
    LocalPinAuthPurpose purpose,
    char* output,
    size_t output_size);
void handle_local_pin_auth_display_failure(const char* reason, bool clear_panel = false);
void show_persistent_error_recovery_if_needed();
void finish_user_signing_terminal(
    const char* request_id,
    const agent_q::AgentQUserSigningOutput* signing_output = nullptr);
void finish_user_signing_error_terminal(
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message);

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

bool is_connect_review_panel_kind(AgentQUiPanelKind kind)
{
    return kind == AgentQUiPanelKind::connect_review;
}

bool local_pin_auth_panel_matches_stage(AgentQUiPanelKind kind)
{
    return kind == AgentQUiPanelKind::local_pin_auth &&
           agent_q::local_pin_auth_flow_active();
}

bool user_signing_review_panel_matches_stage(AgentQUiPanelKind kind)
{
    const agent_q::AgentQUserSigningFlowSnapshot snapshot =
        agent_q::user_signing_flow_snapshot();
    return kind == AgentQUiPanelKind::user_signing_review &&
           snapshot.active &&
           snapshot.stage == agent_q::AgentQUserSigningStage::reviewing;
}

bool policy_update_review_panel_matches_stage(AgentQUiPanelKind kind)
{
    const agent_q::AgentQPolicyUpdateFlowSnapshot snapshot =
        agent_q::policy_update_flow_snapshot();
    return kind == AgentQUiPanelKind::policy_update_review &&
           snapshot.active &&
           snapshot.stage == agent_q::AgentQPolicyUpdateFlowStage::reviewing;
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

bool handle_provisioning_panel_deleted(ProvisioningFlowPanel panel, const char* reason)
{
    const bool wiped = agent_q::provisioning_flow_handle_panel_deleted(panel);
    if (wiped) {
        ESP_LOGW(kTag, "Setup scratch wiped: %s", reason != nullptr ? reason : "panel deleted");
    }
    return wiped;
}

agent_q::AgentQUiPanelCleanupPlan panel_cleanup_plan(
    AgentQUiPanelKind panel_kind,
    agent_q::AgentQUiPanelCleanupEvent event)
{
    return agent_q::ui_panel_cleanup_plan(agent_q::AgentQUiPanelCleanupInput{
        panel_kind,
        event,
        local_reset_panel_matches_stage(panel_kind),
        local_pin_auth_panel_matches_stage(panel_kind),
        policy_update_review_panel_matches_stage(panel_kind),
        user_signing_review_panel_matches_stage(panel_kind),
    });
}

void apply_panel_cleanup_plan(
    const agent_q::AgentQUiPanelCleanupPlan& plan,
    const char* setup_reason,
    const char* reset_reason,
    const char* local_pin_reason)
{
    if (plan.route_provisioning_panel_deleted &&
        !handle_provisioning_panel_deleted(plan.provisioning_panel, setup_reason) &&
        plan.wipe_setup_if_unhandled) {
        wipe_setup_scratch(setup_reason);
    }
    if (plan.wipe_local_reset) {
        wipe_local_reset_scratch(reset_reason);
    }
    if (plan.wipe_local_pin_auth) {
        wipe_local_pin_auth_scratch(local_pin_reason);
    }
    if (plan.recover_local_pin_auth_panel) {
        // LVGL may delete our transient panel when the underlying app redraws.
        // UI object lifetime is not the authority for PIN authorization state;
        // clear_local_pin_auth_if_needed() will either restore the panel or
        // time out the flow according to the explicit state deadline.
        ESP_LOGW(kTag, "Local PIN authorization panel deleted; state loop will recover if active");
    }
    if (plan.recover_policy_update_review_panel) {
        ESP_LOGW(kTag, "Policy update review panel deleted; state loop will recover if active");
    }
    if (plan.wipe_user_signing) {
        agent_q::user_signing_confirmation_cancel_for_pin_loss();
    }
    if (plan.recover_user_signing_review_panel) {
        ESP_LOGW(kTag, "Signature review panel deleted; state loop will recover if active");
    }
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

const char* current_device_state()
{
    if (agent_q::persistent_material_consistency_error_active()) {
        return "error";
    }
    const agent_q::AgentQUserSigningFlowSnapshot user_signing =
        agent_q::user_signing_flow_snapshot();
    if (agent_q::connect_approval_active() ||
        agent_q::protocol_pin_approval_active() ||
        (user_signing.active &&
         (user_signing.stage == agent_q::AgentQUserSigningStage::reviewing ||
          user_signing.stage == agent_q::AgentQUserSigningStage::pin_entry))) {
        return "awaiting_approval";
    }
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    if (agent_q::provisioning_flow_active() ||
        (reset.flow_active &&
         reset.stage != agent_q::AgentQLocalResetStage::settings_menu) ||
        agent_q::local_pin_auth_flow_active() ||
        user_signing.active) {
        return "busy";
    }
    return "idle";
}

const AgentQUsbOperationResponseWriter& usb_operation_response_writer()
{
    static const AgentQUsbOperationResponseWriter writer = {
        agent_q::usb_response_write_error,
        agent_q::usb_response_log_write_failure,
    };
    return writer;
}

agent_q::AgentQUsbDeviceResponseInfo usb_device_response_info()
{
    return agent_q::AgentQUsbDeviceResponseInfo{
        g_device_id,
        current_device_state(),
        kFirmwareName,
        kHardwareId,
        kFirmwareVersion,
        agent_q::provisioning_runtime_state_reported(),
    };
}

bool write_connect_approved_response(const char* id)
{
    const agent_q::AgentQUsbDeviceResponseInfo info{
        g_device_id,
        "idle",
        kFirmwareName,
        kHardwareId,
        kFirmwareVersion,
        nullptr,
    };
    return agent_q::usb_response_write_connect_approved(
        id,
        agent_q::session_id(),
        agent_q::kAgentQSessionAdvertisedTtlMs,
        info);
}

bool write_retry_response_json(JsonDocument& response, void*)
{
    return agent_q::usb_response_write_json(response);
}

static char g_signing_preflight_retry_stored_result[agent_q::kSigningResultMaxSize];

agent_q::AgentQSigningPreflightRetryDisposition respond_to_signing_retry(
    const char* request_id,
    const agent_q::AgentQSigningRetryDeliveryResult& retry,
    const char* stored_result,
    void*)
{
    const agent_q::AgentQSigningRetryResponseResult response_result =
        agent_q::deliver_signing_retry_response(
            request_id,
            retry,
            stored_result,
            write_retry_response_json,
            nullptr);
    switch (response_result) {
        case agent_q::AgentQSigningRetryResponseResult::not_found:
        case agent_q::AgentQSigningRetryResponseResult::invalid_stored_result:
        case agent_q::AgentQSigningRetryResponseResult::replay_write_failed:
            return agent_q::AgentQSigningPreflightRetryDisposition::continue_preflight;
        case agent_q::AgentQSigningRetryResponseResult::replayed_result:
        case agent_q::AgentQSigningRetryResponseResult::error_response:
        case agent_q::AgentQSigningRetryResponseResult::error_write_failed:
            return agent_q::AgentQSigningPreflightRetryDisposition::consumed;
    }
    return agent_q::AgentQSigningPreflightRetryDisposition::consumed;
}

bool read_signing_mode_for_preflight(
    agent_q::AgentQSigningAuthorizationMode* mode,
    void*)
{
    return agent_q::read_signing_authorization_mode(mode);
}

bool write_policy_execution_response(
    const char* id,
    const uint8_t* request_identity,
    const agent_q::AgentQPolicySigningExecutionResult& result)
{
    return agent_q::usb_signing_result_write_policy_execution(
        id,
        agent_q::session_id(),
        request_identity,
        result);
}

enum class PolicyResponseWriteResult {
    ok,
    active_policy_unavailable,
    response_write_failed,
};

PolicyResponseWriteResult write_policy_response(const char* id)
{
    agent_q::AgentQStoredPolicyDocument policy = {};
    if (!agent_q::read_active_policy_document(&policy) || policy.document == nullptr) {
        return PolicyResponseWriteResult::active_policy_unavailable;
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
    JsonArray rules = policy_json["rules"].to<JsonArray>();
    const agent_q::AgentQPolicyDocument& document = *policy.document;
    for (size_t rule_index = 0; rule_index < document.rule_count; ++rule_index) {
        const agent_q::AgentQPolicyRule& source_rule = document.rules[rule_index];
        JsonObject rule = rules.add<JsonObject>();
        rule["id"] = source_rule.id;
        rule["chain"] = source_rule.chain;
        rule["method"] = source_rule.operation;
        rule["action"] = agent_q::agent_q_policy_action_name(source_rule.action);
        JsonArray criteria = rule["criteria"].to<JsonArray>();
        for (size_t criterion_index = 0; criterion_index < source_rule.criterion_count; ++criterion_index) {
            const agent_q::AgentQPolicyCriterion& source_criterion =
                source_rule.criteria[criterion_index];
            JsonObject criterion = criteria.add<JsonObject>();
            criterion["field"] = source_criterion.field;
            criterion["op"] = agent_q::agent_q_policy_operator_name(source_criterion.op);
            if (source_criterion.op == agent_q::AgentQPolicyOperator::in) {
                JsonArray values = criterion["values"].to<JsonArray>();
                for (size_t value_index = 0; value_index < source_criterion.value_count; ++value_index) {
                    values.add(source_criterion.values[value_index]);
                }
            } else {
                criterion["value"] = source_criterion.value;
            }
        }
    }
    return agent_q::usb_response_write_json(response)
               ? PolicyResponseWriteResult::ok
               : PolicyResponseWriteResult::response_write_failed;
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
        } else if (source.event_kind == agent_q::AgentQApprovalHistoryEventKind::signing) {
            record["eventKind"] = "signing";
            record["recordKind"] =
                agent_q::approval_history_signing_record_kind_to_string(source.signing_record_kind);
            record["authorization"] =
                source.confirmation_kind == agent_q::AgentQApprovalHistoryConfirmationKind::policy
                    ? "policy"
                    : "user";
            record["chain"] = source.chain;
            record["method"] = source.method;
            if (source.signing_record_kind == agent_q::AgentQSigningHistoryRecordKind::confirmation &&
                source.confirmation_kind != agent_q::AgentQApprovalHistoryConfirmationKind::none) {
                record["confirmationKind"] =
                    agent_q::approval_history_confirmation_kind_to_string(source.confirmation_kind);
            }
            if (source.signing_terminal_result != agent_q::AgentQSigningHistoryTerminalResult::none) {
                record["terminalResult"] =
                    agent_q::approval_history_signing_terminal_result_to_string(source.signing_terminal_result);
            }
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

bool write_policy_propose_result_response(
    const char* id,
    const char* status,
    const char* reason_code,
    bool include_policy)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["type"] = "policy_propose_result";
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

void clear_active_session()
{
    agent_q::session_clear();
    // W4: buffered signing results are session-scoped; drop them when the session ends
    // so a new session never sees a prior session's results.
    agent_q::signing_result_clear_all();
}

bool persist_unprovisioned_state_for_local_reset()
{
    return agent_q::provisioning_runtime_state_persist(ProvisioningRuntimeState::unprovisioned);
}

bool persist_persistent_material_state(agent_q::AgentQProvisioningPersistedState state)
{
    if (state == agent_q::AgentQProvisioningPersistedState::provisioned) {
        return agent_q::provisioning_runtime_state_persist(ProvisioningRuntimeState::provisioned);
    }
    return agent_q::provisioning_runtime_state_persist(ProvisioningRuntimeState::unprovisioned);
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
        persist_persistent_material_state,
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

agent_q::AgentQSigningHistoryTerminalResult signing_history_terminal_result(
    agent_q::AgentQUserSigningTerminalResult result)
{
    switch (result) {
        case agent_q::AgentQUserSigningTerminalResult::signed_success:
            return agent_q::AgentQSigningHistoryTerminalResult::signed_success;
        case agent_q::AgentQUserSigningTerminalResult::rejected:
            return agent_q::AgentQSigningHistoryTerminalResult::user_rejected;
        case agent_q::AgentQUserSigningTerminalResult::timed_out:
            return agent_q::AgentQSigningHistoryTerminalResult::user_timed_out;
        case agent_q::AgentQUserSigningTerminalResult::signing_failed:
            return agent_q::AgentQSigningHistoryTerminalResult::signing_failed;
        case agent_q::AgentQUserSigningTerminalResult::canceled:
        case agent_q::AgentQUserSigningTerminalResult::history_error:
        case agent_q::AgentQUserSigningTerminalResult::none:
        default:
            return agent_q::AgentQSigningHistoryTerminalResult::none;
    }
}

bool write_user_signing_confirmation_history(
    const agent_q::AgentQUserSigningFlowSnapshot& snapshot,
    void*)
{
    const agent_q::AgentQSigningHistoryAppendInput input{
        agent_q::AgentQSigningHistoryRecordKind::confirmation,
        agent_q::AgentQApprovalHistoryConfirmationKind::local_pin,
        agent_q::AgentQSigningHistoryTerminalResult::none,
        snapshot.chain,
        snapshot.method,
        "device_confirmed",
        snapshot.payload_digest,
        nullptr,
        nullptr,
    };
    return agent_q::approval_history_append_required_signing(
        input,
        static_cast<uint64_t>(esp_timer_get_time() / 1000LL));
}

bool write_user_signing_physical_confirmation_history(
    const agent_q::AgentQUserSigningFlowSnapshot& snapshot,
    void*)
{
    const agent_q::AgentQSigningHistoryAppendInput input{
        agent_q::AgentQSigningHistoryRecordKind::confirmation,
        agent_q::AgentQApprovalHistoryConfirmationKind::physical_confirm,
        agent_q::AgentQSigningHistoryTerminalResult::none,
        snapshot.chain,
        snapshot.method,
        "device_confirmed",
        snapshot.payload_digest,
        nullptr,
        nullptr,
    };
    return agent_q::approval_history_append_required_signing(
        input,
        static_cast<uint64_t>(esp_timer_get_time() / 1000LL));
}

bool write_user_signing_terminal_history(
    const agent_q::AgentQUserSigningFlowSnapshot& snapshot,
    agent_q::AgentQUserSigningTerminalResult result)
{
    const agent_q::AgentQSigningHistoryTerminalResult history_result =
        signing_history_terminal_result(result);
    if (history_result == agent_q::AgentQSigningHistoryTerminalResult::none) {
        return true;
    }
    const char* reason = agent_q::user_signing_flow_terminal_reason(result);
    if (reason == nullptr || reason[0] == '\0') {
        return false;
    }
    const agent_q::AgentQSigningHistoryAppendInput input{
        agent_q::AgentQSigningHistoryRecordKind::terminal,
        agent_q::AgentQApprovalHistoryConfirmationKind::none,
        history_result,
        snapshot.chain,
        snapshot.method,
        reason,
        snapshot.payload_digest,
        nullptr,
        nullptr,
    };
    return agent_q::approval_history_append_required_signing(
        input,
        static_cast<uint64_t>(esp_timer_get_time() / 1000LL));
}

void consume_user_signing_terminal_if_pending()
{
    agent_q::AgentQUserSigningTerminalResult ignored =
        agent_q::AgentQUserSigningTerminalResult::none;
    agent_q::user_signing_flow_consume_terminal_result(&ignored);
}

void finish_user_signing_error_terminal(
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    if (request_id != nullptr && request_id[0] != '\0') {
        agent_q::usb_response_write_error(request_id, error_code, error_message);
    }
    consume_user_signing_terminal_if_pending();
    agent_q::user_signing_flow_clear();
    agent_q::avatar_overlay_show_message(
        display_message != nullptr && display_message[0] != '\0' ? display_message : "Signing failed",
        AgentQMessageKind::error,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void finish_user_signing_terminal(
    const char* request_id,
    const agent_q::AgentQUserSigningOutput* signing_output)
{
    const agent_q::AgentQUserSigningFlowSnapshot snapshot =
        agent_q::user_signing_flow_snapshot();
    const agent_q::AgentQUserSigningTerminalResult result =
        snapshot.terminal_result;
    if (!snapshot.active ||
        snapshot.stage != agent_q::AgentQUserSigningStage::terminal ||
        result == agent_q::AgentQUserSigningTerminalResult::none) {
        if (request_id != nullptr && request_id[0] != '\0') {
            agent_q::usb_response_write_error(request_id, "invalid_state", "Signing request is unavailable.");
        }
        agent_q::avatar_overlay_show_message(
            "Signing unavailable",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
        return;
    }

    if (!write_user_signing_terminal_history(snapshot, result)) {
        if (request_id != nullptr && request_id[0] != '\0') {
            agent_q::usb_response_write_error(request_id, "history_error", "Could not record signing terminal result.");
        }
        consume_user_signing_terminal_if_pending();
        ESP_LOGW(kTag, "user_signing terminal history write failed: id=%s", request_id);
        agent_q::avatar_overlay_show_message(
            result == agent_q::AgentQUserSigningTerminalResult::signed_success
                ? "Signed; history failed"
                : "History error",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
        return;
    }

    bool wrote_response = false;
    const char* response_type = "sign_result";
    const char* display_message = "Signing failed";
    AgentQMessageKind display_kind = AgentQMessageKind::error;
    const char* delivery_failed_message = "Signing failed; USB failed";
    if (result == agent_q::AgentQUserSigningTerminalResult::signed_success) {
        wrote_response = signing_output != nullptr &&
            agent_q::usb_signing_result_write_user_signed(
                request_id,
                agent_q::session_id(),
                "user",
                snapshot,
                *signing_output);
        display_message = wrote_response ? "Signed" : "Signed; USB failed";
        delivery_failed_message = "Signed; USB failed";
        display_kind = wrote_response ? AgentQMessageKind::success : AgentQMessageKind::error;
    } else if (result == agent_q::AgentQUserSigningTerminalResult::rejected) {
        wrote_response = agent_q::usb_signing_result_write_user_terminal(
            request_id, agent_q::session_id(), snapshot.request_identity, result);
        display_message = wrote_response ? "Signing rejected" : "Rejected; USB failed";
        delivery_failed_message = "Rejected; USB failed";
        display_kind = wrote_response ? AgentQMessageKind::rejected : AgentQMessageKind::error;
    } else if (result == agent_q::AgentQUserSigningTerminalResult::timed_out) {
        wrote_response = agent_q::usb_signing_result_write_user_terminal(
            request_id, agent_q::session_id(), snapshot.request_identity, result);
        display_message = wrote_response ? "Signing timed out" : "Timeout; USB failed";
        delivery_failed_message = "Timeout; USB failed";
        display_kind = wrote_response ? AgentQMessageKind::timeout : AgentQMessageKind::error;
    } else if (result == agent_q::AgentQUserSigningTerminalResult::signing_failed) {
        wrote_response = agent_q::usb_signing_result_write_user_terminal(
            request_id, agent_q::session_id(), snapshot.request_identity, result);
        display_message = wrote_response ? "Signing failed" : "Failure; USB failed";
        delivery_failed_message = "Failure; USB failed";
    } else if (request_id != nullptr && request_id[0] != '\0') {
        wrote_response = agent_q::usb_response_write_error(request_id, "invalid_session", "Signing request session ended.");
        response_type = "error";
        display_message = wrote_response ? "Session ended" : "Session; USB failed";
        delivery_failed_message = "Session; USB failed";
    }

    if (!wrote_response) {
        agent_q::usb_response_log_write_failure(response_type, request_id);
        display_message = delivery_failed_message;
    }
    consume_user_signing_terminal_if_pending();
    agent_q::avatar_overlay_show_message(
        display_message,
        display_kind,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void execute_user_signing_critical_section_and_finish(const char* request_id)
{
    agent_q::AgentQUserSigningOutput signing_output = {};
    const agent_q::AgentQUserSigningHandoffReport signing_report =
        agent_q::user_signing_execute_critical_section(&signing_output);
    if (signing_report.result != agent_q::AgentQUserSigningHandoffResult::ok) {
        ESP_LOGW(kTag,
                 "user_signing signing failed: id=%s handoff=%s signing=%s",
                 request_id,
                 agent_q::user_signing_handoff_result_name(signing_report.result),
                 agent_q::sui_transaction_signing_result_to_string(signing_report.signing_result));
        finish_user_signing_terminal(request_id);
        agent_q::user_signing_output_wipe(&signing_output);
        return;
    }
    finish_user_signing_terminal(request_id, &signing_output);
    agent_q::user_signing_output_wipe(&signing_output);
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
    // A newly established session must not inherit the previous session's buffered
    // signing results, so drop them before the session id changes.
    agent_q::signing_result_clear_all();
    return agent_q::session_replace(fill_session_random, nullptr) ==
           agent_q::AgentQSessionStartResult::ok;
}

agent_q::AgentQUsbSessionLossProtocolPinPurpose protocol_pin_loss_purpose(
    const agent_q::AgentQProtocolPinApprovalSnapshot& snapshot)
{
    if (!snapshot.active) {
        return agent_q::AgentQUsbSessionLossProtocolPinPurpose::none;
    }
    switch (snapshot.purpose) {
        case agent_q::AgentQProtocolPinApprovalPurpose::connect:
            return agent_q::AgentQUsbSessionLossProtocolPinPurpose::connect;
        case agent_q::AgentQProtocolPinApprovalPurpose::policy_update:
            return agent_q::AgentQUsbSessionLossProtocolPinPurpose::policy_update;
        case agent_q::AgentQProtocolPinApprovalPurpose::none:
            return agent_q::AgentQUsbSessionLossProtocolPinPurpose::other;
    }
    return agent_q::AgentQUsbSessionLossProtocolPinPurpose::other;
}

agent_q::AgentQUsbSessionLossLocalPinPurpose local_pin_loss_purpose(
    const agent_q::AgentQLocalPinAuthSnapshot& snapshot)
{
    if (!snapshot.flow_active) {
        return agent_q::AgentQUsbSessionLossLocalPinPurpose::none;
    }
    switch (snapshot.purpose) {
        case LocalPinAuthPurpose::connect:
            return agent_q::AgentQUsbSessionLossLocalPinPurpose::connect;
        case LocalPinAuthPurpose::policy_update:
            return agent_q::AgentQUsbSessionLossLocalPinPurpose::policy_update;
        case LocalPinAuthPurpose::user_signing:
            return agent_q::AgentQUsbSessionLossLocalPinPurpose::user_signing;
        case LocalPinAuthPurpose::none:
        case LocalPinAuthPurpose::settings_human_approval_input:
        case LocalPinAuthPurpose::settings_signing_mode:
        case LocalPinAuthPurpose::settings_change_pin:
            return agent_q::AgentQUsbSessionLossLocalPinPurpose::other;
    }
    return agent_q::AgentQUsbSessionLossLocalPinPurpose::other;
}

agent_q::AgentQUsbSessionLossPlan current_usb_session_loss_plan(TickType_t now)
{
    const agent_q::AgentQProtocolPinApprovalSnapshot protocol_pin =
        agent_q::protocol_pin_approval_snapshot();
    const agent_q::AgentQLocalPinAuthSnapshot pin_auth =
        agent_q::local_pin_auth_snapshot(now);
    const agent_q::AgentQUserSigningFlowSnapshot user_signing =
        agent_q::user_signing_flow_snapshot();
    return agent_q::usb_session_loss_plan(agent_q::AgentQUsbSessionLossInput{
        agent_q::session_active(),
	        agent_q::connect_approval_active(),
	        protocol_pin_loss_purpose(protocol_pin),
	        local_pin_loss_purpose(pin_auth),
	        agent_q::policy_update_flow_active(),
	        user_signing.active,
	        user_signing.stage == agent_q::AgentQUserSigningStage::signing_critical_section,
	    });
}

void show_usb_disconnected_message()
{
    agent_q::avatar_overlay_show_message(
        "USB disconnected",
        AgentQMessageKind::usb_disconnected,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void show_usb_connected_message()
{
    char message[40] = "USB connected";
    agent_q::AgentQSigningAuthorizationMode signing_mode =
        agent_q::AgentQSigningAuthorizationMode::user;
    if (provisioned_material_ready() &&
        agent_q::read_signing_authorization_mode(&signing_mode)) {
        snprintf(
            message,
            sizeof(message),
            "USB connected - %s auth",
            signing_mode == agent_q::AgentQSigningAuthorizationMode::policy ? "POLICY" : "USER");
    }
    agent_q::avatar_overlay_show_message(
        message,
        AgentQMessageKind::usb_connected,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void clear_usb_session_state_for_host_loss()
{
    const agent_q::AgentQUsbSessionLossPlan plan =
        current_usb_session_loss_plan(xTaskGetTickCount());

    // Line-framing state is transport state and is reset at the disconnect edge, which
    // always precedes this confirm-path call; this function clears session-bound state.
    if (!plan.relevant) {
        return;
    }

    if (plan.clear_session) {
        clear_active_session();
    }
    if (plan.clear_connect_approval) {
        clear_connect_review_state();
    }
    if (plan.clear_protocol_pin) {
        agent_q::protocol_pin_approval_clear();
    }
    if (plan.wipe_local_pin_auth) {
        wipe_local_pin_auth_scratch("USB host link lost during local PIN authorization");
    }
    if (plan.clear_policy_update_flow) {
        agent_q::policy_update_flow_clear();
    }
    if (plan.cancel_user_signing) {
        cancel_user_signing_after_session_loss("USB host link lost during user_signing");
    }
    if (plan.clear_connect_review_panel) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::connect_review, SensitiveUiClearPolicy::preserve);
    }
    if (plan.clear_local_pin_panel) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    }
    if (plan.clear_policy_update_review_panel) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::policy_update_review, SensitiveUiClearPolicy::preserve);
    }
    if (plan.clear_user_signing_review_panel) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::user_signing_review, SensitiveUiClearPolicy::preserve);
    }
    ESP_LOGW(kTag, "USB host SOF lost; session-bound state cleared");
}

// W4-W2: hold the session for this long after a USB drop so a transient resume can
// reconnect and recover its buffered signing result before the session is torn down.
constexpr uint32_t kUsbSessionGraceMs = 2000;
agent_q::AgentQUsbGraceState g_usb_session_grace;

void poll_usb_host_connection()
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQUsbLinkEvent event = agent_q::usb_link_state_observe(
        usb_serial_jtag_is_connected(),
        now,
        pdMS_TO_TICKS(kUsbHostLinkCheckMs));
    const agent_q::AgentQUsbGraceAction grace = agent_q::usb_session_grace_step(
        event, now, pdMS_TO_TICKS(kUsbSessionGraceMs), g_usb_session_grace);
    switch (event) {
        case agent_q::AgentQUsbLinkEvent::not_due:
        case agent_q::AgentQUsbLinkEvent::initial_observed:
        case agent_q::AgentQUsbLinkEvent::unchanged_connected:
            return;
        case agent_q::AgentQUsbLinkEvent::connected:
            // A fresh connect, or a reconnect that resumed within the grace window.
            show_usb_connected_message();
            return;
        case agent_q::AgentQUsbLinkEvent::unchanged_disconnected:
            // Tear the session down only once the grace window confirms the loss; the
            // loss plan still protects an in-flight critical section.
            if (grace == agent_q::AgentQUsbGraceAction::confirm) {
                if (current_usb_session_loss_plan(now).relevant) {
                    clear_usb_session_state_for_host_loss();
                }
                show_usb_disconnected_message();
            }
            return;
        case agent_q::AgentQUsbLinkEvent::disconnected:
            // Edge: the grace window is now open and the session is held; stay quiet so
            // a quick resume is seamless. A sustained drop confirms above. Reset the line
            // framing here so a resume parses cleanly even if the drop cut a partial line.
            agent_q::usb_line_receiver_reset();
            return;
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

    return agent_q::provisioning_runtime_state_is_unprovisioned() &&
           !agent_q::identification_display_active() &&
           !agent_q::provisioning_flow_active() &&
           !agent_q::local_pin_auth_flow_active() &&
           !agent_q::user_signing_flow_active() &&
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
    return agent_q::provisioning_runtime_state_refresh(persistent_material_ops());
}

bool provisioned_material_ready()
{
    return agent_q::provisioning_runtime_state_material_ready(persistent_material_ops());
}

agent_q::AgentQSessionValidationResult validate_session_for_user_signing(
    const char* session_id,
    void*)
{
    return agent_q::session_validate(session_id);
}

bool user_signing_ingress_busy()
{
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    return agent_q::connect_approval_active() ||
           agent_q::protocol_pin_approval_active() ||
           agent_q::policy_update_flow_active() ||
           agent_q::provisioning_flow_active() ||
           reset.flow_active ||
           agent_q::local_pin_auth_flow_active() ||
           agent_q::user_signing_flow_active();
}

bool show_user_signing_review()
{
    const agent_q::AgentQUserSigningFlowSnapshot snapshot =
        agent_q::user_signing_flow_snapshot();
    agent_q::AgentQUserSigningReviewViewModel model = {};
    if (agent_q::user_signing_review_view_model_build(snapshot, &model) !=
        agent_q::AgentQUserSigningReviewBuildResult::ok) {
        return false;
    }
    return agent_q::modal_draw_user_signing_review_panel(
        model,
        snapshot.request_window);
}

bool show_policy_update_review()
{
    const agent_q::AgentQPolicyUpdateFlowSnapshot snapshot =
        agent_q::policy_update_flow_snapshot();
    if (!snapshot.active ||
        snapshot.stage != agent_q::AgentQPolicyUpdateFlowStage::reviewing) {
        return false;
    }
    const agent_q::AgentQPolicyUpdateReviewViewModel model{
        snapshot.policy_hash,
        snapshot.rule_count,
        snapshot.default_action,
        snapshot.highest_action,
        snapshot.method_summary,
        snapshot.review_summary,
    };
    return agent_q::modal_draw_policy_update_review_panel(
        model,
        snapshot.review_window);
}

bool agent_q_ui_idle_for_local_settings()
{
    LvglLockGuard lock;
    return agent_q::drawing_surface_panel_locked() == nullptr &&
           agent_q::avatar_overlay_mode() == AgentQUiMode::none;
}

bool local_settings_touch_entry_candidate_allowed()
{
    return agent_q::provisioning_runtime_state_is_provisioned() &&
           !agent_q::connect_approval_active() &&
           !agent_q::protocol_pin_approval_active() &&
           !agent_q::identification_display_active() &&
           !agent_q::provisioning_flow_active() &&
           !agent_q::local_pin_auth_flow_active() &&
           !agent_q::user_signing_flow_active() &&
           !agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active &&
           agent_q_ui_idle_for_local_settings();
}

bool write_busy_if_pending_or_local_flow_active(const char* id, bool allow_settings_menu = false)
{
    if (agent_q::connect_approval_active()) {
        agent_q::usb_response_write_error(id, "busy", "Device is awaiting local input.");
        return true;
    }
    if (agent_q::protocol_pin_approval_active()) {
        agent_q::usb_response_write_error(id, "busy", "Device is awaiting local PIN approval.");
        return true;
    }
    if (agent_q::policy_update_flow_active()) {
        agent_q::usb_response_write_error(id, "busy", "Device has a pending policy update.");
        return true;
    }
    if (agent_q::provisioning_flow_active()) {
        agent_q::usb_response_write_error(id, "busy", "Device is showing setup material.");
        return true;
    }
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    if (reset.flow_active) {
        if (allow_settings_menu &&
            reset.stage == agent_q::AgentQLocalResetStage::settings_menu) {
            return false;
        }
        agent_q::usb_response_write_error(
            id,
            "busy",
            reset.stage == agent_q::AgentQLocalResetStage::settings_menu
                ? "Device is showing local settings UI."
                : "Device is showing local reset UI.");
        return true;
    }
    if (agent_q::local_pin_auth_flow_active()) {
        agent_q::usb_response_write_error(id, "busy", "Device is showing local PIN UI.");
        return true;
    }
    if (agent_q::user_signing_flow_active()) {
        agent_q::usb_response_write_error(id, "busy", "Device has a pending signing request.");
        return true;
    }
    return false;
}

bool write_busy_if_pending_or_local_flow_active_default(const char* id)
{
    return write_busy_if_pending_or_local_flow_active(id);
}

bool write_busy_if_pending_or_local_flow_active_allow_settings(const char* id)
{
    return write_busy_if_pending_or_local_flow_active(id, true);
}

bool require_active_matching_session(const char* id, const char* session_id)
{
    switch (agent_q::session_validate(session_id)) {
        case agent_q::AgentQSessionValidationResult::ok:
            return true;
        case agent_q::AgentQSessionValidationResult::invalid_format:
            agent_q::usb_response_write_error(id, "invalid_session", "Invalid sessionId.");
            return false;
        case agent_q::AgentQSessionValidationResult::missing:
            cancel_policy_update_after_session_loss("active session missing during request validation");
            cancel_user_signing_after_session_loss("active session missing during request validation");
            agent_q::usb_response_write_error(id, "invalid_session", "Session is unknown or already ended.");
            return false;
        case agent_q::AgentQSessionValidationResult::mismatch:
        default:
            agent_q::usb_response_write_error(id, "invalid_session", "Session is unknown or already ended.");
            return false;
    }
}

void write_policy_update_invalid_session_and_clear(const char* request_id, const char* log_reason)
{
    if (request_id != nullptr && request_id[0] != '\0') {
        agent_q::usb_response_write_error(request_id, "invalid_session", "Policy update session is unknown or already ended.");
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
        const agent_q::AgentQPolicyUpdateFlowSnapshot snapshot =
            agent_q::policy_update_flow_snapshot();
        clear_agent_q_panel_if_kind(
            AgentQUiPanelKind::policy_update_review,
            SensitiveUiClearPolicy::preserve);
        clear_agent_q_panel_if_kind(
            AgentQUiPanelKind::local_pin_auth,
            SensitiveUiClearPolicy::preserve);
        write_policy_update_invalid_session_and_clear(snapshot.request_id, log_reason);
    }
}

void cancel_user_signing_after_session_loss(const char* log_reason)
{
    const agent_q::AgentQUserSigningFlowSnapshot snapshot =
        agent_q::user_signing_flow_snapshot();
    if (!snapshot.active) {
        return;
    }
    const agent_q::AgentQUserSigningConfirmationResult result =
        agent_q::user_signing_confirmation_cancel_for_session_loss();
    if (result == agent_q::AgentQUserSigningConfirmationResult::busy) {
        ESP_LOGW(kTag, "user_signing stayed active during critical section: %s",
                 log_reason != nullptr ? log_reason : "session loss");
        return;
    }
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::user_signing_review, SensitiveUiClearPolicy::preserve);
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    consume_user_signing_terminal_if_pending();
    ESP_LOGW(kTag, "user_signing canceled: %s",
             log_reason != nullptr ? log_reason : "session loss");
    agent_q::avatar_overlay_show_message(
        "Session ended",
        AgentQMessageKind::error,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
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

enum class RequestBackedPinOwner {
    none,
    protocol_pin_approval,
    user_signing,
};

RequestBackedPinOwner request_backed_pin_owner_for_purpose(LocalPinAuthPurpose purpose)
{
    switch (purpose) {
        case LocalPinAuthPurpose::connect:
        case LocalPinAuthPurpose::policy_update:
            return RequestBackedPinOwner::protocol_pin_approval;
        case LocalPinAuthPurpose::user_signing:
            return RequestBackedPinOwner::user_signing;
        default:
            return RequestBackedPinOwner::none;
    }
}

bool request_backed_local_pin_purpose(LocalPinAuthPurpose purpose)
{
    return request_backed_pin_owner_for_purpose(purpose) !=
           RequestBackedPinOwner::none;
}

bool pending_request_id_for_local_pin_purpose(
    LocalPinAuthPurpose purpose,
    char* output,
    size_t output_size)
{
    switch (request_backed_pin_owner_for_purpose(purpose)) {
        case RequestBackedPinOwner::user_signing: {
            if (output == nullptr || output_size == 0) {
                return false;
            }
            output[0] = '\0';
            const agent_q::AgentQUserSigningFlowSnapshot snapshot =
                agent_q::user_signing_flow_snapshot();
            if (!snapshot.active || snapshot.request_id[0] == '\0') {
                return false;
            }
            if (strlen(snapshot.request_id) >= output_size) {
                return false;
            }
            snprintf(output, output_size, "%s", snapshot.request_id);
            return true;
        }
        case RequestBackedPinOwner::protocol_pin_approval:
            return agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
                purpose,
                output,
                output_size);
        case RequestBackedPinOwner::none:
        default:
            if (output != nullptr && output_size > 0) {
                output[0] = '\0';
            }
            return false;
    }
}

agent_q::AgentQTimeoutWindow timeout_window_from_now_ms(
    TickType_t started_at,
    uint32_t duration_ms)
{
    return agent_q::timeout_window_from_deadline(
        started_at,
        started_at + pdMS_TO_TICKS(duration_ms));
}

agent_q::AgentQTimeoutWindow cap_request_backed_pin_input_window(
    LocalPinAuthPurpose purpose,
    agent_q::AgentQTimeoutWindow input_window)
{
    if (!agent_q::timeout_window_valid(input_window)) {
        return agent_q::kAgentQTimeoutWindowNone;
    }
    switch (request_backed_pin_owner_for_purpose(purpose)) {
        case RequestBackedPinOwner::user_signing: {
            const agent_q::AgentQUserSigningFlowSnapshot snapshot =
                agent_q::user_signing_flow_snapshot();
            if (!snapshot.active) {
                return agent_q::kAgentQTimeoutWindowNone;
            }
            const TickType_t capped_deadline =
                agent_q::timeout_window_cap_deadline(
                    snapshot.request_window,
                    input_window.deadline);
            return agent_q::timeout_window_from_deadline(
                input_window.started_at,
                capped_deadline);
        }
        case RequestBackedPinOwner::protocol_pin_approval: {
            const agent_q::AgentQProtocolPinApprovalSnapshot snapshot =
                agent_q::protocol_pin_approval_snapshot();
            if (!snapshot.active) {
                return agent_q::kAgentQTimeoutWindowNone;
            }
            const TickType_t capped_deadline =
                agent_q::timeout_window_cap_deadline(
                    snapshot.request_window,
                    input_window.deadline);
            return agent_q::timeout_window_from_deadline(
                input_window.started_at,
                capped_deadline);
        }
        case RequestBackedPinOwner::none:
        default:
            return agent_q::kAgentQTimeoutWindowNone;
    }
}

agent_q::AgentQTimeoutWindow local_pin_auth_next_input_window(
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    const agent_q::AgentQTimeoutWindow next_input_window =
        timeout_window_from_now_ms(now, kLocalPinInputWindowMs);
    if (purpose == LocalPinAuthPurpose::settings_human_approval_input ||
        purpose == LocalPinAuthPurpose::settings_signing_mode ||
        purpose == LocalPinAuthPurpose::settings_change_pin) {
        return next_input_window;
    }
    if (!request_backed_local_pin_purpose(purpose)) {
        return agent_q::kAgentQTimeoutWindowNone;
    }
    return cap_request_backed_pin_input_window(purpose, next_input_window);
}

bool resume_request_backed_pin_input_window(
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    switch (request_backed_pin_owner_for_purpose(purpose)) {
        case RequestBackedPinOwner::user_signing:
            return agent_q::user_signing_flow_refresh_pin_deadline(now) ==
                   agent_q::AgentQUserSigningTransitionResult::ok;
        case RequestBackedPinOwner::protocol_pin_approval:
            return agent_q::protocol_pin_approval_refresh_deadline_for_local_pin_purpose(
                purpose,
                now);
        case RequestBackedPinOwner::none:
        default:
            return false;
    }
}

bool pause_request_backed_pin_input_window(LocalPinAuthPurpose purpose, TickType_t now)
{
    switch (request_backed_pin_owner_for_purpose(purpose)) {
        case RequestBackedPinOwner::user_signing:
            return agent_q::user_signing_confirmation_mark_pin_verification_started(now) ==
                   agent_q::AgentQUserSigningConfirmationResult::ok;
        case RequestBackedPinOwner::protocol_pin_approval:
            if (purpose == LocalPinAuthPurpose::policy_update &&
                agent_q::policy_update_flow_mark_pin_verifying() !=
                    agent_q::AgentQPolicyUpdateFlowTransitionResult::ok) {
                return false;
            }
            return agent_q::protocol_pin_approval_pause_deadline_for_local_pin_purpose(
                purpose,
                now);
        case RequestBackedPinOwner::none:
        default:
            return true;
    }
}

bool request_backed_local_pin_input_deadline_reached(LocalPinAuthPurpose purpose, TickType_t now)
{
    switch (request_backed_pin_owner_for_purpose(purpose)) {
        case RequestBackedPinOwner::user_signing:
            return agent_q::user_signing_flow_deadline_reached(now);
        case RequestBackedPinOwner::protocol_pin_approval:
            return agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
                purpose,
                now);
        case RequestBackedPinOwner::none:
        default:
            return false;
    }
}

bool disconnect_pending_policy_update_for_session(const char* id, const char* session_id)
{
    const agent_q::AgentQPolicyUpdateFlowSnapshot policy_snapshot =
        agent_q::policy_update_flow_snapshot();
    if (policy_snapshot.active &&
        policy_snapshot.stage == agent_q::AgentQPolicyUpdateFlowStage::reviewing &&
        session_id != nullptr &&
        policy_snapshot.session_id != nullptr &&
        strcmp(policy_snapshot.session_id, session_id) == 0) {
        clear_agent_q_panel_if_kind(
            AgentQUiPanelKind::policy_update_review,
            SensitiveUiClearPolicy::preserve);
        if (policy_snapshot.request_id != nullptr &&
            policy_snapshot.request_id[0] != '\0' &&
            (id == nullptr || strcmp(policy_snapshot.request_id, id) != 0)) {
            agent_q::usb_response_write_error(
                policy_snapshot.request_id,
                "invalid_session",
                "Policy update session is unknown or already ended.");
        }
        agent_q::policy_update_flow_clear();
        clear_active_session();
        if (agent_q::usb_response_write_disconnect_result(id)) {
            ESP_LOGI(kTag, "disconnect canceled pending policy update review: id=%s", id);
        } else {
            agent_q::usb_response_log_write_failure("disconnect_result", id);
        }
        return true;
    }

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
        agent_q::usb_response_write_error(
            policy_request_id,
            "invalid_session",
            "Policy update session is unknown or already ended.");
    }
    agent_q::policy_update_flow_clear();
    agent_q::protocol_pin_approval_clear();
    clear_active_session();
    if (agent_q::usb_response_write_disconnect_result(id)) {
        ESP_LOGI(kTag, "disconnect canceled pending policy update: id=%s", id);
    } else {
        agent_q::usb_response_log_write_failure("disconnect_result", id);
    }
    return true;
}

bool disconnect_pending_user_signing_for_session(const char* id, const char* session_id)
{
    const agent_q::AgentQUserSigningFlowSnapshot snapshot =
        agent_q::user_signing_flow_snapshot();
    if (!snapshot.active ||
        !agent_q::user_signing_flow_session_matches(session_id)) {
        return false;
    }

    const agent_q::AgentQUserSigningConfirmationResult result =
        agent_q::user_signing_confirmation_cancel_for_disconnect(session_id);
    if (result == agent_q::AgentQUserSigningConfirmationResult::busy) {
        agent_q::usb_response_write_error(id, "busy", "Device is signing a request.");
        return true;
    }

    clear_agent_q_panel_if_kind(AgentQUiPanelKind::user_signing_review, SensitiveUiClearPolicy::preserve);
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    if (snapshot.request_id[0] != '\0' &&
        (id == nullptr || strcmp(snapshot.request_id, id) != 0)) {
        agent_q::usb_response_write_error(
            snapshot.request_id,
            "invalid_session",
            "Signing request session is unknown or already ended.");
    }
    consume_user_signing_terminal_if_pending();
    clear_active_session();
    if (agent_q::usb_response_write_disconnect_result(id)) {
        ESP_LOGI(kTag, "disconnect canceled pending user_signing: id=%s", id);
    } else {
        agent_q::usb_response_log_write_failure("disconnect_result", id);
    }
    agent_q::avatar_overlay_show_message(
        "Signing canceled",
        AgentQMessageKind::rejected,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
    return true;
}

bool backup_phrase_backup_confirmation_ready()
{
    return agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::backup_phrase_displayed);
}

void clear_panel_locked(SensitiveUiClearPolicy policy)
{
    const AgentQUiPanelKind panel_kind = agent_q::drawing_surface_clear_panel_locked();
    if (panel_kind == AgentQUiPanelKind::none ||
        policy != SensitiveUiClearPolicy::wipe) {
        return;
    }

    apply_panel_cleanup_plan(
        panel_cleanup_plan(panel_kind, agent_q::AgentQUiPanelCleanupEvent::explicit_clear),
        "sensitive setup panel cleared",
        "local reset panel cleared",
        "local PIN authorization panel cleared");
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

    return agent_q::provisioning_runtime_state_is_unprovisioned() &&
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
        "Set up Agent-Q",
        AgentQMessageKind::info,
        AgentQUiMode::identification,
        0,
        agent_q::ui_event_bridge_setup_clicked_callback());
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
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::connect_review, SensitiveUiClearPolicy::preserve);
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

void clear_connect_review_state()
{
    agent_q::ui_event_bridge_reset_connect_choices();
    agent_q::connect_approval_clear();
    agent_q::identification_display_clear();
}

void show_result_and_clear_connect_review(const char* message, AgentQMessageKind kind)
{
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::connect_review, SensitiveUiClearPolicy::preserve);
    agent_q::avatar_overlay_show_message(message, kind, AgentQUiMode::result, kAgentQResultDisplayMs);
    clear_connect_review_state();
}

agent_q::AgentQHumanApprovalInputMode connect_review_input_mode()
{
    return agent_q::human_approval_input_mode_or_default();
}

void show_connect_review()
{
    const agent_q::AgentQConnectApprovalSnapshot approval =
        agent_q::connect_approval_snapshot();
    agent_q::identification_display_clear();
    if (agent_q::modal_draw_connect_review_panel(
            approval.client_name,
            connect_review_input_mode(),
            approval.approval_window)) {
        return;
    }
    ESP_LOGW(kTag, "connect could not show Agent-Q review UI");
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
    return agent_q::provisioning_runtime_state_is_unprovisioned();
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

void clear_import_word_entry_if_needed()
{
    if (!agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::import_word_entry)) {
        return;
    }

    const bool panel_active = agent_q_panel_active(AgentQUiPanelKind::import_word_entry);
    const bool expired = agent_q::provisioning_flow_stage_expired(xTaskGetTickCount());
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::import_word_entry);
    } else {
        wipe_setup_scratch("import word entry panel lost");
    }

    if (expired) {
        agent_q::avatar_overlay_show_message("Import expired", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void clear_backup_phrase_if_needed()
{
    if (!agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::backup_phrase_displayed)) {
        return;
    }

    const bool panel_active = agent_q_panel_active(AgentQUiPanelKind::backup_phrase_display);
    const bool expired = agent_q::provisioning_flow_stage_expired(xTaskGetTickCount());
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::backup_phrase_display);
    } else {
        wipe_setup_scratch("backup phrase display lost");
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
    const TickType_t now = xTaskGetTickCount();
    if (!agent_q::provisioning_flow_add_pin_digit(
            digit,
            timeout_window_from_now_ms(now, kLocalPinSetupMs))) {
        return;
    }
    if (!agent_q::modal_draw_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_pin_clear_from_local_ui()
{
    const TickType_t now = xTaskGetTickCount();
    if (!agent_q::provisioning_flow_clear_pin_entry(
            timeout_window_from_now_ms(now, kLocalPinSetupMs))) {
        return;
    }
    if (!agent_q::modal_draw_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_pin_backspace_from_local_ui()
{
    const TickType_t now = xTaskGetTickCount();
    if (!agent_q::provisioning_flow_backspace_pin(
            timeout_window_from_now_ms(now, kLocalPinSetupMs))) {
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
    const TickType_t now = xTaskGetTickCount();
    const ProvisioningFlowPinSubmitResult result =
        agent_q::provisioning_flow_submit_pin(
            timeout_window_from_now_ms(now, kLocalPinSetupMs),
            now + pdMS_TO_TICKS(kLocalProcessingDisplayMs),
            now + pdMS_TO_TICKS(agent_q::kAgentQLocalAuthWorkerMaxMs));
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
        if (agent_q::local_reset_fail_processing_if_expired(now)) {
            agent_q::persistent_material_record_runtime_failure(
                agent_q::AgentQPersistentMaterialRuntimeFailure::local_reset_auth_unavailable,
                persistent_material_ops());
            clear_agent_q_panel_if_kind(AgentQUiPanelKind::reset_pin_entry, SensitiveUiClearPolicy::preserve);
            agent_q::avatar_overlay_show_message("Auth error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            return;
        }
        if (!agent_q_panel_active(AgentQUiPanelKind::reset_pin_entry) &&
            !agent_q::modal_draw_reset_pin_panel()) {
            wipe_local_reset_scratch("local reset PIN verification UI recovery failed");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }
    if (reset.stage == agent_q::AgentQLocalResetStage::wiping) {
        if (!agent_q_panel_active(AgentQUiPanelKind::reset_pin_entry) &&
            !agent_q::modal_draw_reset_pin_panel()) {
            ESP_LOGW(kTag, "Local reset wiping panel could not be restored");
        }
        return;
    }

    const agent_q::AgentQLocalResetLockoutReleaseResult reset_lockout_release =
        agent_q::local_reset_release_lockout_if_elapsed(now);
    if (reset_lockout_release == agent_q::AgentQLocalResetLockoutReleaseResult::failed) {
        wipe_local_reset_scratch("local reset PIN lockout release failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }
    if (reset_lockout_release == agent_q::AgentQLocalResetLockoutReleaseResult::released) {
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
        case agent_q::AgentQLocalResetCommitResult::human_approval_setting_wipe_error:
        case agent_q::AgentQLocalResetCommitResult::signing_mode_wipe_error:
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
    const TickType_t now = xTaskGetTickCount();
    if (!provisioned_material_ready() ||
        agent_q::connect_approval_active() ||
        agent_q::protocol_pin_approval_active() ||
        agent_q::identification_display_active() ||
        agent_q::provisioning_flow_active() ||
        agent_q::user_signing_flow_active() ||
        agent_q::local_reset_snapshot(now).flow_active ||
        !agent_q_ui_idle_for_local_settings()) {
        ESP_LOGW(kTag, "Local settings touch ignored because settings are unavailable");
        agent_q::local_settings_touch_entry_clear();
        return;
    }

    agent_q::local_reset_begin_settings(
        timeout_window_from_now_ms(now, agent_q::kAgentQLocalResetEntryMs));
    if (!agent_q::modal_draw_settings_menu_panel()) {
        wipe_local_reset_scratch("local settings display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void cancel_local_reset_from_ui(const char* message)
{
    const TickType_t now = xTaskGetTickCount();
    if (agent_q::local_reset_snapshot(now).stage !=
        agent_q::AgentQLocalResetStage::pin_entry) {
        ESP_LOGW(kTag, "Stale local reset cancel ignored");
        return;
    }

    clear_agent_q_panel_if_kind(AgentQUiPanelKind::reset_pin_entry);
    agent_q::local_reset_begin_settings(
        timeout_window_from_now_ms(now, agent_q::kAgentQLocalResetEntryMs));
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
        agent_q::user_signing_flow_active() ||
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
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(now);
    if (!agent_q::persistent_material_consistency_error_active() ||
        reset.flow_active ||
        agent_q::connect_approval_active() ||
        agent_q::protocol_pin_approval_active() ||
        agent_q::identification_display_active() ||
        agent_q::provisioning_flow_active() ||
        agent_q::user_signing_flow_active() ||
        agent_q::local_pin_auth_flow_active()) {
        ESP_LOGW(kTag, "Stale error recovery action ignored");
        return;
    }

    agent_q::local_reset_begin_error_recovery_confirm(
        timeout_window_from_now_ms(now, agent_q::kAgentQLocalResetEntryMs));
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
    const TickType_t now = xTaskGetTickCount();
    if (!provisioned_material_ready() ||
        !agent_q::local_reset_begin_pin_entry(
            timeout_window_from_now_ms(now, agent_q::kAgentQLocalResetEntryMs))) {
        ESP_LOGW(kTag, "Stale local reset menu action ignored");
        return;
    }

    if (!agent_q::modal_draw_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

bool begin_connect_pin_auth(const char* id, const char* client_name)
{
    agent_q::identification_display_clear();
    const TickType_t started_at = xTaskGetTickCount();
    const agent_q::AgentQTimeoutWindow request_window =
        timeout_window_from_now_ms(started_at, kConnectApprovalDefaultMs);
    if (!agent_q::protocol_pin_approval_begin_connect(id, request_window)) {
        agent_q::usb_response_write_connect_rejected(id, "invalid_state", "Connect is unavailable.");
        agent_q::connect_approval_clear();
        agent_q::avatar_overlay_show_message("Connect unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return false;
    }
    if (!agent_q::local_pin_auth_begin_connect(request_window)) {
        agent_q::usb_response_write_connect_rejected(id, "invalid_state", "Connect PIN is unavailable.");
        agent_q::connect_approval_clear();
        agent_q::protocol_pin_approval_clear();
        agent_q::avatar_overlay_show_message("Connect unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return false;
    }

    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        agent_q::usb_response_write_connect_rejected(id, "ui_error", "Could not show local PIN UI.");
        wipe_local_pin_auth_scratch("connect PIN display allocation failed");
        agent_q::connect_approval_clear();
        agent_q::protocol_pin_approval_clear();
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return false;
    }
    return true;
}

void clear_policy_update_terminal_state()
{
    agent_q::policy_update_flow_clear();
    agent_q::protocol_pin_approval_clear();
}

void finish_policy_propose_result_terminal(
    const char* request_id,
    agent_q::AgentQPolicyUpdateFlowTerminalResult result,
    const char* display_message,
    AgentQMessageKind display_kind,
    bool refresh_material_consistency = false)
{
    if (!write_policy_propose_result_response(
            request_id,
            agent_q::policy_update_flow_terminal_status(result),
            agent_q::policy_update_flow_terminal_reason(result),
            true)) {
        agent_q::usb_response_log_write_failure("policy_propose_result", request_id);
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
    agent_q::usb_response_write_error(request_id, error_code, error_message);
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
            finish_policy_propose_result_terminal(
                request_id,
                result,
                "Policy updated",
                AgentQMessageKind::success);
            return;
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::rejected:
            finish_policy_propose_result_terminal(
                request_id,
                result,
                "Policy rejected",
                AgentQMessageKind::rejected);
            return;
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::timed_out:
            finish_policy_propose_result_terminal(
                request_id,
                result,
                "Policy timed out",
                AgentQMessageKind::timeout);
            return;
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::ui_error:
            finish_policy_propose_result_terminal(
                request_id,
                result,
                "Display error",
                AgentQMessageKind::error);
            return;
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::storage_error:
            finish_policy_propose_result_terminal(
                request_id,
                result,
                "Policy failed",
                AgentQMessageKind::error);
            return;
        case agent_q::AgentQPolicyUpdateFlowTerminalResult::consistency_error:
            finish_policy_propose_result_terminal(
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

void begin_policy_update_pin_auth_from_review()
{
    const agent_q::AgentQPolicyUpdateFlowSnapshot snapshot =
        agent_q::policy_update_flow_snapshot();
    if (!snapshot.active ||
        snapshot.stage != agent_q::AgentQPolicyUpdateFlowStage::reviewing) {
        ESP_LOGW(kTag, "Stale policy update review continue ignored");
        return;
    }

    agent_q::identification_display_clear();
    const TickType_t started_at = xTaskGetTickCount();
    const agent_q::AgentQPolicyUpdateFlowTransitionResult transition =
        agent_q::policy_update_flow_continue_to_pin(started_at);
    if (transition == agent_q::AgentQPolicyUpdateFlowTransitionResult::timed_out) {
        clear_agent_q_panel_if_kind(
            AgentQUiPanelKind::policy_update_review,
            SensitiveUiClearPolicy::preserve);
        finish_policy_update_terminal(
            snapshot.request_id,
            agent_q::policy_update_flow_record_timed_out(
                static_cast<uint64_t>(esp_timer_get_time() / 1000LL)));
        return;
    }
    if (transition != agent_q::AgentQPolicyUpdateFlowTransitionResult::ok) {
        finish_policy_update_error_terminal(
            snapshot.request_id,
            "invalid_state",
            "Policy update is unavailable.",
            "Policy unavailable");
        return;
    }

    const agent_q::AgentQTimeoutWindow request_window =
        timeout_window_from_now_ms(started_at, kProvisioningApprovalMaxMs);
    if (!agent_q::protocol_pin_approval_begin_policy_update(
            snapshot.request_id,
            snapshot.session_id,
            request_window)) {
        finish_policy_update_error_terminal(
            snapshot.request_id,
            "invalid_state",
            "Policy update is unavailable.",
            "Policy unavailable");
        return;
    }
    if (!agent_q::local_pin_auth_begin_policy_update(request_window)) {
        agent_q::protocol_pin_approval_clear();
        finish_policy_update_error_terminal(
            snapshot.request_id,
            "invalid_state",
            "Policy update PIN is unavailable.",
            "Policy unavailable");
        return;
    }

    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("policy update PIN display allocation failed");
        finish_policy_update_terminal(
            snapshot.request_id,
            agent_q::policy_update_flow_record_ui_error());
    }
}

void handle_policy_update_review_continue_from_ui()
{
    begin_policy_update_pin_auth_from_review();
}

void handle_policy_update_review_reject_from_ui()
{
    const agent_q::AgentQPolicyUpdateFlowSnapshot snapshot =
        agent_q::policy_update_flow_snapshot();
    if (!snapshot.active ||
        snapshot.stage != agent_q::AgentQPolicyUpdateFlowStage::reviewing) {
        ESP_LOGW(kTag, "Stale policy update review reject ignored");
        return;
    }
    const TickType_t now = xTaskGetTickCount();
    clear_agent_q_panel_if_kind(
        AgentQUiPanelKind::policy_update_review,
        SensitiveUiClearPolicy::preserve);
    if (agent_q::policy_update_flow_review_deadline_reached(now)) {
        finish_policy_update_terminal(
            snapshot.request_id,
            agent_q::policy_update_flow_record_timed_out(
                static_cast<uint64_t>(esp_timer_get_time() / 1000LL)));
        return;
    }
    finish_policy_update_terminal(
        snapshot.request_id,
        agent_q::policy_update_flow_record_rejected(
            static_cast<uint64_t>(esp_timer_get_time() / 1000LL)));
}

void handle_user_signing_review_accept_from_ui()
{
    const agent_q::AgentQUserSigningFlowSnapshot snapshot =
        agent_q::user_signing_flow_snapshot();
    if (!snapshot.active ||
        snapshot.stage != agent_q::AgentQUserSigningStage::reviewing) {
        ESP_LOGW(kTag, "Stale user_signing review accept ignored");
        return;
    }

    const TickType_t now = xTaskGetTickCount();
    if (!agent_q::human_approval_requires_pin()) {
        const agent_q::AgentQUserSigningTransitionResult result =
            agent_q::user_signing_flow_record_physical_confirmed_and_write_confirmation_history(
                now,
                write_user_signing_physical_confirmation_history,
                nullptr);
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::user_signing_review, SensitiveUiClearPolicy::preserve);
        if (result == agent_q::AgentQUserSigningTransitionResult::ok) {
            execute_user_signing_critical_section_and_finish(snapshot.request_id);
            return;
        }
        if (agent_q::user_signing_flow_terminal_pending()) {
            finish_user_signing_terminal(snapshot.request_id);
            return;
        }
        finish_user_signing_error_terminal(
            snapshot.request_id,
            result == agent_q::AgentQUserSigningTransitionResult::history_error
                ? "history_error"
                : "invalid_state",
            "Signing request is unavailable.",
            "Signing unavailable");
        return;
    }

    const agent_q::AgentQTimeoutWindow pin_input_window =
        timeout_window_from_now_ms(now, kLocalPinInputWindowMs);
    const agent_q::AgentQUserSigningConfirmationResult result =
        agent_q::user_signing_confirmation_accept_review_and_begin_pin(
            now,
            pin_input_window);
    if (result != agent_q::AgentQUserSigningConfirmationResult::ok) {
        if (agent_q::user_signing_flow_terminal_pending()) {
            finish_user_signing_terminal(snapshot.request_id);
            return;
        }
        finish_user_signing_error_terminal(
            snapshot.request_id,
            result == agent_q::AgentQUserSigningConfirmationResult::local_pin_busy
                ? "busy"
                : "invalid_state",
            "Signing request is unavailable.",
            "Signing unavailable");
        return;
    }

    clear_agent_q_panel_if_kind(AgentQUiPanelKind::user_signing_review, SensitiveUiClearPolicy::preserve);
    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        agent_q::user_signing_confirmation_cancel_for_pin_loss();
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        finish_user_signing_error_terminal(
            snapshot.request_id,
            "ui_error",
            "Could not show signing PIN UI.",
            "Display error");
    }
}

void handle_user_signing_review_reject_from_ui()
{
    const agent_q::AgentQUserSigningFlowSnapshot snapshot =
        agent_q::user_signing_flow_snapshot();
    if (!snapshot.active ||
        snapshot.stage != agent_q::AgentQUserSigningStage::reviewing) {
        ESP_LOGW(kTag, "Stale user_signing review reject ignored");
        return;
    }

    clear_agent_q_panel_if_kind(AgentQUiPanelKind::user_signing_review, SensitiveUiClearPolicy::preserve);
    const agent_q::AgentQUserSigningConfirmationResult result =
        agent_q::user_signing_confirmation_record_device_rejected();
    if (result != agent_q::AgentQUserSigningConfirmationResult::ok) {
        finish_user_signing_error_terminal(
            snapshot.request_id,
            "invalid_state",
            "Signing request is unavailable.",
            "Signing unavailable");
        return;
    }
    finish_user_signing_terminal(snapshot.request_id);
}

void handle_local_pin_auth_display_failure(const char* reason, bool clear_panel)
{
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(xTaskGetTickCount());
    char request_id[kMaxRequestIdSize] = {};
    if (snapshot.purpose == LocalPinAuthPurpose::policy_update) {
        const bool protocol_request_found =
            agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
                LocalPinAuthPurpose::policy_update,
                request_id,
                sizeof(request_id));
        if (!protocol_request_found) {
            const agent_q::AgentQPolicyUpdateFlowSnapshot policy_snapshot =
                agent_q::policy_update_flow_snapshot();
            if (policy_snapshot.active &&
                policy_snapshot.request_id != nullptr &&
                policy_snapshot.request_id[0] != '\0') {
                strlcpy(request_id, policy_snapshot.request_id, sizeof(request_id));
            }
        }
        if (request_id[0] != '\0') {
            wipe_local_pin_auth_scratch(reason);
            if (clear_panel) {
                clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
            }
            finish_policy_update_terminal(
                request_id,
                agent_q::policy_update_flow_record_ui_error());
            return;
        }
    }
    if (snapshot.purpose == LocalPinAuthPurpose::user_signing &&
        pending_request_id_for_local_pin_purpose(
            LocalPinAuthPurpose::user_signing,
            request_id,
            sizeof(request_id))) {
        agent_q::user_signing_confirmation_cancel_for_pin_loss();
        wipe_local_pin_auth_scratch(reason);
        if (clear_panel) {
            clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        }
        finish_user_signing_error_terminal(
            request_id,
            "ui_error",
            "Could not show signing PIN UI.",
            "Display error");
        return;
    }
    if (snapshot.purpose == LocalPinAuthPurpose::connect &&
        agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
            LocalPinAuthPurpose::connect,
            request_id,
            sizeof(request_id))) {
        wipe_local_pin_auth_scratch(reason);
        if (clear_panel) {
            clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        }
        agent_q::usb_response_write_connect_rejected(request_id, "ui_error", "Could not show local PIN UI.");
        agent_q::connect_approval_clear();
        agent_q::protocol_pin_approval_clear();
        agent_q::avatar_overlay_show_message(
            "Display error",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
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

bool finish_request_backed_local_pin_input_timeout_if_reached(
    LocalPinAuthPurpose purpose,
    TickType_t now,
    const char* scratch_reason)
{
    if (!request_backed_local_pin_input_deadline_reached(purpose, now)) {
        return false;
    }

    char request_id[kMaxRequestIdSize] = {};
    pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    wipe_local_pin_auth_scratch(scratch_reason);
    switch (request_backed_pin_owner_for_purpose(purpose)) {
        case RequestBackedPinOwner::protocol_pin_approval:
            if (purpose == LocalPinAuthPurpose::policy_update && request_id[0] != '\0') {
                finish_policy_update_terminal(
                    request_id,
                    agent_q::policy_update_flow_record_timed_out(
                        static_cast<uint64_t>(esp_timer_get_time() / 1000LL)));
                return true;
            }
            if (purpose == LocalPinAuthPurpose::connect && request_id[0] != '\0') {
                agent_q::usb_response_write_connect_rejected(request_id, "timeout", "Connection PIN timed out.");
                agent_q::connect_approval_clear();
                agent_q::protocol_pin_approval_clear();
                agent_q::avatar_overlay_show_message(
                    "Connection timed out",
                    AgentQMessageKind::timeout,
                    AgentQUiMode::result,
                    kAgentQResultDisplayMs);
                return true;
            }
            break;
        case RequestBackedPinOwner::user_signing:
            if (request_id[0] != '\0') {
                const agent_q::AgentQUserSigningConfirmationResult result =
                    agent_q::user_signing_confirmation_record_timeout(now);
                if (result == agent_q::AgentQUserSigningConfirmationResult::ok ||
                    agent_q::user_signing_flow_terminal_pending()) {
                    finish_user_signing_terminal(request_id);
                } else {
                    finish_user_signing_error_terminal(
                        request_id,
                        "invalid_state",
                        "Signing request is unavailable.",
                        "Signing unavailable");
                }
                return true;
            }
            break;
        case RequestBackedPinOwner::none:
        default:
            break;
    }
    return false;
}

void start_settings_human_approval_input_from_settings_menu()
{
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    if (!provisioned_material_ready() ||
        reset.stage != agent_q::AgentQLocalResetStage::settings_menu ||
        agent_q::local_pin_auth_flow_active()) {
        ESP_LOGW(kTag, "Stale human approval input setting action ignored");
        return;
    }

    agent_q::AgentQHumanApprovalInputMode current_human_approval_mode =
        agent_q::AgentQHumanApprovalInputMode::pin;
    if (!agent_q::read_human_approval_input_mode(&current_human_approval_mode)) {
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
    const agent_q::AgentQTimeoutWindow input_window =
        timeout_window_from_now_ms(xTaskGetTickCount(), agent_q::kAgentQLocalResetEntryMs);
    const agent_q::AgentQHumanApprovalInputMode target_human_approval_mode =
        current_human_approval_mode == agent_q::AgentQHumanApprovalInputMode::pin
            ? agent_q::AgentQHumanApprovalInputMode::confirm
            : agent_q::AgentQHumanApprovalInputMode::pin;
    if (!agent_q::local_pin_auth_begin_human_approval_input_setting(
            target_human_approval_mode,
            input_window)) {
        agent_q::avatar_overlay_show_message("Settings unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("human approval input setting display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void start_settings_signing_mode_from_settings_menu()
{
    const agent_q::AgentQLocalResetSnapshot reset =
        agent_q::local_reset_snapshot(xTaskGetTickCount());
    if (!provisioned_material_ready() ||
        reset.stage != agent_q::AgentQLocalResetStage::settings_menu ||
        agent_q::local_pin_auth_flow_active()) {
        ESP_LOGW(kTag, "Stale settings signing mode action ignored");
        return;
    }

    agent_q::AgentQSigningAuthorizationMode current_mode =
        agent_q::AgentQSigningAuthorizationMode::user;
    if (!agent_q::read_signing_authorization_mode(&current_mode)) {
        agent_q::local_reset_wipe();
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::settings_menu, SensitiveUiClearPolicy::preserve);
        agent_q::avatar_overlay_show_message(
            "Settings error",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
        return;
    }

    const agent_q::AgentQSigningAuthorizationMode target_mode =
        current_mode == agent_q::AgentQSigningAuthorizationMode::policy
            ? agent_q::AgentQSigningAuthorizationMode::user
            : agent_q::AgentQSigningAuthorizationMode::policy;
    agent_q::local_reset_wipe();
    const agent_q::AgentQTimeoutWindow input_window =
        timeout_window_from_now_ms(xTaskGetTickCount(), agent_q::kAgentQLocalResetEntryMs);
    if (!agent_q::local_pin_auth_begin_signing_mode_setting(
            target_mode,
            input_window)) {
        agent_q::avatar_overlay_show_message("Settings unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("settings signing mode display allocation failed");
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
    const agent_q::AgentQTimeoutWindow input_window =
        timeout_window_from_now_ms(xTaskGetTickCount(), agent_q::kAgentQLocalResetEntryMs);
    if (!agent_q::local_pin_auth_begin_change_pin(input_window)) {
        agent_q::avatar_overlay_show_message("Change PIN unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    if (!agent_q::modal_draw_local_pin_auth_panel()) {
        wipe_local_pin_auth_scratch("settings Change PIN display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void cancel_local_pin_auth_from_ui(const char* message)
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(now);
    if (!snapshot.flow_active || !snapshot.accepts_keypad_input) {
        ESP_LOGW(kTag, "Stale local PIN authorization cancel ignored");
        return;
    }

    const LocalPinAuthPurpose purpose = snapshot.purpose;
    if (finish_request_backed_local_pin_input_timeout_if_reached(
            purpose,
            now,
            "request-backed local PIN cancel reached timeout")) {
        return;
    }

    char request_id[kMaxRequestIdSize] = {};
    pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));

    clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    if (purpose == LocalPinAuthPurpose::policy_update && request_id[0] != '\0') {
        wipe_local_pin_auth_scratch("local PIN authorization canceled");
        agent_q::protocol_pin_approval_clear();
        const agent_q::AgentQPolicyUpdateFlowTransitionResult transition =
            agent_q::policy_update_flow_return_to_review(
                timeout_window_from_now_ms(now, kProvisioningApprovalMaxMs));
        if (transition != agent_q::AgentQPolicyUpdateFlowTransitionResult::ok) {
            finish_policy_update_error_terminal(
                request_id,
                "invalid_state",
                "Policy update is unavailable.",
                "Policy unavailable");
            return;
        }
        if (!show_policy_update_review()) {
            finish_policy_update_terminal(
                request_id,
                agent_q::policy_update_flow_record_ui_error());
        }
        return;
    }
    if (purpose == LocalPinAuthPurpose::connect && request_id[0] != '\0') {
        wipe_local_pin_auth_scratch("local PIN authorization canceled");
        agent_q::protocol_pin_approval_clear();
        if (!agent_q::connect_approval_return_to_review(
                timeout_window_from_now_ms(now, kConnectApprovalDefaultMs))) {
            agent_q::usb_response_write_connect_rejected(request_id, "invalid_state", "Connect is unavailable.");
            agent_q::connect_approval_clear();
            agent_q::avatar_overlay_show_message("Connect unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            return;
        }
        show_connect_review();
        return;
    }
    if (purpose == LocalPinAuthPurpose::user_signing && request_id[0] != '\0') {
        const agent_q::AgentQUserSigningConfirmationResult result =
            agent_q::user_signing_confirmation_return_to_review_from_pin(
                now,
                timeout_window_from_now_ms(now, kProvisioningApprovalMaxMs));
        if (result == agent_q::AgentQUserSigningConfirmationResult::ok) {
            if (!show_user_signing_review()) {
                agent_q::user_signing_flow_cancel_for_ui_loss();
                finish_user_signing_error_terminal(
                    request_id,
                    "ui_error",
                    "Could not show signing review UI.",
                    "Display error");
            }
        } else {
            finish_user_signing_error_terminal(
                request_id,
                "invalid_state",
                "Signing request is unavailable.",
                "Signing unavailable");
        }
        return;
    }
    if (purpose == LocalPinAuthPurpose::settings_human_approval_input ||
        purpose == LocalPinAuthPurpose::settings_signing_mode ||
        purpose == LocalPinAuthPurpose::settings_change_pin) {
        wipe_local_pin_auth_scratch("local PIN authorization canceled");
        agent_q::local_reset_begin_settings(
            timeout_window_from_now_ms(now, agent_q::kAgentQLocalResetEntryMs));
        if (!agent_q::modal_draw_settings_menu_panel()) {
            wipe_local_reset_scratch("local settings display allocation failed after PIN cancel");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    wipe_local_pin_auth_scratch("local PIN authorization canceled");
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
    if (snapshot.flow_active &&
        finish_request_backed_local_pin_input_timeout_if_reached(
            snapshot.purpose,
            now,
            "request-backed local PIN digit reached timeout")) {
        return;
    }
    const agent_q::AgentQLocalPinAuthInputResult result =
        agent_q::local_pin_auth_add_digit(digit);
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
    if (snapshot.flow_active &&
        finish_request_backed_local_pin_input_timeout_if_reached(
            snapshot.purpose,
            now,
            "request-backed local PIN clear reached timeout")) {
        return;
    }
    if (!agent_q::local_pin_auth_clear_pin()) {
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
    if (snapshot.flow_active &&
        finish_request_backed_local_pin_input_timeout_if_reached(
            snapshot.purpose,
            now,
            "request-backed local PIN backspace reached timeout")) {
        return;
    }
    if (!agent_q::local_pin_auth_backspace_pin()) {
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
    if (snapshot.flow_active &&
        finish_request_backed_local_pin_input_timeout_if_reached(
            snapshot.purpose,
            now,
            "request-backed local PIN submit reached timeout")) {
        return;
    }
    const agent_q::AgentQTimeoutWindow next_input_window =
        local_pin_auth_next_input_window(snapshot.purpose, now);
    const agent_q::AgentQLocalPinAuthSubmitResult result =
        agent_q::local_pin_auth_submit(
            now + pdMS_TO_TICKS(kLocalProcessingRenderDelayMs),
            now + pdMS_TO_TICKS(kLocalProcessingDisplayMs),
            next_input_window,
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
            if (!pause_request_backed_pin_input_window(snapshot.purpose, now)) {
                handle_local_pin_auth_display_failure(
                    "local PIN authorization deadline pause failed",
                    true);
                return;
            }
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
    if (!agent_q::local_reset_add_pin_digit(digit)) {
        return;
    }

    if (!agent_q::modal_draw_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_reset_pin_clear_from_local_ui()
{
    if (!agent_q::local_reset_clear_pin()) {
        return;
    }
    if (!agent_q::modal_draw_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_reset_pin_backspace_from_local_ui()
{
    if (!agent_q::local_reset_backspace_pin()) {
        return;
    }
    if (!agent_q::modal_draw_reset_pin_panel()) {
        wipe_local_reset_scratch("local reset PIN display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_reset_pin_submit_from_local_ui()
{
    const TickType_t now = xTaskGetTickCount();
    if (!provisioned_material_ready()) {
        wipe_local_reset_scratch("local reset material state unavailable");
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::reset_pin_entry, SensitiveUiClearPolicy::preserve);
        agent_q::avatar_overlay_show_message("Reset unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    const agent_q::AgentQLocalResetPinSubmitResult submit_result =
        agent_q::local_reset_submit_pin_for_verification(
            now + pdMS_TO_TICKS(kLocalProcessingRenderDelayMs),
            now + pdMS_TO_TICKS(agent_q::kAgentQLocalAuthWorkerMaxMs));
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
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQLocalPinAuthCommitResult result =
        agent_q::local_pin_auth_commit_if_ready(now);
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
        timeout_window_from_now_ms(now, agent_q::kAgentQLocalResetEntryMs));
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
    wipe_setup_scratch("local backup phrase and PIN committed");
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
        case SetupCommitResult::signing_mode_storage_error:
        case SetupCommitResult::human_approval_setting_storage_error:
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
    if (purpose == LocalPinAuthPurpose::user_signing) {
        char request_id[kMaxRequestIdSize] = {};
        pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
        if (!provisioned_material_ready()) {
            agent_q::user_signing_confirmation_cancel_for_pin_loss();
            wipe_local_pin_auth_scratch("user_signing material state unavailable");
            clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
            finish_user_signing_error_terminal(
                request_id,
                "invalid_state",
                "Signing request is unavailable.",
                "Signing unavailable");
            return;
        }

        const agent_q::AgentQUserSigningConfirmationResult confirmation_result =
            agent_q::user_signing_confirmation_complete_pin_verify_job_and_write_history(
                worker_result,
                now,
                now + pdMS_TO_TICKS(agent_q::kAgentQLocalResetPinLockoutMs),
                write_user_signing_confirmation_history,
                nullptr);
        switch (confirmation_result) {
            case agent_q::AgentQUserSigningConfirmationResult::not_ready:
                return;
            case agent_q::AgentQUserSigningConfirmationResult::wrong_pin:
                if (!agent_q::modal_draw_local_pin_auth_panel("Wrong PIN.")) {
                    handle_local_pin_auth_display_failure(
                        "user_signing PIN display allocation failed after wrong PIN");
                }
                return;
            case agent_q::AgentQUserSigningConfirmationResult::locked:
                if (!agent_q::modal_draw_local_pin_auth_panel("Too many wrong PINs. Wait 30s.")) {
                    handle_local_pin_auth_display_failure(
                        "user_signing PIN lockout display allocation failed");
                }
                return;
            case agent_q::AgentQUserSigningConfirmationResult::auth_unavailable:
                agent_q::persistent_material_record_runtime_failure(
                    agent_q::AgentQPersistentMaterialRuntimeFailure::local_pin_auth_unavailable,
                    persistent_material_ops());
                clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
                finish_user_signing_error_terminal(
                    request_id,
                    "auth_unavailable",
                    "Local PIN verifier unavailable.",
                    "Auth error");
                return;
            case agent_q::AgentQUserSigningConfirmationResult::history_error:
                clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
                finish_user_signing_error_terminal(
                    request_id,
                    "history_error",
                    "Could not record signing confirmation.",
                    "History error");
                return;
            case agent_q::AgentQUserSigningConfirmationResult::ok:
                break;
            case agent_q::AgentQUserSigningConfirmationResult::deadline_expired:
            case agent_q::AgentQUserSigningConfirmationResult::deadline_not_reached:
            case agent_q::AgentQUserSigningConfirmationResult::invalid_session:
            case agent_q::AgentQUserSigningConfirmationResult::inactive:
            case agent_q::AgentQUserSigningConfirmationResult::wrong_stage:
            case agent_q::AgentQUserSigningConfirmationResult::invalid_argument:
            case agent_q::AgentQUserSigningConfirmationResult::invalid_deadline:
            case agent_q::AgentQUserSigningConfirmationResult::session_still_active:
            case agent_q::AgentQUserSigningConfirmationResult::local_pin_busy:
            case agent_q::AgentQUserSigningConfirmationResult::local_pin_unavailable:
            case agent_q::AgentQUserSigningConfirmationResult::stale_state:
            case agent_q::AgentQUserSigningConfirmationResult::busy:
                clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
                if (agent_q::user_signing_flow_terminal_pending()) {
                    finish_user_signing_terminal(request_id);
                    return;
                }
                finish_user_signing_error_terminal(
                    request_id,
                    confirmation_result == agent_q::AgentQUserSigningConfirmationResult::invalid_session
                        ? "invalid_session"
                        : "invalid_state",
                    "Signing request is unavailable.",
                    "Signing unavailable");
                return;
        }

        clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        execute_user_signing_critical_section_and_finish(request_id);
        return;
    }
    if (!provisioned_material_ready()) {
        char request_id[kMaxRequestIdSize] = {};
        pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
        wipe_local_pin_auth_scratch("local PIN authorization material state unavailable");
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        if (purpose == LocalPinAuthPurpose::policy_update && request_id[0] != '\0') {
            agent_q::usb_response_write_error(request_id, "invalid_state", "Policy update is unavailable.");
            agent_q::policy_update_flow_clear();
            agent_q::protocol_pin_approval_clear();
        }
        if (request_id[0] != '\0') {
            if (purpose == LocalPinAuthPurpose::policy_update) {
                agent_q::avatar_overlay_show_message("PIN unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
                return;
            }
            agent_q::usb_response_write_connect_rejected(request_id, "invalid_state", "Connect is unavailable.");
            agent_q::connect_approval_clear();
            agent_q::protocol_pin_approval_clear();
        }
        agent_q::avatar_overlay_show_message("PIN unavailable", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }

    if (finish_request_backed_local_pin_input_timeout_if_reached(
            purpose,
            now,
            "protocol-backed local PIN verifier result reached timeout")) {
        return;
    }

    const agent_q::AgentQTimeoutWindow next_input_window =
        local_pin_auth_next_input_window(purpose, now);
    const agent_q::AgentQLocalPinAuthVerifyResult result =
        agent_q::local_pin_auth_complete_verify_job(
            worker_result,
            next_input_window,
            now + pdMS_TO_TICKS(agent_q::kAgentQLocalResetPinLockoutMs),
            now + pdMS_TO_TICKS(kLocalProcessingDisplayMs));
    if ((result == agent_q::AgentQLocalPinAuthVerifyResult::locked ||
         result == agent_q::AgentQLocalPinAuthVerifyResult::wrong_pin ||
         result == agent_q::AgentQLocalPinAuthVerifyResult::verified_connect ||
         result == agent_q::AgentQLocalPinAuthVerifyResult::verified_policy_update) &&
        request_backed_local_pin_input_deadline_reached(purpose, now)) {
        if (finish_request_backed_local_pin_input_timeout_if_reached(
                purpose,
                now,
                "protocol-backed local PIN authorization timed out")) {
            return;
        }
        agent_q::avatar_overlay_show_message("Auth timed out", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
        return;
    }
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
                if (!write_policy_propose_result_response(request_id, "consistency_error", "consistency_error", true)) {
                    agent_q::usb_response_log_write_failure("policy_propose_result", request_id);
                }
                agent_q::policy_update_flow_clear();
                agent_q::protocol_pin_approval_clear();
                agent_q::avatar_overlay_show_message("Auth error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
                return;
            }
            if (request_id[0] != '\0') {
                agent_q::usb_response_write_connect_rejected(request_id, "auth_unavailable", "Local PIN verifier unavailable.");
                agent_q::connect_approval_clear();
                agent_q::protocol_pin_approval_clear();
            }
            agent_q::avatar_overlay_show_message("Auth error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            return;
        }
        case agent_q::AgentQLocalPinAuthVerifyResult::locked:
            if (purpose == LocalPinAuthPurpose::policy_update &&
                agent_q::policy_update_flow_return_to_pin_entry() !=
                    agent_q::AgentQPolicyUpdateFlowTransitionResult::ok) {
                handle_local_pin_auth_display_failure(
                    "policy update lockout stage transition failed",
                    true);
                return;
            }
            if (!agent_q::modal_draw_local_pin_auth_panel("Too many wrong PINs. Wait 30s.")) {
                handle_local_pin_auth_display_failure("local PIN authorization display allocation failed after wrong PIN");
            }
            return;
        case agent_q::AgentQLocalPinAuthVerifyResult::wrong_pin:
            if (purpose == LocalPinAuthPurpose::policy_update &&
                agent_q::policy_update_flow_return_to_pin_entry() !=
                    agent_q::AgentQPolicyUpdateFlowTransitionResult::ok) {
                handle_local_pin_auth_display_failure(
                    "policy update wrong-PIN stage transition failed",
                    true);
                return;
            }
            if (request_backed_local_pin_purpose(purpose) &&
                !resume_request_backed_pin_input_window(purpose, now)) {
                if (finish_request_backed_local_pin_input_timeout_if_reached(
                        purpose,
                        now,
                        "request-backed local PIN wrong-PIN refresh reached timeout")) {
                    return;
                }
                handle_local_pin_auth_display_failure(
                    "request-backed local PIN wrong-PIN refresh failed",
                    true);
                return;
            }
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
                    agent_q::usb_response_write_error(request_id, "rng_error", "Could not create session id.");
                }
                ESP_LOGE(kTag, "connect PIN could not create session id: id=%s", request_id);
                wipe_local_pin_auth_scratch("connect PIN session creation failed");
                clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
                agent_q::connect_approval_clear();
                agent_q::protocol_pin_approval_clear();
                agent_q::avatar_overlay_show_message("RNG error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
                return;
            }
            wipe_local_pin_auth_scratch("connect PIN approved");
            clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
            agent_q::connect_approval_clear();
            if (request_id[0] != '\0') {
                if (!write_connect_approved_response(request_id)) {
                    agent_q::usb_response_log_write_failure("connect_result", request_id);
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
    const TickType_t now = xTaskGetTickCount();
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
        timeout_window_from_now_ms(now, agent_q::kAgentQLocalResetEntryMs));
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
        if (snapshot.purpose == LocalPinAuthPurpose::user_signing) {
            char request_id[kMaxRequestIdSize] = {};
            pending_request_id_for_local_pin_purpose(snapshot.purpose, request_id, sizeof(request_id));
            if (finish_request_backed_local_pin_input_timeout_if_reached(
                    snapshot.purpose,
                    now,
                    "user_signing local PIN authorization timed out")) {
                return;
            }
            if (agent_q::local_pin_auth_processing_deadline_expired(now)) {
                agent_q::user_signing_confirmation_cancel_for_pin_loss();
                wipe_local_pin_auth_scratch("user_signing local PIN verifier timed out");
                clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
                agent_q::persistent_material_record_runtime_failure(
                    agent_q::AgentQPersistentMaterialRuntimeFailure::local_pin_auth_unavailable,
                    persistent_material_ops());
                finish_user_signing_error_terminal(
                    request_id,
                    "auth_unavailable",
                    "Local PIN verifier unavailable.",
                    "Auth error");
                return;
            }
            if (!agent_q_panel_active(AgentQUiPanelKind::local_pin_auth) &&
                !agent_q::modal_draw_local_pin_auth_panel()) {
                handle_local_pin_auth_display_failure(
                    "user_signing PIN authorization processing UI recovery failed",
                    true);
            }
            return;
        }
        if (finish_request_backed_local_pin_input_timeout_if_reached(
                snapshot.purpose,
                now,
                "protocol-backed local PIN authorization timed out")) {
            return;
        }
        if (request_backed_local_pin_input_deadline_reached(snapshot.purpose, now)) {
            agent_q::avatar_overlay_show_message("Auth timed out", AgentQMessageKind::timeout, AgentQUiMode::result, kAgentQResultDisplayMs);
            return;
        }
        if (!agent_q::local_pin_auth_fail_processing_if_expired(now)) {
            if (!agent_q_panel_active(AgentQUiPanelKind::local_pin_auth) &&
                !agent_q::modal_draw_local_pin_auth_panel()) {
                handle_local_pin_auth_display_failure(
                    "local PIN authorization processing UI recovery failed",
                    true);
            }
            return;
        }

        const LocalPinAuthPurpose purpose = snapshot.purpose;
        char request_id[kMaxRequestIdSize] = {};
        pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        if (snapshot.stage == LocalPinAuthStage::pin_verifying) {
            agent_q::persistent_material_record_runtime_failure(
                agent_q::AgentQPersistentMaterialRuntimeFailure::local_pin_auth_unavailable,
                persistent_material_ops());
            if (purpose == LocalPinAuthPurpose::policy_update && request_id[0] != '\0') {
                if (!write_policy_propose_result_response(request_id, "consistency_error", "consistency_error", true)) {
                    agent_q::usb_response_log_write_failure("policy_propose_result", request_id);
                }
                agent_q::policy_update_flow_clear();
                agent_q::protocol_pin_approval_clear();
                agent_q::avatar_overlay_show_message("Auth error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
                return;
            }
            if (request_id[0] != '\0') {
                agent_q::usb_response_write_connect_rejected(request_id, "auth_unavailable", "Local PIN verifier unavailable.");
                agent_q::connect_approval_clear();
                agent_q::protocol_pin_approval_clear();
            }
            agent_q::avatar_overlay_show_message("Auth error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
            return;
        }
        if (purpose == LocalPinAuthPurpose::policy_update && request_id[0] != '\0') {
            finish_policy_update_terminal(
                request_id,
                agent_q::policy_update_flow_record_timed_out(
                    static_cast<uint64_t>(esp_timer_get_time() / 1000LL)));
            return;
        }
        if (request_id[0] != '\0') {
            agent_q::usb_response_write_connect_rejected(request_id, "timeout", "Connection PIN timed out.");
            agent_q::connect_approval_clear();
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
    if (purpose == LocalPinAuthPurpose::user_signing && request_id[0] != '\0') {
        if (finish_request_backed_local_pin_input_timeout_if_reached(
                purpose,
                now,
                "user_signing local PIN authorization timed out")) {
            return;
        }
        if (agent_q::local_pin_auth_deadline_expired(now)) {
            clear_agent_q_panel_if_kind(AgentQUiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
            wipe_local_pin_auth_scratch("user_signing local PIN input timed out");
            const agent_q::AgentQUserSigningConfirmationResult result =
                agent_q::user_signing_confirmation_record_timeout(now);
            if (result == agent_q::AgentQUserSigningConfirmationResult::ok ||
                agent_q::user_signing_flow_terminal_pending()) {
                finish_user_signing_terminal(request_id);
            } else {
                finish_user_signing_error_terminal(
                    request_id,
                    "invalid_state",
                    "Signing request is unavailable.",
                    "Signing unavailable");
            }
            return;
        }

        const agent_q::AgentQLocalPinAuthLockoutReleaseResult lockout_release =
            agent_q::local_pin_auth_release_lockout_if_elapsed(now);
        if (lockout_release == agent_q::AgentQLocalPinAuthLockoutReleaseResult::failed) {
            handle_local_pin_auth_display_failure(
                "user_signing local PIN lockout release failed",
                true);
            return;
        }
        if (lockout_release == agent_q::AgentQLocalPinAuthLockoutReleaseResult::released) {
            if (!resume_request_backed_pin_input_window(purpose, now)) {
                if (finish_request_backed_local_pin_input_timeout_if_reached(
                        purpose,
                        now,
                        "user_signing local PIN lockout release reached timeout")) {
                    return;
                }
                handle_local_pin_auth_display_failure(
                    "user_signing local PIN lockout release refresh failed",
                    true);
                return;
            }
            if (!agent_q::modal_draw_local_pin_auth_panel("Try again.")) {
                handle_local_pin_auth_display_failure(
                    "user_signing PIN authorization lockout display allocation failed");
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
        if (panel_active) {
            return;
        }
        if (agent_q::modal_draw_local_pin_auth_panel()) {
            return;
        }
        agent_q::user_signing_confirmation_cancel_for_pin_loss();
        finish_user_signing_error_terminal(
            request_id,
            "ui_error",
            "Could not restore signing PIN UI.",
            "Display error");
        return;
    }
    if (finish_request_backed_local_pin_input_timeout_if_reached(
            purpose,
            now,
            "protocol-backed local PIN authorization timed out")) {
        return;
    }

    const agent_q::AgentQLocalPinAuthLockoutReleaseResult lockout_release =
        agent_q::local_pin_auth_release_lockout_if_elapsed(now);
    if (lockout_release == agent_q::AgentQLocalPinAuthLockoutReleaseResult::failed) {
        handle_local_pin_auth_display_failure(
            "local PIN lockout release failed",
            true);
        return;
    }
    if (lockout_release == agent_q::AgentQLocalPinAuthLockoutReleaseResult::released) {
        if (request_backed_local_pin_purpose(purpose) &&
            !resume_request_backed_pin_input_window(purpose, now)) {
            if (finish_request_backed_local_pin_input_timeout_if_reached(
                    purpose,
                    now,
                    "protocol-backed local PIN lockout release reached timeout")) {
                return;
            }
            handle_local_pin_auth_display_failure(
                "protocol-backed local PIN lockout release refresh failed",
                true);
            return;
        }
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
                agent_q::usb_response_write_connect_rejected(request_id, "ui_error", "Could not restore local PIN UI.");
                agent_q::connect_approval_clear();
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
        agent_q::usb_response_write_connect_rejected(request_id,
                                        expired ? "timeout" : "rejected",
                                        expired ? "Connection PIN timed out." : "Connection PIN UI closed.");
        agent_q::connect_approval_clear();
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

void clear_user_signing_review_if_needed()
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQUserSigningFlowSnapshot snapshot =
        agent_q::user_signing_flow_snapshot();
    if (!snapshot.active ||
        snapshot.stage != agent_q::AgentQUserSigningStage::reviewing) {
        return;
    }

    const bool panel_active = agent_q_panel_active(AgentQUiPanelKind::user_signing_review);
    const agent_q::AgentQUserSigningTransitionResult timeout_result =
        agent_q::user_signing_flow_record_timeout(now);
    if (timeout_result == agent_q::AgentQUserSigningTransitionResult::deadline_not_reached) {
        if (panel_active) {
            return;
        }
        if (!show_user_signing_review()) {
            agent_q::user_signing_flow_clear();
            agent_q::usb_response_write_error(
                snapshot.request_id,
                "ui_error",
                "Could not restore signing review UI.");
            agent_q::avatar_overlay_show_message(
                "Display error",
                AgentQMessageKind::error,
                AgentQUiMode::result,
                kAgentQResultDisplayMs);
        }
        return;
    }
    if (timeout_result == agent_q::AgentQUserSigningTransitionResult::ok ||
        agent_q::user_signing_flow_terminal_pending()) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::user_signing_review, SensitiveUiClearPolicy::preserve);
        finish_user_signing_terminal(snapshot.request_id);
        return;
    }

    ESP_LOGW(kTag,
             "Signature review timeout check returned %d",
             static_cast<int>(timeout_result));
}

void clear_policy_update_review_if_needed()
{
    const TickType_t now = xTaskGetTickCount();
    const agent_q::AgentQPolicyUpdateFlowSnapshot snapshot =
        agent_q::policy_update_flow_snapshot();
    if (!snapshot.active ||
        snapshot.stage != agent_q::AgentQPolicyUpdateFlowStage::reviewing) {
        return;
    }

    const bool panel_active = agent_q_panel_active(AgentQUiPanelKind::policy_update_review);
    if (!agent_q::policy_update_flow_review_deadline_reached(now)) {
        if (panel_active) {
            return;
        }
        if (!show_policy_update_review()) {
            finish_policy_update_terminal(
                snapshot.request_id,
                agent_q::policy_update_flow_record_ui_error());
        }
        return;
    }

    clear_agent_q_panel_if_kind(
        AgentQUiPanelKind::policy_update_review,
        SensitiveUiClearPolicy::preserve);
    finish_policy_update_terminal(
        snapshot.request_id,
        agent_q::policy_update_flow_record_timed_out(
            static_cast<uint64_t>(esp_timer_get_time() / 1000LL)));
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
        agent_q::ui_event_bridge_enqueue_settings_requested();
    }
}

bool connect_local_pin_flow_active()
{
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(xTaskGetTickCount());
    return snapshot.flow_active &&
           snapshot.purpose == LocalPinAuthPurpose::connect;
}

bool begin_connect_pin_auth_from_review(TickType_t now)
{
    if (!agent_q::connect_approval_review_action_available(now)) {
        return false;
    }
    const agent_q::AgentQConnectApprovalSnapshot approval =
        agent_q::connect_approval_snapshot();
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::connect_review, SensitiveUiClearPolicy::preserve);
    return begin_connect_pin_auth(approval.request_id, approval.client_name);
}

void drain_connect_review_choice_events()
{
    if (connect_local_pin_flow_active()) {
        agent_q::ui_event_bridge_reset_connect_choices();
        return;
    }

    ConnectApprovalChoice choice = ConnectApprovalChoice::none;
    while (agent_q::ui_event_bridge_receive_connect_choice(&choice)) {
        if (agent_q::connect_approval_awaiting_choice()) {
            const TickType_t now = xTaskGetTickCount();
            if (choice == ConnectApprovalChoice::approved &&
                agent_q::human_approval_requires_pin()) {
                begin_connect_pin_auth_from_review(now);
                agent_q::ui_event_bridge_reset_connect_choices();
                return;
            }
            agent_q::connect_approval_choose(choice, now);
            agent_q::ui_event_bridge_reset_connect_choices();
            return;
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
            timeout_window_from_now_ms(xTaskGetTickCount(), kBackupPhraseDisplayMs));
    if (generation_result == ProvisioningFlowGenerateResult::ok) {
        if (agent_q::modal_draw_backup_phrase_display(agent_q::provisioning_flow_backup_phrase())) {
            ESP_LOGI(kTag, "Local setup backup phrase displayed");
        } else {
            wipe_setup_scratch("local setup backup phrase display allocation failed");
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
        timeout_window_from_now_ms(xTaskGetTickCount(), kProvisioningApprovalMaxMs));
    if (!agent_q::modal_draw_setup_choice_panel()) {
        wipe_setup_scratch("setup choice display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void start_local_import_from_setup_choice()
{
    if (!setup_choice_action_allowed()) {
        ESP_LOGW(kTag, "Stale local import action ignored");
        return;
    }

    agent_q::provisioning_flow_begin_import_phrase(
        timeout_window_from_now_ms(xTaskGetTickCount(), kProvisioningApprovalMaxMs));
    if (!agent_q::modal_draw_import_word_entry_panel()) {
        wipe_setup_scratch("import word entry display allocation failed");
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
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::backup_phrase_display, SensitiveUiClearPolicy::preserve);
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::import_word_entry, SensitiveUiClearPolicy::preserve);
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
    wipe_setup_scratch("provisioning scratch wipe");
    ESP_LOGI(kTag, "Local setup canceled from backup phrase UI");
    agent_q::avatar_overlay_show_message("Setup canceled", AgentQMessageKind::rejected, AgentQUiMode::result, kAgentQResultDisplayMs);
}

// Cancel inside the generate (backup_phrase_displayed) or import (import_word_entry)
// screen goes BACK to the setup-choice menu rather than ending setup. The in-progress
// phrase is wiped first (same protection as a full cancel) so nothing leaks across the
// re-pick. Setup is entirely device-local (SPEC: local controls own the setup transitions,
// there are no USB setup transition requests), and status stays `busy` throughout, so
// returning to the menu changes nothing a host can observe beyond the unchanged `busy`.
// NOTE: built but NOT yet exercised on hardware — verify nav + scratch wipe + re-pick.
void return_to_setup_choice_from_local_ui()
{
    if (!agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::backup_phrase_displayed) &&
        !agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::import_word_entry)) {
        ESP_LOGW(kTag, "Stale local back-to-choice ignored");
        return;
    }

    clear_agent_q_panel_if_kind(AgentQUiPanelKind::backup_phrase_display, SensitiveUiClearPolicy::preserve);
    clear_agent_q_panel_if_kind(AgentQUiPanelKind::import_word_entry, SensitiveUiClearPolicy::preserve);
    wipe_setup_scratch("provisioning back-to-choice wipe");
    ESP_LOGI(kTag, "Returned to setup choice from generate/import UI");

    agent_q::provisioning_flow_begin_setup_choice(
        timeout_window_from_now_ms(xTaskGetTickCount(), kProvisioningApprovalMaxMs));
    if (!agent_q::modal_draw_setup_choice_panel()) {
        wipe_setup_scratch("setup choice display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void confirm_backup_phrase_from_local_ui()
{
    if (!backup_phrase_backup_confirmation_ready()) {
        ESP_LOGW(kTag, "Stale local backup confirmation ignored");
        return;
    }

    if (!agent_q::provisioning_flow_begin_pin_setup_from_displayed_phrase(
            timeout_window_from_now_ms(xTaskGetTickCount(), kLocalPinSetupMs))) {
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

void handle_import_slot_from_local_ui(uint8_t slot)
{
    if (!agent_q::provisioning_flow_import_select_slot(
            slot,
            timeout_window_from_now_ms(xTaskGetTickCount(), kProvisioningApprovalMaxMs))) {
        return;
    }
    if (!agent_q::modal_draw_import_word_entry_panel()) {
        wipe_setup_scratch("import word entry display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_import_letter_from_local_ui(char letter)
{
    if (!agent_q::provisioning_flow_import_add_letter(
            letter,
            timeout_window_from_now_ms(xTaskGetTickCount(), kProvisioningApprovalMaxMs))) {
        return;
    }
    if (!agent_q::modal_draw_import_word_entry_panel()) {
        wipe_setup_scratch("import word entry display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_import_clear_from_local_ui()
{
    if (agent_q::provisioning_flow_import_clear_active(
            timeout_window_from_now_ms(xTaskGetTickCount(), kProvisioningApprovalMaxMs)) &&
        !agent_q::modal_draw_import_word_entry_panel()) {
        wipe_setup_scratch("import word entry display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_import_candidate_from_local_ui(uint16_t word_index)
{
    if (agent_q::provisioning_flow_import_select_candidate(
            word_index,
            timeout_window_from_now_ms(xTaskGetTickCount(), kProvisioningApprovalMaxMs)) &&
        !agent_q::modal_draw_import_word_entry_panel()) {
        wipe_setup_scratch("import word entry display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_import_previous_from_local_ui()
{
    if (agent_q::provisioning_flow_import_previous_page(
            timeout_window_from_now_ms(xTaskGetTickCount(), kProvisioningApprovalMaxMs)) &&
        !agent_q::modal_draw_import_word_entry_panel()) {
        wipe_setup_scratch("import word entry display allocation failed");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void start_pin_setup_after_imported_entropy()
{
    agent_q::provisioning_flow_begin_pin_setup_after_import(
        timeout_window_from_now_ms(xTaskGetTickCount(), kLocalPinSetupMs));

    if (!agent_q::modal_draw_pin_setup_panel()) {
        wipe_setup_scratch("local PIN setup display allocation failed after import");
        agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
    }
}

void handle_import_next_from_local_ui()
{
    if (!agent_q::provisioning_flow_stage_is(ProvisioningFlowStage::import_word_entry) ||
        !agent_q::provisioning_flow_import_current_page_complete()) {
        return;
    }

    if (agent_q::provisioning_flow_import_next_page(
            timeout_window_from_now_ms(xTaskGetTickCount(), kProvisioningApprovalMaxMs))) {
        if (!agent_q::modal_draw_import_word_entry_panel()) {
            wipe_setup_scratch("import word entry display allocation failed");
            agent_q::avatar_overlay_show_message("Display error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    if (!agent_q::provisioning_flow_import_all_words_complete()) {
        return;
    }

    const agent_q::Bip39EntropyDecodeResult result =
        agent_q::provisioning_flow_decode_entropy_from_words();
    if (result != agent_q::Bip39EntropyDecodeResult::ok) {
        agent_q::provisioning_flow_import_refresh_deadline(
            timeout_window_from_now_ms(xTaskGetTickCount(), kProvisioningApprovalMaxMs));
        if (!agent_q::modal_draw_import_word_entry_panel("Checksum failed. Recheck words.")) {
            wipe_setup_scratch("import checksum failure display allocation failed");
            agent_q::avatar_overlay_show_message("Import error", AgentQMessageKind::error, AgentQUiMode::result, kAgentQResultDisplayMs);
        }
        return;
    }

    start_pin_setup_after_imported_entropy();
}

void drain_ui_events()
{
    AgentQUiEvent event;
    while (agent_q::ui_event_bridge_receive(&event)) {
        if (event.kind == AgentQUiEventKind::setup_requested) {
            show_setup_choice_from_setup_touch();
            continue;
        }

        if (event.kind == AgentQUiEventKind::setup_generate_requested) {
            start_local_provisioning_from_setup_touch();
            continue;
        }

        if (event.kind == AgentQUiEventKind::setup_import_requested) {
            start_local_import_from_setup_choice();
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

        if (event.kind == AgentQUiEventKind::settings_human_approval_input_requested) {
            start_settings_human_approval_input_from_settings_menu();
            continue;
        }

        if (event.kind == AgentQUiEventKind::settings_signing_mode_requested) {
            start_settings_signing_mode_from_settings_menu();
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

        if (event.kind == AgentQUiEventKind::backup_phrase_cancel_requested) {
            return_to_setup_choice_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::backup_phrase_confirm_requested) {
            confirm_backup_phrase_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::import_slot_requested) {
            handle_import_slot_from_local_ui(event.slot);
            continue;
        }

        if (event.kind == AgentQUiEventKind::import_letter_requested) {
            handle_import_letter_from_local_ui(event.letter);
            continue;
        }

        if (event.kind == AgentQUiEventKind::import_clear_requested) {
            handle_import_clear_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::import_candidate_requested) {
            handle_import_candidate_from_local_ui(event.word_index);
            continue;
        }

        if (event.kind == AgentQUiEventKind::import_previous_requested) {
            handle_import_previous_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::import_next_requested) {
            handle_import_next_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::import_cancel_requested) {
            return_to_setup_choice_from_local_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::policy_update_review_continue_requested) {
            handle_policy_update_review_continue_from_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::policy_update_review_reject_requested) {
            handle_policy_update_review_reject_from_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::user_signing_review_accept_requested) {
            handle_user_signing_review_accept_from_ui();
            continue;
        }

        if (event.kind == AgentQUiEventKind::user_signing_review_reject_requested) {
            handle_user_signing_review_reject_from_ui();
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
        apply_panel_cleanup_plan(
            panel_cleanup_plan(event.panel_kind, agent_q::AgentQUiPanelCleanupEvent::external_delete),
            "setup panel deleted",
            "local reset panel deleted",
            "local PIN authorization panel deleted");
    }
}

void ensure_connect_review_ui()
{
    if (!agent_q::connect_approval_awaiting_choice()) {
        return;
    }
    if (connect_local_pin_flow_active()) {
        return;
    }

    bool needs_connect_review_panel = false;
    {
        LvglLockGuard lock;
        needs_connect_review_panel = agent_q::drawing_surface_panel_locked() == nullptr ||
                               !is_connect_review_panel_kind(agent_q::drawing_surface_panel_kind_locked());
    }
    if (!needs_connect_review_panel) {
        return;
    }

    const agent_q::AgentQConnectApprovalSnapshot approval =
        agent_q::connect_approval_snapshot();
    show_connect_review();
    ESP_LOGW(kTag, "connect review UI recovered: id=%s", approval.request_id);
}

void send_connect_review_response_if_needed()
{
    drain_connect_review_choice_events();

    agent_q::AgentQConnectApprovalSnapshot approval =
        agent_q::connect_approval_snapshot();
    if (!approval.active || approval.choice == ConnectApprovalChoice::none) {
        if (connect_local_pin_flow_active()) {
            return;
        }
        if (agent_q::connect_approval_deadline_reached(xTaskGetTickCount())) {
            char request_id[kMaxRequestIdSize] = {};
            agent_q::connect_approval_request_id(request_id, sizeof(request_id));
            // Device leaves awaiting_approval before reporting the result.
            agent_q::connect_approval_clear();
            agent_q::usb_response_write_connect_rejected(request_id, "timeout", "Connection approval timed out.");
            ESP_LOGI(kTag, "connect timed out: id=%s", request_id);
            show_result_and_clear_connect_review("Connection timed out", AgentQMessageKind::timeout);
        }
        return;
    }

    const bool approved = approval.choice == ConnectApprovalChoice::approved;
    char request_id[kMaxRequestIdSize] = {};
    agent_q::connect_approval_request_id(request_id, sizeof(request_id));
    agent_q::connect_approval_clear();
    if (approved) {
        if (!replace_active_session()) {
            agent_q::usb_response_write_error(request_id, "rng_error", "Could not create session id.");
            ESP_LOGE(kTag, "connect could not create session id: id=%s", request_id);
            show_result_and_clear_connect_review("RNG error", AgentQMessageKind::error);
            return;
        }
        if (write_connect_approved_response(request_id)) {
            ESP_LOGI(kTag, "connect approved: id=%s", request_id);
        } else {
            agent_q::usb_response_log_write_failure("connect_result", request_id);
        }
        show_result_and_clear_connect_review("Connected", AgentQMessageKind::success);
    } else {
        if (agent_q::usb_response_write_connect_rejected(request_id, "rejected", "Connection rejected.")) {
            ESP_LOGI(kTag, "connect rejected: id=%s", request_id);
        } else {
            agent_q::usb_response_log_write_failure("connect_result", request_id);
        }
        show_result_and_clear_connect_review("Connection rejected", AgentQMessageKind::rejected);
    }
}

void show_policy_signing_notification(
    const char* message,
    AgentQMessageKind kind)
{
    agent_q::avatar_overlay_show_message(
        message,
        kind,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

const agent_q::AgentQUsbGetStatusHandlerOps& usb_get_status_handler_ops()
{
    static const agent_q::AgentQUsbGetStatusHandlerOps ops = {
        refresh_persistent_material_consistency,
        usb_device_response_info,
    };
    return ops;
}

void handle_get_status_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_get_status_request(
        id,
        request,
        writer,
        usb_get_status_handler_ops());
}

const agent_q::AgentQUsbIdentifyDeviceHandlerOps& usb_identify_device_handler_ops()
{
    static const agent_q::AgentQUsbIdentifyDeviceHandlerOps ops = {
        write_busy_if_pending_or_local_flow_active_default,
        is_safe_identification_code,
        show_identification_code,
        usb_device_response_info,
        kIdentifyDisplayDefaultMs,
    };
    return ops;
}

void handle_identify_device_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_identify_device_request(
        id,
        request,
        writer,
        usb_identify_device_handler_ops());
}

agent_q::AgentQTimeoutWindow make_connect_approval_window()
{
    const TickType_t started_at = xTaskGetTickCount();
    return agent_q::timeout_window_from_deadline(
        started_at,
        started_at + pdMS_TO_TICKS(kConnectApprovalDefaultMs));
}

void show_connect_unavailable()
{
    agent_q::avatar_overlay_show_message(
        "Connect unavailable",
        AgentQMessageKind::error,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void reset_connect_review_choice_queue()
{
    agent_q::ui_event_bridge_reset_connect_choices();
}

void record_connect_waiting_for_review(const char* id, const char* client_name)
{
    ESP_LOGI(kTag, "connect waiting for review: id=%s agent-q=%s", id, client_name);
}

const agent_q::AgentQUsbConnectHandlerOps& connect_handler_ops()
{
    static const agent_q::AgentQUsbConnectHandlerOps ops = {
        provisioned_material_ready,
        write_busy_if_pending_or_local_flow_active_default,
        make_connect_approval_window,
        agent_q::connect_approval_begin,
        show_connect_unavailable,
        reset_connect_review_choice_queue,
        show_connect_review,
        record_connect_waiting_for_review,
    };
    return ops;
}

void handle_connect_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_connect_request(id, request, writer, connect_handler_ops());
}

const agent_q::AgentQUsbRetainedResultHandlerOps& retained_result_handler_ops()
{
    static const agent_q::AgentQUsbRetainedResultHandlerOps ops = {
        provisioned_material_ready,
        require_active_matching_session,
    };
    return ops;
}

void handle_get_result_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_get_result_request(id, request, writer, retained_result_handler_ops());
}

void handle_ack_result_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_ack_result_request(id, request, writer, retained_result_handler_ops());
}

agent_q::AgentQUsbPolicyResponseWriteResult write_policy_response_for_session_read(const char* id)
{
    switch (write_policy_response(id)) {
        case PolicyResponseWriteResult::ok:
            return agent_q::AgentQUsbPolicyResponseWriteResult::ok;
        case PolicyResponseWriteResult::active_policy_unavailable:
            return agent_q::AgentQUsbPolicyResponseWriteResult::active_policy_unavailable;
        case PolicyResponseWriteResult::response_write_failed:
            return agent_q::AgentQUsbPolicyResponseWriteResult::response_write_failed;
    }
    return agent_q::AgentQUsbPolicyResponseWriteResult::response_write_failed;
}

void record_active_policy_unavailable_for_session_read()
{
    agent_q::persistent_material_record_runtime_failure(
        agent_q::AgentQPersistentMaterialRuntimeFailure::active_policy_unavailable,
        persistent_material_ops());
}

const agent_q::AgentQUsbSessionReadHandlerOps& session_read_handler_ops()
{
    static const agent_q::AgentQUsbSessionReadHandlerOps ops = {
        provisioned_material_ready,
        write_busy_if_pending_or_local_flow_active_allow_settings,
        require_active_matching_session,
        agent_q::read_signing_authorization_mode,
        write_accounts_response,
        write_policy_response_for_session_read,
        record_active_policy_unavailable_for_session_read,
    };
    return ops;
}

void handle_get_capabilities_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_get_capabilities_request(id, request, writer, session_read_handler_ops());
}

void handle_get_accounts_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_get_accounts_request(id, request, writer, session_read_handler_ops());
}

void handle_policy_get_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_policy_get_request(id, request, writer, session_read_handler_ops());
}

const agent_q::AgentQUsbDisconnectHandlerOps& disconnect_handler_ops()
{
    static const agent_q::AgentQUsbDisconnectHandlerOps ops = {
        require_active_matching_session,
        disconnect_pending_policy_update_for_session,
        disconnect_pending_user_signing_for_session,
        write_busy_if_pending_or_local_flow_active_allow_settings,
        clear_active_session,
    };
    return ops;
}

void handle_disconnect_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_disconnect_request(id, request, writer, disconnect_handler_ops());
}

const agent_q::AgentQUsbApprovalHistoryHandlerOps& approval_history_handler_ops()
{
    static const agent_q::AgentQUsbApprovalHistoryHandlerOps ops = {
        provisioned_material_ready,
        write_busy_if_pending_or_local_flow_active_allow_settings,
        require_active_matching_session,
        write_approval_history_response,
    };
    return ops;
}

void handle_get_approval_history_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_get_approval_history_request(
        id,
        request,
        writer,
        approval_history_handler_ops());
}

agent_q::AgentQTimeoutWindow make_policy_update_review_window()
{
    const TickType_t review_started_at = xTaskGetTickCount();
    return timeout_window_from_now_ms(review_started_at, kProvisioningApprovalMaxMs);
}

void record_policy_update_waiting_for_review(const char* id)
{
    ESP_LOGI(kTag, "policy update waiting for local review: id=%s", id);
}

const agent_q::AgentQUsbPolicyProposeHandlerOps& policy_propose_handler_ops()
{
    static const agent_q::AgentQUsbPolicyProposeHandlerOps ops = {
        provisioned_material_ready,
        write_busy_if_pending_or_local_flow_active_default,
        require_active_matching_session,
        make_policy_update_review_window,
        agent_q::policy_update_flow_begin,
        agent_q::policy_update_flow_begin_result_reason,
        write_policy_propose_result_response,
        show_policy_update_review,
        agent_q::policy_update_flow_record_ui_error,
        finish_policy_update_terminal,
        record_policy_update_waiting_for_review,
    };
    return ops;
}

void handle_policy_propose_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_policy_propose_request(id, request, writer, policy_propose_handler_ops());
}

void record_signing_account_unavailable_runtime_failure()
{
    agent_q::persistent_material_record_runtime_failure(
        agent_q::AgentQPersistentMaterialRuntimeFailure::root_material_unreadable,
        persistent_material_ops());
}

agent_q::AgentQPolicySigningExecutionResult execute_policy_sign_transaction_for_usb(
    const agent_q::AgentQSignTransactionPolicyRuntimeResult& policy_result)
{
    return agent_q::execute_policy_sign_transaction(policy_result, persistent_material_ops());
}

agent_q::AgentQTimeoutWindow make_user_signing_window()
{
    const TickType_t signing_started_at = xTaskGetTickCount();
    return agent_q::timeout_window_from_deadline(
        signing_started_at,
        signing_started_at + pdMS_TO_TICKS(agent_q::kAgentQUserSigningApprovalWindowMs));
}

void show_user_signing_display_error()
{
    agent_q::avatar_overlay_show_message(
        "Display error",
        AgentQMessageKind::error,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void show_policy_signing_notice(
    const char* message,
    agent_q::AgentQUsbSigningNoticeKind kind)
{
    AgentQMessageKind message_kind = AgentQMessageKind::info;
    switch (kind) {
        case agent_q::AgentQUsbSigningNoticeKind::rejected:
            message_kind = AgentQMessageKind::rejected;
            break;
        case agent_q::AgentQUsbSigningNoticeKind::error:
            message_kind = AgentQMessageKind::error;
            break;
        case agent_q::AgentQUsbSigningNoticeKind::success:
            message_kind = AgentQMessageKind::success;
            break;
        case agent_q::AgentQUsbSigningNoticeKind::info:
        default:
            message_kind = AgentQMessageKind::info;
            break;
    }
    show_policy_signing_notification(message, message_kind);
}

void log_policy_rejected(
    const char* id,
    const char* chain,
    const char* method,
    const char* rule_ref)
{
    ESP_LOGI(kTag, "sign_transaction policy rejected: id=%s chain=%s method=%s rule=%s",
             id,
             chain,
             method,
             rule_ref);
}

void log_policy_signing_failed(
    const char* id,
    const char* chain,
    const char* method)
{
    ESP_LOGW(kTag, "sign_transaction policy signing failed: id=%s chain=%s method=%s",
             id,
             chain,
             method);
}

void log_policy_signed(
    const char* id,
    const char* chain,
    const char* method,
    const char* rule_ref)
{
    ESP_LOGI(kTag, "sign_transaction policy signed: id=%s chain=%s method=%s rule=%s",
             id,
             chain,
             method,
             rule_ref);
}

void record_user_signing_waiting_for_review(
    const char* id,
    agent_q::AgentQSigningRoute signing_route)
{
    switch (signing_route) {
        case agent_q::AgentQSigningRoute::unsupported:
            ESP_LOGW(kTag, "unsupported signing route reached review wait log: id=%s", id);
            break;
        case agent_q::AgentQSigningRoute::sui_sign_transaction:
            ESP_LOGI(kTag, "sign_transaction waiting for device review: id=%s", id);
            break;
        case agent_q::AgentQSigningRoute::sui_sign_personal_message:
            ESP_LOGI(kTag, "sign_personal_message waiting for device review: id=%s", id);
            break;
    }
}

void clear_user_signing_flow_for_usb()
{
    agent_q::user_signing_flow_clear();
}

const agent_q::AgentQUsbSigningHandlerOps& usb_signing_handler_ops()
{
    static const agent_q::AgentQUsbSigningHandlerOps ops = {
        provisioned_material_ready,
        user_signing_ingress_busy,
        validate_session_for_user_signing,
        nullptr,
        read_signing_mode_for_preflight,
        nullptr,
        respond_to_signing_retry,
        nullptr,
        g_signing_preflight_retry_stored_result,
        sizeof(g_signing_preflight_retry_stored_result),
        agent_q::evaluate_sign_transaction_preflight,
        agent_q::evaluate_sign_personal_message_preflight,
        record_signing_account_unavailable_runtime_failure,
        agent_q::evaluate_sign_transaction_policy,
        execute_policy_sign_transaction_for_usb,
        write_policy_execution_response,
        agent_q::clear_policy_signing_execution_result,
        agent_q::clear_sign_transaction_policy_runtime_result,
        make_user_signing_window,
        agent_q::user_signing_flow_begin,
        agent_q::user_signing_flow_begin_personal_message,
        agent_q::clear_prepared_sui_sign_transaction,
        agent_q::clear_prepared_sui_sign_personal_message,
        show_user_signing_review,
        clear_user_signing_flow_for_usb,
        show_user_signing_display_error,
        record_user_signing_waiting_for_review,
        show_policy_signing_notice,
        log_policy_rejected,
        log_policy_signing_failed,
        log_policy_signed,
        agent_q::usb_response_log_write_failure,
    };
    return ops;
}

void handle_sign_transaction_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_sign_transaction_request(id, request, writer, usb_signing_handler_ops());
}

void handle_sign_personal_message_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    agent_q::handle_usb_sign_personal_message_request(id, request, writer, usb_signing_handler_ops());
}

const agent_q::AgentQUsbOperationHandlers& usb_operation_handlers()
{
    static const agent_q::AgentQUsbOperationHandlers handlers = {
        handle_get_status_request,
        handle_identify_device_request,
        handle_connect_request,
        handle_sign_transaction_request,
        handle_sign_personal_message_request,
        handle_get_result_request,
        handle_ack_result_request,
        handle_disconnect_request,
        handle_get_capabilities_request,
        handle_get_accounts_request,
        handle_policy_get_request,
        handle_get_approval_history_request,
        handle_policy_propose_request,
    };
    return handlers;
}

void handle_line(const char* line)
{
    agent_q::handle_usb_request_line(
        line,
        usb_operation_response_writer(),
        usb_operation_handlers());
}

void write_usb_line_error(const char* code, const char* message)
{
    agent_q::usb_response_write_error(nullptr, code, message);
}

void poll_usb_input()
{
    agent_q::usb_line_receiver_poll(handle_line, write_usb_line_error);
}

void usb_request_task(void*)
{
    // Ordering matters: any pending YES/NO choice is resolved and its response is
    // sent (send_connect_review_response_if_needed) before new input is read
    // (poll_usb_input). A new request therefore cannot be handled until the
    // in-flight approval response has been written in the same loop pass.
    while (true) {
        drain_local_auth_worker_results();
        clear_identification_if_needed();
        clear_agent_q_message_if_needed();
        clear_setup_choice_if_needed();
        clear_backup_phrase_if_needed();
        clear_import_word_entry_if_needed();
        clear_pin_setup_if_needed();
        clear_local_reset_if_needed();
        clear_local_pin_auth_if_needed();
        clear_policy_update_review_if_needed();
        clear_user_signing_review_if_needed();
        drain_ui_events();
        commit_local_reset_if_ready();
        commit_local_pin_setting_if_ready();
        poll_local_settings_touch_entry();
        show_persistent_error_recovery_if_needed();
        send_connect_review_response_if_needed();
        ensure_connect_review_ui();
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
    agent_q::provisioning_runtime_state_load(
        local_reset_persistence_ops(),
        persistent_material_ops());
    agent_q::session_init();
    if (!agent_q::local_auth_worker_init()) {
        ESP_LOGE(kTag, "Local auth worker init failed");
    }
    agent_q::connect_approval_clear();
    agent_q::identification_display_clear();
    wipe_setup_scratch("usb request server init");
    wipe_local_reset_scratch("usb request server init");
    if (!agent_q::ui_event_bridge_init()) {
        ESP_LOGE(kTag, "UI event bridge init failed");
    }
    agent_q::ui_event_bridge_register_callbacks();
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

    agent_q::usb_link_state_clear();
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
    agent_q::ui_event_bridge_enqueue_surface_ready();
}

}  // namespace agent_q
