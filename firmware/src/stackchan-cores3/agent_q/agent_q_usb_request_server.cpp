#include "agent_q_usb_request_server.h"

#include <stdio.h>
#include <string.h>

#include <ArduinoJson.h>
#include <memory>
#include "agent_q_sign_route.h"
#include "agent_q_avatar_overlay_drawing.h"
#include "agent_q_approval_history.h"
#include "agent_q_bip39.h"
#include "agent_q_bip39_wordlist.h"
#include "agent_q_connect_approval.h"
#include "agent_q_connect_review_response_flow.h"
#include "agent_q_human_approval_settings.h"
#include "agent_q_drawing_surface.h"
#include "agent_q_entropy.h"
#include "agent_q_identification_display.h"
#include "agent_q_json_input.h"
#include "agent_q_local_auth.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_local_pin_auth.h"
#include "agent_q_local_settings_reset_ui_flow.h"
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
#include "agent_q_provisioning_ui_flow.h"
#include "agent_q_provisioning_runtime_state.h"
#include "agent_q_request_backed_local_pin_context.h"
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
#include "agent_q_transient_ui_flow.h"
#include "agent_q_usb_link_state.h"
#include "agent_q_usb_approval_history_handler.h"
#include "agent_q_usb_connect_handler.h"
#include "agent_q_usb_device_handlers.h"
#include "agent_q_usb_disconnect_handler.h"
#include "agent_q_usb_operation_dispatch.h"
#include "agent_q_usb_operation_response_writer.h"
#include "agent_q_usb_policy_propose_handler.h"
#include "agent_q_usb_policy_propose_result_writer.h"
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
using ProvisioningFlowPanel = agent_q::AgentQProvisioningFlowPanel;
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
agent_q::AgentQLocalSettingsResetUiFlowOps local_settings_reset_ui_ops();
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
    return agent_q::local_settings_reset_ui_panel_matches_stage(kind);
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

bool write_policy_propose_result_with_current_policy(
    const char* id,
    const char* status,
    const char* reason_code)
{
    const agent_q::AgentQPolicyUpdateFlowSnapshot snapshot =
        agent_q::policy_update_flow_snapshot();
    return agent_q::usb_policy_propose_result_write(id, status, reason_code, &snapshot);
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

bool pending_request_id_for_local_pin_purpose(
    LocalPinAuthPurpose purpose,
    char* output,
    size_t output_size)
{
    return agent_q::request_backed_local_pin_request_id(
        purpose,
        output,
        output_size);
}

agent_q::AgentQTimeoutWindow timeout_window_from_now_ms(
    TickType_t started_at,
    uint32_t duration_ms)
{
    return agent_q::timeout_window_from_deadline(
        started_at,
        started_at + pdMS_TO_TICKS(duration_ms));
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
    if (!agent_q::request_backed_local_pin_purpose(purpose)) {
        return agent_q::kAgentQTimeoutWindowNone;
    }
    return agent_q::request_backed_local_pin_cap_input_window(
        purpose,
        next_input_window);
}

bool resume_request_backed_pin_input_window(
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    return agent_q::request_backed_local_pin_resume_input_window(purpose, now);
}

bool pause_request_backed_pin_input_window(LocalPinAuthPurpose purpose, TickType_t now)
{
    return agent_q::request_backed_local_pin_pause_input_window(purpose, now);
}

bool request_backed_local_pin_input_deadline_reached(LocalPinAuthPurpose purpose, TickType_t now)
{
    return agent_q::request_backed_local_pin_deadline_reached(purpose, now);
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

void clear_request_ui_for_identification();

TickType_t transient_ui_now()
{
    return xTaskGetTickCount();
}

AgentQUiMode transient_ui_overlay_mode()
{
    LvglLockGuard lock;
    return agent_q::avatar_overlay_mode();
}

bool transient_ui_show_message(
    const char* message,
    AgentQMessageKind kind,
    AgentQUiMode mode,
    uint32_t duration_ms,
    lv_event_cb_t click_callback)
{
    return agent_q::avatar_overlay_show_message(
        message,
        kind,
        mode,
        duration_ms,
        click_callback);
}

void transient_ui_log_warn(const char* message)
{
    ESP_LOGW(kTag, "%s", message != nullptr ? message : "Agent-Q transient UI warning");
}

const agent_q::AgentQTransientUiFlowOps& transient_ui_flow_ops()
{
    static const agent_q::AgentQTransientUiFlowOps ops = {
        transient_ui_now,
        provisioning_welcome_available,
        clear_request_ui_for_identification,
        agent_q::identification_display_begin,
        agent_q::identification_display_deadline_reached,
        agent_q::identification_display_clear,
        transient_ui_overlay_mode,
        agent_q::avatar_overlay_clear,
        agent_q::avatar_overlay_message_deadline_reached,
        transient_ui_show_message,
        agent_q::ui_event_bridge_setup_clicked_callback,
        transient_ui_log_warn,
    };
    return ops;
}

void show_provisioning_welcome_if_available()
{
    agent_q::transient_ui_show_provisioning_welcome_if_available(
        transient_ui_flow_ops());
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
    agent_q::transient_ui_show_identification_code(
        code,
        duration_ms,
        transient_ui_flow_ops());
}

void clear_identification_if_needed()
{
    agent_q::transient_ui_clear_identification_if_needed(transient_ui_flow_ops());
}

void clear_agent_q_message_if_needed()
{
    agent_q::transient_ui_clear_message_if_needed(transient_ui_flow_ops());
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

TickType_t provisioning_ui_now()
{
    return xTaskGetTickCount();
}

bool draw_import_word_entry_panel_for_provisioning(const char* notice)
{
    return agent_q::modal_draw_import_word_entry_panel(notice);
}

bool draw_pin_setup_panel_for_provisioning(const char* notice)
{
    return agent_q::modal_draw_pin_setup_panel(notice);
}

bool draw_pin_setup_processing_or_panel_for_provisioning()
{
    return agent_q::modal_draw_processing_overlay_on_current_panel(AgentQUiPanelKind::pin_entry) ||
           agent_q::modal_draw_pin_setup_panel();
}

void provisioning_ui_show_message(const char* message, AgentQMessageKind kind)
{
    agent_q::avatar_overlay_show_message(
        message,
        kind,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

agent_q::AgentQPersistentMaterialCommitResult commit_setup_with_prepared_auth_for_provisioning(
    const uint8_t* root_material,
    size_t root_material_size,
    const agent_q::AgentQLocalAuthPreparedRecord* prepared_auth)
{
    return agent_q::persistent_material_commit_setup_with_prepared_auth(
        root_material,
        root_material_size,
        prepared_auth,
        persistent_material_ops());
}

void provisioning_ui_log_info(const char* message)
{
    ESP_LOGI(kTag, "%s", message != nullptr ? message : "");
}

void provisioning_ui_log_warn(const char* message)
{
    ESP_LOGW(kTag, "%s", message != nullptr ? message : "");
}

TickType_t local_settings_reset_ui_now()
{
    return xTaskGetTickCount();
}

bool local_settings_reset_ui_display_ready()
{
    LvglLockGuard lock;
    return agent_q::drawing_surface_ready();
}

bool local_settings_reset_ui_panel_active()
{
    LvglLockGuard lock;
    return agent_q::drawing_surface_panel_locked() != nullptr &&
           local_reset_panel_matches_stage(agent_q::drawing_surface_panel_kind_locked());
}

bool local_settings_start_available()
{
    const TickType_t now = xTaskGetTickCount();
    return provisioned_material_ready() &&
           !agent_q::connect_approval_active() &&
           !agent_q::protocol_pin_approval_active() &&
           !agent_q::identification_display_active() &&
           !agent_q::provisioning_flow_active() &&
           !agent_q::user_signing_flow_active() &&
           !agent_q::local_reset_snapshot(now).flow_active &&
           agent_q_ui_idle_for_local_settings();
}

bool local_error_recovery_available()
{
    return !agent_q::connect_approval_active() &&
           !agent_q::protocol_pin_approval_active() &&
           !agent_q::identification_display_active() &&
           !agent_q::provisioning_flow_active() &&
           !agent_q::local_pin_auth_flow_active() &&
           !agent_q::user_signing_flow_active() &&
           !agent_q::local_reset_snapshot(xTaskGetTickCount()).flow_active;
}

bool draw_local_settings_reset_processing_overlay(AgentQUiPanelKind kind)
{
    return agent_q::modal_draw_processing_overlay_on_current_panel(kind);
}

void local_settings_reset_ui_show_message(const char* message, AgentQMessageKind kind)
{
    agent_q::avatar_overlay_show_message(
        message,
        kind,
        AgentQUiMode::result,
        kAgentQResultDisplayMs);
}

void local_settings_reset_ui_record_material_failure(
    agent_q::AgentQPersistentMaterialRuntimeFailure failure)
{
    agent_q::persistent_material_record_runtime_failure(
        failure,
        persistent_material_ops());
}

void local_settings_reset_ui_log_warn(const char* message)
{
    ESP_LOGW(kTag, "%s", message != nullptr ? message : "");
}

void local_settings_reset_ui_log_error(const char* message)
{
    ESP_LOGE(kTag, "%s", message != nullptr ? message : "");
}

const agent_q::AgentQProvisioningUiFlowOps& provisioning_ui_ops()
{
    static const agent_q::AgentQProvisioningUiFlowOps ops = {
        provisioning_ui_now,
        local_setup_start_allowed,
        setup_choice_action_allowed,
        agent_q_panel_active,
        clear_agent_q_panel_if_kind,
        agent_q::modal_draw_setup_choice_panel,
        agent_q::modal_draw_backup_phrase_display,
        draw_import_word_entry_panel_for_provisioning,
        draw_pin_setup_panel_for_provisioning,
        draw_pin_setup_processing_or_panel_for_provisioning,
        agent_q::avatar_overlay_clear,
        provisioning_ui_show_message,
        commit_setup_with_prepared_auth_for_provisioning,
        provisioning_ui_log_info,
        provisioning_ui_log_warn,
        kProvisioningApprovalMaxMs,
        kBackupPhraseDisplayMs,
        kLocalPinSetupMs,
        kLocalProcessingDisplayMs,
        agent_q::kAgentQLocalAuthWorkerMaxMs,
    };
    return ops;
}

agent_q::AgentQLocalSettingsResetUiFlowOps local_settings_reset_ui_ops()
{
    return agent_q::AgentQLocalSettingsResetUiFlowOps{
        local_settings_reset_ui_now,
        provisioned_material_ready,
        local_settings_start_available,
        local_error_recovery_available,
        agent_q::persistent_material_consistency_error_active,
        local_settings_reset_ui_display_ready,
        agent_q_panel_active,
        local_settings_reset_ui_panel_active,
        clear_agent_q_panel_if_kind,
        clear_agent_q_panel_if_local_reset_stage,
        agent_q::modal_draw_settings_menu_panel,
        agent_q::modal_draw_error_recovery_panel,
        agent_q::modal_draw_reset_pin_panel,
        draw_local_settings_reset_processing_overlay,
        agent_q::local_settings_touch_entry_clear,
        local_settings_reset_ui_show_message,
        local_settings_reset_ui_record_material_failure,
        local_settings_reset_ui_log_warn,
        local_settings_reset_ui_log_error,
        local_reset_persistence_ops(),
        agent_q::kAgentQLocalResetEntryMs,
        kLocalProcessingRenderDelayMs,
        kLocalProcessingDisplayMs,
        agent_q::kAgentQLocalAuthWorkerMaxMs,
    };
}

void clear_setup_choice_if_needed()
{
    agent_q::provisioning_ui_clear_setup_choice_if_needed(provisioning_ui_ops());
}

void clear_import_word_entry_if_needed()
{
    agent_q::provisioning_ui_clear_import_word_entry_if_needed(provisioning_ui_ops());
}

void clear_backup_phrase_if_needed()
{
    agent_q::provisioning_ui_clear_backup_phrase_if_needed(provisioning_ui_ops());
}

void clear_pin_setup_if_needed()
{
    agent_q::provisioning_ui_clear_pin_setup_if_needed(provisioning_ui_ops());
}

void handle_pin_digit_from_local_ui(char digit)
{
    agent_q::provisioning_ui_handle_pin_digit(digit, provisioning_ui_ops());
}

void handle_pin_clear_from_local_ui()
{
    agent_q::provisioning_ui_handle_pin_clear(provisioning_ui_ops());
}

void handle_pin_backspace_from_local_ui()
{
    agent_q::provisioning_ui_handle_pin_backspace(provisioning_ui_ops());
}

void handle_pin_submit_from_local_ui()
{
    agent_q::provisioning_ui_handle_pin_submit(provisioning_ui_ops());
}

void clear_local_reset_if_needed()
{
    agent_q::local_settings_reset_ui_clear_if_needed(local_settings_reset_ui_ops());
}

void commit_local_reset_if_ready()
{
    agent_q::local_settings_reset_ui_commit_if_ready(local_settings_reset_ui_ops());
}

void start_local_settings_from_touch()
{
    agent_q::local_settings_reset_ui_start_from_touch(local_settings_reset_ui_ops());
}

void cancel_local_reset_from_ui(const char* message)
{
    agent_q::local_settings_reset_ui_cancel_reset_from_ui(
        message,
        local_settings_reset_ui_ops());
}

void close_local_settings_from_ui()
{
    agent_q::local_settings_reset_ui_close_settings_from_ui(local_settings_reset_ui_ops());
}

void show_persistent_error_recovery_if_needed()
{
    agent_q::local_settings_reset_ui_show_persistent_error_recovery_if_needed(
        local_settings_reset_ui_ops());
}

void cancel_error_recovery_from_ui()
{
    agent_q::local_settings_reset_ui_cancel_error_recovery_from_ui(
        local_settings_reset_ui_ops());
}

void confirm_error_recovery_from_ui()
{
    agent_q::local_settings_reset_ui_confirm_error_recovery_from_ui(
        local_settings_reset_ui_ops());
}

void start_reset_pin_from_settings_menu()
{
    agent_q::local_settings_reset_ui_start_reset_pin_from_settings_menu(
        local_settings_reset_ui_ops());
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
    if (!write_policy_propose_result_with_current_policy(
            request_id,
            agent_q::policy_update_flow_terminal_status(result),
            agent_q::policy_update_flow_terminal_reason(result))) {
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
    switch (agent_q::request_backed_local_pin_owner_for_purpose(purpose)) {
        case agent_q::AgentQRequestBackedLocalPinOwner::protocol_pin_approval:
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
        case agent_q::AgentQRequestBackedLocalPinOwner::user_signing:
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
        case agent_q::AgentQRequestBackedLocalPinOwner::none:
        default:
            break;
    }
    return false;
}

void start_settings_human_approval_input_from_settings_menu()
{
    if (agent_q::local_pin_auth_flow_active()) {
        ESP_LOGW(kTag, "Stale human approval input setting action ignored");
        return;
    }
    if (!agent_q::local_settings_reset_ui_begin_settings_pin_auth_handoff(
            "Stale human approval input setting action ignored",
            local_settings_reset_ui_ops())) {
        return;
    }

    agent_q::AgentQHumanApprovalInputMode current_human_approval_mode =
        agent_q::AgentQHumanApprovalInputMode::pin;
    if (!agent_q::read_human_approval_input_mode(&current_human_approval_mode)) {
        clear_agent_q_panel_if_kind(AgentQUiPanelKind::settings_menu, SensitiveUiClearPolicy::preserve);
        agent_q::avatar_overlay_show_message(
            "Settings error",
            AgentQMessageKind::error,
            AgentQUiMode::result,
            kAgentQResultDisplayMs);
        return;
    }
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
    if (agent_q::local_pin_auth_flow_active()) {
        ESP_LOGW(kTag, "Stale settings signing mode action ignored");
        return;
    }
    if (!agent_q::local_settings_reset_ui_begin_settings_pin_auth_handoff(
            "Stale settings signing mode action ignored",
            local_settings_reset_ui_ops())) {
        return;
    }

    agent_q::AgentQSigningAuthorizationMode current_mode =
        agent_q::AgentQSigningAuthorizationMode::user;
    if (!agent_q::read_signing_authorization_mode(&current_mode)) {
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
    if (agent_q::local_pin_auth_flow_active()) {
        ESP_LOGW(kTag, "Stale settings Change PIN action ignored");
        return;
    }
    if (!agent_q::local_settings_reset_ui_begin_settings_pin_auth_handoff(
            "Stale settings Change PIN action ignored",
            local_settings_reset_ui_ops())) {
        return;
    }

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
        agent_q::local_settings_reset_ui_restore_settings_menu(
            "local settings display allocation failed after PIN cancel",
            "Display error",
            AgentQMessageKind::error,
            local_settings_reset_ui_ops());
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
    agent_q::local_settings_reset_ui_handle_reset_pin_digit(
        digit,
        local_settings_reset_ui_ops());
}

void handle_reset_pin_clear_from_local_ui()
{
    agent_q::local_settings_reset_ui_handle_reset_pin_clear(
        local_settings_reset_ui_ops());
}

void handle_reset_pin_backspace_from_local_ui()
{
    agent_q::local_settings_reset_ui_handle_reset_pin_backspace(
        local_settings_reset_ui_ops());
}

void handle_reset_pin_submit_from_local_ui()
{
    agent_q::local_settings_reset_ui_handle_reset_pin_submit(
        local_settings_reset_ui_ops());
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

    agent_q::local_settings_reset_ui_restore_settings_menu(
        "local settings display allocation failed after PIN commit",
        result == agent_q::AgentQLocalPinAuthCommitResult::pin_changed ? "PIN changed" : "Settings saved",
        AgentQMessageKind::success,
        local_settings_reset_ui_ops());
}

void handle_setup_auth_worker_result(agent_q::AgentQLocalAuthWorkerResult& worker_result)
{
    agent_q::provisioning_ui_handle_setup_auth_worker_result(
        worker_result,
        provisioning_ui_ops());
}

void handle_local_reset_auth_worker_result(const agent_q::AgentQLocalAuthWorkerResult& worker_result)
{
    agent_q::local_settings_reset_ui_handle_auth_worker_result(
        worker_result,
        local_settings_reset_ui_ops());
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
                if (!write_policy_propose_result_with_current_policy(request_id, "consistency_error", "consistency_error")) {
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

    agent_q::local_settings_reset_ui_restore_settings_menu(
        "local settings display allocation failed after PIN commit",
        "PIN changed",
        AgentQMessageKind::success,
        local_settings_reset_ui_ops());
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
                if (!write_policy_propose_result_with_current_policy(request_id, "consistency_error", "consistency_error")) {
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

bool receive_connect_review_choice(ConnectApprovalChoice* choice)
{
    return agent_q::ui_event_bridge_receive_connect_choice(choice);
}

bool connect_review_panel_visible()
{
    LvglLockGuard lock;
    return agent_q::drawing_surface_panel_locked() != nullptr &&
           is_connect_review_panel_kind(agent_q::drawing_surface_panel_kind_locked());
}

void log_connect_review_flow_info(const char* message, const char* id)
{
    ESP_LOGI(kTag, "%s: id=%s", message != nullptr ? message : "connect", id != nullptr ? id : "");
}

void log_connect_review_flow_error(const char* message, const char* id)
{
    ESP_LOGE(kTag, "%s: id=%s", message != nullptr ? message : "connect error", id != nullptr ? id : "");
}

void log_connect_review_recovered(const char* id)
{
    ESP_LOGW(kTag, "connect review UI recovered: id=%s", id != nullptr ? id : "");
}

const agent_q::AgentQConnectReviewResponseFlowOps& connect_review_response_flow_ops()
{
    static const agent_q::AgentQConnectReviewResponseFlowOps ops = {
        xTaskGetTickCount,
        connect_local_pin_flow_active,
        agent_q::ui_event_bridge_reset_connect_choices,
        receive_connect_review_choice,
        agent_q::connect_approval_awaiting_choice,
        agent_q::human_approval_requires_pin,
        begin_connect_pin_auth_from_review,
        agent_q::connect_approval_choose,
        agent_q::connect_approval_snapshot,
        agent_q::connect_approval_deadline_reached,
        agent_q::connect_approval_request_id,
        agent_q::connect_approval_clear,
        replace_active_session,
        agent_q::usb_response_write_error,
        write_connect_approved_response,
        agent_q::usb_response_write_connect_rejected,
        log_connect_review_flow_info,
        log_connect_review_flow_error,
        agent_q::usb_response_log_write_failure,
        log_connect_review_recovered,
        show_result_and_clear_connect_review,
        connect_review_panel_visible,
        show_connect_review,
    };
    return ops;
}

void run_connect_review_response_flow()
{
    agent_q::connect_review_response_flow_run(connect_review_response_flow_ops());
}

void start_local_provisioning_from_setup_touch()
{
    agent_q::provisioning_ui_start_generate_from_setup_choice(provisioning_ui_ops());
}

void show_setup_choice_from_setup_touch()
{
    agent_q::provisioning_ui_show_setup_choice_from_touch(provisioning_ui_ops());
}

void start_local_import_from_setup_choice()
{
    agent_q::provisioning_ui_start_import_from_setup_choice(provisioning_ui_ops());
}

void cancel_setup_from_local_ui()
{
    agent_q::provisioning_ui_cancel_from_local_ui(provisioning_ui_ops());
}

void return_to_setup_choice_from_local_ui()
{
    agent_q::provisioning_ui_return_to_setup_choice(provisioning_ui_ops());
}

void confirm_backup_phrase_from_local_ui()
{
    agent_q::provisioning_ui_confirm_backup_phrase(provisioning_ui_ops());
}

void handle_import_slot_from_local_ui(uint8_t slot)
{
    agent_q::provisioning_ui_handle_import_slot(slot, provisioning_ui_ops());
}

void handle_import_letter_from_local_ui(char letter)
{
    agent_q::provisioning_ui_handle_import_letter(letter, provisioning_ui_ops());
}

void handle_import_clear_from_local_ui()
{
    agent_q::provisioning_ui_handle_import_clear(provisioning_ui_ops());
}

void handle_import_candidate_from_local_ui(uint16_t word_index)
{
    agent_q::provisioning_ui_handle_import_candidate(word_index, provisioning_ui_ops());
}

void handle_import_previous_from_local_ui()
{
    agent_q::provisioning_ui_handle_import_previous(provisioning_ui_ops());
}

void handle_import_next_from_local_ui()
{
    agent_q::provisioning_ui_handle_import_next(provisioning_ui_ops());
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
            if (agent_q::provisioning_flow_snapshot().accepts_setup_pin_input) {
                handle_pin_digit_from_local_ui(event.digit);
            } else if (agent_q::local_settings_reset_ui_accepts_reset_pin_input()) {
                handle_reset_pin_digit_from_local_ui(event.digit);
            } else if (local_pin_auth_accepts_keypad_input()) {
                handle_local_pin_auth_digit_from_ui(event.digit);
            }
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_clear_requested) {
            if (agent_q::provisioning_flow_snapshot().accepts_setup_pin_input) {
                handle_pin_clear_from_local_ui();
            } else if (agent_q::local_settings_reset_ui_accepts_reset_pin_input()) {
                handle_reset_pin_clear_from_local_ui();
            } else if (local_pin_auth_accepts_keypad_input()) {
                handle_local_pin_auth_clear_from_ui();
            }
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_backspace_requested) {
            if (agent_q::provisioning_flow_snapshot().accepts_setup_pin_input) {
                handle_pin_backspace_from_local_ui();
            } else if (agent_q::local_settings_reset_ui_accepts_reset_pin_input()) {
                handle_reset_pin_backspace_from_local_ui();
            } else if (local_pin_auth_accepts_keypad_input()) {
                handle_local_pin_auth_backspace_from_ui();
            }
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_submit_requested) {
            if (agent_q::provisioning_flow_snapshot().accepts_setup_pin_input) {
                handle_pin_submit_from_local_ui();
            } else if (agent_q::local_settings_reset_ui_accepts_reset_pin_input()) {
                handle_reset_pin_submit_from_local_ui();
            } else if (local_pin_auth_accepts_keypad_input()) {
                handle_local_pin_auth_submit_from_ui();
            }
            continue;
        }

        if (event.kind == AgentQUiEventKind::pin_cancel_requested) {
            if (agent_q::provisioning_flow_snapshot().accepts_setup_pin_input) {
                cancel_setup_from_local_ui();
            } else if (agent_q::local_settings_reset_ui_accepts_reset_pin_input()) {
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
        agent_q::transient_ui_identification_code_safe,
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

agent_q::SuiAccountDerivationResult derive_sui_account_for_session_read(
    uint8_t public_key_out[agent_q::kSuiEd25519PublicKeyBytes],
    char* address_out,
    size_t address_out_size)
{
    return agent_q::derive_sui_ed25519_account_from_stored_root(
        public_key_out,
        address_out,
        address_out_size);
}

void record_root_material_unreadable_for_session_read()
{
    // A provisioned device whose stored root material is no longer readable is
    // inconsistent. Fail closed so status/connect/account reads stop treating
    // it as provisioned until local recovery/reset handles the condition.
    agent_q::persistent_material_record_runtime_failure(
        agent_q::AgentQPersistentMaterialRuntimeFailure::root_material_unreadable,
        persistent_material_ops());
}

bool read_active_policy_for_session_read(
    const char** schema,
    char* policy_id_out,
    size_t policy_id_out_size,
    const char** default_action,
    size_t* rule_count,
    const agent_q::AgentQPolicyDocument** document)
{
    if (schema == nullptr ||
        policy_id_out == nullptr ||
        policy_id_out_size == 0 ||
        default_action == nullptr ||
        rule_count == nullptr ||
        document == nullptr) {
        return false;
    }

    agent_q::AgentQStoredPolicyDocument stored_policy = {};
    if (!agent_q::read_active_policy_document(&stored_policy) ||
        stored_policy.document == nullptr) {
        return false;
    }
    *schema = stored_policy.schema;
    snprintf(policy_id_out, policy_id_out_size, "%s", stored_policy.policy_id);
    *default_action = stored_policy.default_action;
    *rule_count = stored_policy.rule_count;
    *document = stored_policy.document;
    return true;
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
        derive_sui_account_for_session_read,
        record_root_material_unreadable_for_session_read,
        read_active_policy_for_session_read,
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
        agent_q::approval_history_read_page,
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

void run_usb_request_server_maintenance_phase()
{
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
}

void run_usb_request_server_local_ui_phase()
{
    drain_ui_events();
    commit_local_reset_if_ready();
    commit_local_pin_setting_if_ready();
    poll_local_settings_touch_entry();
    show_persistent_error_recovery_if_needed();
}

void run_usb_request_server_connect_response_phase()
{
    run_connect_review_response_flow();
}

void run_usb_request_server_transport_phase()
{
    if (g_usb_ready) {
        poll_usb_host_connection();
        poll_usb_input();
    }
}

void run_usb_request_server_tick()
{
    run_usb_request_server_maintenance_phase();
    run_usb_request_server_local_ui_phase();
    run_usb_request_server_connect_response_phase();
    run_usb_request_server_transport_phase();
}

void usb_request_task(void*)
{
    // Ordering matters: any pending YES/NO choice is resolved and its response is
    // sent (run_usb_request_server_connect_response_phase) before new input is read
    // (poll_usb_input). A new request therefore cannot be handled until the
    // in-flight approval response has been written in the same loop pass.
    while (true) {
        run_usb_request_server_tick();
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
