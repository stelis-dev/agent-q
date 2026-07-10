#include "usb_request_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ArduinoJson.h>
#include <memory>
#include "protocol/sign_route.h"
#include "avatar_overlay_drawing.h"
#include "protocol/approval_history.h"
#include "bip39.h"
#include "bip39_wordlist.h"
#include "transport/connect_approval.h"
#include "transport/connect_review_response_flow.h"
#include "human_approval_settings.h"
#include "drawing_surface.h"
#include "entropy.h"
#include "identification_display.h"
#include "device_activity_projection.h"
#include "protocol/json_input.h"
#include "protocol/device_response.h"
#include "local_auth.h"
#include "local_auth_worker.h"
#include "local_pin_auth.h"
#include "local_pin_auth_ui_flow.h"
#include "local_transport_ble.h"
#include "local_transport_pairing.h"
#include "storage_maintenance_ui_flow.h"
#include "local_settings_touch_entry.h"
#include "storage_maintenance.h"
#include "modal_drawing.h"
#include "persistent_material.h"
#include "stackchan_storage_names.h"
#include "transport/payload_delivery_admission.h"
#include "transport/payload_delivery_resolution.h"
#include "transport/payload_delivery_store.h"
#include "policy/policy_proposal_parser.h"
#include "policy/policy_store.h"
#include "policy/policy_update_flow.h"
#include "policy_update_review_ui_flow.h"
#include "protocol/protocol_constants.h"
#include "protocol_pin_approval.h"
#include "provisioning_flow.h"
#include "provisioning_ui_flow.h"
#include "provisioning_runtime_state.h"
#include "request_backed_local_pin_context.h"
#include "protocol/request_id.h"
#include "protocol/session_state.h"
#include "signing/sign_personal_message_user_ingress.h"
#include "signing/sign_transaction_policy_runtime.h"
#include "policy_signing_execution.h"
#include "user_signing_confirmation.h"
#include "signing/user_signing_flow.h"
#include "signing/sign_transaction_user_ingress.h"
#include "user_signing_review_view_model.h"
#include "user_signing_review_ui_flow.h"
#include "signing/user_signing_critical_section.h"
#include "protocol/signing_mode.h"
#include "sui_account.h"
#include "sui_account_settings.h"
#include "sui_account_store.h"
#include "sui_signing_preparation.h"
#include "sui_zklogin_proof_store.h"
#include "sui_zklogin_proposal_flow.h"
#include "sui_zklogin_review_ui_flow.h"
#include "transport/timeout_window.h"
#include "transient_ui_flow.h"
#include "transport/usb_link_state.h"
#include "protocol/usb_approval_history_handler.h"
#include "transport/usb_connect_handler.h"
#include "protocol/usb_device_handlers.h"
#include "transport/usb_disconnect_handler.h"
#include "protocol/usb_operation_dispatch.h"
#include "protocol/usb_operation_manifest.h"
#include "protocol/usb_operation_response_writer.h"
#include "policy/usb_policy_handlers.h"
#include "transport/usb_payload_transfer_handlers.h"
#include "ui_panel_cleanup.h"
#include "protocol/usb_operation_type.h"
#include "usb_line_receiver.h"
#include "protocol/usb_request_envelope.h"
#include "protocol/usb_request_line_handler.h"
#include "transport/usb_retained_response_handlers.h"
#include "protocol/usb_session_read_handlers.h"
#include "protocol/usb_sui_zklogin_credential_handlers.h"
#include "signing/usb_signing_handlers.h"
#include "signing/usb_signing_outcome_writer.h"
#include "usb_response_writer.h"
#include "ui_event_bridge.h"
#include "signing/signing_retry_delivery.h"
#include "signing/signing_retry_response.h"
#include "signing/signing_preflight.h"
#include "protocol/signing_response_store.h"
#include "transport/usb_session_grace.h"
#include "usb_session_loss.h"
#include "user_signing_service_adapter.h"
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

using UiPanelKind = signing::UiPanelKind;
using UiEvent = signing::UiEvent;
using UiEventKind = signing::UiEventKind;
using MessageKind = signing::MessageKind;
using UiMode = signing::UiMode;
using ConnectApprovalChoice = signing::ConnectApprovalChoice;
using LocalPinAuthPurpose = signing::LocalPinAuthPurpose;
using LocalPinAuthStage = signing::LocalPinAuthStage;
using UsbOperationResponseWriter = signing::UsbOperationResponseWriter;
using ProvisioningFlowPanel = signing::ProvisioningFlowPanel;
using ProvisioningRuntimeState = signing::ProvisioningRuntimeState;
using SensitiveUiClearPolicy = signing::SensitiveUiClearPolicy;

constexpr const char* kTag = "UsbRequestServer";
constexpr int kProtocolVersion = signing::kProtocolVersion;
constexpr const char* kFirmwareName = "Agent-Q Firmware";
constexpr const char* kHardwareId = "stackchan-cores3";
constexpr const char* kFirmwareVersion = "0.0.0";
constexpr const char* kNvsNamespace = signing::kStackChanDeviceIdentityNvsNamespace;
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
// This task still combines transport polling, JSON request dispatch, persistent
// material checks, and immediate target UI effects. Keep explicit headroom for
// current connect/status paths while staying within the StackChan internal RAM
// budget after QR and BLE are enabled.
constexpr uint32_t kUsbRequestTaskStackBytes = 24 * 1024;
constexpr size_t kPolicyReadbackEnvelopeReserveBytes = 1024;
constexpr size_t kMaxRequestIdSize = signing::kRequestIdSize;
constexpr size_t kDeviceIdSize = 37;
constexpr size_t kIdentifyCodeSize = 5;
constexpr size_t kClientNameSize = 65;
constexpr int kScreenWidth = 320;
constexpr int kSettingsTouchEntryWidth = 64;
constexpr int kSettingsTouchEntryHeight = 56;
constexpr uint32_t kResultDisplayMs = 1800;

static_assert(
    signing::kPolicyProposalMaxSerializedObjectBytes + kPolicyReadbackEnvelopeReserveBytes <=
        signing::kUsbResponseLineMaxBytes,
    "policy_get readback for accepted policy proposals must fit within the USB response line cap");

char g_device_id[kDeviceIdSize];
static_assert(
    kMaxRequestIdSize == signing::kProtocolPinRequestIdSize,
    "Protocol PIN approval request-id storage must match USB request-id storage.");
static_assert(
    kMaxRequestIdSize == signing::kConnectApprovalRequestIdSize,
    "Connect approval request-id storage must match USB request-id storage.");
static_assert(
    kClientNameSize == signing::kConnectApprovalClientNameSize,
    "Connect approval client-name storage must match USB client-name storage.");

bool g_usb_ready = false;
TaskHandle_t g_usb_task = nullptr;

enum class ProtocolTransport {
    none,
    usb,
    local_transport,
};

ProtocolTransport g_current_request_transport = ProtocolTransport::none;
ProtocolTransport g_pending_connect_transport = ProtocolTransport::none;
ProtocolTransport g_active_session_transport = ProtocolTransport::none;
ProtocolTransport g_active_user_signing_transport = ProtocolTransport::none;
ProtocolTransport g_pending_policy_update_transport = ProtocolTransport::none;
ProtocolTransport g_pending_credential_proposal_transport = ProtocolTransport::none;
ProtocolTransport g_signing_outcome_transport_context = ProtocolTransport::none;

bool refresh_persistent_material_consistency();
bool provisioned_material_ready();
bool ui_idle_for_local_settings();
bool write_busy_if_pending_or_local_flow_active_for_operation(
    const char* id,
    const UsbOperationResponseWriter& writer,
    signing::UsbOperationType operation);
signing::PersistentMaterialOps persistent_material_ops();
signing::StorageMaintenancePersistenceOps storage_maintenance_persistence_ops();
signing::StorageMaintenanceUiFlowOps storage_maintenance_ui_ops();
signing::LocalPinAuthUiFlowOps local_pin_auth_ui_flow_ops();
const signing::PolicyUpdateReviewUiFlowOps& policy_update_review_ui_flow_ops();
const signing::SuiZkLoginReviewUiFlowOps& sui_zklogin_review_ui_flow_ops();
const signing::UserSigningReviewUiFlowOps& user_signing_review_ui_flow_ops();
bool clear_signing_panel_if_kind(
    UiPanelKind expected_kind,
    SensitiveUiClearPolicy policy = SensitiveUiClearPolicy::wipe);
void clear_connect_review_state();
void cancel_policy_update_after_session_loss(const char* log_reason);
void cancel_sui_zklogin_proposal_after_session_loss(const char* log_reason);
void cancel_user_signing_after_session_loss(const char* log_reason);
signing::UsbSessionLossPlan current_usb_session_loss_plan(TickType_t now);
void clear_session_bound_state_for_plan(
    const signing::UsbSessionLossPlan& plan,
    const char* local_pin_reason,
    const char* user_signing_reason,
    bool force_user_signing_clear,
    const char* log_message);
void show_persistent_error_recovery_if_needed();
void finish_user_signing_terminal(
    const char* request_id,
    const signing::UserSigningOutput* signing_output = nullptr);
void finish_user_signing_error_terminal(
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message);
void finish_policy_update_terminal(
    const char* request_id,
    signing::PolicyUpdateFlowTerminalResult result);
void finish_policy_update_error_terminal(
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message);
void finish_sui_zklogin_proposal_terminal(
    const char* request_id,
    signing::SuiZkLoginProposalTerminalResult result);
void finish_sui_zklogin_proposal_error_terminal(
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message);
void start_local_chain_settings_from_touch();
void show_chain_settings_menu_from_active_settings();
bool draw_sui_settings_panel_from_current_state();
void show_sui_settings_from_chain_settings();
void show_chain_settings_menu_from_sui_settings();
void start_sui_gas_sponsor_from_sui_settings();
void start_sui_zklogin_clear_from_sui_settings();
void handle_connect_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer);
void handle_sign_transaction_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer);

void wipe_setup_scratch(const char* reason)
{
    const bool had_setup_scratch = signing::provisioning_flow_active();
    signing::provisioning_flow_wipe();
    if (had_setup_scratch) {
        ESP_LOGW(kTag, "Setup scratch wiped: %s", reason != nullptr ? reason : "unspecified");
    }
}

void clear_storage_maintenance_flow(const char* reason)
{
    const bool had_storage_action_scratch =
        signing::storage_maintenance_snapshot(xTaskGetTickCount()).flow_active;
    signing::storage_maintenance_clear_flow();
    signing::local_settings_touch_entry_clear();
    if (had_storage_action_scratch) {
        ESP_LOGW(kTag, "Storage maintenance scratch wiped: %s", reason != nullptr ? reason : "unspecified");
    }
}

void clear_local_pin_auth_scratch(const char* reason)
{
    const bool had_pin_auth = signing::local_pin_auth_flow_active();
    signing::local_pin_auth_clear_flow();
    if (had_pin_auth) {
        ESP_LOGW(kTag, "Local PIN authorization scratch wiped: %s", reason != nullptr ? reason : "unspecified");
    }
}

bool is_connect_review_panel_kind(UiPanelKind kind)
{
    return kind == UiPanelKind::connect_review;
}

bool local_pin_auth_panel_matches_stage(UiPanelKind kind)
{
    return signing::local_pin_auth_ui_panel_matches_stage(kind);
}

bool user_signing_review_panel_matches_stage(UiPanelKind kind)
{
    const signing::UserSigningFlowCoreSnapshot snapshot =
        signing::user_signing_flow_core_snapshot();
    return kind == UiPanelKind::user_signing_review &&
           snapshot.active &&
           snapshot.stage == signing::UserSigningStage::reviewing;
}

bool policy_update_review_panel_matches_stage(UiPanelKind kind)
{
    const signing::PolicyUpdateFlowSnapshot snapshot =
        signing::policy_update_flow_snapshot();
    return kind == UiPanelKind::policy_update_review &&
           snapshot.active &&
           snapshot.stage == signing::PolicyUpdateFlowStage::reviewing;
}

bool sui_zklogin_review_panel_matches_stage(UiPanelKind kind)
{
    const signing::SuiZkLoginProposalSnapshot snapshot =
        signing::sui_zklogin_proposal_flow_snapshot();
    return kind == UiPanelKind::sui_zklogin_review &&
           snapshot.active &&
           snapshot.stage == signing::SuiZkLoginProposalStage::reviewing;
}

bool local_pin_auth_accepts_keypad_input()
{
    return signing::local_pin_auth_ui_accepts_keypad_input();
}

bool storage_maintenance_panel_matches_stage(UiPanelKind kind)
{
    return signing::storage_maintenance_ui_panel_matches_stage(kind);
}

bool handle_provisioning_panel_deleted(ProvisioningFlowPanel panel, const char* reason)
{
    const bool wiped = signing::provisioning_flow_handle_panel_deleted(panel);
    if (wiped) {
        ESP_LOGW(kTag, "Setup scratch wiped: %s", reason != nullptr ? reason : "panel deleted");
    }
    return wiped;
}

signing::UiPanelCleanupPlan panel_cleanup_plan(
    UiPanelKind panel_kind,
    signing::UiPanelCleanupEvent event)
{
    return signing::ui_panel_cleanup_plan(signing::UiPanelCleanupInput{
        panel_kind,
        event,
        storage_maintenance_panel_matches_stage(panel_kind),
        local_pin_auth_panel_matches_stage(panel_kind),
        policy_update_review_panel_matches_stage(panel_kind),
        sui_zklogin_review_panel_matches_stage(panel_kind),
        user_signing_review_panel_matches_stage(panel_kind),
    });
}

void apply_panel_cleanup_plan(
    const signing::UiPanelCleanupPlan& plan,
    const char* setup_reason,
    const char* reset_reason,
    const char* local_pin_reason)
{
    if (plan.route_provisioning_panel_deleted &&
        !handle_provisioning_panel_deleted(plan.provisioning_panel, setup_reason) &&
        plan.wipe_setup_if_unhandled) {
        wipe_setup_scratch(setup_reason);
    }
    if (plan.clear_storage_maintenance) {
        clear_storage_maintenance_flow(reset_reason);
    }
    if (plan.clear_local_pin_auth) {
        clear_local_pin_auth_scratch(local_pin_reason);
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
    if (plan.recover_sui_zklogin_review_panel) {
        ESP_LOGW(kTag, "Sui zkLogin review panel deleted; state loop will recover if active");
    }
    if (plan.wipe_user_signing) {
        signing::user_signing_confirmation_cancel_for_pin_loss();
    }
    if (plan.recover_user_signing_review_panel) {
        ESP_LOGW(kTag, "Signature review panel deleted; state loop will recover if active");
    }
}

signing::TimeoutTick current_timeout_tick()
{
    return static_cast<signing::TimeoutTick>(xTaskGetTickCount());
}

bool resolve_request_payload_ref(
    JsonDocument& request,
    JsonDocument& resolved_payload,
    signing::TimeoutTick now_tick,
    const signing::UsbRequestEnvelope& envelope,
    const signing::UsbOperationResponseWriter& writer)
{
    return signing::payload_delivery_resolve_request_payload_ref(
        request,
        resolved_payload,
        now_tick,
        envelope,
        writer);
}

signing::DeviceActivityProjection current_device_activity()
{
    const signing::TimeoutTick now = current_timeout_tick();
    const signing::PayloadDeliverySnapshot payload_delivery =
        signing::payload_delivery_advance_and_snapshot(now);
    const signing::DeviceActivityFacts facts = {
        signing::persistent_material_consistency_error_active(),
        signing::provisioning_runtime_state_is_provisioned(),
        ui_idle_for_local_settings(),
        signing::identification_display_active(),
        signing::connect_approval_active(),
        signing::protocol_pin_approval_active(),
        signing::provisioning_flow_active(),
        signing::local_pin_auth_flow_active(),
        payload_delivery.state == signing::PayloadDeliveryState::receiving,
        payload_delivery.state == signing::PayloadDeliveryState::finalized,
        signing::policy_update_flow_snapshot(),
        signing::sui_zklogin_proposal_flow_snapshot(),
        signing::storage_maintenance_snapshot(now),
        signing::user_signing_flow_core_snapshot(),
    };
    return signing::project_device_activity(facts);
}

const char* current_device_state()
{
    return signing::device_activity_state_name(
        current_device_activity().device_state);
}

const UsbOperationResponseWriter& usb_operation_response_writer()
{
    static const UsbOperationResponseWriter writer = {
        signing::usb_response_write_method_error,
        signing::usb_response_write_success_result,
        signing::usb_response_write_transport_success_result,
        signing::usb_response_log_write_failure,
    };
    return writer;
}

bool reject_missing_response_route_method_error(
    const char*,
    const char*,
    const char*)
{
    return false;
}

bool reject_missing_response_route_success(
    const char*,
    const char*,
    JsonObjectConst)
{
    return false;
}

bool reject_missing_response_route_transport_success(
    const char*,
    JsonObjectConst)
{
    return false;
}

void log_missing_response_route(const char* method, const char* id)
{
    ESP_LOGE(
        kTag,
        "Response route missing: method=%s id=%s",
        method != nullptr ? method : "unknown",
        id != nullptr ? id : "unknown");
}

const UsbOperationResponseWriter& missing_operation_response_writer()
{
    static const UsbOperationResponseWriter writer = {
        reject_missing_response_route_method_error,
        reject_missing_response_route_success,
        reject_missing_response_route_transport_success,
        log_missing_response_route,
    };
    return writer;
}

const UsbOperationResponseWriter& operation_response_writer_for_transport(
    ProtocolTransport transport);

struct ScopedRequestTransport {
    explicit ScopedRequestTransport(ProtocolTransport next)
        : previous(g_current_request_transport)
    {
        g_current_request_transport = next;
    }

    ~ScopedRequestTransport()
    {
        g_current_request_transport = previous;
    }

    ProtocolTransport previous;
};

signing::UsbDeviceStatusInfo usb_device_status_info()
{
    return signing::UsbDeviceStatusInfo{
        {
            g_device_id,
            current_device_state(),
            kFirmwareName,
            kHardwareId,
            kFirmwareVersion,
        },
        signing::provisioning_runtime_state_reported(),
    };
}

bool write_connect_approved_response(const char* id)
{
    const signing::DeviceResponseDeviceFields info{
        g_device_id,
        "idle",
        kFirmwareName,
        kHardwareId,
        kFirmwareVersion,
    };
    return signing::usb_response_write_connect_approved(
        id,
        signing::session_id(),
        signing::kSessionAdvertisedTtlMs,
        info);
}

bool write_connect_approved_with_writer(
    const signing::UsbOperationResponseWriter& writer,
    const char* id)
{
    const signing::DeviceResponseDeviceFields info{
        g_device_id,
        "idle",
        kFirmwareName,
        kHardwareId,
        kFirmwareVersion,
    };
    JsonDocument result;
    result["sessionId"] = signing::session_id();
    result["sessionTtlMs"] = signing::kSessionAdvertisedTtlMs;
    signing::device_response_write_device_fields(result["device"].to<JsonObject>(), info);
    return writer.for_method("connect").write_success_result(
        id,
        "connect",
        result.as<JsonObjectConst>());
}

struct ConnectErrorResponseContext {
    const char* id;
    const char* code;
};

bool write_connect_error_response_callback(
    const signing::UsbOperationResponseWriter& writer,
    void* context)
{
    const ConnectErrorResponseContext* response =
        static_cast<const ConnectErrorResponseContext*>(context);
    return response != nullptr &&
           writer.for_method("connect").write_error(response->id, response->code);
}

bool write_connect_approved_response_callback(
    const signing::UsbOperationResponseWriter& writer,
    void* context)
{
    return write_connect_approved_with_writer(
        writer,
        static_cast<const char*>(context));
}

bool write_local_transport_connect_error_response(const char* id, const char* code)
{
    ConnectErrorResponseContext context{id, code};
    return signing::local_transport_pairing_write_response(
        write_connect_error_response_callback,
        &context);
}

bool write_local_transport_connect_approved_response(const char* id)
{
    return signing::local_transport_pairing_write_response(
        write_connect_approved_response_callback,
        const_cast<char*>(id));
}

bool write_connect_error_response(const char* id, const char* code)
{
    bool written = false;
    switch (g_pending_connect_transport) {
        case ProtocolTransport::usb:
            written = signing::usb_response_write_error(id, code);
            break;
        case ProtocolTransport::local_transport:
            written = write_local_transport_connect_error_response(id, code);
            break;
        case ProtocolTransport::none:
            break;
    }
    g_pending_connect_transport = ProtocolTransport::none;
    return written;
}

bool write_connect_rejected_response(const char* id, const char* code)
{
    return write_connect_error_response(id, code);
}

bool write_connect_approved_response_for_pending_transport(const char* id)
{
    bool written = false;
    switch (g_pending_connect_transport) {
        case ProtocolTransport::usb:
            written = write_connect_approved_response(id);
            break;
        case ProtocolTransport::local_transport:
            written = write_local_transport_connect_approved_response(id);
            break;
        case ProtocolTransport::none:
            break;
    }
    g_pending_connect_transport = ProtocolTransport::none;
    return written;
}

bool write_local_transport_response_bytes(const char* data, size_t length, void*)
{
    if (data != nullptr && length == 1 && data[0] == '\n') {
        return true;
    }
    return signing::local_transport_pairing_write_line(data, length);
}

void delay_response_ms(uint32_t duration_ms, void*)
{
    vTaskDelay(pdMS_TO_TICKS(duration_ms));
}

const signing::UsbJsonResponseWriteOps& local_transport_json_response_write_ops()
{
    static const signing::UsbJsonResponseWriteOps ops{
        write_local_transport_response_bytes,
        delay_response_ms,
        nullptr,
    };
    return ops;
}

struct LocalTransportMethodErrorContext {
    const char* id;
    const char* method;
    const char* code;
};

bool write_local_transport_method_error_callback(
    const UsbOperationResponseWriter& writer,
    void* context)
{
    const LocalTransportMethodErrorContext* response =
        static_cast<const LocalTransportMethodErrorContext*>(context);
    return response != nullptr &&
           writer.for_method(response->method).write_error(response->id, response->code);
}

bool write_local_transport_method_error(
    const char* id,
    const char* method,
    const char* code)
{
    LocalTransportMethodErrorContext context{id, method, code};
    return signing::local_transport_pairing_write_response(
        write_local_transport_method_error_callback,
        &context);
}

struct LocalTransportSuccessContext {
    const char* id;
    const char* method;
    JsonObjectConst result;
    bool transport_success;
};

bool write_local_transport_success_callback(
    const UsbOperationResponseWriter& writer,
    void* context)
{
    const LocalTransportSuccessContext* response =
        static_cast<const LocalTransportSuccessContext*>(context);
    if (response == nullptr) {
        return false;
    }
    return response->transport_success
               ? writer.write_transport_success_result(response->id, response->result)
               : writer.write_success_result(response->id, response->method, response->result);
}

bool write_local_transport_success_result(
    const char* id,
    const char* method,
    JsonObjectConst result)
{
    LocalTransportSuccessContext context{id, method, result, false};
    return signing::local_transport_pairing_write_response(
        write_local_transport_success_callback,
        &context);
}

bool write_local_transport_transport_success_result(
    const char* id,
    JsonObjectConst result)
{
    LocalTransportSuccessContext context{id, nullptr, result, true};
    return signing::local_transport_pairing_write_response(
        write_local_transport_success_callback,
        &context);
}

const UsbOperationResponseWriter& local_transport_operation_response_writer()
{
    static const UsbOperationResponseWriter writer = {
        write_local_transport_method_error,
        write_local_transport_success_result,
        write_local_transport_transport_success_result,
        signing::usb_response_log_write_failure,
    };
    return writer;
}

const UsbOperationResponseWriter& operation_response_writer_for_transport(
    ProtocolTransport transport)
{
    switch (transport) {
        case ProtocolTransport::usb:
            return usb_operation_response_writer();
        case ProtocolTransport::local_transport:
            return local_transport_operation_response_writer();
        case ProtocolTransport::none:
        default:
            return missing_operation_response_writer();
    }
}

bool reject_missing_response_route_bytes(const char*, size_t, void*)
{
    return false;
}

const signing::UsbJsonResponseWriteOps& missing_json_response_write_ops()
{
    static const signing::UsbJsonResponseWriteOps ops{
        reject_missing_response_route_bytes,
        delay_response_ms,
        nullptr,
    };
    return ops;
}

bool write_json_response_for_transport(
    JsonDocument& response,
    ProtocolTransport transport)
{
    switch (transport) {
        case ProtocolTransport::usb:
            return signing::usb_response_write_json(response);
        case ProtocolTransport::local_transport:
            return signing::usb_json_response_write(
                response,
                local_transport_json_response_write_ops());
        case ProtocolTransport::none:
        default:
            return false;
    }
}

bool write_method_error_response_for_transport(
    const char* id,
    const char* method,
    const char* code,
    ProtocolTransport transport)
{
    if (transport == ProtocolTransport::none) {
        return false;
    }
    if (transport == ProtocolTransport::usb) {
        return signing::usb_response_write_method_error(id, method, code);
    }
    JsonDocument response;
    if (!signing::device_response_prepare_method_error(response, id, method, code)) {
        return false;
    }
    return write_json_response_for_transport(response, transport);
}

bool write_method_error_response_for_active_user_signing(
    const char* id,
    const char* method,
    const char* code)
{
    return write_method_error_response_for_transport(
        id,
        method,
        code,
        g_active_user_signing_transport);
}

bool write_retry_response_json(JsonDocument& response, void*)
{
    return write_json_response_for_transport(response, g_current_request_transport);
}

static char g_signing_preflight_retry_stored_response[signing::kResponseMaxSize];

signing::PreflightRetryDisposition respond_to_signing_retry(
    const char* request_id,
    const char* method,
    const signing::RetryDeliveryResult& retry,
    const char* stored_response,
    void*)
{
    const signing::RetryResponseResult response_result =
        signing::deliver_signing_retry_response(
            request_id,
            method,
            retry,
            stored_response,
            write_retry_response_json,
            nullptr);
    switch (response_result) {
        case signing::RetryResponseResult::not_found:
        case signing::RetryResponseResult::invalid_stored_response:
        case signing::RetryResponseResult::replay_write_failed:
            return signing::PreflightRetryDisposition::continue_preflight;
        case signing::RetryResponseResult::replayed_result:
        case signing::RetryResponseResult::error_response:
        case signing::RetryResponseResult::error_write_failed:
            return signing::PreflightRetryDisposition::consumed;
    }
    return signing::PreflightRetryDisposition::consumed;
}

bool read_signing_mode_for_preflight(
    signing::AuthorizationMode* mode,
    void*)
{
    return signing::read_signing_authorization_mode(mode);
}

bool write_method_error_for_signing_outcome(
    const char* id,
    const char* method,
    const char* code,
    void* context)
{
    const ProtocolTransport transport =
        context != nullptr
            ? *static_cast<const ProtocolTransport*>(context)
            : ProtocolTransport::none;
    return write_method_error_response_for_transport(id, method, code, transport);
}

signing::UsbSigningOutcomeWriterOps signing_outcome_writer_ops_for_transport(
    ProtocolTransport transport)
{
    g_signing_outcome_transport_context = transport;
    const signing::UsbJsonResponseWriteOps response_write_ops =
        transport == ProtocolTransport::usb
            ? signing::usb_response_json_write_ops()
            : transport == ProtocolTransport::local_transport
                ? local_transport_json_response_write_ops()
                : missing_json_response_write_ops();
    return signing::UsbSigningOutcomeWriterOps{
        response_write_ops,
        write_method_error_for_signing_outcome,
        &g_signing_outcome_transport_context,
    };
}

bool write_policy_execution_response(
    const char* id,
    const uint8_t* request_identity,
    const signing::PolicySigningExecutionResult& result)
{
    return signing::usb_signing_outcome_write_policy_execution(
        id,
        signing::session_id(),
        request_identity,
        result,
        signing_outcome_writer_ops_for_transport(g_current_request_transport));
}

bool write_policy_propose_outcome_with_current_policy(
    const char* id,
    const char* status,
    const char* reason_code)
{
    const signing::PolicyUpdateFlowSnapshot snapshot =
        signing::policy_update_flow_snapshot();
    return signing::usb_policy_propose_outcome_write(
        id,
        status,
        reason_code,
        &snapshot,
        operation_response_writer_for_transport(
            g_pending_policy_update_transport));
}

void clear_active_session()
{
    signing::session_clear();
    // Buffered signing responses are session-scoped; drop them when the session
    // ends so a new session never sees a prior session's results.
    signing::signing_response_clear_all();
    signing::payload_delivery_clear_all();
    g_active_session_transport = ProtocolTransport::none;
}

bool persist_persistent_material_state(signing::ProvisioningPersistedState state)
{
    if (state == signing::ProvisioningPersistedState::provisioned) {
        return signing::provisioning_runtime_state_persist(ProvisioningRuntimeState::provisioned);
    }
    return signing::provisioning_runtime_state_persist(ProvisioningRuntimeState::unprovisioned);
}

void handle_persistent_material_consistency_error(const char* message)
{
    clear_session_bound_state_for_plan(
        current_usb_session_loss_plan(xTaskGetTickCount()),
        "persistent material consistency error during local PIN authorization",
        "persistent material consistency error during user_signing",
        true,
        "Persistent material consistency error; session-bound state cleared");
    ESP_LOGE(kTag, "%s", message != nullptr ? message : "Persistent material consistency error; failing closed");
}

void record_storage_maintenance_material_failure(signing::PersistentMaterialRuntimeFailure failure)
{
    signing::persistent_material_record_runtime_failure(
        failure,
        persistent_material_ops());
}

signing::StorageMaintenancePersistenceOps storage_maintenance_persistence_ops()
{
    return signing::StorageMaintenancePersistenceOps{
        clear_active_session,
        persist_persistent_material_state,
        record_storage_maintenance_material_failure,
    };
}

signing::PersistentMaterialOps persistent_material_ops()
{
    return signing::PersistentMaterialOps{
        persist_persistent_material_state,
        handle_persistent_material_consistency_error,
    };
}

signing::HistoryTerminalResult history_terminal_result(
    signing::UserSigningTerminalResult result)
{
    switch (result) {
        case signing::UserSigningTerminalResult::signed_success:
            return signing::HistoryTerminalResult::signed_success;
        case signing::UserSigningTerminalResult::rejected:
            return signing::HistoryTerminalResult::user_rejected;
        case signing::UserSigningTerminalResult::timed_out:
            return signing::HistoryTerminalResult::user_timed_out;
        case signing::UserSigningTerminalResult::signing_failed:
            return signing::HistoryTerminalResult::signing_failed;
        case signing::UserSigningTerminalResult::canceled:
        case signing::UserSigningTerminalResult::history_error:
        case signing::UserSigningTerminalResult::none:
        default:
            return signing::HistoryTerminalResult::none;
    }
}

bool write_user_signing_confirmation_history(
    const signing::UserSigningFlowCoreSnapshot& snapshot,
    void*)
{
    const signing::HistoryAppendInput input{
        signing::HistoryRecordKind::confirmation,
        signing::ApprovalHistoryConfirmationKind::local_pin,
        signing::HistoryTerminalResult::none,
        snapshot.chain,
        snapshot.method,
        snapshot.blind_signing_confirmation
            ? "blind_signing_confirmed"
            : "device_confirmed",
        snapshot.payload_digest,
        nullptr,
    };
    return signing::approval_history_append_required_signing(
        input,
        static_cast<uint64_t>(esp_timer_get_time() / 1000LL));
}

bool write_user_signing_physical_confirmation_history(
    const signing::UserSigningFlowCoreSnapshot& snapshot,
    void*)
{
    const signing::HistoryAppendInput input{
        signing::HistoryRecordKind::confirmation,
        signing::ApprovalHistoryConfirmationKind::physical_confirm,
        signing::HistoryTerminalResult::none,
        snapshot.chain,
        snapshot.method,
        snapshot.blind_signing_confirmation
            ? "blind_signing_confirmed"
            : "device_confirmed",
        snapshot.payload_digest,
        nullptr,
    };
    return signing::approval_history_append_required_signing(
        input,
        static_cast<uint64_t>(esp_timer_get_time() / 1000LL));
}

bool write_user_signing_terminal_history(
    const signing::UserSigningFlowCoreSnapshot& snapshot,
    signing::UserSigningTerminalResult result)
{
    const signing::HistoryTerminalResult history_result =
        history_terminal_result(result);
    if (history_result == signing::HistoryTerminalResult::none) {
        return true;
    }
    const char* reason = signing::user_signing_flow_terminal_reason(result);
    if (reason == nullptr || reason[0] == '\0') {
        return false;
    }
    const signing::HistoryAppendInput input{
        signing::HistoryRecordKind::terminal,
        signing::ApprovalHistoryConfirmationKind::none,
        history_result,
        snapshot.chain,
        snapshot.method,
        reason,
        snapshot.payload_digest,
        nullptr,
    };
    return signing::approval_history_append_required_signing(
        input,
        static_cast<uint64_t>(esp_timer_get_time() / 1000LL));
}

void consume_user_signing_terminal_if_pending()
{
    signing::UserSigningTerminalResult ignored =
        signing::UserSigningTerminalResult::none;
    signing::user_signing_flow_consume_terminal_result(&ignored);
}

void finish_user_signing_error_terminal(
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    const ProtocolTransport response_transport = g_active_user_signing_transport;
    if (request_id != nullptr && request_id[0] != '\0') {
        const signing::UserSigningFlowCoreSnapshot snapshot =
            signing::user_signing_flow_core_snapshot();
        write_method_error_response_for_transport(
            request_id,
            snapshot.method,
            error_code,
            response_transport);
    }
    consume_user_signing_terminal_if_pending();
    signing::user_signing_flow_clear();
    g_active_user_signing_transport = ProtocolTransport::none;
    signing::avatar_overlay_show_message(
        display_message != nullptr && display_message[0] != '\0' ? display_message : "Signing failed",
        MessageKind::error,
        UiMode::result,
        kResultDisplayMs);
}

void finish_user_signing_terminal(
    const char* request_id,
    const signing::UserSigningOutput* signing_output)
{
    const ProtocolTransport response_transport = g_active_user_signing_transport;
    const signing::UserSigningFlowCoreSnapshot snapshot =
        signing::user_signing_flow_core_snapshot();
    const signing::UserSigningTerminalResult result =
        snapshot.terminal_result;
    if (!snapshot.active ||
        snapshot.stage != signing::UserSigningStage::terminal ||
        result == signing::UserSigningTerminalResult::none) {
        if (request_id != nullptr && request_id[0] != '\0') {
            write_method_error_response_for_transport(
                request_id,
                snapshot.method,
                "invalid_state",
                response_transport);
        }
        signing::avatar_overlay_show_message(
            "Signing unavailable",
            MessageKind::error,
            UiMode::result,
            kResultDisplayMs);
        g_active_user_signing_transport = ProtocolTransport::none;
        return;
    }

    if (!write_user_signing_terminal_history(snapshot, result)) {
        if (request_id != nullptr && request_id[0] != '\0') {
            write_method_error_response_for_transport(
                request_id,
                snapshot.method,
                "history_unavailable",
                response_transport);
        }
        consume_user_signing_terminal_if_pending();
        g_active_user_signing_transport = ProtocolTransport::none;
        ESP_LOGW(kTag, "user_signing terminal history write failed: id=%s", request_id);
        signing::avatar_overlay_show_message(
            result == signing::UserSigningTerminalResult::signed_success
                ? "Signed; history failed"
                : "History error",
            MessageKind::error,
            UiMode::result,
            kResultDisplayMs);
        return;
    }

    bool wrote_response = false;
    const char* response_type = snapshot.method;
    const char* display_message = "Signing failed";
    MessageKind display_kind = MessageKind::error;
    const char* delivery_failed_message = "Signing failed; response failed";
    if (result == signing::UserSigningTerminalResult::signed_success) {
        wrote_response = signing_output != nullptr &&
            signing::usb_signing_outcome_write_user_signed(
                request_id,
                signing::session_id(),
                "user",
                snapshot,
                *signing_output,
                signing_outcome_writer_ops_for_transport(response_transport));
        display_message = wrote_response ? "Signed" : "Signed; response failed";
        delivery_failed_message = "Signed; response failed";
        display_kind = wrote_response ? MessageKind::success : MessageKind::error;
    } else if (result == signing::UserSigningTerminalResult::rejected) {
        wrote_response = signing::usb_signing_outcome_write_user_terminal(
            request_id,
            signing::session_id(),
            snapshot.request_identity,
            snapshot.method,
            result,
            signing_outcome_writer_ops_for_transport(response_transport));
        display_message = wrote_response ? "Signing rejected" : "Rejected; response failed";
        delivery_failed_message = "Rejected; response failed";
        display_kind = wrote_response ? MessageKind::rejected : MessageKind::error;
    } else if (result == signing::UserSigningTerminalResult::timed_out) {
        wrote_response = signing::usb_signing_outcome_write_user_terminal(
            request_id,
            signing::session_id(),
            snapshot.request_identity,
            snapshot.method,
            result,
            signing_outcome_writer_ops_for_transport(response_transport));
        display_message = wrote_response ? "Signing timed out" : "Timeout; response failed";
        delivery_failed_message = "Timeout; response failed";
        display_kind = wrote_response ? MessageKind::timeout : MessageKind::error;
    } else if (result == signing::UserSigningTerminalResult::signing_failed) {
        wrote_response = signing::usb_signing_outcome_write_user_terminal(
            request_id,
            signing::session_id(),
            snapshot.request_identity,
            snapshot.method,
            result,
            signing_outcome_writer_ops_for_transport(response_transport));
        display_message = wrote_response ? "Signing failed" : "Failure; response failed";
        delivery_failed_message = "Failure; response failed";
    } else if (request_id != nullptr && request_id[0] != '\0') {
        wrote_response = write_method_error_response_for_transport(
            request_id,
            snapshot.method,
            "invalid_session",
            response_transport);
        response_type = snapshot.method;
        display_message = wrote_response ? "Session ended" : "Session response failed";
        delivery_failed_message = "Session response failed";
    }

    if (!wrote_response) {
        signing::usb_response_log_write_failure(response_type, request_id);
        display_message = delivery_failed_message;
    }
    consume_user_signing_terminal_if_pending();
    g_active_user_signing_transport = ProtocolTransport::none;
    signing::avatar_overlay_show_message(
        display_message,
        display_kind,
        UiMode::result,
        kResultDisplayMs);
}

struct UserSigningOutputReadyContext {
    const char* request_id = nullptr;
};

struct UserSigningTerminalFinishContext {
    const char* request_id = nullptr;
};

bool user_signing_signed_response_fits(
    const signing::UserSigningFlowCoreSnapshot& snapshot,
    const signing::UserSigningOutput& signing_output,
    void* context)
{
    const UserSigningOutputReadyContext* ready_context =
        static_cast<const UserSigningOutputReadyContext*>(context);
    if (ready_context == nullptr ||
        ready_context->request_id == nullptr ||
        ready_context->request_id[0] == '\0' ||
        strcmp(ready_context->request_id, snapshot.request_id) != 0) {
        return false;
    }
    return signing::usb_signing_outcome_user_signed_response_fits(
        ready_context->request_id,
        "user",
        snapshot,
        signing_output);
}

bool finish_user_signing_from_common(
    const signing::UserSigningOutput* signing_output,
    void* context)
{
    const UserSigningTerminalFinishContext* finish_context =
        static_cast<const UserSigningTerminalFinishContext*>(context);
    if (finish_context == nullptr) {
        return false;
    }
    finish_user_signing_terminal(finish_context->request_id, signing_output);
    return true;
}

void execute_user_signing_critical_section_and_finish(const char* request_id)
{
    const signing::UserSigningFlowCoreSnapshot snapshot =
        signing::user_signing_flow_core_snapshot();
    if (!provisioned_material_ready()) {
        if (request_id != nullptr && request_id[0] != '\0') {
            write_method_error_response_for_transport(
                request_id,
                snapshot.method,
                "invalid_state",
                g_active_user_signing_transport);
        }
        signing::user_signing_flow_clear();
        g_active_user_signing_transport = ProtocolTransport::none;
        signing::avatar_overlay_show_message(
            "Signing unavailable",
            MessageKind::error,
            UiMode::result,
            kResultDisplayMs);
        return;
    }
    UserSigningOutputReadyContext ready_context{request_id};
    UserSigningTerminalFinishContext finish_context{request_id};
    const signing::UserSigningCriticalSectionOps critical_ops{
        signing::sign_user_signing_payload_from_active_identity,
    };
    const signing::UserSigningHandoffFinishReport signing_report =
        signing::user_signing_execute_critical_section_and_finish(
            user_signing_signed_response_fits,
            &ready_context,
            finish_user_signing_from_common,
            &finish_context,
            critical_ops);
    if (signing_report.handoff.result != signing::UserSigningHandoffResult::ok) {
        ESP_LOGW(kTag,
                 "user_signing signing failed: id=%s handoff=%s signing=%s",
                 request_id,
                 signing::user_signing_handoff_result_name(signing_report.handoff.result),
                 signing::user_signing_sign_status_name(signing_report.handoff.signing_status));
    }
}

bool fill_protocol_random(void* output, size_t size, const char* purpose)
{
    if (signing::fill_secure_random(output, size)) {
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
    if (g_pending_connect_transport == ProtocolTransport::none) {
        return false;
    }
    // A newly established session must not inherit the previous session's buffered
    // signing responses, so drop them before the session id changes.
    signing::signing_response_clear_all();
    signing::payload_delivery_clear_all();
    if (signing::session_replace(fill_session_random, nullptr) !=
        signing::SessionStartResult::ok) {
        return false;
    }
    g_active_session_transport = g_pending_connect_transport;
    return true;
}

signing::UsbSessionLossProtocolPinPurpose protocol_pin_loss_purpose(
    const signing::ProtocolPinApprovalSnapshot& snapshot)
{
    if (!snapshot.active) {
        return signing::UsbSessionLossProtocolPinPurpose::none;
    }
    switch (snapshot.purpose) {
        case signing::ProtocolPinApprovalPurpose::connect:
            return signing::UsbSessionLossProtocolPinPurpose::connect;
        case signing::ProtocolPinApprovalPurpose::policy_update:
            return signing::UsbSessionLossProtocolPinPurpose::policy_update;
        case signing::ProtocolPinApprovalPurpose::sui_zklogin_proposal:
            return signing::UsbSessionLossProtocolPinPurpose::sui_zklogin_proposal;
        case signing::ProtocolPinApprovalPurpose::none:
            return signing::UsbSessionLossProtocolPinPurpose::other;
    }
    return signing::UsbSessionLossProtocolPinPurpose::other;
}

signing::UsbSessionLossLocalPinPurpose local_pin_loss_purpose(
    const signing::LocalPinAuthSnapshot& snapshot)
{
    if (!snapshot.flow_active) {
        return signing::UsbSessionLossLocalPinPurpose::none;
    }
    switch (snapshot.purpose) {
        case LocalPinAuthPurpose::connect:
            return signing::UsbSessionLossLocalPinPurpose::connect;
        case LocalPinAuthPurpose::policy_update:
            return signing::UsbSessionLossLocalPinPurpose::policy_update;
        case LocalPinAuthPurpose::sui_zklogin_proposal:
            return signing::UsbSessionLossLocalPinPurpose::sui_zklogin_proposal;
        case LocalPinAuthPurpose::user_signing:
            return signing::UsbSessionLossLocalPinPurpose::user_signing;
        case LocalPinAuthPurpose::none:
        case LocalPinAuthPurpose::settings_human_approval_input:
        case LocalPinAuthPurpose::settings_signing_mode:
        case LocalPinAuthPurpose::settings_policy_reset:
        case LocalPinAuthPurpose::settings_change_pin:
        case LocalPinAuthPurpose::settings_sui_accept_gas_sponsor:
        case LocalPinAuthPurpose::settings_sui_zklogin_clear:
            return signing::UsbSessionLossLocalPinPurpose::other;
    }
    return signing::UsbSessionLossLocalPinPurpose::other;
}

signing::UsbSessionLossPlan current_usb_session_loss_plan(TickType_t now)
{
    const signing::ProtocolPinApprovalSnapshot protocol_pin =
        signing::protocol_pin_approval_snapshot();
    const signing::LocalPinAuthSnapshot pin_auth =
        signing::local_pin_auth_snapshot(now);
    const signing::UserSigningFlowCoreSnapshot user_signing =
        signing::user_signing_flow_core_snapshot();
    const bool usb_connect_approval =
        signing::connect_approval_active() &&
        g_pending_connect_transport != ProtocolTransport::local_transport;
    const bool usb_session_active =
        signing::session_active() &&
        g_active_session_transport != ProtocolTransport::local_transport;
    return signing::usb_session_loss_plan(signing::UsbSessionLossInput{
        usb_session_active,
        usb_connect_approval,
        protocol_pin_loss_purpose(protocol_pin),
        usb_connect_approval ? local_pin_loss_purpose(pin_auth)
                             : signing::UsbSessionLossLocalPinPurpose::none,
        signing::policy_update_flow_active(),
        signing::sui_zklogin_proposal_flow_active(),
        user_signing.active,
        user_signing.stage == signing::UserSigningStage::signing_critical_section,
    });
}

signing::UsbSessionLossPlan current_local_transport_session_loss_plan(TickType_t now)
{
    const signing::ProtocolPinApprovalSnapshot protocol_pin =
        signing::protocol_pin_approval_snapshot();
    const signing::LocalPinAuthSnapshot pin_auth =
        signing::local_pin_auth_snapshot(now);
    const signing::UserSigningFlowCoreSnapshot user_signing =
        signing::user_signing_flow_core_snapshot();
    const bool local_connect_approval =
        signing::connect_approval_active() &&
        g_pending_connect_transport == ProtocolTransport::local_transport;
    const bool local_session_active =
        signing::session_active() &&
        g_active_session_transport == ProtocolTransport::local_transport;
    const bool local_transport_owns_session_bound_state =
        local_connect_approval || local_session_active;
    return signing::usb_session_loss_plan(signing::UsbSessionLossInput{
        local_session_active,
        local_connect_approval,
        local_transport_owns_session_bound_state
            ? protocol_pin_loss_purpose(protocol_pin)
            : signing::UsbSessionLossProtocolPinPurpose::none,
        local_transport_owns_session_bound_state
            ? local_pin_loss_purpose(pin_auth)
            : signing::UsbSessionLossLocalPinPurpose::none,
        signing::policy_update_flow_active() && local_session_active,
        signing::sui_zklogin_proposal_flow_active() && local_session_active,
        user_signing.active && local_session_active,
        user_signing.stage == signing::UserSigningStage::signing_critical_section,
    });
}

void clear_session_bound_state_for_plan(
    const signing::UsbSessionLossPlan& plan,
    const char* local_pin_reason,
    const char* user_signing_reason,
    bool force_user_signing_clear,
    const char* log_message)
{
    if (!plan.relevant && !force_user_signing_clear) {
        return;
    }

    if (plan.clear_session) {
        clear_active_session();
    }
    if (plan.clear_connect_approval) {
        clear_connect_review_state();
    }
    if (plan.clear_protocol_pin) {
        signing::protocol_pin_approval_clear();
    }
    if (plan.clear_local_pin_auth) {
        clear_local_pin_auth_scratch(local_pin_reason);
    }
    if (plan.clear_policy_update_flow) {
        signing::policy_update_flow_clear();
        g_pending_policy_update_transport = ProtocolTransport::none;
    }
    if (plan.clear_sui_zklogin_proposal_flow) {
        signing::sui_zklogin_proposal_flow_clear();
        g_pending_credential_proposal_transport = ProtocolTransport::none;
    }
    if (plan.cancel_user_signing) {
        cancel_user_signing_after_session_loss(user_signing_reason);
    } else if (force_user_signing_clear) {
        signing::user_signing_flow_clear();
        g_active_user_signing_transport = ProtocolTransport::none;
    }
    if (plan.clear_connect_review_panel) {
        clear_signing_panel_if_kind(UiPanelKind::connect_review, SensitiveUiClearPolicy::preserve);
    }
    if (plan.clear_local_pin_panel) {
        clear_signing_panel_if_kind(UiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    }
    if (plan.clear_policy_update_review_panel) {
        clear_signing_panel_if_kind(UiPanelKind::policy_update_review, SensitiveUiClearPolicy::preserve);
    }
    if (plan.clear_sui_zklogin_review_panel) {
        clear_signing_panel_if_kind(UiPanelKind::sui_zklogin_review, SensitiveUiClearPolicy::preserve);
    }
    if (plan.clear_user_signing_review_panel || force_user_signing_clear) {
        clear_signing_panel_if_kind(UiPanelKind::user_signing_review, SensitiveUiClearPolicy::preserve);
    }
    ESP_LOGW(kTag, "%s", log_message);
}

void show_usb_disconnected_message()
{
    signing::avatar_overlay_show_message(
        "USB disconnected",
        MessageKind::usb_disconnected,
        UiMode::result,
        kResultDisplayMs);
}

void show_usb_connected_message()
{
    char message[40] = "USB connected";
    signing::AuthorizationMode signing_mode =
        signing::AuthorizationMode::user;
    if (provisioned_material_ready() &&
        signing::read_signing_authorization_mode(&signing_mode)) {
        snprintf(
            message,
            sizeof(message),
            "USB connected - %s auth",
            signing_mode == signing::AuthorizationMode::policy ? "POLICY" : "USER");
    }
    signing::avatar_overlay_show_message(
        message,
        MessageKind::usb_connected,
        UiMode::result,
        kResultDisplayMs);
}

void clear_usb_session_state_for_host_loss()
{
    const signing::UsbSessionLossPlan plan =
        current_usb_session_loss_plan(xTaskGetTickCount());

    // Line-framing state is transport state and is reset at the disconnect edge, which
    // always precedes this confirm-path call; this function clears session-bound state.
    clear_session_bound_state_for_plan(
        plan,
        "USB host link lost during local PIN authorization",
        "USB host link lost during user_signing",
        false,
        "USB host SOF lost; session-bound state cleared");
}

// Hold the session briefly after a USB drop so a transient resume can reconnect
// and recover its buffered signing response before the session is torn down.
constexpr uint32_t kUsbSessionGraceMs = 2000;
signing::UsbGraceState g_usb_session_grace;

void poll_usb_host_connection()
{
    const TickType_t now = xTaskGetTickCount();
    const signing::UsbLinkEvent event = signing::usb_link_state_observe(
        usb_serial_jtag_is_connected(),
        now,
        pdMS_TO_TICKS(kUsbHostLinkCheckMs));
    const signing::UsbGraceAction grace = signing::usb_session_grace_step(
        event, now, pdMS_TO_TICKS(kUsbSessionGraceMs), g_usb_session_grace);
    switch (event) {
        case signing::UsbLinkEvent::not_due:
        case signing::UsbLinkEvent::initial_observed:
        case signing::UsbLinkEvent::unchanged_connected:
            return;
        case signing::UsbLinkEvent::connected:
            // A fresh connect, or a reconnect that resumed within the grace window.
            show_usb_connected_message();
            return;
        case signing::UsbLinkEvent::unchanged_disconnected:
            // Tear the session down only once the grace window confirms the loss; the
            // loss plan still protects an in-flight critical section.
            if (grace == signing::UsbGraceAction::confirm) {
                if (current_usb_session_loss_plan(now).relevant) {
                    clear_usb_session_state_for_host_loss();
                }
                show_usb_disconnected_message();
            }
            return;
        case signing::UsbLinkEvent::disconnected:
            // Edge: the grace window is now open and the session is held; stay quiet so
            // a quick resume is seamless. A sustained drop confirms above. Reset the line
            // framing here so a resume parses cleanly even if the drop cut a partial line.
            signing::usb_line_receiver_reset();
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
    signing::wipe_sensitive_buffer(bytes, sizeof(bytes));
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
            signing::drawing_surface_panel_locked() == nullptr &&
            signing::avatar_overlay_mode() == UiMode::identification;
    }

    return signing::provisioning_runtime_state_is_unprovisioned() &&
           !signing::identification_display_active() &&
           !signing::provisioning_flow_active() &&
           !signing::local_pin_auth_flow_active() &&
           !signing::user_signing_flow_active() &&
           !signing::storage_maintenance_snapshot(xTaskGetTickCount()).flow_active &&
           !signing::connect_approval_active() &&
           !signing::protocol_pin_approval_active() &&
           welcome_visible;
}

bool ui_panel_active(UiPanelKind kind)
{
    LvglLockGuard lock;
    return signing::drawing_surface_panel_active(kind);
}

bool refresh_persistent_material_consistency()
{
    return signing::provisioning_runtime_state_refresh(persistent_material_ops());
}

bool provisioned_material_ready()
{
    return signing::provisioning_runtime_state_material_ready(persistent_material_ops());
}

signing::SessionValidationResult validate_session_for_user_signing(
    const char* session_id,
    void*)
{
    return signing::session_validate(session_id);
}

bool user_signing_ingress_busy()
{
    return signing::device_activity_blocks_user_signing_ingress(
        current_device_activity());
}

bool unrelated_user_signing_ingress_busy()
{
    const signing::UsbOperationManifestEntry* entry =
        signing::usb_operation_manifest_entry(
            signing::UsbOperationType::sign_personal_message);
    if (entry == nullptr) {
        return true;
    }
    const signing::PayloadDeliveryAdmissionDecision admission =
        signing::payload_delivery_admit_operation(
            signing::PayloadDeliveryOperationAdmissionInput{
                current_timeout_tick(),
                entry->payload_delivery_operation,
            });
    return user_signing_ingress_busy() ||
           signing::payload_delivery_admission_blocks_sensitive_flow(admission);
}

bool write_payload_delivery_operation_busy(
    const char* id,
    const UsbOperationResponseWriter& writer,
    signing::UsbOperationType operation)
{
    const signing::UsbOperationManifestEntry* entry =
        signing::usb_operation_manifest_entry(operation);
    if (entry == nullptr) {
        writer.write_error(id, "internal_output_error");
        return true;
    }
    const signing::PayloadDeliveryAdmissionDecision admission =
        signing::payload_delivery_admit_operation(
            signing::PayloadDeliveryOperationAdmissionInput{
                current_timeout_tick(),
                entry->payload_delivery_operation,
            });
    if (!signing::payload_delivery_admission_blocks_sensitive_flow(admission)) {
        return false;
    }
    writer.write_error(id, "busy");
    return true;
}

bool write_payload_delivery_identify_device_busy(
    const char* id,
    const UsbOperationResponseWriter& writer)
{
    return write_busy_if_pending_or_local_flow_active_for_operation(
        id,
        writer,
        signing::UsbOperationType::identify_device);
}

bool write_payload_delivery_connect_busy(
    const char* id,
    const UsbOperationResponseWriter& writer)
{
    return write_busy_if_pending_or_local_flow_active_for_operation(
        id,
        writer,
        signing::UsbOperationType::connect);
}

bool write_connect_admission_error(
    const char* id,
    const UsbOperationResponseWriter& writer)
{
    if (signing::session_active()) {
        return false;
    }
    return write_payload_delivery_connect_busy(id, writer);
}

bool write_existing_session_connect_response(
    const char* id,
    const UsbOperationResponseWriter& writer)
{
    if (!signing::session_active()) {
        return false;
    }
    if (g_active_session_transport != ProtocolTransport::none &&
        g_active_session_transport != g_current_request_transport) {
        writer.write_error(id, "invalid_state");
        return true;
    }
    if (!write_connect_approved_with_writer(writer, id)) {
        signing::usb_response_log_write_failure("connect", id);
    }
    return true;
}

bool write_payload_delivery_policy_propose_busy(
    const char* id,
    const UsbOperationResponseWriter& writer)
{
    return write_busy_if_pending_or_local_flow_active_for_operation(
        id,
        writer,
        signing::UsbOperationType::policy_propose);
}

bool write_payload_delivery_credential_propose_busy(
    const char* id,
    const UsbOperationResponseWriter& writer)
{
    return write_busy_if_pending_or_local_flow_active_for_operation(
        id,
        writer,
        signing::UsbOperationType::credential_propose);
}

bool write_payload_delivery_disconnect_admission_error(
    const char* id,
    signing::UsbOperationType operation,
    const UsbOperationResponseWriter& writer)
{
    const signing::UsbOperationManifestEntry* entry =
        signing::usb_operation_manifest_entry(operation);
    if (entry == nullptr) {
        writer.write_error(id, "internal_output_error");
        return true;
    }
    const signing::PayloadDeliveryAdmissionDecision admission =
        signing::payload_delivery_admit_operation(
            signing::PayloadDeliveryOperationAdmissionInput{
                current_timeout_tick(),
                entry->payload_delivery_operation,
            });
    if (signing::payload_delivery_admission_allows_disconnect_cleanup(admission)) {
        return false;
    }
    writer.write_error(id, "busy");
    return true;
}

bool write_payload_delivery_safe_read_admission_error(
    const char* id,
    signing::UsbOperationType operation,
    const UsbOperationResponseWriter& writer)
{
    const signing::UsbOperationManifestEntry* entry =
        signing::usb_operation_manifest_entry(operation);
    if (entry == nullptr) {
        writer.write_error(id, "internal_output_error");
        return true;
    }
    const signing::PayloadDeliveryAdmissionDecision admission =
        signing::payload_delivery_admit_operation(
            signing::PayloadDeliveryOperationAdmissionInput{
                current_timeout_tick(),
                entry->payload_delivery_operation,
            });
    if (signing::payload_delivery_admission_allows_safe_read(admission)) {
        return false;
    }
    writer.write_error(id, "busy");
    return true;
}

bool write_payload_delivery_retained_response_admission_error(
    const char* id,
    signing::UsbOperationType operation,
    const UsbOperationResponseWriter& writer)
{
    const signing::UsbOperationManifestEntry* entry =
        signing::usb_operation_manifest_entry(operation);
    if (entry == nullptr) {
        writer.write_error(id, "internal_output_error");
        return true;
    }
    const signing::PayloadDeliveryAdmissionDecision admission =
        signing::payload_delivery_admit_operation(
            signing::PayloadDeliveryOperationAdmissionInput{
                current_timeout_tick(),
                entry->payload_delivery_operation,
            });
    if (signing::payload_delivery_admission_allows_retained_response_cleanup(admission)) {
        return false;
    }
    writer.write_error(id, "busy");
    return true;
}

bool show_user_signing_review()
{
    return signing::user_signing_review_ui_show(user_signing_review_ui_flow_ops());
}

bool show_policy_update_review()
{
    return signing::policy_update_review_ui_show(policy_update_review_ui_flow_ops());
}

bool show_sui_zklogin_review()
{
    return signing::sui_zklogin_review_ui_show(sui_zklogin_review_ui_flow_ops());
}

bool ui_idle_for_local_settings()
{
    LvglLockGuard lock;
    return signing::drawing_surface_panel_locked() == nullptr &&
           signing::avatar_overlay_mode() == UiMode::none;
}

bool local_settings_touch_entry_candidate_allowed()
{
    return signing::device_activity_allows_local_settings_touch_entry(
        current_device_activity());
}

bool write_busy_if_pending_or_local_flow_active(
    const char* id,
    const UsbOperationResponseWriter& writer,
    bool allow_settings_menu = false,
    bool allow_payload_delivery = false)
{
    const signing::DeviceActivityUsbRequestBlock block =
        signing::device_activity_usb_request_block(
            current_device_activity(),
            { allow_settings_menu, allow_payload_delivery });
    if (!block.blocked) {
        return false;
    }
    writer.write_error(id, block.code);
    return true;
}

bool write_busy_if_pending_or_local_flow_active_for_operation(
    const char* id,
    const UsbOperationResponseWriter& writer,
    signing::UsbOperationType operation)
{
    return write_busy_if_pending_or_local_flow_active(id, writer, false, true) ||
           write_payload_delivery_operation_busy(id, writer, operation);
}

bool write_busy_if_pending_or_local_flow_active_allow_settings(
    const char* id,
    const UsbOperationResponseWriter& writer)
{
    return write_busy_if_pending_or_local_flow_active(id, writer, true, true);
}

bool write_busy_if_pending_or_local_flow_active_allow_payload_delivery(
    const char* id,
    const UsbOperationResponseWriter& writer)
{
    return write_busy_if_pending_or_local_flow_active(id, writer, false, true);
}

bool require_active_matching_session(
    const char* id,
    const char* session_id,
    const UsbOperationResponseWriter& writer)
{
    switch (signing::session_validate(session_id)) {
        case signing::SessionValidationResult::ok:
            if (g_active_session_transport != ProtocolTransport::none &&
                g_active_session_transport != g_current_request_transport) {
                writer.write_error(id, "invalid_session");
                return false;
            }
            return true;
        case signing::SessionValidationResult::invalid_format:
            writer.write_error(id, "invalid_session");
            return false;
        case signing::SessionValidationResult::missing:
            cancel_policy_update_after_session_loss("active session missing during request validation");
            cancel_sui_zklogin_proposal_after_session_loss("active session missing during request validation");
            cancel_user_signing_after_session_loss("active session missing during request validation");
            writer.write_error(id, "invalid_session");
            return false;
        case signing::SessionValidationResult::mismatch:
        default:
            writer.write_error(id, "invalid_session");
            return false;
    }
}

void write_policy_update_invalid_session_and_clear(const char* request_id, const char* log_reason)
{
    if (request_id != nullptr && request_id[0] != '\0') {
        operation_response_writer_for_transport(g_pending_policy_update_transport)
            .for_method("policy_propose")
            .write_error(request_id, "invalid_session");
    }
    signing::policy_update_flow_clear();
    signing::protocol_pin_approval_clear();
    g_pending_policy_update_transport = ProtocolTransport::none;
    ESP_LOGW(kTag, "Policy update canceled: %s", log_reason != nullptr ? log_reason : "invalid session");
    signing::avatar_overlay_show_message(
        "Session ended",
        MessageKind::error,
        UiMode::result,
        kResultDisplayMs);
}

void cancel_policy_update_after_session_loss(const char* log_reason)
{
    char request_id[kMaxRequestIdSize] = {};
    if (signing::protocol_pin_approval_policy_update_request_id(request_id, sizeof(request_id))) {
        const signing::LocalPinAuthSnapshot pin_auth =
            signing::local_pin_auth_snapshot(xTaskGetTickCount());
        if (pin_auth.flow_active &&
            pin_auth.purpose == LocalPinAuthPurpose::policy_update) {
            clear_local_pin_auth_scratch("session loss canceled pending policy update");
            clear_signing_panel_if_kind(UiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        }
        write_policy_update_invalid_session_and_clear(request_id, log_reason);
        return;
    }

    if (signing::policy_update_flow_active()) {
        const signing::PolicyUpdateFlowSnapshot snapshot =
            signing::policy_update_flow_snapshot();
        clear_signing_panel_if_kind(
            UiPanelKind::policy_update_review,
            SensitiveUiClearPolicy::preserve);
        clear_signing_panel_if_kind(
            UiPanelKind::local_pin_auth,
            SensitiveUiClearPolicy::preserve);
        write_policy_update_invalid_session_and_clear(snapshot.request_id, log_reason);
    }
}

void write_sui_zklogin_proposal_invalid_session_and_clear(
    const char* request_id,
    const char* log_reason)
{
    if (request_id != nullptr && request_id[0] != '\0') {
        operation_response_writer_for_transport(g_pending_credential_proposal_transport)
            .for_method("credential_propose")
            .write_error(request_id, "invalid_session");
    }
    signing::sui_zklogin_proposal_flow_clear();
    signing::protocol_pin_approval_clear();
    g_pending_credential_proposal_transport = ProtocolTransport::none;
    ESP_LOGW(kTag, "Sui zkLogin proposal canceled: %s",
             log_reason != nullptr ? log_reason : "invalid session");
    signing::avatar_overlay_show_message(
        "Session ended",
        MessageKind::error,
        UiMode::result,
        kResultDisplayMs);
}

void cancel_sui_zklogin_proposal_after_session_loss(const char* log_reason)
{
    char request_id[kMaxRequestIdSize] = {};
    if (signing::protocol_pin_approval_sui_zklogin_proposal_request_id(
            request_id,
            sizeof(request_id))) {
        const signing::LocalPinAuthSnapshot pin_auth =
            signing::local_pin_auth_snapshot(xTaskGetTickCount());
        if (pin_auth.flow_active &&
            pin_auth.purpose == LocalPinAuthPurpose::sui_zklogin_proposal) {
            clear_local_pin_auth_scratch("session loss canceled pending Sui zkLogin proposal");
            clear_signing_panel_if_kind(UiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        }
        write_sui_zklogin_proposal_invalid_session_and_clear(request_id, log_reason);
        return;
    }

    if (signing::sui_zklogin_proposal_flow_active()) {
        const signing::SuiZkLoginProposalSnapshot snapshot =
            signing::sui_zklogin_proposal_flow_snapshot();
        clear_signing_panel_if_kind(
            UiPanelKind::sui_zklogin_review,
            SensitiveUiClearPolicy::preserve);
        clear_signing_panel_if_kind(
            UiPanelKind::local_pin_auth,
            SensitiveUiClearPolicy::preserve);
        write_sui_zklogin_proposal_invalid_session_and_clear(snapshot.request_id, log_reason);
    }
}

void cancel_user_signing_after_session_loss(const char* log_reason)
{
    const signing::UserSigningFlowCoreSnapshot snapshot =
        signing::user_signing_flow_core_snapshot();
    if (!snapshot.active) {
        return;
    }
    const signing::UserSigningConfirmationResult result =
        signing::user_signing_confirmation_cancel_for_session_loss();
    if (result == signing::UserSigningConfirmationResult::busy) {
        ESP_LOGW(kTag, "user_signing stayed active during critical section: %s",
                 log_reason != nullptr ? log_reason : "session loss");
        return;
    }
    clear_signing_panel_if_kind(UiPanelKind::user_signing_review, SensitiveUiClearPolicy::preserve);
    clear_signing_panel_if_kind(UiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    consume_user_signing_terminal_if_pending();
    g_active_user_signing_transport = ProtocolTransport::none;
    ESP_LOGW(kTag, "user_signing canceled: %s",
             log_reason != nullptr ? log_reason : "session loss");
    signing::avatar_overlay_show_message(
        "Session ended",
        MessageKind::error,
        UiMode::result,
        kResultDisplayMs);
}

bool require_pending_policy_update_session(const char* request_id)
{
    switch (signing::protocol_pin_approval_validate_policy_update_session()) {
        case signing::SessionValidationResult::ok:
            return true;
        case signing::SessionValidationResult::invalid_format:
        case signing::SessionValidationResult::missing:
        case signing::SessionValidationResult::mismatch:
        default:
            write_policy_update_invalid_session_and_clear(request_id, "pending policy update session invalid");
            return false;
    }
}

bool require_pending_sui_zklogin_proposal_session(const char* request_id)
{
    switch (signing::protocol_pin_approval_validate_sui_zklogin_proposal_session()) {
        case signing::SessionValidationResult::ok:
            return true;
        case signing::SessionValidationResult::invalid_format:
        case signing::SessionValidationResult::missing:
        case signing::SessionValidationResult::mismatch:
        default:
            write_sui_zklogin_proposal_invalid_session_and_clear(
                request_id,
                "pending Sui zkLogin proposal session invalid");
            return false;
    }
}

signing::TimeoutWindow timeout_window_from_now_ms(
    TickType_t started_at,
    uint32_t duration_ms)
{
    return signing::timeout_window_from_deadline(
        started_at,
        started_at + pdMS_TO_TICKS(duration_ms));
}

signing::TimeoutWindow make_sui_zklogin_proposal_window(
    signing::TimeoutTick now)
{
    return timeout_window_from_now_ms(now, kProvisioningApprovalMaxMs);
}

bool show_sui_zklogin_proposal_review(const char* id)
{
    if (show_sui_zklogin_review()) {
        return true;
    }
    finish_sui_zklogin_proposal_terminal(
        id,
        signing::sui_zklogin_proposal_flow_record_ui_error());
    return false;
}

bool write_disconnect_success(
    const UsbOperationResponseWriter& writer,
    const char* id)
{
    JsonDocument result_doc;
    return writer.write_success_result(
        id,
        "disconnect",
        result_doc.to<JsonObject>());
}

bool disconnect_pending_policy_update_for_session(
    const char* id,
    const char* session_id,
    const UsbOperationResponseWriter& writer)
{
    const signing::PolicyUpdateFlowSnapshot policy_snapshot =
        signing::policy_update_flow_snapshot();
    if (policy_snapshot.active &&
        policy_snapshot.stage == signing::PolicyUpdateFlowStage::reviewing &&
        session_id != nullptr &&
        policy_snapshot.session_id != nullptr &&
        strcmp(policy_snapshot.session_id, session_id) == 0) {
        clear_signing_panel_if_kind(
            UiPanelKind::policy_update_review,
            SensitiveUiClearPolicy::preserve);
        if (policy_snapshot.request_id != nullptr &&
            policy_snapshot.request_id[0] != '\0' &&
            (id == nullptr || strcmp(policy_snapshot.request_id, id) != 0)) {
            writer.for_method("policy_propose")
                .write_error(policy_snapshot.request_id, "invalid_session");
        }
        signing::policy_update_flow_clear();
        g_pending_policy_update_transport = ProtocolTransport::none;
        clear_active_session();
        if (write_disconnect_success(writer, id)) {
            ESP_LOGI(kTag, "disconnect canceled pending policy update review: id=%s", id);
        } else {
            signing::usb_response_log_write_failure("disconnect", id);
        }
        return true;
    }

    if (!signing::protocol_pin_approval_policy_update_session_matches(session_id)) {
        return false;
    }

    char policy_request_id[kMaxRequestIdSize] = {};
    signing::protocol_pin_approval_policy_update_request_id(
        policy_request_id,
        sizeof(policy_request_id));
    const signing::LocalPinAuthSnapshot pin_auth =
        signing::local_pin_auth_snapshot(xTaskGetTickCount());
    if (pin_auth.flow_active &&
        pin_auth.purpose == LocalPinAuthPurpose::policy_update) {
        clear_local_pin_auth_scratch("disconnect canceled pending policy update");
        clear_signing_panel_if_kind(UiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    }
    if (policy_request_id[0] != '\0' &&
        (id == nullptr || strcmp(policy_request_id, id) != 0)) {
        writer.for_method("policy_propose")
            .write_error(policy_request_id, "invalid_session");
    }
    signing::policy_update_flow_clear();
    signing::protocol_pin_approval_clear();
    g_pending_policy_update_transport = ProtocolTransport::none;
    clear_active_session();
    if (write_disconnect_success(writer, id)) {
        ESP_LOGI(kTag, "disconnect canceled pending policy update: id=%s", id);
    } else {
        signing::usb_response_log_write_failure("disconnect", id);
    }
    return true;
}

bool disconnect_pending_sui_zklogin_proposal_for_session(
    const char* id,
    const char* session_id,
    const UsbOperationResponseWriter& writer)
{
    const signing::SuiZkLoginProposalSnapshot proposal_snapshot =
        signing::sui_zklogin_proposal_flow_snapshot();
    if (proposal_snapshot.active &&
        session_id != nullptr &&
        proposal_snapshot.session_id != nullptr &&
        strcmp(proposal_snapshot.session_id, session_id) == 0) {
        const signing::LocalPinAuthSnapshot pin_auth =
            signing::local_pin_auth_snapshot(xTaskGetTickCount());
        if (pin_auth.flow_active &&
            pin_auth.purpose == LocalPinAuthPurpose::sui_zklogin_proposal) {
            clear_local_pin_auth_scratch("disconnect canceled pending Sui zkLogin proposal");
            clear_signing_panel_if_kind(UiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
        }
        clear_signing_panel_if_kind(
            UiPanelKind::sui_zklogin_review,
            SensitiveUiClearPolicy::preserve);
        if (proposal_snapshot.request_id != nullptr &&
            proposal_snapshot.request_id[0] != '\0' &&
            (id == nullptr || strcmp(proposal_snapshot.request_id, id) != 0)) {
            writer.for_method("credential_propose")
                .write_error(proposal_snapshot.request_id, "invalid_session");
        }
        signing::sui_zklogin_proposal_flow_clear();
        signing::protocol_pin_approval_clear();
        g_pending_credential_proposal_transport = ProtocolTransport::none;
        clear_active_session();
        if (write_disconnect_success(writer, id)) {
            ESP_LOGI(kTag, "disconnect canceled pending Sui zkLogin proposal: id=%s", id);
        } else {
            signing::usb_response_log_write_failure("disconnect", id);
        }
        return true;
    }

    if (!signing::protocol_pin_approval_sui_zklogin_proposal_session_matches(session_id)) {
        return false;
    }

    char proposal_request_id[kMaxRequestIdSize] = {};
    signing::protocol_pin_approval_sui_zklogin_proposal_request_id(
        proposal_request_id,
        sizeof(proposal_request_id));
    const signing::LocalPinAuthSnapshot pin_auth =
        signing::local_pin_auth_snapshot(xTaskGetTickCount());
    if (pin_auth.flow_active &&
        pin_auth.purpose == LocalPinAuthPurpose::sui_zklogin_proposal) {
        clear_local_pin_auth_scratch("disconnect canceled pending Sui zkLogin proposal");
        clear_signing_panel_if_kind(UiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    }
    clear_signing_panel_if_kind(
        UiPanelKind::sui_zklogin_review,
        SensitiveUiClearPolicy::preserve);
    if (proposal_request_id[0] != '\0' &&
        (id == nullptr || strcmp(proposal_request_id, id) != 0)) {
        writer.for_method("credential_propose")
            .write_error(proposal_request_id, "invalid_session");
    }
    signing::sui_zklogin_proposal_flow_clear();
    signing::protocol_pin_approval_clear();
    g_pending_credential_proposal_transport = ProtocolTransport::none;
    clear_active_session();
    if (write_disconnect_success(writer, id)) {
        ESP_LOGI(kTag, "disconnect canceled pending Sui zkLogin proposal: id=%s", id);
    } else {
        signing::usb_response_log_write_failure("disconnect", id);
    }
    return true;
}

bool disconnect_pending_user_signing_for_session(
    const char* id,
    const char* session_id,
    const UsbOperationResponseWriter& writer)
{
    const signing::UserSigningFlowCoreSnapshot snapshot =
        signing::user_signing_flow_core_snapshot();
    if (!snapshot.active ||
        !signing::user_signing_flow_session_matches(session_id)) {
        return false;
    }

    const signing::UserSigningConfirmationResult result =
        signing::user_signing_confirmation_cancel_for_disconnect(session_id);
    if (result == signing::UserSigningConfirmationResult::busy) {
        writer.for_method("disconnect").write_error(id, "busy");
        return true;
    }

    clear_signing_panel_if_kind(UiPanelKind::user_signing_review, SensitiveUiClearPolicy::preserve);
    clear_signing_panel_if_kind(UiPanelKind::local_pin_auth, SensitiveUiClearPolicy::preserve);
    if (snapshot.request_id[0] != '\0' &&
        (id == nullptr || strcmp(snapshot.request_id, id) != 0)) {
        writer.for_method(snapshot.method)
            .write_error(snapshot.request_id, "invalid_session");
    }
    consume_user_signing_terminal_if_pending();
    g_active_user_signing_transport = ProtocolTransport::none;
    clear_active_session();
    if (write_disconnect_success(writer, id)) {
        ESP_LOGI(kTag, "disconnect canceled pending user_signing: id=%s", id);
    } else {
        signing::usb_response_log_write_failure("disconnect", id);
    }
    signing::avatar_overlay_show_message(
        "Signing canceled",
        MessageKind::rejected,
        UiMode::result,
        kResultDisplayMs);
    return true;
}

void clear_panel_locked(SensitiveUiClearPolicy policy)
{
    const UiPanelKind panel_kind = signing::drawing_surface_clear_panel_locked();
    if (panel_kind == UiPanelKind::none ||
        policy != SensitiveUiClearPolicy::wipe) {
        return;
    }

    apply_panel_cleanup_plan(
        panel_cleanup_plan(panel_kind, signing::UiPanelCleanupEvent::explicit_clear),
        "sensitive setup panel cleared",
        "storage maintenance panel cleared",
        "local PIN authorization panel cleared");
}

bool provisioning_welcome_available()
{
    bool ui_display_idle = false;
    {
        LvglLockGuard lock;
        ui_display_idle =
            signing::drawing_surface_ready() &&
            signing::drawing_surface_panel_locked() == nullptr &&
            signing::avatar_overlay_mode() == UiMode::none;
    }

    return signing::provisioning_runtime_state_is_unprovisioned() &&
           !signing::connect_approval_active() &&
           !signing::protocol_pin_approval_active() &&
           !signing::identification_display_active() &&
           !signing::provisioning_flow_active() &&
           !signing::local_pin_auth_flow_active() &&
           !signing::storage_maintenance_snapshot(xTaskGetTickCount()).flow_active &&
           ui_display_idle;
}

void clear_request_ui_for_identification();

TickType_t transient_ui_now()
{
    return xTaskGetTickCount();
}

UiMode transient_ui_overlay_mode()
{
    LvglLockGuard lock;
    return signing::avatar_overlay_mode();
}

bool transient_ui_show_message(
    const char* message,
    MessageKind kind,
    UiMode mode,
    uint32_t duration_ms,
    lv_event_cb_t click_callback)
{
    return signing::avatar_overlay_show_message(
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

const signing::TransientUiFlowOps& transient_ui_flow_ops()
{
    static const signing::TransientUiFlowOps ops = {
        transient_ui_now,
        provisioning_welcome_available,
        clear_request_ui_for_identification,
        signing::identification_display_begin,
        signing::identification_display_deadline_reached,
        signing::identification_display_clear,
        transient_ui_overlay_mode,
        signing::avatar_overlay_clear,
        signing::avatar_overlay_message_deadline_reached,
        transient_ui_show_message,
        signing::ui_event_bridge_setup_clicked_callback,
        transient_ui_log_warn,
    };
    return ops;
}

void show_provisioning_welcome_if_available()
{
    signing::transient_ui_show_provisioning_welcome_if_available(
        transient_ui_flow_ops());
}

void show_idle_signing_ui_for_current_state()
{
    show_persistent_error_recovery_if_needed();
    show_provisioning_welcome_if_available();
}

bool clear_signing_panel_if_kind(UiPanelKind expected_kind, SensitiveUiClearPolicy policy)
{
    LvglLockGuard lock;
    if (!signing::drawing_surface_panel_active(expected_kind)) {
        return true;
    }
    clear_panel_locked(policy);
    return true;
}

void clear_request_ui_for_identification()
{
    signing::avatar_overlay_clear();
    clear_signing_panel_if_kind(UiPanelKind::connect_review, SensitiveUiClearPolicy::preserve);
}

void show_identification_code(const char* code, uint32_t duration_ms)
{
    signing::transient_ui_show_identification_code(
        code,
        duration_ms,
        transient_ui_flow_ops());
}

void clear_identification_if_needed()
{
    signing::transient_ui_clear_identification_if_needed(transient_ui_flow_ops());
}

void clear_signing_message_if_needed()
{
    signing::transient_ui_clear_message_if_needed(transient_ui_flow_ops());
}

void clear_connect_review_state()
{
    signing::ui_event_bridge_reset_connect_choices();
    signing::connect_approval_clear();
    g_pending_connect_transport = ProtocolTransport::none;
    signing::identification_display_clear();
}

MessageKind connect_review_terminal_kind_to_message_kind(
    signing::ConnectReviewTerminalUiKind kind)
{
    switch (kind) {
        case signing::ConnectReviewTerminalUiKind::success:
            return MessageKind::success;
        case signing::ConnectReviewTerminalUiKind::rejected:
            return MessageKind::rejected;
        case signing::ConnectReviewTerminalUiKind::timeout:
            return MessageKind::timeout;
        case signing::ConnectReviewTerminalUiKind::error:
        default:
            return MessageKind::error;
    }
}

void show_result_and_clear_connect_review(
    const char* message,
    signing::ConnectReviewTerminalUiKind kind)
{
    clear_signing_panel_if_kind(UiPanelKind::connect_review, SensitiveUiClearPolicy::preserve);
    signing::avatar_overlay_show_message(
        message,
        connect_review_terminal_kind_to_message_kind(kind),
        UiMode::result,
        kResultDisplayMs);
    clear_connect_review_state();
}

signing::HumanApprovalInputMode connect_review_input_mode()
{
    return signing::human_approval_input_mode_or_default();
}

void show_connect_review()
{
    const signing::ConnectApprovalSnapshot approval =
        signing::connect_approval_snapshot();
    signing::identification_display_clear();
    if (signing::modal_draw_connect_review_panel(
            approval.client_name,
            connect_review_input_mode(),
            approval.approval_window)) {
        return;
    }
    ESP_LOGW(kTag, "connect could not show Agent-Q review UI");
}

bool setup_app_action_allowed()
{
    if (signing::connect_approval_active() ||
        signing::protocol_pin_approval_active() ||
        signing::storage_maintenance_snapshot(xTaskGetTickCount()).flow_active) {
        return false;
    }
    if (!refresh_persistent_material_consistency()) {
        return false;
    }
    return signing::provisioning_runtime_state_is_unprovisioned();
}

TickType_t provisioning_ui_now()
{
    return xTaskGetTickCount();
}

bool draw_import_word_entry_panel_for_provisioning(const char* notice)
{
    return signing::modal_draw_import_word_entry_panel(notice);
}

bool draw_pin_setup_panel_for_provisioning(const char* notice)
{
    return signing::modal_draw_pin_setup_panel(notice);
}

bool draw_pin_setup_processing_or_panel_for_provisioning()
{
    return signing::modal_draw_processing_overlay_on_current_panel(UiPanelKind::pin_entry) ||
           signing::modal_draw_pin_setup_panel();
}

void provisioning_ui_show_message(const char* message, MessageKind kind)
{
    signing::avatar_overlay_show_message(
        message,
        kind,
        UiMode::result,
        kResultDisplayMs);
}

signing::ProvisioningFlowCommitResult commit_setup_with_prepared_auth_for_provisioning(
    const uint8_t* root_material,
    size_t root_material_size,
    const signing::LocalAuthPreparedRecord* prepared_auth)
{
    const signing::PersistentMaterialCommitResult result =
        signing::persistent_material_commit_setup_with_prepared_auth(
            root_material,
            root_material_size,
            prepared_auth,
            persistent_material_ops());
    switch (result) {
        case signing::PersistentMaterialCommitResult::ok:
            return signing::ProvisioningFlowCommitResult::ok;
        case signing::PersistentMaterialCommitResult::missing_input:
            return signing::ProvisioningFlowCommitResult::missing_input;
        case signing::PersistentMaterialCommitResult::root_storage_error:
        case signing::PersistentMaterialCommitResult::policy_storage_error:
        case signing::PersistentMaterialCommitResult::local_auth_storage_error:
        case signing::PersistentMaterialCommitResult::signing_mode_storage_error:
        case signing::PersistentMaterialCommitResult::human_approval_setting_storage_error:
        case signing::PersistentMaterialCommitResult::sui_account_settings_storage_error:
        case signing::PersistentMaterialCommitResult::state_storage_error:
            return signing::ProvisioningFlowCommitResult::storage_error;
    }
    return signing::ProvisioningFlowCommitResult::storage_error;
}

void provisioning_ui_log_info(const char* message)
{
    ESP_LOGI(kTag, "%s", message != nullptr ? message : "");
}

void provisioning_ui_log_warn(const char* message)
{
    ESP_LOGW(kTag, "%s", message != nullptr ? message : "");
}

TickType_t storage_maintenance_ui_now()
{
    return xTaskGetTickCount();
}

bool storage_maintenance_ui_display_ready()
{
    LvglLockGuard lock;
    return signing::drawing_surface_ready();
}

bool storage_maintenance_ui_panel_active()
{
    LvglLockGuard lock;
    return signing::drawing_surface_panel_locked() != nullptr &&
           storage_maintenance_panel_matches_stage(signing::drawing_surface_panel_kind_locked());
}

bool local_settings_start_available()
{
    return provisioned_material_ready() &&
           signing::device_activity_allows_local_settings_start(
               current_device_activity());
}

bool local_error_recovery_available()
{
    return signing::device_activity_allows_local_error_recovery(
        current_device_activity());
}

bool draw_storage_maintenance_processing_overlay(UiPanelKind kind)
{
    return signing::modal_draw_processing_overlay_on_current_panel(kind);
}

void storage_maintenance_ui_show_message(const char* message, MessageKind kind)
{
    signing::avatar_overlay_show_message(
        message,
        kind,
        UiMode::result,
        kResultDisplayMs);
}

void storage_maintenance_ui_record_material_failure(
    signing::PersistentMaterialRuntimeFailure failure)
{
    signing::persistent_material_record_runtime_failure(
        failure,
        persistent_material_ops());
}

void storage_maintenance_ui_log_warn(const char* message)
{
    ESP_LOGW(kTag, "%s", message != nullptr ? message : "");
}

void storage_maintenance_ui_log_error(const char* message)
{
    ESP_LOGE(kTag, "%s", message != nullptr ? message : "");
}

const signing::ProvisioningUiFlowOps& provisioning_ui_ops()
{
    static const signing::ProvisioningUiFlowOps ops = {
        provisioning_ui_now,
        local_setup_start_allowed,
        setup_app_action_allowed,
        ui_panel_active,
        clear_signing_panel_if_kind,
        signing::modal_draw_setup_choice_panel,
        signing::modal_draw_backup_phrase_display,
        draw_import_word_entry_panel_for_provisioning,
        draw_pin_setup_panel_for_provisioning,
        draw_pin_setup_processing_or_panel_for_provisioning,
        signing::avatar_overlay_clear,
        provisioning_ui_show_message,
        commit_setup_with_prepared_auth_for_provisioning,
        provisioning_ui_log_info,
        provisioning_ui_log_warn,
        kProvisioningApprovalMaxMs,
        kBackupPhraseDisplayMs,
        kLocalPinSetupMs,
        kLocalProcessingDisplayMs,
        signing::kLocalAuthWorkerMaxMs,
    };
    return ops;
}

signing::StorageMaintenanceUiFlowOps storage_maintenance_ui_ops()
{
    return signing::StorageMaintenanceUiFlowOps{
        storage_maintenance_ui_now,
        provisioned_material_ready,
        local_settings_start_available,
        local_error_recovery_available,
        signing::persistent_material_consistency_error_active,
        storage_maintenance_ui_display_ready,
        ui_panel_active,
        storage_maintenance_ui_panel_active,
        clear_signing_panel_if_kind,
        signing::modal_draw_settings_menu_panel,
        signing::modal_draw_error_recovery_panel,
        signing::modal_draw_action_pin_panel,
        draw_storage_maintenance_processing_overlay,
        signing::local_settings_touch_entry_clear,
        storage_maintenance_ui_show_message,
        storage_maintenance_ui_record_material_failure,
        storage_maintenance_ui_log_warn,
        storage_maintenance_ui_log_error,
        storage_maintenance_persistence_ops(),
        signing::kStorageMaintenanceEntryMs,
        kLocalProcessingRenderDelayMs,
        kLocalProcessingDisplayMs,
        signing::kLocalAuthWorkerMaxMs,
    };
}

uint64_t local_pin_auth_wall_clock_ms()
{
    return static_cast<uint64_t>(esp_timer_get_time() / 1000LL);
}

bool local_pin_auth_panel_visible()
{
    LvglLockGuard lock;
    return signing::drawing_surface_panel_locked() != nullptr &&
           local_pin_auth_panel_matches_stage(signing::drawing_surface_panel_kind_locked());
}

bool draw_local_pin_auth_panel_for_flow(const char* notice)
{
    return signing::modal_draw_local_pin_auth_panel(notice);
}

bool draw_local_pin_auth_processing_overlay(UiPanelKind kind)
{
    return signing::modal_draw_processing_overlay_on_current_panel(kind);
}

void local_pin_auth_ui_show_message(const char* message, MessageKind kind)
{
    signing::avatar_overlay_show_message(
        message,
        kind,
        UiMode::result,
        kResultDisplayMs);
}

void local_pin_auth_record_material_failure(
    signing::PersistentMaterialRuntimeFailure failure)
{
    signing::persistent_material_record_runtime_failure(
        failure,
        persistent_material_ops());
}

const char* sui_proof_status_label(signing::SuiZkLoginProofRecordStatus status)
{
    switch (status) {
        case signing::SuiZkLoginProofRecordStatus::active:
            return "active";
        case signing::SuiZkLoginProofRecordStatus::missing:
            return "none";
        case signing::SuiZkLoginProofRecordStatus::invalid:
        case signing::SuiZkLoginProofRecordStatus::storage_error:
            return "error";
    }
    return "error";
}

const char* sui_active_identity_kind_label(signing::SuiActiveIdentityKind kind)
{
    switch (kind) {
        case signing::SuiActiveIdentityKind::none:
            return "none";
        case signing::SuiActiveIdentityKind::native:
            return "native";
        case signing::SuiActiveIdentityKind::zklogin:
            return "zkLogin";
        case signing::SuiActiveIdentityKind::error:
            return "error";
    }
    return "error";
}

bool sui_zklogin_proof_clear_available()
{
    return signing::sui_zklogin_proof_record_status() !=
           signing::SuiZkLoginProofRecordStatus::missing;
}

signing::LocalPinAuthSettingsCompletionResult
complete_policy_reset_setting_for_local_pin_auth()
{
    return signing::local_pin_auth_settings_completion_for_policy_reset(
        signing::store_default_policy());
}

signing::LocalPinAuthSettingsCompletionResult
complete_sui_zklogin_clear_setting_for_local_pin_auth()
{
    const bool wiped = signing::wipe_sui_zklogin_proof_record();
    clear_active_session();
    const bool cleared =
        wiped &&
        signing::sui_zklogin_proof_record_status() ==
            signing::SuiZkLoginProofRecordStatus::missing;
    return signing::local_pin_auth_settings_completion_for_sui_zklogin_clear(cleared);
}

bool begin_settings_pin_auth_handoff_for_local_pin_auth(const char* stale_log_message)
{
    return signing::storage_maintenance_ui_begin_settings_pin_auth_handoff(
        stale_log_message,
        storage_maintenance_ui_ops());
}

void restore_settings_menu_for_local_pin_auth(
    const char* display_failure_wipe_reason,
    const char* display_failure_message,
    MessageKind display_failure_kind)
{
    signing::storage_maintenance_ui_restore_settings_menu(
        display_failure_wipe_reason,
        display_failure_message,
        display_failure_kind,
        storage_maintenance_ui_ops());
}

void restore_sui_settings_for_local_pin_auth(
    const char* display_failure_wipe_reason,
    const char* display_failure_message,
    MessageKind display_failure_kind)
{
    const TickType_t now = xTaskGetTickCount();
    signing::storage_maintenance_begin_settings(
        signing::timeout_window_from_deadline(
            now,
            now + pdMS_TO_TICKS(signing::kStorageMaintenanceEntryMs)));
    if (draw_sui_settings_panel_from_current_state()) {
        return;
    }
    clear_storage_maintenance_flow(
        display_failure_wipe_reason != nullptr && display_failure_wipe_reason[0] != '\0'
            ? display_failure_wipe_reason
            : "local Sui settings display allocation failed");
    signing::avatar_overlay_show_message(
        display_failure_message != nullptr && display_failure_message[0] != '\0'
            ? display_failure_message
            : "Display error",
        display_failure_kind,
        UiMode::result,
        kResultDisplayMs);
}

signing::LocalPinAuthConnectPinBeginResult
begin_connect_pin_auth_for_local_pin_auth(
    const char* request_id,
    TickType_t now,
    signing::TimeoutWindow request_window)
{
    if (!signing::protocol_pin_approval_begin_connect(
            request_id,
            now,
            request_window)) {
        return signing::LocalPinAuthConnectPinBeginResult::unavailable;
    }
    if (!signing::local_pin_auth_begin_connect(now, request_window)) {
        return signing::LocalPinAuthConnectPinBeginResult::pin_unavailable;
    }
    return signing::LocalPinAuthConnectPinBeginResult::started;
}

const char* local_pin_connect_rejection_code(
    signing::LocalPinAuthConnectRejectReason reason)
{
    switch (reason) {
        case signing::LocalPinAuthConnectRejectReason::invalid_state:
            return "invalid_state";
        case signing::LocalPinAuthConnectRejectReason::ui_error:
            return "ui_error";
        case signing::LocalPinAuthConnectRejectReason::timeout:
            return "timeout";
        case signing::LocalPinAuthConnectRejectReason::user_rejected:
            return "user_rejected";
        case signing::LocalPinAuthConnectRejectReason::auth_unavailable:
            return "auth_unavailable";
    }
    return "invalid_state";
}

void write_connect_rejected_from_pin_for_local_pin_auth(
    const char* request_id,
    signing::LocalPinAuthConnectRejectReason reason)
{
    write_connect_rejected_response(
        request_id,
        local_pin_connect_rejection_code(reason));
}

void finish_connect_rejection_cleanup_for_local_pin_auth(bool clear_protocol_pin)
{
    signing::connect_approval_clear();
    g_pending_connect_transport = ProtocolTransport::none;
    if (clear_protocol_pin) {
        signing::protocol_pin_approval_clear();
    }
}

bool return_connect_review_from_pin_for_local_pin_auth(
    TickType_t now,
    signing::TimeoutWindow approval_window)
{
    char request_id[signing::kRequestIdSize] = {};
    signing::protocol_pin_approval_request_id_for_local_pin_purpose(
        signing::LocalPinAuthPurpose::connect,
        request_id,
        sizeof(request_id));
    signing::protocol_pin_approval_clear();
    if (signing::connect_approval_return_to_review(now, approval_window)) {
        return true;
    }
    write_connect_rejected_response(request_id, "invalid_state");
    signing::connect_approval_clear();
    return false;
}

signing::LocalPinAuthConnectSessionResult
replace_connect_session_from_pin_for_local_pin_auth(const char* request_id)
{
    if (replace_active_session()) {
        return signing::LocalPinAuthConnectSessionResult::connected;
    }
    if (request_id != nullptr && request_id[0] != '\0') {
        write_connect_error_response(request_id, "rng_unavailable");
    }
    ESP_LOGE(
        kTag,
        "connect PIN could not create session id: id=%s",
        request_id != nullptr ? request_id : "");
    return signing::LocalPinAuthConnectSessionResult::session_unavailable;
}

void finish_connect_session_error_for_local_pin_auth(const char*)
{
    signing::connect_approval_clear();
    g_pending_connect_transport = ProtocolTransport::none;
    signing::protocol_pin_approval_clear();
}

void finish_connect_approved_for_local_pin_auth(const char* request_id)
{
    signing::connect_approval_clear();
    if (request_id != nullptr && request_id[0] != '\0') {
        const bool written = write_connect_approved_response_for_pending_transport(request_id);
        if (!written) {
            signing::usb_response_log_write_failure("connect", request_id);
        }
    }
    signing::protocol_pin_approval_clear();
    ESP_LOGI(kTag, "connect PIN approved: id=%s", request_id != nullptr ? request_id : "");
}

void clear_policy_update_terminal_state();

bool policy_update_request_id_for_local_pin_auth(char* output, size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return false;
    }
    if (signing::protocol_pin_approval_request_id_for_local_pin_purpose(
            signing::LocalPinAuthPurpose::policy_update,
            output,
            output_size)) {
        return true;
    }
    const signing::PolicyUpdateFlowSnapshot snapshot =
        signing::policy_update_flow_snapshot();
    if (!snapshot.active ||
        snapshot.request_id == nullptr ||
        snapshot.request_id[0] == '\0') {
        return false;
    }
    strlcpy(output, snapshot.request_id, output_size);
    return true;
}

bool request_id_for_local_pin_auth(
    signing::LocalPinAuthPurpose purpose,
    char* output,
    size_t output_size)
{
    if (purpose == signing::LocalPinAuthPurpose::policy_update) {
        return policy_update_request_id_for_local_pin_auth(output, output_size);
    }
    return signing::request_backed_local_pin_request_id(purpose, output, output_size);
}

signing::PolicyUpdateFlowTransitionResult
return_policy_update_review_from_pin_for_local_pin_auth(
    TickType_t now,
    signing::TimeoutWindow review_window)
{
    signing::protocol_pin_approval_clear();
    return signing::policy_update_flow_return_to_review(now, review_window);
}

void finish_policy_update_unavailable_from_pin_for_local_pin_auth(
    const char* request_id,
    signing::LocalPinAuthPolicyUpdateUnavailableReason reason)
{
    switch (reason) {
        case signing::LocalPinAuthPolicyUpdateUnavailableReason::material_unavailable:
            if (request_id != nullptr && request_id[0] != '\0') {
                operation_response_writer_for_transport(g_pending_policy_update_transport)
                    .for_method("policy_propose")
                    .write_error(request_id, "invalid_state");
            }
            clear_policy_update_terminal_state();
            return;
        case signing::LocalPinAuthPolicyUpdateUnavailableReason::auth_unavailable:
            if (request_id != nullptr && request_id[0] != '\0') {
                const bool written =
                    write_policy_propose_outcome_with_current_policy(
                        request_id,
                        "consistency_error",
                        "consistency_error");
                if (!written) {
                    signing::usb_response_log_write_failure("policy_propose", request_id);
                }
            }
            clear_policy_update_terminal_state();
            return;
    }
}

signing::LocalPinAuthSuiZkLoginPinBeginResult
begin_sui_zklogin_proposal_pin_from_review_for_local_pin_auth(
    const char* request_id,
    TickType_t now)
{
    const signing::SuiZkLoginProposalSnapshot snapshot =
        signing::sui_zklogin_proposal_flow_snapshot();
    if (request_id == nullptr ||
        !snapshot.active ||
        snapshot.stage != signing::SuiZkLoginProposalStage::pin_entry ||
        snapshot.request_id == nullptr ||
        strcmp(snapshot.request_id, request_id) != 0) {
        return signing::LocalPinAuthSuiZkLoginPinBeginResult::unavailable;
    }
    if (!signing::protocol_pin_approval_begin_sui_zklogin_proposal(
            request_id,
            snapshot.session_id,
            now,
            snapshot.request_window)) {
        return signing::LocalPinAuthSuiZkLoginPinBeginResult::pin_unavailable;
    }
    if (!signing::local_pin_auth_begin_sui_zklogin_proposal(
            now,
            snapshot.request_window)) {
        signing::protocol_pin_approval_clear();
        return signing::LocalPinAuthSuiZkLoginPinBeginResult::pin_unavailable;
    }
    return signing::LocalPinAuthSuiZkLoginPinBeginResult::started;
}

signing::SuiZkLoginProposalTransitionResult
return_sui_zklogin_review_from_pin_for_local_pin_auth(TickType_t now)
{
    signing::protocol_pin_approval_clear();
    return signing::sui_zklogin_proposal_flow_return_to_review(now);
}

signing::SuiZkLoginProposalTerminalResult
record_sui_zklogin_consistency_error_from_pin_for_local_pin_auth()
{
    return signing::SuiZkLoginProposalTerminalResult::consistency_error;
}

signing::UserSigningConfirmationResult
complete_user_signing_pin_verify_from_local_pin_auth(
    const signing::LocalAuthWorkerResult& worker_result,
    TickType_t now,
    TickType_t lockout_until)
{
    return signing::user_signing_confirmation_complete_pin_verify_job_and_write_history(
        worker_result,
        now,
        lockout_until,
        write_user_signing_confirmation_history,
        nullptr);
}

void cancel_user_signing_for_ui_loss_from_local_pin_auth()
{
    signing::user_signing_flow_cancel_for_ui_loss();
}

void finish_user_signing_terminal_for_local_pin_auth(const char* request_id)
{
    finish_user_signing_terminal(request_id);
}

void local_pin_auth_log_warn(const char* message)
{
    ESP_LOGW(kTag, "%s", message != nullptr ? message : "");
}

signing::LocalPinAuthUiFlowOps local_pin_auth_ui_flow_ops()
{
    signing::LocalPinAuthUiFlowOps ops{};

    ops.timing.now = xTaskGetTickCount;
    ops.timing.wall_clock_ms = local_pin_auth_wall_clock_ms;
    ops.material_settings.provisioned_material_ready = provisioned_material_ready;
    ops.material_settings.human_approval_requires_pin = signing::human_approval_requires_pin;
    ops.material_settings.read_human_approval_input_mode = signing::read_human_approval_input_mode;
    ops.material_settings.read_signing_authorization_mode = signing::read_signing_authorization_mode;
    ops.material_settings.read_sui_account_settings = signing::read_sui_account_settings;
    ops.material_settings.complete_policy_reset_setting = complete_policy_reset_setting_for_local_pin_auth;
    ops.material_settings.sui_zklogin_proof_clear_available = sui_zklogin_proof_clear_available;
    ops.material_settings.complete_sui_zklogin_clear_setting =
        complete_sui_zklogin_clear_setting_for_local_pin_auth;
    ops.material_settings.begin_settings_pin_auth_handoff = begin_settings_pin_auth_handoff_for_local_pin_auth;
    ops.material_settings.restore_settings_menu = restore_settings_menu_for_local_pin_auth;
    ops.material_settings.restore_sui_settings = restore_sui_settings_for_local_pin_auth;

    ops.display.clear_panel_if_kind = clear_signing_panel_if_kind;
    ops.display.local_pin_panel_visible = local_pin_auth_panel_visible;
    ops.display.draw_local_pin_auth_panel = draw_local_pin_auth_panel_for_flow;
    ops.display.draw_processing_overlay_on_current_panel = draw_local_pin_auth_processing_overlay;
    ops.display.show_message = local_pin_auth_ui_show_message;
    ops.material_settings.record_material_failure = local_pin_auth_record_material_failure;
    ops.display.log_write_failure = signing::usb_response_log_write_failure;
    ops.display.log_warn = local_pin_auth_log_warn;

    ops.connect.begin_connect_pin_auth = begin_connect_pin_auth_for_local_pin_auth;
    ops.connect.write_connect_rejected_from_pin =
        write_connect_rejected_from_pin_for_local_pin_auth;
    ops.connect.finish_connect_rejection_cleanup =
        finish_connect_rejection_cleanup_for_local_pin_auth;
    ops.connect.return_connect_review_from_pin = return_connect_review_from_pin_for_local_pin_auth;
    ops.connect.show_connect_review = show_connect_review;
    ops.connect.replace_connect_session_from_pin = replace_connect_session_from_pin_for_local_pin_auth;
    ops.connect.finish_connect_session_error = finish_connect_session_error_for_local_pin_auth;
    ops.connect.finish_connect_approved = finish_connect_approved_for_local_pin_auth;

    ops.policy_update.show_policy_update_review = show_policy_update_review;
    ops.request.request_id_for_pin = request_id_for_local_pin_auth;
    ops.policy_update.require_pending_policy_update_session = require_pending_policy_update_session;
    ops.policy_update.return_policy_update_review_from_pin =
        return_policy_update_review_from_pin_for_local_pin_auth;
    ops.policy_update.return_policy_update_pin_entry_from_pin =
        signing::policy_update_flow_return_to_pin_entry;
    ops.policy_update.record_policy_update_ui_error_from_pin = signing::policy_update_flow_record_ui_error;
    ops.policy_update.record_policy_update_timed_out_from_pin = signing::policy_update_flow_record_timed_out;
    ops.policy_update.commit_policy_update_from_pin = signing::policy_update_flow_commit;
    ops.policy_update.finish_policy_update_unavailable_from_pin =
        finish_policy_update_unavailable_from_pin_for_local_pin_auth;
    ops.policy_update.finish_policy_update_terminal = finish_policy_update_terminal;
    ops.policy_update.finish_policy_update_error_terminal = finish_policy_update_error_terminal;

    ops.sui_zklogin.require_pending_sui_zklogin_proposal_session =
        require_pending_sui_zklogin_proposal_session;
    ops.sui_zklogin.begin_sui_zklogin_proposal_pin_from_review =
        begin_sui_zklogin_proposal_pin_from_review_for_local_pin_auth;
    ops.sui_zklogin.return_sui_zklogin_review_from_pin =
        return_sui_zklogin_review_from_pin_for_local_pin_auth;
    ops.sui_zklogin.return_sui_zklogin_pin_entry_from_pin =
        signing::sui_zklogin_proposal_flow_return_to_pin_entry;
    ops.sui_zklogin.record_sui_zklogin_ui_error_from_pin =
        signing::sui_zklogin_proposal_flow_record_ui_error;
    ops.sui_zklogin.record_sui_zklogin_timed_out_from_pin =
        signing::sui_zklogin_proposal_flow_record_timed_out;
    ops.sui_zklogin.record_sui_zklogin_rejected_from_pin =
        signing::sui_zklogin_proposal_flow_record_rejected;
    ops.sui_zklogin.record_sui_zklogin_consistency_error_from_pin =
        record_sui_zklogin_consistency_error_from_pin_for_local_pin_auth;
    ops.sui_zklogin.commit_sui_zklogin_from_pin = signing::sui_zklogin_proposal_flow_commit;
    ops.sui_zklogin.finish_sui_zklogin_proposal_terminal = finish_sui_zklogin_proposal_terminal;
    ops.sui_zklogin.finish_sui_zklogin_proposal_error_terminal =
        finish_sui_zklogin_proposal_error_terminal;
    ops.sui_zklogin.show_sui_zklogin_review = show_sui_zklogin_review;

    ops.user_signing.show_user_signing_review = show_user_signing_review;
    ops.user_signing.cancel_user_signing_for_pin_loss =
        signing::user_signing_confirmation_cancel_for_pin_loss;
    ops.user_signing.record_user_signing_timeout_from_pin =
        signing::user_signing_confirmation_record_timeout;
    ops.user_signing.return_user_signing_review_from_pin =
        signing::user_signing_confirmation_return_to_review_from_pin;
    ops.user_signing.cancel_user_signing_for_ui_loss = cancel_user_signing_for_ui_loss_from_local_pin_auth;
    ops.user_signing.complete_user_signing_pin_verify_from_pin =
        complete_user_signing_pin_verify_from_local_pin_auth;
    ops.user_signing.user_signing_terminal_pending_from_pin = signing::user_signing_flow_terminal_pending;
    ops.user_signing.execute_user_signing_from_pin = execute_user_signing_critical_section_and_finish;
    ops.user_signing.finish_user_signing_terminal = finish_user_signing_terminal_for_local_pin_auth;
    ops.user_signing.finish_user_signing_error_terminal = finish_user_signing_error_terminal;

    ops.timing.connect_approval_ms = kConnectApprovalDefaultMs;
    ops.timing.provisioning_approval_ms = kProvisioningApprovalMaxMs;
    ops.timing.local_pin_input_window_ms = kLocalPinInputWindowMs;
    ops.timing.local_processing_render_delay_ms = kLocalProcessingRenderDelayMs;
    ops.timing.local_processing_display_ms = kLocalProcessingDisplayMs;
    ops.timing.local_auth_worker_max_ms = signing::kLocalAuthWorkerMaxMs;
    ops.timing.storage_maintenance_entry_ms = signing::kStorageMaintenanceEntryMs;
    return ops;
}

void clear_setup_choice_if_needed()
{
    signing::provisioning_ui_clear_setup_choice_if_needed(provisioning_ui_ops());
}

void clear_import_word_entry_if_needed()
{
    signing::provisioning_ui_clear_import_word_entry_if_needed(provisioning_ui_ops());
}

void clear_backup_phrase_if_needed()
{
    signing::provisioning_ui_clear_backup_phrase_if_needed(provisioning_ui_ops());
}

void clear_pin_setup_if_needed()
{
    signing::provisioning_ui_clear_pin_setup_if_needed(provisioning_ui_ops());
}

void handle_pin_digit_from_local_ui(char digit)
{
    signing::provisioning_ui_handle_pin_digit(digit, provisioning_ui_ops());
}

void handle_pin_clear_from_local_ui()
{
    signing::provisioning_ui_handle_pin_clear(provisioning_ui_ops());
}

void handle_pin_backspace_from_local_ui()
{
    signing::provisioning_ui_handle_pin_backspace(provisioning_ui_ops());
}

void handle_pin_submit_from_local_ui()
{
    signing::provisioning_ui_handle_pin_submit(provisioning_ui_ops());
}

void clear_storage_maintenance_if_needed()
{
    signing::storage_maintenance_ui_clear_if_needed(storage_maintenance_ui_ops());
}

void commit_storage_maintenance_if_ready()
{
    signing::storage_maintenance_ui_commit_if_ready(storage_maintenance_ui_ops());
}

void start_local_settings_from_touch()
{
    signing::storage_maintenance_ui_start_from_touch(storage_maintenance_ui_ops());
}

void start_local_chain_settings_from_touch()
{
    if (!local_settings_start_available()) {
        ESP_LOGW(kTag, "Local chain settings touch ignored because settings are unavailable");
        signing::local_settings_touch_entry_clear();
        return;
    }

    const TickType_t now = xTaskGetTickCount();
    signing::storage_maintenance_begin_settings(
        timeout_window_from_now_ms(now, signing::kStorageMaintenanceEntryMs));
    show_chain_settings_menu_from_active_settings();
}

void cancel_storage_maintenance_from_ui(const char* message)
{
    signing::storage_maintenance_ui_cancel_action_pin_from_ui(
        message,
        storage_maintenance_ui_ops());
}

void close_local_settings_from_ui()
{
    signing::storage_maintenance_ui_close_settings_from_ui(storage_maintenance_ui_ops());
}

void start_local_transport_pairing_from_settings_menu()
{
    close_local_settings_from_ui();
    signing::local_transport_pairing_begin(xTaskGetTickCount());
}

void clear_local_transport_pairing_panel()
{
    clear_signing_panel_if_kind(UiPanelKind::local_transport_pairing, SensitiveUiClearPolicy::preserve);
}

void sync_local_transport_pairing_panel()
{
    if (!ui_panel_active(UiPanelKind::local_transport_pairing)) {
        return;
    }
    if (!signing::local_transport_pairing_snapshot().active) {
        clear_local_transport_pairing_panel();
    }
}

void cancel_local_transport_pairing_from_ui()
{
    signing::local_transport_pairing_cancel();
    clear_local_transport_pairing_panel();
    signing::avatar_overlay_show_message(
        "Pairing canceled",
        MessageKind::rejected,
        UiMode::result,
        kResultDisplayMs);
}

void show_persistent_error_recovery_if_needed()
{
    signing::storage_maintenance_ui_show_persistent_error_recovery_if_needed(
        storage_maintenance_ui_ops());
}

void cancel_error_recovery_from_ui()
{
    signing::storage_maintenance_ui_cancel_error_recovery_from_ui(
        storage_maintenance_ui_ops());
}

void confirm_error_recovery_from_ui()
{
    signing::storage_maintenance_ui_confirm_error_recovery_from_ui(
        storage_maintenance_ui_ops());
}

void start_wallet_erase_pin_from_settings_menu()
{
    signing::storage_maintenance_ui_start_wallet_erase_pin_from_settings_menu(
        storage_maintenance_ui_ops());
}

bool begin_connect_pin_auth(const char* id, const char* client_name)
{
    (void)client_name;
    return signing::local_pin_auth_ui_begin_connect(
        id,
        local_pin_auth_ui_flow_ops());
}

void clear_policy_update_terminal_state()
{
    signing::policy_update_flow_clear();
    signing::protocol_pin_approval_clear();
    g_pending_policy_update_transport = ProtocolTransport::none;
}

void finish_policy_propose_terminal(
    const char* request_id,
    signing::PolicyUpdateFlowTerminalResult result,
    const char* display_message,
    MessageKind display_kind,
    bool refresh_material_consistency = false)
{
    if (!write_policy_propose_outcome_with_current_policy(
            request_id,
            signing::policy_update_flow_terminal_status(result),
            signing::policy_update_flow_terminal_reason(result))) {
        signing::usb_response_log_write_failure("policy_propose", request_id);
    }
    clear_policy_update_terminal_state();
    if (refresh_material_consistency) {
        refresh_persistent_material_consistency();
    }
    signing::avatar_overlay_show_message(
        display_message,
        display_kind,
        UiMode::result,
        kResultDisplayMs);
}

void finish_policy_update_error_terminal(
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    (void)error_message;
    operation_response_writer_for_transport(g_pending_policy_update_transport)
        .for_method("policy_propose")
        .write_error(request_id, error_code);
    clear_policy_update_terminal_state();
    signing::avatar_overlay_show_message(
        display_message,
        MessageKind::error,
        UiMode::result,
        kResultDisplayMs);
}

void finish_policy_update_terminal(
    const char* request_id,
    signing::PolicyUpdateFlowTerminalResult result)
{
    if (request_id == nullptr || request_id[0] == '\0') {
        clear_policy_update_terminal_state();
        return;
    }

    switch (result) {
        case signing::PolicyUpdateFlowTerminalResult::applied:
            finish_policy_propose_terminal(
                request_id,
                result,
                "Policy updated",
                MessageKind::success);
            return;
        case signing::PolicyUpdateFlowTerminalResult::rejected:
            finish_policy_propose_terminal(
                request_id,
                result,
                "Policy rejected",
                MessageKind::rejected);
            return;
        case signing::PolicyUpdateFlowTerminalResult::timed_out:
            finish_policy_propose_terminal(
                request_id,
                result,
                "Policy timed out",
                MessageKind::timeout);
            return;
        case signing::PolicyUpdateFlowTerminalResult::ui_error:
            finish_policy_propose_terminal(
                request_id,
                result,
                "Display error",
                MessageKind::error);
            return;
        case signing::PolicyUpdateFlowTerminalResult::storage_error:
            finish_policy_propose_terminal(
                request_id,
                result,
                "Policy failed",
                MessageKind::error);
            return;
        case signing::PolicyUpdateFlowTerminalResult::consistency_error:
            finish_policy_propose_terminal(
                request_id,
                result,
                "Policy error",
                MessageKind::error,
                true);
            return;
        case signing::PolicyUpdateFlowTerminalResult::history_error:
            finish_policy_update_error_terminal(
                request_id,
                "history_unavailable",
                "Could not record policy update.",
                "History error");
            return;
        case signing::PolicyUpdateFlowTerminalResult::invalid_state:
        default:
            finish_policy_update_error_terminal(
                request_id,
                "invalid_state",
                "Policy update is unavailable.",
                "Policy unavailable");
            return;
    }
}

void clear_sui_zklogin_proposal_terminal_state()
{
    signing::sui_zklogin_proposal_flow_clear();
    signing::protocol_pin_approval_clear();
    g_pending_credential_proposal_transport = ProtocolTransport::none;
}

void finish_sui_zklogin_proposal_outcome_terminal(
    const char* request_id,
    signing::SuiZkLoginProposalTerminalResult result,
    const char* display_message,
    MessageKind display_kind)
{
    const bool session_ended =
        signing::sui_zklogin_proposal_terminal_ends_session(result);
    if (!signing::write_usb_credential_proposal_outcome_response(
            request_id,
            operation_response_writer_for_transport(
                g_pending_credential_proposal_transport),
            result,
            session_ended)) {
        signing::usb_response_log_write_failure("credential_propose", request_id);
    }
    clear_sui_zklogin_proposal_terminal_state();
    if (session_ended) {
        clear_active_session();
    }
    signing::avatar_overlay_show_message(
        display_message,
        display_kind,
        UiMode::result,
        kResultDisplayMs);
}

void finish_sui_zklogin_proposal_error_terminal(
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    (void)error_message;
    operation_response_writer_for_transport(g_pending_credential_proposal_transport)
        .for_method("credential_propose")
        .write_error(request_id, error_code);
    clear_sui_zklogin_proposal_terminal_state();
    signing::avatar_overlay_show_message(
        display_message,
        MessageKind::error,
        UiMode::result,
        kResultDisplayMs);
}

void finish_sui_zklogin_proposal_terminal(
    const char* request_id,
    signing::SuiZkLoginProposalTerminalResult result)
{
    if (request_id == nullptr || request_id[0] == '\0') {
        clear_sui_zklogin_proposal_terminal_state();
        return;
    }

    switch (result) {
        case signing::SuiZkLoginProposalTerminalResult::activated:
            finish_sui_zklogin_proposal_outcome_terminal(
                request_id,
                result,
                "zkLogin activated",
                MessageKind::success);
            return;
        case signing::SuiZkLoginProposalTerminalResult::rejected:
            finish_sui_zklogin_proposal_outcome_terminal(
                request_id,
                result,
                "zkLogin rejected",
                MessageKind::rejected);
            return;
        case signing::SuiZkLoginProposalTerminalResult::timed_out:
            finish_sui_zklogin_proposal_outcome_terminal(
                request_id,
                result,
                "zkLogin timed out",
                MessageKind::timeout);
            return;
        case signing::SuiZkLoginProposalTerminalResult::invalid_proof:
            finish_sui_zklogin_proposal_outcome_terminal(
                request_id,
                result,
                "zkLogin invalid",
                MessageKind::error);
            return;
        case signing::SuiZkLoginProposalTerminalResult::ui_error:
            finish_sui_zklogin_proposal_outcome_terminal(
                request_id,
                result,
                "Display error",
                MessageKind::error);
            return;
        case signing::SuiZkLoginProposalTerminalResult::storage_error:
            finish_sui_zklogin_proposal_outcome_terminal(
                request_id,
                result,
                "zkLogin failed",
                MessageKind::error);
            return;
        case signing::SuiZkLoginProposalTerminalResult::consistency_error:
            finish_sui_zklogin_proposal_outcome_terminal(
                request_id,
                result,
                "zkLogin error",
                MessageKind::error);
            return;
        case signing::SuiZkLoginProposalTerminalResult::invalid_state:
        default:
            finish_sui_zklogin_proposal_error_terminal(
                request_id,
                "invalid_state",
                "Sui zkLogin proposal is unavailable.",
                "zkLogin unavailable");
            return;
    }
}

void begin_policy_update_pin_auth_from_review()
{
    signing::policy_update_review_ui_continue(policy_update_review_ui_flow_ops());
}

void handle_policy_update_review_continue_from_ui()
{
    begin_policy_update_pin_auth_from_review();
}

void handle_policy_update_review_reject_from_ui()
{
    signing::policy_update_review_ui_reject(policy_update_review_ui_flow_ops());
}

void handle_sui_zklogin_review_continue_from_ui()
{
    signing::sui_zklogin_review_ui_continue(sui_zklogin_review_ui_flow_ops());
}

void handle_sui_zklogin_review_reject_from_ui()
{
    signing::sui_zklogin_review_ui_reject(sui_zklogin_review_ui_flow_ops());
}

void handle_user_signing_review_accept_from_ui()
{
    signing::user_signing_review_ui_accept(user_signing_review_ui_flow_ops());
}

void handle_user_signing_review_reject_from_ui()
{
    signing::user_signing_review_ui_reject(user_signing_review_ui_flow_ops());
}

void handle_user_signing_review_scroll_started_from_ui()
{
    signing::user_signing_review_ui_scroll_started(user_signing_review_ui_flow_ops());
}

void handle_user_signing_review_scroll_finished_from_ui()
{
    signing::user_signing_review_ui_scroll_finished(user_signing_review_ui_flow_ops());
}

void start_settings_human_approval_input_from_settings_menu()
{
    signing::local_pin_auth_ui_start_settings_human_approval_input(
        local_pin_auth_ui_flow_ops());
}

void start_settings_signing_mode_from_settings_menu()
{
    signing::local_pin_auth_ui_start_settings_signing_mode(
        local_pin_auth_ui_flow_ops());
}

void start_settings_policy_reset_from_settings_menu()
{
    signing::local_pin_auth_ui_start_settings_policy_reset(
        local_pin_auth_ui_flow_ops());
}

void start_settings_change_pin_from_settings_menu()
{
    signing::local_pin_auth_ui_start_settings_change_pin(
        local_pin_auth_ui_flow_ops());
}

void show_chain_settings_menu_from_active_settings()
{
    const signing::StorageMaintenanceSnapshot reset =
        signing::storage_maintenance_snapshot(xTaskGetTickCount());
    if (reset.stage != signing::StorageMaintenanceStage::settings_menu) {
        ESP_LOGW(kTag, "Stale chain settings action ignored");
        return;
    }

    if (!signing::modal_draw_chain_settings_menu_panel()) {
        clear_storage_maintenance_flow("Chain settings display allocation failed");
        signing::avatar_overlay_show_message(
            "Display error",
            MessageKind::error,
            UiMode::result,
            kResultDisplayMs);
    }
}

bool draw_sui_settings_panel_from_current_state()
{
    const signing::SuiActiveIdentity identity =
        signing::resolve_active_sui_identity();
    const signing::SuiZkLoginProofRecordStatus proof_status =
        signing::sui_zklogin_proof_record_status();
    const char* address =
        identity.address[0] != '\0' ? identity.address : "unavailable";
    const char* max_epoch =
        identity.kind == signing::SuiActiveIdentityKind::zklogin &&
                identity.zklogin.max_epoch[0] != '\0'
            ? identity.zklogin.max_epoch
            : "none";
    const char* proof_hash =
        identity.kind == signing::SuiActiveIdentityKind::zklogin &&
                identity.zklogin.proof_hash[0] != '\0'
            ? identity.zklogin.proof_hash
            : nullptr;
    signing::SuiAccountSettings account_settings =
        signing::kDefaultSuiAccountSettings;
    const bool account_settings_read_ok =
        signing::read_sui_account_settings(&account_settings);

    const signing::SuiSettingsViewModel model{
        sui_active_identity_kind_label(identity.kind),
        address,
        sui_proof_status_label(proof_status),
        max_epoch,
        proof_hash,
        account_settings_read_ok
            ? (account_settings.accept_gas_sponsor ? "ACCEPT" : "REJECT")
            : "ERR",
        account_settings_read_ok,
        proof_status != signing::SuiZkLoginProofRecordStatus::missing,
    };
    return signing::modal_draw_sui_settings_panel(model);
}

void show_sui_settings_from_chain_settings()
{
    const signing::StorageMaintenanceSnapshot reset =
        signing::storage_maintenance_snapshot(xTaskGetTickCount());
    if (reset.stage != signing::StorageMaintenanceStage::settings_menu ||
        !ui_panel_active(UiPanelKind::chain_settings_menu)) {
        ESP_LOGW(kTag, "Stale Sui settings action ignored");
        return;
    }

    if (!draw_sui_settings_panel_from_current_state()) {
        clear_storage_maintenance_flow("Sui settings display allocation failed");
        signing::avatar_overlay_show_message(
            "Display error",
            MessageKind::error,
            UiMode::result,
            kResultDisplayMs);
    }
}

void show_chain_settings_menu_from_sui_settings()
{
    const signing::StorageMaintenanceSnapshot reset =
        signing::storage_maintenance_snapshot(xTaskGetTickCount());
    if (reset.stage != signing::StorageMaintenanceStage::settings_menu ||
        !ui_panel_active(UiPanelKind::sui_settings)) {
        ESP_LOGW(kTag, "Stale Sui settings back ignored");
        return;
    }
    if (!signing::modal_draw_chain_settings_menu_panel()) {
        clear_storage_maintenance_flow("chain settings display allocation failed after Sui back");
        signing::avatar_overlay_show_message(
            "Display error",
            MessageKind::error,
            UiMode::result,
            kResultDisplayMs);
    }
}

void start_sui_gas_sponsor_from_sui_settings()
{
    if (!ui_panel_active(UiPanelKind::sui_settings)) {
        ESP_LOGW(kTag, "Stale Sui gas sponsor setting ignored");
        return;
    }
    signing::local_pin_auth_ui_start_settings_sui_accept_gas_sponsor(
        local_pin_auth_ui_flow_ops());
}

void start_sui_zklogin_clear_from_sui_settings()
{
    if (!ui_panel_active(UiPanelKind::sui_settings)) {
        ESP_LOGW(kTag, "Stale Sui zkLogin clear ignored");
        return;
    }
    signing::local_pin_auth_ui_start_settings_sui_zklogin_clear(
        local_pin_auth_ui_flow_ops());
}

void cancel_local_pin_auth_from_ui(const char* message)
{
    signing::local_pin_auth_ui_cancel(message, local_pin_auth_ui_flow_ops());
}

void handle_local_pin_auth_digit_from_ui(char digit)
{
    signing::local_pin_auth_ui_handle_digit(
        digit,
        local_pin_auth_ui_flow_ops());
}

void handle_local_pin_auth_clear_from_ui()
{
    signing::local_pin_auth_ui_handle_clear(local_pin_auth_ui_flow_ops());
}

void handle_local_pin_auth_backspace_from_ui()
{
    signing::local_pin_auth_ui_handle_backspace(local_pin_auth_ui_flow_ops());
}

void handle_local_pin_auth_submit_from_ui()
{
    signing::local_pin_auth_ui_handle_submit(local_pin_auth_ui_flow_ops());
}

void handle_action_pin_digit_from_local_ui(char digit)
{
    signing::storage_maintenance_ui_handle_action_pin_digit(
        digit,
        storage_maintenance_ui_ops());
}

void handle_action_pin_clear_from_local_ui()
{
    signing::storage_maintenance_ui_handle_action_pin_clear(
        storage_maintenance_ui_ops());
}

void handle_action_pin_backspace_from_local_ui()
{
    signing::storage_maintenance_ui_handle_action_pin_backspace(
        storage_maintenance_ui_ops());
}

void handle_action_pin_submit_from_local_ui()
{
    signing::storage_maintenance_ui_handle_action_pin_submit(
        storage_maintenance_ui_ops());
}

void commit_local_pin_setting_if_ready()
{
    signing::local_pin_auth_ui_commit_setting_if_ready(
        local_pin_auth_ui_flow_ops());
}

void handle_setup_auth_worker_result(signing::LocalAuthWorkerResult& worker_result)
{
    signing::provisioning_ui_handle_setup_auth_worker_result(
        worker_result,
        provisioning_ui_ops());
}

void handle_storage_maintenance_auth_worker_result(const signing::LocalAuthWorkerResult& worker_result)
{
    signing::storage_maintenance_ui_handle_auth_worker_result(
        worker_result,
        storage_maintenance_ui_ops());
}

void handle_local_pin_auth_verify_worker_result(
    const signing::LocalAuthWorkerResult& worker_result)
{
    signing::local_pin_auth_ui_handle_verify_worker_result(
        worker_result,
        local_pin_auth_ui_flow_ops());
}

void handle_local_pin_auth_prepare_worker_result(
    const signing::LocalAuthWorkerResult& worker_result)
{
    signing::local_pin_auth_ui_handle_prepare_worker_result(
        worker_result,
        local_pin_auth_ui_flow_ops());
}

void drain_local_auth_worker_results()
{
    signing::LocalAuthWorkerResult worker_result = {};
    while (signing::local_auth_worker_poll_result(&worker_result)) {
        switch (worker_result.owner) {
            case signing::LocalAuthWorkerOwner::provisioning_setup:
                handle_setup_auth_worker_result(worker_result);
                break;
            case signing::LocalAuthWorkerOwner::storage_maintenance:
                handle_storage_maintenance_auth_worker_result(worker_result);
                break;
            case signing::LocalAuthWorkerOwner::local_pin_auth:
                if (worker_result.operation == signing::LocalAuthWorkerOperation::verify_pin) {
                    handle_local_pin_auth_verify_worker_result(worker_result);
                } else {
                    handle_local_pin_auth_prepare_worker_result(worker_result);
                }
                break;
        }
        signing::local_auth_worker_wipe_result(&worker_result);
    }
}

void clear_local_pin_auth_if_needed()
{
    signing::local_pin_auth_ui_clear_if_needed(local_pin_auth_ui_flow_ops());
}

void clear_user_signing_review_if_needed()
{
    signing::user_signing_review_ui_clear_if_needed(user_signing_review_ui_flow_ops());
}

void clear_policy_update_review_if_needed()
{
    signing::policy_update_review_ui_clear_if_needed(policy_update_review_ui_flow_ops());
}

void clear_sui_zklogin_review_if_needed()
{
    signing::sui_zklogin_review_ui_clear_if_needed(sui_zklogin_review_ui_flow_ops());
}

void poll_local_settings_touch_entry()
{
    if (!local_settings_touch_entry_candidate_allowed()) {
        signing::local_settings_touch_entry_clear();
        return;
    }

    const auto touch = hal_bridge::get_touch_point();
    signing::LocalSettingsTouchEntryTarget target =
        signing::LocalSettingsTouchEntryTarget::none;
    if (touch.num > 0 && touch.y >= 0 && touch.y < kSettingsTouchEntryHeight) {
        if (touch.x < kSettingsTouchEntryWidth) {
            target = signing::LocalSettingsTouchEntryTarget::chain_settings;
        } else if (touch.x >= kScreenWidth - kSettingsTouchEntryWidth) {
            target = signing::LocalSettingsTouchEntryTarget::device_settings;
        }
    }
    const TickType_t now = xTaskGetTickCount();
    if (signing::local_settings_touch_entry_update(
            target,
            now,
            pdMS_TO_TICKS(kSettingsTouchEntryMs))) {
        if (target == signing::LocalSettingsTouchEntryTarget::chain_settings) {
            signing::ui_event_bridge_enqueue_chain_settings_requested();
        } else {
            signing::ui_event_bridge_enqueue_settings_requested();
        }
    }
}

bool connect_local_pin_flow_active()
{
    const signing::LocalPinAuthSnapshot snapshot =
        signing::local_pin_auth_snapshot(xTaskGetTickCount());
    return snapshot.flow_active &&
           snapshot.purpose == LocalPinAuthPurpose::connect;
}

void clear_local_transport_protocol_state_if_disconnected()
{
    if (signing::local_transport_pairing_established() &&
        signing::local_transport_pairing_connected()) {
        return;
    }

    const signing::UsbSessionLossPlan plan =
        current_local_transport_session_loss_plan(xTaskGetTickCount());
    if (plan.relevant) {
        clear_session_bound_state_for_plan(
            plan,
            "local transport disconnected during local PIN authorization",
            "local transport disconnected during user_signing",
            false,
            "local transport disconnected; session-bound state cleared");
        signing::avatar_overlay_show_message(
            "Local transport disconnected",
            MessageKind::usb_disconnected,
            UiMode::result,
            kResultDisplayMs);
    }
}

bool begin_connect_pin_auth_from_review(signing::TimeoutTick now)
{
    if (!signing::connect_approval_review_action_available(now)) {
        return false;
    }
    const signing::ConnectApprovalSnapshot approval =
        signing::connect_approval_snapshot();
    clear_signing_panel_if_kind(UiPanelKind::connect_review, SensitiveUiClearPolicy::preserve);
    return begin_connect_pin_auth(approval.request_id, approval.client_name);
}

bool receive_connect_review_choice(ConnectApprovalChoice* choice)
{
    return signing::ui_event_bridge_receive_connect_choice(choice);
}

bool connect_review_panel_visible()
{
    LvglLockGuard lock;
    return signing::drawing_surface_panel_locked() != nullptr &&
           is_connect_review_panel_kind(signing::drawing_surface_panel_kind_locked());
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

const signing::ConnectReviewResponseFlowOps& connect_review_response_flow_ops()
{
    static const signing::ConnectReviewResponseFlowOps ops = {
        xTaskGetTickCount,
        connect_local_pin_flow_active,
        signing::ui_event_bridge_reset_connect_choices,
        receive_connect_review_choice,
        signing::connect_approval_awaiting_choice,
        signing::human_approval_requires_pin,
        begin_connect_pin_auth_from_review,
        signing::connect_approval_choose,
        signing::connect_approval_snapshot,
        signing::connect_approval_deadline_reached,
        signing::connect_approval_request_id,
        signing::connect_approval_clear,
        replace_active_session,
        write_connect_error_response,
        write_connect_approved_response_for_pending_transport,
        write_connect_rejected_response,
        log_connect_review_flow_info,
        log_connect_review_flow_error,
        signing::usb_response_log_write_failure,
        log_connect_review_recovered,
        show_result_and_clear_connect_review,
        connect_review_panel_visible,
        show_connect_review,
    };
    return ops;
}

void run_connect_review_response_flow()
{
    signing::connect_review_response_flow_run(connect_review_response_flow_ops());
}

void start_local_provisioning_from_setup_touch()
{
    signing::provisioning_ui_start_generate_from_setup_choice(provisioning_ui_ops());
}

void show_setup_choice_from_setup_touch()
{
    signing::provisioning_ui_show_setup_choice_from_touch(provisioning_ui_ops());
}

void start_local_import_from_setup_choice()
{
    signing::provisioning_ui_start_import_from_setup_choice(provisioning_ui_ops());
}

void cancel_setup_from_local_ui()
{
    signing::provisioning_ui_cancel_from_local_ui(provisioning_ui_ops());
}

void return_to_setup_choice_from_local_ui()
{
    signing::provisioning_ui_return_to_setup_choice(provisioning_ui_ops());
}

void confirm_backup_phrase_from_local_ui()
{
    signing::provisioning_ui_confirm_backup_phrase(provisioning_ui_ops());
}

void handle_import_slot_from_local_ui(uint8_t slot)
{
    signing::provisioning_ui_handle_import_slot(slot, provisioning_ui_ops());
}

void handle_import_letter_from_local_ui(char letter)
{
    signing::provisioning_ui_handle_import_letter(letter, provisioning_ui_ops());
}

void handle_import_clear_from_local_ui()
{
    signing::provisioning_ui_handle_import_clear(provisioning_ui_ops());
}

void handle_import_candidate_from_local_ui(uint16_t word_index)
{
    signing::provisioning_ui_handle_import_candidate(word_index, provisioning_ui_ops());
}

void handle_import_previous_from_local_ui()
{
    signing::provisioning_ui_handle_import_previous(provisioning_ui_ops());
}

void handle_import_next_from_local_ui()
{
    signing::provisioning_ui_handle_import_next(provisioning_ui_ops());
}

void drain_ui_events()
{
    UiEvent event;
    while (signing::ui_event_bridge_receive(&event)) {
        if (event.kind == UiEventKind::setup_requested) {
            show_setup_choice_from_setup_touch();
            continue;
        }

        if (event.kind == UiEventKind::setup_generate_requested) {
            start_local_provisioning_from_setup_touch();
            continue;
        }

        if (event.kind == UiEventKind::setup_import_requested) {
            start_local_import_from_setup_choice();
            continue;
        }

        if (event.kind == UiEventKind::setup_cancel_requested) {
            cancel_setup_from_local_ui();
            continue;
        }

        if (event.kind == UiEventKind::ui_surface_ready) {
            show_idle_signing_ui_for_current_state();
            continue;
        }

        if (event.kind == UiEventKind::settings_requested) {
            start_local_settings_from_touch();
            continue;
        }

        if (event.kind == UiEventKind::chain_settings_requested) {
            start_local_chain_settings_from_touch();
            continue;
        }

        if (event.kind == UiEventKind::chain_settings_sui_requested) {
            show_sui_settings_from_chain_settings();
            continue;
        }

        if (event.kind == UiEventKind::settings_cancel_requested) {
            close_local_settings_from_ui();
            continue;
        }

        if (event.kind == UiEventKind::settings_human_approval_input_requested) {
            start_settings_human_approval_input_from_settings_menu();
            continue;
        }

        if (event.kind == UiEventKind::settings_signing_mode_requested) {
            start_settings_signing_mode_from_settings_menu();
            continue;
        }

        if (event.kind == UiEventKind::settings_policy_reset_requested) {
            start_settings_policy_reset_from_settings_menu();
            continue;
        }

        if (event.kind == UiEventKind::settings_change_pin_requested) {
            start_settings_change_pin_from_settings_menu();
            continue;
        }

        if (event.kind == UiEventKind::settings_wallet_erase_requested) {
            start_wallet_erase_pin_from_settings_menu();
            continue;
        }

        if (event.kind == UiEventKind::settings_local_transport_pairing_requested) {
            start_local_transport_pairing_from_settings_menu();
            continue;
        }

        if (event.kind == UiEventKind::local_transport_pairing_cancel_requested) {
            cancel_local_transport_pairing_from_ui();
            continue;
        }

        if (event.kind == UiEventKind::sui_settings_back_requested) {
            show_chain_settings_menu_from_sui_settings();
            continue;
        }

        if (event.kind == UiEventKind::sui_settings_gas_sponsor_requested) {
            start_sui_gas_sponsor_from_sui_settings();
            continue;
        }

        if (event.kind == UiEventKind::sui_settings_clear_requested) {
            start_sui_zklogin_clear_from_sui_settings();
            continue;
        }

        if (event.kind == UiEventKind::error_recovery_action_requested) {
            confirm_error_recovery_from_ui();
            continue;
        }

        if (event.kind == UiEventKind::error_recovery_cancel_requested) {
            cancel_error_recovery_from_ui();
            continue;
        }

        if (event.kind == UiEventKind::storage_action_cancel_requested) {
            cancel_storage_maintenance_from_ui("Storage action canceled");
            continue;
        }

        if (event.kind == UiEventKind::backup_phrase_cancel_requested) {
            return_to_setup_choice_from_local_ui();
            continue;
        }

        if (event.kind == UiEventKind::backup_phrase_confirm_requested) {
            confirm_backup_phrase_from_local_ui();
            continue;
        }

        if (event.kind == UiEventKind::import_slot_requested) {
            handle_import_slot_from_local_ui(event.slot);
            continue;
        }

        if (event.kind == UiEventKind::import_letter_requested) {
            handle_import_letter_from_local_ui(event.letter);
            continue;
        }

        if (event.kind == UiEventKind::import_clear_requested) {
            handle_import_clear_from_local_ui();
            continue;
        }

        if (event.kind == UiEventKind::import_candidate_requested) {
            handle_import_candidate_from_local_ui(event.word_index);
            continue;
        }

        if (event.kind == UiEventKind::import_previous_requested) {
            handle_import_previous_from_local_ui();
            continue;
        }

        if (event.kind == UiEventKind::import_next_requested) {
            handle_import_next_from_local_ui();
            continue;
        }

        if (event.kind == UiEventKind::import_cancel_requested) {
            return_to_setup_choice_from_local_ui();
            continue;
        }

        if (event.kind == UiEventKind::policy_update_review_continue_requested) {
            handle_policy_update_review_continue_from_ui();
            continue;
        }

        if (event.kind == UiEventKind::policy_update_review_reject_requested) {
            handle_policy_update_review_reject_from_ui();
            continue;
        }

        if (event.kind == UiEventKind::sui_zklogin_review_continue_requested) {
            handle_sui_zklogin_review_continue_from_ui();
            continue;
        }

        if (event.kind == UiEventKind::sui_zklogin_review_reject_requested) {
            handle_sui_zklogin_review_reject_from_ui();
            continue;
        }

        if (event.kind == UiEventKind::user_signing_review_accept_requested) {
            handle_user_signing_review_accept_from_ui();
            continue;
        }

        if (event.kind == UiEventKind::user_signing_review_reject_requested) {
            handle_user_signing_review_reject_from_ui();
            continue;
        }

        if (event.kind == UiEventKind::user_signing_review_scroll_started) {
            handle_user_signing_review_scroll_started_from_ui();
            continue;
        }

        if (event.kind == UiEventKind::user_signing_review_scroll_finished) {
            handle_user_signing_review_scroll_finished_from_ui();
            continue;
        }

        if (event.kind == UiEventKind::pin_digit_requested) {
            if (signing::provisioning_flow_snapshot().accepts_setup_pin_input) {
                handle_pin_digit_from_local_ui(event.digit);
            } else if (signing::storage_maintenance_ui_accepts_action_pin_input()) {
                handle_action_pin_digit_from_local_ui(event.digit);
            } else if (local_pin_auth_accepts_keypad_input()) {
                handle_local_pin_auth_digit_from_ui(event.digit);
            }
            continue;
        }

        if (event.kind == UiEventKind::pin_clear_requested) {
            if (signing::provisioning_flow_snapshot().accepts_setup_pin_input) {
                handle_pin_clear_from_local_ui();
            } else if (signing::storage_maintenance_ui_accepts_action_pin_input()) {
                handle_action_pin_clear_from_local_ui();
            } else if (local_pin_auth_accepts_keypad_input()) {
                handle_local_pin_auth_clear_from_ui();
            }
            continue;
        }

        if (event.kind == UiEventKind::pin_backspace_requested) {
            if (signing::provisioning_flow_snapshot().accepts_setup_pin_input) {
                handle_pin_backspace_from_local_ui();
            } else if (signing::storage_maintenance_ui_accepts_action_pin_input()) {
                handle_action_pin_backspace_from_local_ui();
            } else if (local_pin_auth_accepts_keypad_input()) {
                handle_local_pin_auth_backspace_from_ui();
            }
            continue;
        }

        if (event.kind == UiEventKind::pin_submit_requested) {
            if (signing::provisioning_flow_snapshot().accepts_setup_pin_input) {
                handle_pin_submit_from_local_ui();
            } else if (signing::storage_maintenance_ui_accepts_action_pin_input()) {
                handle_action_pin_submit_from_local_ui();
            } else if (local_pin_auth_accepts_keypad_input()) {
                handle_local_pin_auth_submit_from_ui();
            }
            continue;
        }

        if (event.kind == UiEventKind::pin_cancel_requested) {
            if (signing::provisioning_flow_snapshot().accepts_setup_pin_input) {
                cancel_setup_from_local_ui();
            } else if (signing::storage_maintenance_ui_accepts_action_pin_input()) {
                cancel_storage_maintenance_from_ui("Storage action canceled");
            } else if (local_pin_auth_accepts_keypad_input()) {
                cancel_local_pin_auth_from_ui("Settings canceled");
            }
            continue;
        }

        if (event.kind != UiEventKind::panel_deleted) {
            continue;
        }
        if (event.panel_kind == UiPanelKind::local_transport_pairing) {
            signing::local_transport_pairing_handle_display_loss();
            continue;
        }
        apply_panel_cleanup_plan(
            panel_cleanup_plan(event.panel_kind, signing::UiPanelCleanupEvent::external_delete),
            "setup panel deleted",
            "storage maintenance panel deleted",
            "local PIN authorization panel deleted");
    }
}

void show_policy_signing_notification(
    const char* message,
    MessageKind kind)
{
    signing::avatar_overlay_show_message(
        message,
        kind,
        UiMode::result,
        kResultDisplayMs);
}

const signing::UsbGetStatusHandlerOps& usb_get_status_handler_ops()
{
    static const signing::UsbGetStatusHandlerOps ops = {
        refresh_persistent_material_consistency,
        write_payload_delivery_safe_read_admission_error,
        usb_device_status_info,
    };
    return ops;
}

void handle_get_status_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_get_status_request(
        id,
        request,
        writer,
        usb_get_status_handler_ops());
}

const signing::UsbOperationHandlers& usb_operation_handlers();

void handle_protocol_request_line(
    const char* line,
    const UsbOperationResponseWriter& writer,
    ProtocolTransport transport)
{
    ScopedRequestTransport scoped_transport(transport);
    signing::handle_usb_request_line(
        line,
        current_timeout_tick(),
        writer,
        usb_operation_handlers(),
        resolve_request_payload_ref);
}

void handle_local_transport_request_line(
    const char* line,
    const UsbOperationResponseWriter& writer)
{
    handle_protocol_request_line(
        line,
        writer,
        ProtocolTransport::local_transport);
}

const signing::UsbIdentifyDeviceHandlerOps& usb_identify_device_handler_ops()
{
    static const signing::UsbIdentifyDeviceHandlerOps ops = {
        write_payload_delivery_identify_device_busy,
        signing::transient_ui_identification_code_safe,
        show_identification_code,
        usb_device_status_info,
        kIdentifyDisplayDefaultMs,
    };
    return ops;
}

void handle_identify_device_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_identify_device_request(
        id,
        request,
        writer,
        usb_identify_device_handler_ops());
}

signing::TimeoutWindow make_connect_approval_window(signing::TimeoutTick now)
{
    return signing::timeout_window_from_deadline(
        now,
        now + pdMS_TO_TICKS(kConnectApprovalDefaultMs));
}

void show_connect_unavailable()
{
    signing::avatar_overlay_show_message(
        "Connect unavailable",
        MessageKind::error,
        UiMode::result,
        kResultDisplayMs);
}

void reset_connect_review_choice_queue()
{
    signing::ui_event_bridge_reset_connect_choices();
}

void record_connect_waiting_for_review(const char* id, const char* client_name)
{
    ESP_LOGI(kTag, "connect waiting for review: id=%s client=%s", id, client_name);
}

bool begin_connect_approval(
    const char* id,
    const char* client_name,
    signing::TimeoutTick now,
    signing::TimeoutWindow approval_window)
{
    if (!signing::connect_approval_begin(id, client_name, now, approval_window)) {
        return false;
    }
    g_pending_connect_transport = g_current_request_transport;
    return true;
}

const signing::UsbConnectHandlerOps& connect_handler_ops()
{
    static const signing::UsbConnectHandlerOps ops = {
        provisioned_material_ready,
        write_connect_admission_error,
        write_existing_session_connect_response,
        current_timeout_tick,
        make_connect_approval_window,
        begin_connect_approval,
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
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_connect_request(id, request, writer, connect_handler_ops());
}

const signing::UsbRetainedResponseHandlerOps& retained_response_handler_ops()
{
    static const signing::UsbRetainedResponseHandlerOps ops = {
        provisioned_material_ready,
        write_payload_delivery_retained_response_admission_error,
        require_active_matching_session,
    };
    return ops;
}

void handle_get_result_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_get_result_request(id, request, writer, retained_response_handler_ops());
}

void handle_ack_result_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_ack_result_request(id, request, writer, retained_response_handler_ops());
}

void record_root_material_unreadable_for_session_read()
{
    // A provisioned device whose stored root material is unreadable is inconsistent.
    // Fail closed so status/connect/account reads stop treating it as provisioned
    // until local recovery/reset handles the condition.
    signing::persistent_material_record_runtime_failure(
        signing::PersistentMaterialRuntimeFailure::root_material_unreadable,
        persistent_material_ops());
}

void record_active_policy_unavailable_for_session_read()
{
    signing::persistent_material_record_runtime_failure(
        signing::PersistentMaterialRuntimeFailure::active_policy_unavailable,
        persistent_material_ops());
}

bool sui_zklogin_credential_available_for_session_read()
{
    return signing::resolve_active_sui_identity().kind ==
           signing::SuiActiveIdentityKind::native;
}

const signing::UsbSessionReadHandlerOps& session_read_handler_ops()
{
    static const signing::UsbSessionReadHandlerOps ops = {
        provisioned_material_ready,
        write_busy_if_pending_or_local_flow_active_allow_settings,
        write_payload_delivery_safe_read_admission_error,
        require_active_matching_session,
        signing::read_signing_authorization_mode,
        signing::read_sui_account_settings,
        sui_zklogin_credential_available_for_session_read,
        signing::resolve_active_sui_identity,
        record_root_material_unreadable_for_session_read,
    };
    return ops;
}

signing::TimeoutWindow payload_transfer_timeout_window_for_size(size_t size_bytes)
{
    const uint32_t window_ms = signing::payload_delivery_timeout_window_ms_for_size(size_bytes);
    const TickType_t now = xTaskGetTickCount();
    return signing::timeout_window_from_deadline(
        now,
        now + pdMS_TO_TICKS(static_cast<uint32_t>(window_ms)));
}

const signing::UsbPayloadTransferHandlerOps& payload_transfer_handler_ops()
{
    static const signing::UsbPayloadTransferHandlerOps ops = {
        provisioned_material_ready,
        write_busy_if_pending_or_local_flow_active_allow_payload_delivery,
        require_active_matching_session,
        current_timeout_tick,
        payload_transfer_timeout_window_for_size,
    };
    return ops;
}

const signing::UsbPolicyHandlerOps& policy_handler_ops();

void handle_get_capabilities_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_get_capabilities_request(id, request, writer, session_read_handler_ops());
}

void handle_get_accounts_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_get_accounts_request(id, request, writer, session_read_handler_ops());
}

void handle_policy_get_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_policy_get_request(id, request, writer, policy_handler_ops());
}

void handle_payload_transfer_begin_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_payload_transfer_begin_request(
        id,
        request,
        writer,
        payload_transfer_handler_ops());
}

void handle_payload_transfer_chunk_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_payload_transfer_chunk_request(
        id,
        request,
        writer,
        payload_transfer_handler_ops());
}

void handle_payload_transfer_finish_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_payload_transfer_finish_request(
        id,
        request,
        writer,
        payload_transfer_handler_ops());
}

void handle_payload_transfer_abort_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_payload_transfer_abort_request(
        id,
        request,
        writer,
        payload_transfer_handler_ops());
}

const signing::UsbDisconnectHandlerOps& disconnect_handler_ops()
{
    static const signing::UsbDisconnectHandlerOps ops = {
        require_active_matching_session,
        disconnect_pending_policy_update_for_session,
        disconnect_pending_sui_zklogin_proposal_for_session,
        disconnect_pending_user_signing_for_session,
        write_busy_if_pending_or_local_flow_active_allow_settings,
        write_payload_delivery_disconnect_admission_error,
        clear_active_session,
    };
    return ops;
}

void handle_disconnect_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_disconnect_request(id, request, writer, disconnect_handler_ops());
}

const signing::UsbApprovalHistoryHandlerOps& approval_history_handler_ops()
{
    static const signing::UsbApprovalHistoryHandlerOps ops = {
        provisioned_material_ready,
        write_busy_if_pending_or_local_flow_active_allow_settings,
        write_payload_delivery_safe_read_admission_error,
        require_active_matching_session,
        signing::approval_history_read_page,
    };
    return ops;
}

void handle_get_approval_history_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_get_approval_history_request(
        id,
        request,
        writer,
        approval_history_handler_ops());
}

signing::TimeoutWindow make_policy_update_review_window(signing::TimeoutTick now)
{
    return timeout_window_from_now_ms(now, kProvisioningApprovalMaxMs);
}

void record_policy_update_waiting_for_review(const char* id)
{
    ESP_LOGI(kTag, "policy update waiting for local review: id=%s", id);
}

signing::PolicyUpdateFlowBeginResult begin_policy_update_for_current_transport(
    JsonVariantConst policy,
    const char* request_id,
    const char* session_id,
    TickType_t now,
    signing::TimeoutWindow review_window)
{
    const signing::PolicyUpdateFlowBeginResult result =
        signing::policy_update_flow_begin(
            policy,
            request_id,
            session_id,
            now,
            review_window);
    if (result == signing::PolicyUpdateFlowBeginResult::ok) {
        g_pending_policy_update_transport = g_current_request_transport;
    }
    return result;
}

const signing::UsbPolicyHandlerOps& policy_handler_ops()
{
    static const signing::UsbPolicyHandlerOps ops = {
        provisioned_material_ready,
        write_busy_if_pending_or_local_flow_active_allow_settings,
        write_payload_delivery_safe_read_admission_error,
        write_payload_delivery_policy_propose_busy,
        require_active_matching_session,
        record_active_policy_unavailable_for_session_read,
        current_timeout_tick,
        make_policy_update_review_window,
        begin_policy_update_for_current_transport,
        signing::policy_update_flow_begin_result_reason,
        show_policy_update_review,
        signing::policy_update_flow_record_ui_error,
        finish_policy_update_terminal,
        record_policy_update_waiting_for_review,
    };
    return ops;
}

void handle_policy_propose_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_policy_propose_request(id, request, writer, policy_handler_ops());
}

signing::UsbSuiZkLoginCredentialPrepareResult prepare_sui_zklogin_credential_for_common(
    const char*,
    signing::UsbSuiZkLoginCredentialPreparation* output)
{
    if (output == nullptr) {
        return signing::UsbSuiZkLoginCredentialPrepareResult::internal_output_error;
    }
    memset(output, 0, sizeof(*output));
    const signing::SuiActiveIdentity identity = signing::resolve_active_sui_identity();
    if (identity.kind != signing::SuiActiveIdentityKind::native ||
        identity.address[0] == '\0' ||
        identity.public_key_size != signing::kSuiSchemePrefixedEd25519PublicKeyBytes) {
        return signing::UsbSuiZkLoginCredentialPrepareResult::invalid_state;
    }
    strlcpy(output->address, identity.address, sizeof(output->address));
    memcpy(output->public_key, identity.public_key, identity.public_key_size);
    output->public_key_size = identity.public_key_size;
    return signing::UsbSuiZkLoginCredentialPrepareResult::ok;
}

signing::UsbSuiZkLoginCredentialProposalBeginResult begin_sui_zklogin_proposal_for_common(
    JsonVariantConst params,
    const char* request_id,
    const char* session_id,
    signing::TimeoutTick now,
    signing::TimeoutWindow request_window)
{
    const signing::SuiZkLoginProposalBeginResult result =
        signing::sui_zklogin_proposal_flow_begin(
            params,
            request_id,
            session_id,
            now,
            request_window);
    if (result == signing::SuiZkLoginProposalBeginResult::ok) {
        g_pending_credential_proposal_transport = g_current_request_transport;
        return signing::UsbSuiZkLoginCredentialProposalBeginResult::ok;
    }
    return signing::UsbSuiZkLoginCredentialProposalBeginResult::invalid_proof;
}

bool write_sui_zklogin_credential_propose_state_error(
    const char* id,
    const signing::UsbOperationResponseWriter& writer)
{
    const signing::SuiActiveIdentity identity = signing::resolve_active_sui_identity();
    if (identity.kind == signing::SuiActiveIdentityKind::native) {
        return false;
    }
    writer.write_error(id, "invalid_state");
    return true;
}

const signing::UsbSuiZkLoginCredentialHandlerOps& sui_zklogin_credential_handler_ops()
{
    static const signing::UsbActiveSessionRequestGuardOps prepare_guard_ops = {
        provisioned_material_ready,
        nullptr,
        write_payload_delivery_safe_read_admission_error,
        require_active_matching_session,
    };
    static const signing::UsbActiveSessionRequestGuardOps propose_guard_ops = {
        provisioned_material_ready,
        nullptr,
        nullptr,
        require_active_matching_session,
    };
    static const signing::UsbSuiZkLoginCredentialHandlerOps ops = {
        write_busy_if_pending_or_local_flow_active_allow_settings,
        write_payload_delivery_credential_propose_busy,
        nullptr,
        write_sui_zklogin_credential_propose_state_error,
        prepare_guard_ops,
        propose_guard_ops,
        signing::UsbSessionIdMode::optional_default_empty,
        signing::UsbSessionIdMode::optional_default_empty,
        prepare_sui_zklogin_credential_for_common,
        current_timeout_tick,
        make_sui_zklogin_proposal_window,
        begin_sui_zklogin_proposal_for_common,
        nullptr,
        show_sui_zklogin_proposal_review,
    };
    return ops;
}

void handle_credential_prepare_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_credential_prepare_request(
        id,
        request,
        writer,
        sui_zklogin_credential_handler_ops());
}

void handle_credential_propose_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_credential_propose_request(
        id,
        request,
        writer,
        sui_zklogin_credential_handler_ops());
}

void record_signing_account_unavailable_runtime_failure()
{
    signing::persistent_material_record_runtime_failure(
        signing::PersistentMaterialRuntimeFailure::root_material_unreadable,
        persistent_material_ops());
}

signing::PolicySigningExecutionResult execute_policy_sign_transaction_for_usb(
    const signing::SignTransactionPolicyRuntimeResult& policy_result)
{
    return signing::execute_policy_sign_transaction(policy_result, persistent_material_ops());
}

signing::TimeoutWindow make_user_signing_window(signing::TimeoutTick now)
{
    return signing::timeout_window_from_deadline(
        now,
        now + pdMS_TO_TICKS(signing::kUserSigningApprovalWindowMs));
}

void show_user_signing_display_error()
{
    signing::avatar_overlay_show_message(
        "Display error",
        MessageKind::error,
        UiMode::result,
        kResultDisplayMs);
}

void show_policy_signing_notice(
    const char* message,
    signing::UsbSigningNoticeKind kind)
{
    MessageKind message_kind = MessageKind::info;
    switch (kind) {
        case signing::UsbSigningNoticeKind::rejected:
            message_kind = MessageKind::rejected;
            break;
        case signing::UsbSigningNoticeKind::error:
            message_kind = MessageKind::error;
            break;
        case signing::UsbSigningNoticeKind::success:
            message_kind = MessageKind::success;
            break;
        case signing::UsbSigningNoticeKind::info:
        default:
            message_kind = MessageKind::info;
            break;
    }
    show_policy_signing_notification(message, message_kind);
}

bool policy_update_review_panel_active()
{
    return ui_panel_active(UiPanelKind::policy_update_review);
}

bool sui_zklogin_review_panel_active()
{
    return ui_panel_active(UiPanelKind::sui_zklogin_review);
}

bool user_signing_review_panel_active()
{
    return ui_panel_active(UiPanelKind::user_signing_review);
}

bool draw_local_pin_auth_panel_for_review_flow()
{
    return signing::modal_draw_local_pin_auth_panel();
}

void review_flow_log_warn(const char* message)
{
    ESP_LOGW(kTag, "%s", message != nullptr ? message : "review flow warning");
}

signing::PolicyUpdateReviewPinBeginResult begin_policy_update_pin_from_review(
    const signing::PolicyUpdateFlowSnapshot& current,
    TickType_t started_at,
    signing::TimeoutWindow request_window,
    uint64_t uptime_ms)
{
    const signing::PolicyUpdateFlowTransitionResult transition =
        signing::policy_update_flow_continue_to_pin(started_at);
    if (transition == signing::PolicyUpdateFlowTransitionResult::timed_out) {
        return signing::PolicyUpdateReviewPinBeginResult{
            signing::PolicyUpdateReviewPinBeginStatus::timed_out,
            signing::policy_update_flow_record_timed_out(uptime_ms)};
    }
    if (transition != signing::PolicyUpdateFlowTransitionResult::ok) {
        return signing::PolicyUpdateReviewPinBeginResult{
            signing::PolicyUpdateReviewPinBeginStatus::unavailable,
            signing::PolicyUpdateFlowTerminalResult::invalid_state};
    }
    if (!signing::protocol_pin_approval_begin_policy_update(
            current.request_id,
            current.session_id,
            started_at,
            request_window)) {
        return signing::PolicyUpdateReviewPinBeginResult{
            signing::PolicyUpdateReviewPinBeginStatus::unavailable,
            signing::PolicyUpdateFlowTerminalResult::invalid_state};
    }
    if (!signing::local_pin_auth_begin_policy_update(started_at, request_window)) {
        signing::protocol_pin_approval_clear();
        return signing::PolicyUpdateReviewPinBeginResult{
            signing::PolicyUpdateReviewPinBeginStatus::pin_unavailable,
            signing::PolicyUpdateFlowTerminalResult::invalid_state};
    }
    return signing::PolicyUpdateReviewPinBeginResult{
        signing::PolicyUpdateReviewPinBeginStatus::started,
        signing::PolicyUpdateFlowTerminalResult::invalid_state};
}

signing::SuiZkLoginReviewPinBeginResult begin_sui_zklogin_pin_from_review(
    const signing::SuiZkLoginProposalSnapshot& current,
    TickType_t started_at)
{
    const signing::SuiZkLoginProposalTransitionResult transition =
        signing::sui_zklogin_proposal_flow_continue_to_pin(started_at);
    if (transition == signing::SuiZkLoginProposalTransitionResult::timed_out) {
        return signing::SuiZkLoginReviewPinBeginResult{
            signing::SuiZkLoginReviewPinBeginStatus::timed_out,
            signing::sui_zklogin_proposal_flow_record_timed_out()};
    }
    if (transition != signing::SuiZkLoginProposalTransitionResult::ok) {
        return signing::SuiZkLoginReviewPinBeginResult{
            signing::SuiZkLoginReviewPinBeginStatus::unavailable,
            signing::SuiZkLoginProposalTerminalResult::invalid_state};
    }
    if (!signing::protocol_pin_approval_begin_sui_zklogin_proposal(
            current.request_id,
            current.session_id,
            started_at,
            current.request_window)) {
        return signing::SuiZkLoginReviewPinBeginResult{
            signing::SuiZkLoginReviewPinBeginStatus::pin_unavailable,
            signing::SuiZkLoginProposalTerminalResult::invalid_state};
    }
    if (!signing::local_pin_auth_begin_sui_zklogin_proposal(
            started_at,
            current.request_window)) {
        signing::protocol_pin_approval_clear();
        return signing::SuiZkLoginReviewPinBeginResult{
            signing::SuiZkLoginReviewPinBeginStatus::pin_unavailable,
            signing::SuiZkLoginProposalTerminalResult::invalid_state};
    }
    return signing::SuiZkLoginReviewPinBeginResult{
        signing::SuiZkLoginReviewPinBeginStatus::started,
        signing::SuiZkLoginProposalTerminalResult::invalid_state};
}

void cancel_user_signing_confirmation_for_pin_loss()
{
    signing::user_signing_confirmation_cancel_for_pin_loss();
}

signing::UserSigningReviewAcceptResult
accept_user_signing_review_without_pin(TickType_t now)
{
    const signing::UserSigningTransitionResult result =
        signing::user_signing_flow_record_physical_confirmed_and_write_confirmation_history(
            now,
            write_user_signing_physical_confirmation_history,
            nullptr);
    if (result == signing::UserSigningTransitionResult::ok) {
        return signing::UserSigningReviewAcceptResult::execute;
    }
    if (signing::user_signing_flow_terminal_pending()) {
        return signing::UserSigningReviewAcceptResult::finish_terminal;
    }
    return result == signing::UserSigningTransitionResult::history_error
               ? signing::UserSigningReviewAcceptResult::history_error
               : signing::UserSigningReviewAcceptResult::unavailable;
}

signing::UserSigningReviewPinBeginResult begin_user_signing_pin_from_review(
    TickType_t now,
    signing::TimeoutWindow pin_input_window)
{
    const signing::UserSigningConfirmationResult result =
        signing::user_signing_confirmation_accept_review_and_begin_pin(
            now,
            pin_input_window);
    if (result == signing::UserSigningConfirmationResult::ok) {
        return signing::UserSigningReviewPinBeginResult::started;
    }
    if (signing::user_signing_flow_terminal_pending()) {
        return signing::UserSigningReviewPinBeginResult::finish_terminal;
    }
    return result == signing::UserSigningConfirmationResult::local_pin_busy
               ? signing::UserSigningReviewPinBeginResult::busy
               : signing::UserSigningReviewPinBeginResult::unavailable;
}

signing::UserSigningReviewRejectResult reject_user_signing_review()
{
    const signing::UserSigningConfirmationResult result =
        signing::user_signing_confirmation_record_device_rejected();
    return result == signing::UserSigningConfirmationResult::ok
               ? signing::UserSigningReviewRejectResult::finish_terminal
               : signing::UserSigningReviewRejectResult::unavailable;
}

void finish_user_signing_terminal_for_review(const char* request_id)
{
    finish_user_signing_terminal(request_id);
}

const signing::PolicyUpdateReviewUiFlowOps& policy_update_review_ui_flow_ops()
{
    static const signing::PolicyUpdateReviewUiFlowOps ops = {
        xTaskGetTickCount,
        local_pin_auth_wall_clock_ms,
        signing::policy_update_flow_snapshot,
        signing::modal_draw_policy_update_review_panel,
        clear_signing_panel_if_kind,
        policy_update_review_panel_active,
        signing::identification_display_clear,
        begin_policy_update_pin_from_review,
        draw_local_pin_auth_panel_for_review_flow,
        clear_local_pin_auth_scratch,
        signing::policy_update_flow_review_deadline_reached,
        signing::policy_update_flow_record_timed_out,
        signing::policy_update_flow_record_rejected,
        signing::policy_update_flow_record_ui_error,
        finish_policy_update_terminal,
        finish_policy_update_error_terminal,
        review_flow_log_warn,
        kProvisioningApprovalMaxMs,
    };
    return ops;
}

const signing::SuiZkLoginReviewUiFlowOps& sui_zklogin_review_ui_flow_ops()
{
    static const signing::SuiZkLoginReviewUiFlowOps ops = {
        xTaskGetTickCount,
        signing::sui_zklogin_proposal_flow_snapshot,
        signing::modal_draw_sui_zklogin_review_panel,
        clear_signing_panel_if_kind,
        sui_zklogin_review_panel_active,
        signing::identification_display_clear,
        begin_sui_zklogin_pin_from_review,
        draw_local_pin_auth_panel_for_flow,
        clear_local_pin_auth_scratch,
        signing::sui_zklogin_proposal_flow_deadline_reached,
        signing::sui_zklogin_proposal_flow_record_timed_out,
        signing::sui_zklogin_proposal_flow_record_rejected,
        signing::sui_zklogin_proposal_flow_record_ui_error,
        finish_sui_zklogin_proposal_terminal,
        finish_sui_zklogin_proposal_error_terminal,
        review_flow_log_warn,
    };
    return ops;
}

const signing::UserSigningReviewUiFlowOps& user_signing_review_ui_flow_ops()
{
    static const signing::UserSigningReviewUiFlowOps ops = {
        xTaskGetTickCount,
        signing::user_signing_flow_core_snapshot,
        signing::user_signing_flow_review_timer_state,
        signing::user_signing_flow_snapshot_copy,
        signing::user_signing_review_view_model_build,
        signing::modal_draw_user_signing_review_panel,
        signing::modal_draw_user_signing_review_timer,
        clear_signing_panel_if_kind,
        user_signing_review_panel_active,
        signing::human_approval_requires_pin,
        accept_user_signing_review_without_pin,
        begin_user_signing_pin_from_review,
        reject_user_signing_review,
        signing::user_signing_flow_record_timeout,
        signing::user_signing_flow_pause_review_deadline,
        signing::user_signing_flow_resume_review_deadline,
        signing::user_signing_flow_clear,
        signing::user_signing_flow_terminal_pending,
        cancel_user_signing_confirmation_for_pin_loss,
        draw_local_pin_auth_panel_for_review_flow,
        write_method_error_response_for_active_user_signing,
        show_user_signing_display_error,
        execute_user_signing_critical_section_and_finish,
        finish_user_signing_terminal_for_review,
        finish_user_signing_error_terminal,
        review_flow_log_warn,
        kLocalPinInputWindowMs,
    };
    return ops;
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
    signing::Route signing_route)
{
    switch (signing_route) {
        case signing::Route::unsupported:
            ESP_LOGW(kTag, "unsupported signing route reached review wait log: id=%s", id);
            break;
        case signing::Route::sui_sign_transaction:
            ESP_LOGI(kTag, "sign_transaction waiting for device review: id=%s", id);
            break;
        case signing::Route::sui_sign_personal_message:
            ESP_LOGI(kTag, "sign_personal_message waiting for device review: id=%s", id);
            break;
    }
}

void clear_user_signing_flow_for_transport()
{
    signing::user_signing_flow_clear();
    g_active_user_signing_transport = ProtocolTransport::none;
}

signing::UserSigningFlowBeginResult begin_transaction_user_signing_for_transport(
    signing::TimeoutTick now,
    const signing::UserSigningTransactionBeginInput& input)
{
    const signing::UserSigningFlowBeginResult result =
        signing::user_signing_flow_begin(now, input);
    if (result == signing::UserSigningFlowBeginResult::ok) {
        g_active_user_signing_transport = g_current_request_transport;
    }
    return result;
}

signing::UserSigningFlowBeginResult begin_personal_message_user_signing_for_transport(
    signing::TimeoutTick now,
    const signing::UserSigningPersonalMessageBeginInput& input)
{
    const signing::UserSigningFlowBeginResult result =
        signing::user_signing_flow_begin_personal_message(now, input);
    if (result == signing::UserSigningFlowBeginResult::ok) {
        g_active_user_signing_transport = g_current_request_transport;
    }
    return result;
}

const signing::UsbSigningHandlerOps& usb_signing_handler_ops()
{
    static const signing::UsbSigningHandlerOps ops = {
        provisioned_material_ready,
        user_signing_ingress_busy,
        unrelated_user_signing_ingress_busy,
        current_timeout_tick,
        validate_session_for_user_signing,
        nullptr,
        signing::payload_delivery_admit_operation,
        read_signing_mode_for_preflight,
        nullptr,
        respond_to_signing_retry,
        nullptr,
        g_signing_preflight_retry_stored_response,
        sizeof(g_signing_preflight_retry_stored_response),
        signing::stackchan_sui_signing_preparation_ops(),
        signing::evaluate_sign_transaction_preflight,
        signing::evaluate_sign_personal_message_preflight,
        record_signing_account_unavailable_runtime_failure,
        signing::evaluate_sign_transaction_policy,
        execute_policy_sign_transaction_for_usb,
        write_policy_execution_response,
        signing::clear_policy_signing_execution_result,
        signing::clear_sign_transaction_policy_runtime_result,
        make_user_signing_window,
        begin_transaction_user_signing_for_transport,
        begin_personal_message_user_signing_for_transport,
        signing::clear_sui_prepared_sign_transaction,
        signing::clear_sui_prepared_personal_message,
        show_user_signing_review,
        clear_user_signing_flow_for_transport,
        show_user_signing_display_error,
        record_user_signing_waiting_for_review,
        show_policy_signing_notice,
        log_policy_rejected,
        log_policy_signing_failed,
        log_policy_signed,
        signing::usb_response_log_write_failure,
    };
    return ops;
}

void handle_sign_transaction_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_sign_transaction_request(id, request, writer, usb_signing_handler_ops());
}

void handle_sign_personal_message_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer)
{
    signing::handle_usb_sign_personal_message_request(id, request, writer, usb_signing_handler_ops());
}

const signing::UsbOperationHandlers& usb_operation_handlers()
{
    static const signing::UsbOperationHandlers handlers = {
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
        handle_credential_prepare_request,
        handle_credential_propose_request,
        handle_payload_transfer_begin_request,
        handle_payload_transfer_chunk_request,
        handle_payload_transfer_finish_request,
        handle_payload_transfer_abort_request,
    };
    return handlers;
}

void handle_line(const char* line)
{
    handle_protocol_request_line(
        line,
        usb_operation_response_writer(),
        ProtocolTransport::usb);
}

void write_usb_line_error(const char* code)
{
    signing::usb_response_write_error(nullptr, code);
}

void poll_usb_input()
{
    signing::usb_line_receiver_poll(handle_line, write_usb_line_error);
}

void run_usb_request_server_maintenance_phase()
{
    signing::payload_delivery_clear_expired(xTaskGetTickCount());
    drain_local_auth_worker_results();
    clear_identification_if_needed();
    clear_signing_message_if_needed();
    clear_setup_choice_if_needed();
    clear_backup_phrase_if_needed();
    clear_import_word_entry_if_needed();
    clear_pin_setup_if_needed();
    clear_storage_maintenance_if_needed();
    clear_local_pin_auth_if_needed();
    clear_policy_update_review_if_needed();
    clear_sui_zklogin_review_if_needed();
    clear_user_signing_review_if_needed();
}

void run_usb_request_server_local_ui_phase()
{
    drain_ui_events();
    commit_storage_maintenance_if_ready();
    commit_local_pin_setting_if_ready();
    signing::local_transport_ble_poll();
    signing::local_transport_pairing_poll(
        xTaskGetTickCount(),
        handle_local_transport_request_line);
    clear_local_transport_protocol_state_if_disconnected();
    sync_local_transport_pairing_panel();
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

namespace signing {

void init_usb_request_server()
{
    load_or_create_device_id();
    signing::provisioning_runtime_state_load(
        storage_maintenance_persistence_ops(),
        persistent_material_ops());
    signing::session_init();
    signing::user_signing_flow_set_session_validator(
        validate_session_for_user_signing,
        nullptr);
    if (!signing::local_auth_worker_init()) {
        ESP_LOGE(kTag, "Local auth worker init failed");
    }
    signing::connect_approval_clear();
    signing::identification_display_clear();
    wipe_setup_scratch("usb request server init");
    clear_storage_maintenance_flow("usb request server init");
    if (!signing::ui_event_bridge_init()) {
        ESP_LOGE(kTag, "UI event bridge init failed");
    }
    signing::ui_event_bridge_register_callbacks();
    signing::avatar_overlay_clear();

    if (!usb_serial_jtag_is_driver_installed()) {
        usb_serial_jtag_driver_config_t config = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
        config.tx_buffer_size = 1024;
        // The protocol accepts one bounded JSONL request frame up to
        // kRequestLineMaxBytes. The driver RX queue must be at least
        // that large so a single host write cannot overflow before the request
        // task drains it.
        config.rx_buffer_size = signing::kRequestLineMaxBytes + 512;
        const esp_err_t result = usb_serial_jtag_driver_install(&config);
        if (result != ESP_OK) {
            ESP_LOGE(kTag, "USB serial driver install failed: %s", esp_err_to_name(result));
            return;
        }
    }
    usb_serial_jtag_vfs_use_driver();

    signing::usb_link_state_clear();
    g_usb_ready = true;
    if (g_usb_task == nullptr) {
        BaseType_t task_created = xTaskCreatePinnedToCore(
            usb_request_task, "usb_request", kUsbRequestTaskStackBytes, nullptr, 4, &g_usb_task, 1);
        if (task_created != pdPASS) {
            ESP_LOGE(kTag, "USB request task start failed");
            g_usb_ready = false;
            g_usb_task = nullptr;
            return;
        }
    }
    ESP_LOGI(kTag, "USB request server ready");
}

void notify_signing_ui_surface_ready()
{
    {
        LvglLockGuard lock;
        signing::drawing_surface_mark_ready();
    }
    signing::ui_event_bridge_enqueue_surface_ready();
}

}  // namespace signing
