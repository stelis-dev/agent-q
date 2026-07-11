#include "protocol_runtime.h"

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "protocol/device_contract.h"
#include "protocol/device_response.h"
#include "protocol/json_input.h"
#include "protocol/approval_history.h"
#include "protocol/approval_history_json_writer.h"
#include "numeric/u64_decimal.h"
#include "policy/policy_store.h"
#include "policy/policy_proposal_parser.h"
#include "policy/policy_handlers.h"
#include "policy/policy_update_flow.h"
#include "policy/policy_update_marker.h"
#include "protocol/protocol_constants.h"
#include "protocol/protocol_transport.h"
#include "protocol/request_id.h"
#include "protocol/request_line.h"
#include "protocol/sign_route.h"
#include "protocol/signing_mode.h"
#include "protocol/signing_response_store.h"
#include "protocol/active_session_request_guard.h"
#include "protocol/json_response.h"
#include "protocol/approval_history_handler.h"
#include "protocol/device_handlers.h"
#include "protocol/operation_manifest.h"
#include "protocol/request_line_handler.h"
#include "protocol/session_read_handlers.h"
#include "protocol/sui_zklogin_credential_handlers.h"
#include "sui/network.h"
#include "sui/public_identity.h"
#include "sui/account_settings_types.h"
#include "sui/account_binding.h"
#include "sui/sign_transaction_adapter.h"
#include "sui/signing_preparation.h"
#include "sui/signing_limits.h"
#include "signing/policy_signing_execution_result.h"
#include "signing/protocol_transport_loss.h"
#include "signing/sign_transaction_policy_runtime.h"
#include "signing/signing_retry_response.h"
#include "signing/user_signing_critical_section.h"
#include "signing/user_signing_flow.h"
#include "signing/signing_handlers.h"
#include "signing/signing_outcome_writer.h"
#include "transport/connect_approval.h"
#include "transport/connect_review_response_flow.h"
#include "transport/usb_link_state.h"
#include "transport/payload_delivery_admission.h"
#include "transport/payload_delivery_resolution.h"
#include "transport/payload_delivery_store.h"
#include "transport/connect_handler.h"
#include "transport/disconnect_handler.h"
#include "transport/payload_transfer_handlers.h"
#include "transport/retained_response_handlers.h"
#include "transport/transport_exclusivity.h"
#include "transport/usb_session_grace.h"

#include "credential_preparation_state.h"
#include "local_transport_pairing.h"
#include "protocol/base64.h"
#include "protocol_input_encoding.h"
#include "secure_random.h"
#include "sensitive_memory.h"
#include "protocol/session_state.h"
#include "sui/zklogin_credential_payload.h"
#include "sui_zklogin_credential_store.h"
#include "sui_zklogin_proposal_state.h"
#include "sui_zklogin_signing_service.h"

namespace stopwatch_target {
namespace {

constexpr const char* kTag = "StopWatchUSB";
constexpr size_t kLineBufferBytes = signing::kRequestLineMaxBytes + 1;
constexpr size_t kReadChunkBytes = 512;
constexpr size_t kWriteChunkBytes = 512;
constexpr uint32_t kWriteTimeoutMs = 100;
constexpr uint32_t kUsbHostLinkCheckMs = 10;
constexpr uint32_t kUsbSessionGraceMs = 2000;
constexpr uint32_t kIdentifyDisplayMs = 30000;
constexpr uint32_t kConnectApprovalMs = 30000;
constexpr uint32_t kSigningApprovalMs = 30000;
constexpr uint32_t kPolicyUpdateReviewMs = 30000;
constexpr size_t kApprovalHistoryPageMax = 4;
constexpr const char* kFirmwareName = "Agent-Q Firmware";
constexpr const char* kHardwareId = "stopwatch-esp32s3";
constexpr const char* kFirmwareVersion = "0.0.0";
constexpr const char* kFallbackDeviceId = "stopwatch-esp32s3-unavailable";
constexpr size_t kSigningPayloadLabelSize = 32;
constexpr size_t kReviewValuePreviewSize = 36;
constexpr size_t kPayloadTransferChunkMaxBytes = signing::kPayloadDeliveryDefaultChunkMaxBytes;
constexpr size_t kPolicyReadbackEnvelopeReserveBytes = 1024;
constexpr uint32_t kSigningNoticeDisplayMs = 2500;

static_assert(
    signing::kPolicyProposalMaxSerializedObjectBytes + kPolicyReadbackEnvelopeReserveBytes <=
        signing::kJsonResponseLineMaxBytes,
    "policy_get readback for accepted policy proposals must fit within the USB response line cap");

using PayloadTransferAdmissionResult = signing::PayloadDeliveryAdmissionResult;
using PayloadTransferAdmissionReason = signing::PayloadDeliveryAdmissionReason;
using PayloadTransferAdmissionDecision = signing::PayloadDeliveryAdmissionDecision;
using PayloadTransferResult = signing::PayloadDeliveryResult;

char g_line_buffer[kLineBufferBytes];
size_t g_line_size = 0;
bool g_discarding_line = false;
ProtocolStatus g_status = {};
char g_device_id[40] = {};
ProtocolRuntimeState g_runtime_state{LocalAuthProjectionStatus::missing, false, false};
struct ProjectedStorageStateCache {
    bool valid;
    CredentialProjectionStatus credential;
    SettingsProjectionStatus settings;
};
ProjectedStorageStateCache g_projected_storage_cache{
    false,
    CredentialProjectionStatus::missing,
    SettingsProjectionStatus::missing,
};
PendingRequest g_pending_request{
    PendingRequestKind::none,
    {},
    {},
    signing::kTimeoutWindowNone,
};
signing::ProtocolTransportRoute g_current_request_route = {};
signing::ProtocolTransportRoute g_pending_response_route = {};
signing::ProtocolTransport g_active_session_transport =
    signing::ProtocolTransport::none;
IdentificationDisplay g_identification_display{false, {}};
uint32_t g_identification_display_deadline_ms = 0;
SigningNotice g_signing_notice{false, SigningNoticeKind::info, {}};
uint32_t g_signing_notice_deadline_ms = 0;
signing::UsbGraceState g_usb_session_grace;
signing::UserSigningFlowSnapshot g_user_signing_snapshot_scratch = {};
char g_signing_preflight_retry_stored_response[signing::kResponseMaxSize] = {};

bool reject_line(const char* id, const char* method, const char* code);
void record_success(const char* id, const char* method);
void record_error(const char* id, const char* method, const char* code);
bool write_success_response(const char* id, const char* method, JsonObjectConst result);
const signing::ResponseWriter& usb_operation_response_writer();
signing::ResponseWriter common_method_response_writer();
const signing::ApprovalHistoryHandlerOps& approval_history_handler_ops();
const signing::GetStatusHandlerOps& get_status_handler_ops();
const signing::IdentifyDeviceHandlerOps& identify_device_handler_ops();
void finish_policy_update(
    const char* id,
    signing::PolicyUpdateFlowTerminalResult terminal_result);
bool reject_if_payload_transfer_blocks_sensitive_flow(const char* id, const char* method);
bool reject_if_payload_transfer_blocks_safe_read(const char* id, const char* method);
CredentialProjectionStatus credential_projection_status();
SettingsProjectionStatus settings_projection_status();
StateProjectionInput state_projection_input();
StateProjectionInput cached_state_projection_input();
void invalidate_projected_storage_cache();
void refresh_projected_storage_cache();
bool finish_user_signing_terminal(
    const char* id,
    const uint8_t* signature = nullptr,
    size_t signature_size = 0,
    const uint8_t* message_bytes = nullptr,
    size_t message_size = 0);
const char* user_signing_terminal_error_code(
    signing::UserSigningTerminalResult result);
bool write_user_signing_terminal_history(
    const signing::UserSigningFlowCoreSnapshot& snapshot,
    signing::UserSigningTerminalResult result);
bool write_policy_execution_response(
    const char* id,
    const uint8_t* request_identity,
    const signing::PolicySigningExecutionResult& result);
void show_policy_signing_notice_for_common(
    const char* message,
    signing::SigningNoticeKind kind);

class ScopedRequestContext {
public:
    explicit ScopedRequestContext(const signing::ProtocolTransportRoute& route)
        : previous_route_(g_current_request_route)
    {
        g_current_request_route = route;
    }

    ~ScopedRequestContext()
    {
        g_current_request_route = previous_route_;
    }

private:
    signing::ProtocolTransportRoute previous_route_;
};

uint32_t current_payload_transfer_ms()
{
    return static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
}

signing::TimeoutWindow make_sui_zklogin_proposal_window(uint32_t now_ms)
{
    return signing::timeout_window_from_deadline(
        now_ms,
        now_ms + kSuiZkLoginProposalWindowMs);
}

signing::TimeoutWindow make_connect_approval_window(uint32_t now_ms)
{
    return signing::timeout_window_from_deadline(
        now_ms,
        now_ms + kConnectApprovalMs);
}

signing::TimeoutWindow make_signing_approval_window(uint32_t now_ms)
{
    return signing::timeout_window_from_deadline(
        now_ms,
        now_ms + kSigningApprovalMs);
}

signing::TimeoutWindow make_policy_update_review_window(uint32_t now_ms)
{
    return signing::timeout_window_from_deadline(
        now_ms,
        now_ms + kPolicyUpdateReviewMs);
}

bool pending_kind_is_signing(PendingRequestKind kind)
{
    return kind == PendingRequestKind::sign_transaction ||
           kind == PendingRequestKind::sign_personal_message;
}

bool any_request_pending()
{
    return g_pending_request.kind != PendingRequestKind::none ||
           signing::connect_approval_active();
}

const char* pending_signing_method()
{
    if (g_pending_request.kind == PendingRequestKind::sign_transaction) {
        return "sign_transaction";
    }
    if (g_pending_request.kind == PendingRequestKind::sign_personal_message) {
        return "sign_personal_message";
    }
    return "";
}

void copy_status_text(char* output, size_t output_size, const char* value)
{
    if (output == nullptr || output_size == 0) {
        return;
    }
    output[0] = '\0';
    if (value == nullptr) {
        return;
    }
    strlcpy(output, value, output_size);
}

void copy_middle_elided(
    const char* input,
    char* output,
    size_t output_size,
    size_t prefix_chars,
    size_t suffix_chars)
{
    if (output == nullptr || output_size == 0) {
        return;
    }
    output[0] = '\0';
    if (input == nullptr) {
        return;
    }
    const size_t length = strlen(input);
    if (length + 1 <= output_size ||
        prefix_chars + suffix_chars + 4 >= output_size ||
        length <= prefix_chars + suffix_chars + 3) {
        strlcpy(output, input, output_size);
        return;
    }
    memcpy(output, input, prefix_chars);
    memcpy(output + prefix_chars, "...", 3);
    memcpy(output + prefix_chars + 3, input + length - suffix_chars, suffix_chars);
    output[prefix_chars + 3 + suffix_chars] = '\0';
}

bool append_review_text(char* output, size_t output_size, const char* text)
{
    if (output == nullptr || output_size == 0 || text == nullptr) {
        return false;
    }
    const size_t used = strlen(output);
    if (used >= output_size) {
        return false;
    }
    const int written = snprintf(output + used, output_size - used, "%s", text);
    return written >= 0 && static_cast<size_t>(written) < output_size - used;
}

bool append_review_line(
    char* output,
    size_t output_size,
    const char* label,
    const char* value)
{
    if (label == nullptr || label[0] == '\0' ||
        value == nullptr || value[0] == '\0') {
        return true;
    }
    char preview[kReviewValuePreviewSize] = {};
    copy_middle_elided(value, preview, sizeof(preview), 12, 8);
    if (output[0] != '\0' && !append_review_text(output, output_size, "\n")) {
        return false;
    }
    return append_review_text(output, output_size, label) &&
           append_review_text(output, output_size, ": ") &&
           append_review_text(output, output_size, preview);
}

const signing::SuiReviewRow* find_review_row(
    const signing::SuiReviewSummary& review,
    const char* label)
{
    if (label == nullptr) {
        return nullptr;
    }
    for (uint16_t index = 0; index < review.row_count; ++index) {
        if (strcmp(review.rows[index].label, label) == 0) {
            return &review.rows[index];
        }
    }
    return nullptr;
}

bool append_review_row(
    char* output,
    size_t output_size,
    const signing::SuiReviewSummary& review,
    const char* row_label,
    const char* display_label)
{
    const signing::SuiReviewRow* row = find_review_row(review, row_label);
    if (row == nullptr) {
        return true;
    }
    return append_review_line(output, output_size, display_label, row->value);
}

void format_device_id()
{
    if (g_device_id[0] != '\0') {
        return;
    }

    uint8_t mac[6] = {};
    const esp_err_t result = esp_efuse_mac_get_default(mac);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Device id MAC read failed: %s", esp_err_to_name(result));
        strlcpy(g_device_id, kFallbackDeviceId, sizeof(g_device_id));
        return;
    }
    snprintf(
        g_device_id,
        sizeof(g_device_id),
        "%s-%02x%02x%02x%02x%02x%02x",
        kHardwareId,
        static_cast<unsigned>(mac[0]),
        static_cast<unsigned>(mac[1]),
        static_cast<unsigned>(mac[2]),
        static_cast<unsigned>(mac[3]),
        static_cast<unsigned>(mac[4]),
        static_cast<unsigned>(mac[5]));
}

const char* device_state()
{
    return stopwatch_device_state(state_projection_input());
}

signing::DeviceStatusInfo device_status_info()
{
    format_device_id();
    const StateProjectionInput projection = state_projection_input();
    return signing::DeviceStatusInfo{
        signing::DeviceResponseDeviceFields{
            g_device_id,
            stopwatch_device_state(projection),
            kFirmwareName,
            kHardwareId,
            kFirmwareVersion,
        },
        stopwatch_provisioning_state(projection),
    };
}

CredentialProjectionStatus credential_projection_status()
{
    switch (sui_zklogin_credential_status()) {
    case SuiZkLoginCredentialStatus::active:
        return CredentialProjectionStatus::active;
    case SuiZkLoginCredentialStatus::invalid:
        return CredentialProjectionStatus::invalid;
    case SuiZkLoginCredentialStatus::storage_error:
        return CredentialProjectionStatus::storage_error;
    case SuiZkLoginCredentialStatus::missing:
    default:
        return CredentialProjectionStatus::missing;
    }
}

SettingsProjectionStatus settings_projection_status()
{
    bool missing = false;

    switch (signing::active_policy_status()) {
    case signing::PolicyStoreStatus::active:
        break;
    case signing::PolicyStoreStatus::storage_error:
        return SettingsProjectionStatus::storage_error;
    case signing::PolicyStoreStatus::invalid:
        return SettingsProjectionStatus::invalid;
    case signing::PolicyStoreStatus::missing:
    default:
        missing = true;
        break;
    }

    switch (signing::authorization_mode_status()) {
    case signing::AuthorizationModeStatus::active:
        break;
    case signing::AuthorizationModeStatus::unreadable:
        return SettingsProjectionStatus::storage_error;
    case signing::AuthorizationModeStatus::invalid:
        return SettingsProjectionStatus::invalid;
    case signing::AuthorizationModeStatus::missing:
    default:
        missing = true;
        break;
    }

    switch (signing::approval_history_status()) {
    case signing::ApprovalHistoryStorageStatus::active:
    case signing::ApprovalHistoryStorageStatus::missing:
        break;
    case signing::ApprovalHistoryStorageStatus::storage_error:
        return SettingsProjectionStatus::storage_error;
    case signing::ApprovalHistoryStorageStatus::invalid:
    default:
        return SettingsProjectionStatus::invalid;
    }

    switch (signing::policy_update_marker_status()) {
    case signing::PolicyUpdateMarkerStatus::clear:
        break;
    case signing::PolicyUpdateMarkerStatus::storage_error:
        return SettingsProjectionStatus::storage_error;
    case signing::PolicyUpdateMarkerStatus::pending:
    case signing::PolicyUpdateMarkerStatus::invalid:
    default:
        return SettingsProjectionStatus::invalid;
    }

    return missing ? SettingsProjectionStatus::missing : SettingsProjectionStatus::active;
}

StateProjectionInput state_projection_input()
{
    return StateProjectionInput{
        g_runtime_state.auth_status,
        credential_projection_status(),
        settings_projection_status(),
        g_runtime_state.locally_unlocked,
        g_runtime_state.ui_busy,
    };
}

void invalidate_projected_storage_cache()
{
    g_projected_storage_cache.valid = false;
}

void refresh_projected_storage_cache()
{
    g_projected_storage_cache.credential = credential_projection_status();
    g_projected_storage_cache.settings = settings_projection_status();
    g_projected_storage_cache.valid = true;
}

StateProjectionInput cached_state_projection_input()
{
    if (!g_projected_storage_cache.valid) {
        refresh_projected_storage_cache();
    }
    return StateProjectionInput{
        g_runtime_state.auth_status,
        g_projected_storage_cache.credential,
        g_projected_storage_cache.settings,
        g_runtime_state.locally_unlocked,
        g_runtime_state.ui_busy,
    };
}

bool credential_status_is_error(SuiZkLoginCredentialStatus status)
{
    return status == SuiZkLoginCredentialStatus::invalid ||
           status == SuiZkLoginCredentialStatus::storage_error;
}

bool credential_status_allows_install(SuiZkLoginCredentialStatus status)
{
    return status == SuiZkLoginCredentialStatus::missing;
}

void clear_pending_response_route()
{
    g_pending_response_route.clear();
}

bool remember_current_response_route()
{
    if (!g_current_request_route.bound()) {
        return false;
    }
    g_pending_response_route = g_current_request_route;
    return true;
}

void clear_pending_request()
{
    if (pending_kind_is_signing(g_pending_request.kind)) {
        signing::user_signing_flow_clear();
    }
    memset(&g_pending_request, 0, sizeof(g_pending_request));
    g_pending_request.kind = PendingRequestKind::none;
    g_pending_request.request_window = signing::kTimeoutWindowNone;
    clear_pending_response_route();
}

void reject_expired_signing_request(uint32_t now_ms)
{
    if (!pending_kind_is_signing(g_pending_request.kind)) {
        return;
    }
    const signing::UserSigningTransitionResult result =
        signing::user_signing_flow_record_timeout(now_ms);
    if (result == signing::UserSigningTransitionResult::deadline_not_reached ||
        result == signing::UserSigningTransitionResult::inactive) {
        return;
    }
    char pending_id[signing::kRequestIdSize] = {};
    strlcpy(pending_id, g_pending_request.id, sizeof(pending_id));
    if (result == signing::UserSigningTransitionResult::ok ||
        signing::user_signing_flow_terminal_pending()) {
        finish_user_signing_terminal(pending_id);
    } else {
        reject_line(pending_id, pending_signing_method(), "invalid_state");
        signing::user_signing_flow_clear();
    }
    clear_pending_request();
}

void reject_expired_policy_update_request(uint32_t now_ms)
{
    if (g_pending_request.kind != PendingRequestKind::policy_propose ||
        !signing::policy_update_flow_review_deadline_reached(now_ms)) {
        return;
    }
    char pending_id[signing::kRequestIdSize] = {};
    strlcpy(pending_id, g_pending_request.id, sizeof(pending_id));
    finish_policy_update(
        pending_id,
        signing::policy_update_flow_record_timed_out(now_ms));
}

const char* pending_credential_proposal_request_to_notify(const char* current_request_id)
{
    if (g_pending_request.kind != PendingRequestKind::credential_propose ||
        g_pending_request.id[0] == '\0') {
        return nullptr;
    }
    if (current_request_id != nullptr && strcmp(g_pending_request.id, current_request_id) == 0) {
        return nullptr;
    }
    return g_pending_request.id;
}

void cancel_pending_credential_proposal_after_session_loss(const char* current_request_id)
{
    if (g_pending_request.kind != PendingRequestKind::credential_propose) {
        return;
    }
    const char* canceled_proposal_id =
        pending_credential_proposal_request_to_notify(current_request_id);
    if (canceled_proposal_id != nullptr) {
        reject_line(canceled_proposal_id, "credential_propose", "invalid_session");
    }
    sui_zklogin_proposal_state_clear();
    credential_preparation_state_clear();
    clear_pending_request();
}

void cancel_pending_signing_after_session_loss(const char* current_request_id)
{
    if (!pending_kind_is_signing(g_pending_request.kind)) {
        return;
    }
    if (current_request_id == nullptr || strcmp(g_pending_request.id, current_request_id) != 0) {
        const signing::UserSigningTransitionResult result =
            signing::user_signing_flow_cancel_for_session_loss();
        if (result == signing::UserSigningTransitionResult::ok ||
            signing::user_signing_flow_terminal_pending()) {
            finish_user_signing_terminal(g_pending_request.id);
        } else {
            reject_line(g_pending_request.id, pending_signing_method(), "invalid_session");
        }
    }
    clear_pending_request();
}

void finish_policy_update(
    const char* id,
    signing::PolicyUpdateFlowTerminalResult terminal_result)
{
    const signing::PolicyUpdateFlowSnapshot snapshot =
        signing::policy_update_flow_snapshot();
    const char* status = signing::policy_update_flow_terminal_status(terminal_result);
    const char* reason = signing::policy_update_flow_terminal_reason(terminal_result);
    if (id == nullptr ||
        status == nullptr || status[0] == '\0' ||
        reason == nullptr || reason[0] == '\0') {
        record_error(id, "policy_propose", "internal_output_error");
    } else {
        if (signing::policy_propose_outcome_write(
                id,
                status,
                reason,
                snapshot.active ? &snapshot : nullptr,
                common_method_response_writer())) {
            record_success(id, "policy_propose");
        } else {
            record_error(id, "policy_propose", "internal_output_error");
        }
    }
    signing::policy_update_flow_clear();
    clear_pending_request();
}

void cancel_pending_policy_update_after_session_loss(const char* current_request_id)
{
    if (g_pending_request.kind != PendingRequestKind::policy_propose) {
        return;
    }
    if (current_request_id == nullptr || strcmp(g_pending_request.id, current_request_id) != 0) {
        finish_policy_update(
            g_pending_request.id,
            signing::policy_update_flow_record_ui_error());
        return;
    }
    signing::policy_update_flow_clear();
    clear_pending_request();
}

void clear_session_scoped_state()
{
    signing::connect_approval_clear();
    if (signing::session_active()) {
        signing::signing_response_clear_session(signing::session_id());
    }
    sui_zklogin_proposal_state_clear();
    credential_preparation_state_clear();
    signing::policy_update_flow_clear();
    signing::payload_delivery_clear_all();
    signing::session_clear();
    g_active_session_transport = signing::ProtocolTransport::none;
    clear_pending_response_route();
}

signing::ProtocolTransportLossPlan current_protocol_transport_loss_plan(
    signing::ProtocolTransport transport)
{
    const CredentialPreparationSnapshot preparation =
        credential_preparation_snapshot();
    const signing::UserSigningFlowCoreSnapshot user_signing =
        signing::user_signing_flow_core_snapshot();
    const signing::ProtocolTransport session_bound_transport =
        g_pending_response_route.bound()
            ? g_pending_response_route.transport()
            : g_active_session_transport;
    signing::ProtocolTransportLossState state = {};
    state.lost_transport = transport;
    state.session = {
        signing::session_active(),
        g_active_session_transport,
    };
    state.connect_approval = {
        signing::connect_approval_active(),
        g_pending_response_route.transport(),
    };
    state.policy_update = {
        signing::policy_update_flow_active(),
        session_bound_transport,
    };
    state.credential_preparation = {
        preparation.active,
        session_bound_transport,
    };
    state.credential_proposal = {
        sui_zklogin_proposal_state_active(),
        session_bound_transport,
    };
    state.user_signing = {
        user_signing.active,
        session_bound_transport,
    };
    state.user_signing_critical =
        user_signing.stage == signing::UserSigningStage::signing_critical_section;
    return signing::protocol_transport_loss_plan(state);
}

void clear_active_session_after_transport_loss()
{
    if (signing::session_active()) {
        signing::signing_response_clear_session(signing::session_id());
    }
    signing::payload_delivery_clear_all();
    signing::session_clear();
    g_active_session_transport = signing::ProtocolTransport::none;
}

void clear_protocol_state_after_transport_loss(
    signing::ProtocolTransport transport)
{
    const signing::ProtocolTransportLossPlan plan =
        current_protocol_transport_loss_plan(transport);
    if (!plan.relevant) {
        return;
    }

    const signing::UserSigningFlowCoreSnapshot user_signing =
        signing::user_signing_flow_core_snapshot();
    const bool preserve_critical_signing =
        g_pending_response_route.transport() == transport &&
        user_signing.active &&
        user_signing.stage == signing::UserSigningStage::signing_critical_section;

    if (plan.clear_connect_approval) {
        char request_id[signing::kRequestIdSize] = {};
        signing::connect_approval_request_id(request_id, sizeof(request_id));
        if (request_id[0] != '\0') {
            reject_line(request_id, "connect", "invalid_session");
        }
        signing::connect_approval_clear();
    }

    if (plan.clear_policy_update_flow) {
        if (g_pending_request.kind == PendingRequestKind::policy_propose &&
            g_pending_response_route.transport() == transport) {
            reject_line(g_pending_request.id, "policy_propose", "invalid_session");
            signing::policy_update_flow_clear();
            clear_pending_request();
        } else {
            signing::policy_update_flow_clear();
        }
    }

    if (plan.clear_credential_proposal_flow) {
        if (g_pending_request.kind == PendingRequestKind::credential_propose &&
            g_pending_response_route.transport() == transport) {
            reject_line(g_pending_request.id, "credential_propose", "invalid_session");
            sui_zklogin_proposal_state_clear();
            credential_preparation_state_clear();
            clear_pending_request();
        } else {
            sui_zklogin_proposal_state_clear();
        }
    }
    if (plan.clear_credential_preparation) {
        credential_preparation_state_clear();
    }

    if (plan.cancel_user_signing) {
        if (pending_kind_is_signing(g_pending_request.kind) &&
            g_pending_response_route.transport() == transport) {
            cancel_pending_signing_after_session_loss(nullptr);
        } else {
            signing::user_signing_flow_clear();
        }
    }

    if (plan.clear_session) {
        clear_active_session_after_transport_loss();
    }

    if (!preserve_critical_signing &&
        g_pending_response_route.transport() == transport) {
        clear_pending_response_route();
    }
}

void reset_line_receiver_state()
{
    g_line_size = 0;
    g_discarding_line = false;
    g_line_buffer[0] = '\0';
}

bool refresh_usb_connection()
{
    const bool connected = g_status.usb_ready && usb_serial_jtag_is_connected();
    g_status.usb_connected = connected;
    const TickType_t now = static_cast<TickType_t>(current_payload_transfer_ms());
    const signing::UsbLinkEvent event = signing::usb_link_state_observe(
        connected,
        now,
        static_cast<TickType_t>(kUsbHostLinkCheckMs));
    const signing::UsbGraceAction grace = signing::usb_session_grace_step(
        event,
        now,
        static_cast<TickType_t>(kUsbSessionGraceMs),
        g_usb_session_grace);
    if (event == signing::UsbLinkEvent::disconnected) {
        reset_line_receiver_state();
    }
    if (grace == signing::UsbGraceAction::confirm) {
        clear_protocol_state_after_transport_loss(signing::ProtocolTransport::usb);
    }
    return connected;
}

bool init_usb_transport()
{
    if (!usb_serial_jtag_is_driver_installed()) {
        usb_serial_jtag_driver_config_t config = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
        config.tx_buffer_size = 1024;
        config.rx_buffer_size = signing::kRequestLineMaxBytes + kReadChunkBytes;
        const esp_err_t result = usb_serial_jtag_driver_install(&config);
        if (result != ESP_OK) {
            ESP_LOGE(kTag, "USB serial driver install failed: %s", esp_err_to_name(result));
            return false;
        }
    }
    usb_serial_jtag_vfs_use_driver();
    return true;
}

bool write_usb_bytes(const char* data, size_t length)
{
    if (data == nullptr || length == 0) {
        return false;
    }
    size_t offset = 0;
    while (offset < length) {
        const size_t remaining = length - offset;
        const size_t chunk = remaining > kWriteChunkBytes ? kWriteChunkBytes : remaining;
        const int written = usb_serial_jtag_write_bytes(
            data + offset,
            chunk,
            pdMS_TO_TICKS(kWriteTimeoutMs));
        if (written <= 0 || static_cast<size_t>(written) > chunk) {
            ESP_LOGW(kTag, "USB write failed: requested=%u written=%d",
                     static_cast<unsigned>(chunk),
                     written);
            return false;
        }
        offset += static_cast<size_t>(written);
    }
    return usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(kWriteTimeoutMs)) == ESP_OK;
}

bool write_usb_response_bytes(const char* data, size_t length, void*)
{
    return write_usb_bytes(data, length);
}

void delay_usb_response_ms(uint32_t duration_ms, void*)
{
    vTaskDelay(pdMS_TO_TICKS(duration_ms));
}

const signing::JsonResponseWriteOps& usb_json_response_write_ops()
{
    static const signing::JsonResponseWriteOps ops{
        write_usb_response_bytes,
        delay_usb_response_ms,
        nullptr,
    };
    return ops;
}

const signing::ProtocolTransportEndpoint& usb_protocol_transport_endpoint()
{
    static const signing::ProtocolTransportEndpoint endpoint{
        signing::ProtocolTransport::usb,
        usb_operation_response_writer(),
        usb_json_response_write_ops(),
    };
    return endpoint;
}

const signing::ProtocolTransportRoute& current_response_route()
{
    if (g_current_request_route.bound()) {
        return g_current_request_route;
    }
    if (g_pending_response_route.bound()) {
        return g_pending_response_route;
    }
    static const signing::ProtocolTransportRoute unbound_route = {};
    return unbound_route;
}

const signing::JsonResponseWriteOps& current_json_response_write_ops()
{
    return current_response_route().json_response_write_ops();
}

bool write_retry_response_json(JsonDocument& response, void*)
{
    return signing::json_response_write(response, current_json_response_write_ops());
}

bool write_method_error_for_signing_outcome(
    const char* id,
    const char* method,
    const char* code,
    void*)
{
    return reject_line(id, method, code);
}

signing::SigningOutcomeWriterOps signing_outcome_writer_ops()
{
    return signing::SigningOutcomeWriterOps{
        current_json_response_write_ops(),
        write_method_error_for_signing_outcome,
        nullptr,
    };
}

bool write_json_response(JsonDocument& response, size_t output_size)
{
    (void)output_size;
    if (response.overflowed()) {
        copy_status_text(g_status.last_error, sizeof(g_status.last_error), "internal_output_error");
        return false;
    }
    const size_t measured_len = measureJson(response);
    if (measured_len == 0 || measured_len > signing::kJsonResponseLineMaxBytes) {
        return false;
    }
    return signing::json_response_write(response, current_json_response_write_ops());
}

bool write_error_response(const char* id, const char* method, const char* code)
{
    JsonDocument response;
    if (!signing::device_response_prepare_method_error(response, id, method, code)) {
        return false;
    }
    return write_json_response(response, 768);
}

bool write_success_response(const char* id, const char* method, JsonObjectConst result)
{
    JsonDocument response;
    if (!signing::device_response_prepare_success_result(response, id, method, result)) {
        return false;
    }
    if (!write_json_response(response, signing::kResponseMaxSize)) {
        return false;
    }
    record_success(id, method);
    return true;
}

bool write_empty_success_response(const char* id, const char* method)
{
    JsonDocument result;
    JsonObject object = result.to<JsonObject>();
    return write_success_response(id, method, object);
}

bool finish_user_signing_terminal(
    const char* id,
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* message_bytes,
    size_t message_size)
{
    const signing::UserSigningFlowCoreSnapshot snapshot =
        signing::user_signing_flow_core_snapshot();
    const signing::UserSigningTerminalResult result = snapshot.terminal_result;
    if (!snapshot.active ||
        snapshot.stage != signing::UserSigningStage::terminal ||
        result == signing::UserSigningTerminalResult::none) {
        if (id != nullptr && id[0] != '\0') {
            reject_line(id, pending_signing_method(), "invalid_state");
        }
        signing::user_signing_flow_clear();
        return false;
    }
    if (!write_user_signing_terminal_history(snapshot, result)) {
        if (id != nullptr && id[0] != '\0') {
            reject_line(id, snapshot.method, "history_unavailable");
        }
        signing::user_signing_flow_clear();
        return false;
    }

    bool written = false;
    if (result == signing::UserSigningTerminalResult::signed_success) {
        signing::UserSigningOutput signing_output = {};
        signing_output.signing_route = snapshot.signing_route;
        signing_output.signature_size = signature_size;
        if (signature != nullptr &&
            signature_size > 0 &&
            signature_size <= sizeof(signing_output.signature)) {
            memcpy(signing_output.signature, signature, signature_size);
        }
        if (message_bytes != nullptr &&
            message_size > 0 &&
            message_size <= sizeof(signing_output.message_bytes)) {
            memcpy(signing_output.message_bytes, message_bytes, message_size);
            signing_output.message_bytes_size = message_size;
        }
        written = signing::signing_outcome_write_user_signed(
            id,
            signing::session_id(),
            "user",
            snapshot,
            signing_output,
            signing_outcome_writer_ops());
        wipe_sensitive_buffer(&signing_output, sizeof(signing_output));
        if (written) {
            record_success(id, snapshot.method);
        } else {
            record_error(id, snapshot.method, "internal_output_error");
        }
    } else {
        const char* code = user_signing_terminal_error_code(result);
        if (code == nullptr || code[0] == '\0') {
            code = "invalid_state";
        }
        (void)code;
        written = signing::signing_outcome_write_user_terminal(
            id,
            signing::session_id(),
            snapshot.request_identity,
            snapshot.method,
            result,
            signing_outcome_writer_ops());
        if (written) {
            record_error(id, snapshot.method, code);
        } else {
            record_error(id, snapshot.method, "internal_output_error");
        }
    }
    signing::user_signing_flow_clear();
    return written;
}

struct UserSigningOutputReadyContext {
    const char* request_id;
};

struct UserSigningTerminalFinishContext {
    const char* request_id;
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
        strcmp(ready_context->request_id, snapshot.request_id) != 0 ||
        signing_output.signing_route != snapshot.signing_route) {
        return false;
    }
    JsonDocument response;
    return signing::signing_outcome_prepare_signed_response(
               response,
               ready_context->request_id,
               "user",
               snapshot.signing_route,
               signing_output.signature,
               signing_output.signature_size,
               signing_output.message_bytes_size > 0 ? signing_output.message_bytes : nullptr,
               signing_output.message_bytes_size) &&
           signing::signing_outcome_response_fits(response);
}

bool finish_user_signing_from_common(
    const signing::UserSigningOutput* signing_output,
    void* context)
{
    const UserSigningTerminalFinishContext* finish_context =
        static_cast<const UserSigningTerminalFinishContext*>(context);
    if (finish_context == nullptr ||
        finish_context->request_id == nullptr ||
        finish_context->request_id[0] == '\0') {
        return false;
    }
    if (signing_output != nullptr) {
        return finish_user_signing_terminal(
            finish_context->request_id,
            signing_output->signature,
            signing_output->signature_size,
            signing_output->message_bytes_size > 0 ? signing_output->message_bytes : nullptr,
            signing_output->message_bytes_size);
    }
    return finish_user_signing_terminal(finish_context->request_id);
}

signing::UserSigningSignStatus map_user_signing_status(
    SuiZkLoginSigningResult result)
{
    switch (result) {
        case SuiZkLoginSigningResult::ok:
            return signing::UserSigningSignStatus::ok;
        case SuiZkLoginSigningResult::invalid_input:
            return signing::UserSigningSignStatus::invalid_input;
        case SuiZkLoginSigningResult::account_unavailable:
            return signing::UserSigningSignStatus::account_unavailable;
        case SuiZkLoginSigningResult::signature_output_too_small:
            return signing::UserSigningSignStatus::signature_output_too_small;
        case SuiZkLoginSigningResult::zklogin_envelope_error:
            return signing::UserSigningSignStatus::signature_envelope_error;
        case SuiZkLoginSigningResult::signing_error:
        default:
            return signing::UserSigningSignStatus::signing_error;
    }
}

signing::UserSigningSignStatus sign_user_signing_payload(
    signing::Route route,
    const uint8_t* payload,
    size_t payload_size,
    uint8_t signature_out[signing::kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out,
    void*)
{
    SuiZkLoginSigningResult result = SuiZkLoginSigningResult::invalid_input;
    switch (route) {
        case signing::Route::sui_sign_transaction:
            result = sign_sui_zklogin_transaction(
                payload,
                payload_size,
                signature_out,
                signature_size_out);
            break;
        case signing::Route::sui_sign_personal_message:
            result = sign_sui_zklogin_personal_message(
                payload,
                payload_size,
                signature_out,
                signature_size_out);
            break;
        case signing::Route::unsupported:
        default:
            result = SuiZkLoginSigningResult::invalid_input;
            break;
    }
    return map_user_signing_status(result);
}

bool write_payload_transfer_success_response(const char* id, JsonObjectConst result)
{
    JsonDocument response;
    if (!signing::device_response_prepare_transport_success_result(response, id, result)) {
        return false;
    }
    return write_json_response(response, 768);
}

bool write_connect_response_with_writer(
    const char* id,
    const signing::ResponseWriter& writer)
{
    format_device_id();

    JsonDocument result;
    result["sessionId"] = signing::session_id();
    result["sessionTtlMs"] = signing::kSessionAdvertisedTtlMs;
    const signing::DeviceResponseDeviceFields info{
        g_device_id,
        device_state(),
        kFirmwareName,
        kHardwareId,
        kFirmwareVersion,
    };
    signing::device_response_write_device_fields(result["device"].to<JsonObject>(), info);
    return writer.write_success_result(id, "connect", result.as<JsonObjectConst>());
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

const char* user_signing_terminal_error_code(
    signing::UserSigningTerminalResult result)
{
    switch (result) {
        case signing::UserSigningTerminalResult::rejected:
            return "user_rejected";
        case signing::UserSigningTerminalResult::timed_out:
            return "timeout";
        case signing::UserSigningTerminalResult::signing_failed:
            return "signing_failed";
        case signing::UserSigningTerminalResult::history_error:
            return "history_unavailable";
        case signing::UserSigningTerminalResult::canceled:
            return "invalid_session";
        case signing::UserSigningTerminalResult::signed_success:
        case signing::UserSigningTerminalResult::none:
        default:
            return "";
    }
}

bool write_user_signing_confirmation_history(
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
        nullptr,
    };
    return signing::approval_history_append_required_signing(
        input,
        current_payload_transfer_ms());
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
        nullptr,
    };
    return signing::approval_history_append_required_signing(
        input,
        current_payload_transfer_ms());
}

bool append_policy_signing_history(
    signing::HistoryRecordKind record_kind,
    signing::HistoryTerminalResult terminal_result,
    const char* reason_code,
    const char* payload_digest,
    const char* policy_hash,
    const char* rule_ref,
    bool enforce_write_budget)
{
    if (reason_code == nullptr || reason_code[0] == '\0' ||
        payload_digest == nullptr || payload_digest[0] == '\0' ||
        policy_hash == nullptr || policy_hash[0] == '\0' ||
        rule_ref == nullptr || rule_ref[0] == '\0') {
        return false;
    }
    const signing::HistoryAppendInput input{
        record_kind,
        signing::ApprovalHistoryConfirmationKind::policy,
        terminal_result,
        "sui",
        "sign_transaction",
        reason_code,
        payload_digest,
        policy_hash,
        rule_ref,
    };
    return enforce_write_budget
               ? signing::approval_history_append_budgeted_signing(
                     input,
                     current_payload_transfer_ms())
               : signing::approval_history_append_required_signing(
                     input,
                     current_payload_transfer_ms());
}

void record_success(const char* id, const char* method)
{
    copy_status_text(g_status.last_id, sizeof(g_status.last_id), id);
    copy_status_text(g_status.last_method, sizeof(g_status.last_method), method);
    copy_status_text(g_status.last_error, sizeof(g_status.last_error), "none");
}

void record_error(const char* id, const char* method, const char* code)
{
    copy_status_text(g_status.last_id, sizeof(g_status.last_id), id);
    copy_status_text(g_status.last_method, sizeof(g_status.last_method), method);
    copy_status_text(g_status.last_error, sizeof(g_status.last_error), code);
}

bool reject_line(const char* id, const char* method, const char* code)
{
    record_error(id, method, code);
    if (method != nullptr && strcmp(method, "connect") == 0) {
        ++g_status.rejected_connects;
    }
    if (!write_error_response(id, method, code)) {
        record_error(id, method, "internal_output_error");
        return false;
    }
    return true;
}

bool secure_random_fill_with_context(void* output, size_t size, void* context)
{
    (void)context;
    return secure_random_fill(output, size);
}

bool identification_code_safe(const char* value)
{
    if (value == nullptr) {
        return false;
    }
    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        const char c = *cursor;
        if (c < '0' || c > '9') {
            return false;
        }
        ++length;
    }
    return length == 4;
}

void clear_identification_display_if_expired(uint32_t now_ms)
{
    if (!g_identification_display.active) {
        return;
    }
    if (static_cast<int32_t>(now_ms - g_identification_display_deadline_ms) >= 0) {
        memset(&g_identification_display, 0, sizeof(g_identification_display));
        g_identification_display_deadline_ms = 0;
    }
}

void show_identification_code(const char* code, uint32_t duration_ms)
{
    memset(&g_identification_display, 0, sizeof(g_identification_display));
    g_identification_display.active = true;
    strlcpy(g_identification_display.code, code, sizeof(g_identification_display.code));
    g_identification_display_deadline_ms = current_payload_transfer_ms() + duration_ms;
}

SigningNoticeKind signing_notice_kind_for_common(signing::SigningNoticeKind kind)
{
    switch (kind) {
        case signing::SigningNoticeKind::rejected:
            return SigningNoticeKind::rejected;
        case signing::SigningNoticeKind::error:
            return SigningNoticeKind::error;
        case signing::SigningNoticeKind::success:
            return SigningNoticeKind::success;
        case signing::SigningNoticeKind::info:
        default:
            return SigningNoticeKind::info;
    }
}

void clear_signing_notice_if_expired(uint32_t now_ms)
{
    if (!g_signing_notice.active) {
        return;
    }
    if (static_cast<int32_t>(now_ms - g_signing_notice_deadline_ms) >= 0) {
        memset(&g_signing_notice, 0, sizeof(g_signing_notice));
        g_signing_notice.kind = SigningNoticeKind::info;
        g_signing_notice_deadline_ms = 0;
    }
}

void show_policy_signing_notice_for_common(
    const char* message,
    signing::SigningNoticeKind kind)
{
    memset(&g_signing_notice, 0, sizeof(g_signing_notice));
    g_signing_notice.active = true;
    g_signing_notice.kind = signing_notice_kind_for_common(kind);
    strlcpy(
        g_signing_notice.message,
        message != nullptr && message[0] != '\0' ? message : "Signing result",
        sizeof(g_signing_notice.message));
    g_signing_notice_deadline_ms = current_payload_transfer_ms() + kSigningNoticeDisplayMs;
}

bool active_auth_allows_session_method(const char* id, const char* method)
{
    if (g_runtime_state.auth_status != LocalAuthProjectionStatus::active) {
        reject_line(id, method, "invalid_state");
        return false;
    }
    if (settings_projection_status() != SettingsProjectionStatus::active) {
        clear_session_scoped_state();
        reject_line(id, method, "invalid_state");
        return false;
    }
    if (!g_runtime_state.locally_unlocked) {
        reject_line(id, method, "auth_unavailable");
        return false;
    }
    if (signing::session_active() &&
        g_active_session_transport != signing::ProtocolTransport::none &&
        g_current_request_route.transport() != g_active_session_transport) {
        reject_line(id, method, "invalid_session");
        return false;
    }
    if (g_pending_request.kind == PendingRequestKind::credential_propose &&
        !signing::session_active()) {
        cancel_pending_credential_proposal_after_session_loss(id);
        reject_line(id, method, "invalid_session");
        return false;
    }
    if (pending_kind_is_signing(g_pending_request.kind) &&
        !signing::session_active()) {
        cancel_pending_signing_after_session_loss(id);
        reject_line(id, method, "invalid_session");
        return false;
    }
    if (g_pending_request.kind == PendingRequestKind::policy_propose &&
        !signing::session_active()) {
        cancel_pending_policy_update_after_session_loss(id);
        reject_line(id, method, "invalid_session");
        return false;
    }
    if (g_runtime_state.ui_busy ||
        any_request_pending()) {
        reject_line(id, method, "busy");
        return false;
    }
    return true;
}

bool reject_if_credential_store_error(const char* id, const char* method)
{
    const SuiZkLoginCredentialStatus status = sui_zklogin_credential_status();
    if (!credential_status_is_error(status)) {
        return false;
    }
    clear_session_scoped_state();
    reject_line(id, method, "invalid_state");
    return true;
}

bool require_credential_install_available(const char* id, const char* method)
{
    const SuiZkLoginCredentialStatus status = sui_zklogin_credential_status();
    if (credential_status_allows_install(status)) {
        return true;
    }
    if (credential_status_is_error(status)) {
        clear_session_scoped_state();
    }
    reject_line(id, method, "invalid_state");
    return false;
}

signing::SessionValidationResult validate_session_for_user_signing(
    const char* session_id,
    void*)
{
    return signing::session_validate(session_id);
}

bool signing_material_ready_for_common_handler()
{
    return g_runtime_state.auth_status == LocalAuthProjectionStatus::active &&
           settings_projection_status() == SettingsProjectionStatus::active &&
           g_runtime_state.locally_unlocked;
}

bool user_signing_ingress_busy()
{
    return pending_kind_is_signing(g_pending_request.kind) ||
           signing::user_signing_flow_active();
}

bool unrelated_user_signing_ingress_busy()
{
    return any_request_pending() ||
           signing::user_signing_flow_active();
}

bool read_signing_mode_for_preflight(
    signing::AuthorizationMode* mode,
    void*)
{
    return signing::read_signing_authorization_mode(mode);
}

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
            record_success(request_id, method);
            return signing::PreflightRetryDisposition::consumed;
        case signing::RetryResponseResult::error_response:
            record_error(
                request_id,
                method,
                retry.error_code != nullptr ? retry.error_code : "internal_output_error");
            return signing::PreflightRetryDisposition::consumed;
        case signing::RetryResponseResult::error_write_failed:
            record_error(request_id, method, "internal_output_error");
            return signing::PreflightRetryDisposition::consumed;
    }
    return signing::PreflightRetryDisposition::consumed;
}

void record_account_unavailable_runtime_failure()
{
    // StopWatch stores zkLogin credential state separately from settings. The
    // credential projection already fails closed when the active proof/key
    // record is missing, invalid, or unreadable.
}

struct TransactionAccountCheckContext {
    const signing::SuiPolicySubjectFacts* facts = nullptr;
    const char* network = nullptr;
    signing::SuiSigningPreparationResult result =
        signing::SuiSigningPreparationResult::account_unavailable;
};

bool check_transaction_account_with_credential(
    const SuiZkLoginCredentialRecord& credential,
    void* context_ptr)
{
    auto* context = static_cast<TransactionAccountCheckContext*>(context_ptr);
    if (context == nullptr || context->facts == nullptr ||
        context->network == nullptr) {
        return false;
    }
    if (strcmp(credential.proof.network, context->network) != 0) {
        context->result = signing::SuiSigningPreparationResult::invalid_network;
        return true;
    }
    context->result = signing::verify_sui_transaction_account_binding(
                          *context->facts,
                          credential.proof.address,
                          false) == signing::SuiTransactionAccountBindingResult::ok
        ? signing::SuiSigningPreparationResult::ok
        : signing::SuiSigningPreparationResult::account_unavailable;
    return true;
}

struct PersonalMessageAccountCheckContext {
    const char* network = nullptr;
    char* account_address = nullptr;
    signing::SuiSigningPreparationResult result =
        signing::SuiSigningPreparationResult::account_unavailable;
};

bool check_personal_message_account_with_credential(
    const SuiZkLoginCredentialRecord& credential,
    void* context_ptr)
{
    auto* context = static_cast<PersonalMessageAccountCheckContext*>(context_ptr);
    if (context == nullptr || context->network == nullptr ||
        context->account_address == nullptr) {
        return false;
    }
    if (strcmp(credential.proof.network, context->network) != 0) {
        context->result = signing::SuiSigningPreparationResult::invalid_network;
        return true;
    }
    context->result = strlcpy(
                          context->account_address,
                          credential.proof.address,
                          signing::kSuiAddressStringBufferSize) <
            signing::kSuiAddressStringBufferSize
        ? signing::SuiSigningPreparationResult::ok
        : signing::SuiSigningPreparationResult::account_unavailable;
    return true;
}

struct NetworkCheckContext {
    const char* network = nullptr;
    signing::SuiSigningPreparationResult result =
        signing::SuiSigningPreparationResult::account_unavailable;
};

bool check_network_with_credential(
    const SuiZkLoginCredentialRecord& credential,
    void* context_ptr)
{
    auto* context = static_cast<NetworkCheckContext*>(context_ptr);
    if (context == nullptr || context->network == nullptr) {
        return false;
    }
    context->result = strcmp(credential.proof.network, context->network) == 0
        ? signing::SuiSigningPreparationResult::ok
        : signing::SuiSigningPreparationResult::invalid_network;
    return true;
}

signing::SuiSigningPreparationResult check_stopwatch_transaction_account(
    const signing::SuiPolicySubjectFacts& facts,
    const char* network,
    void*)
{
    if (network == nullptr || network[0] == '\0') {
        return signing::SuiSigningPreparationResult::account_unavailable;
    }
    TransactionAccountCheckContext context{&facts, network};
    return with_sui_zklogin_credential(
               check_transaction_account_with_credential,
               &context) == SuiZkLoginCredentialAccessResult::consumed
        ? context.result
        : signing::SuiSigningPreparationResult::account_unavailable;
}

signing::SuiSigningPreparationResult check_stopwatch_personal_message_account(
    const char* network,
    char account_address[signing::kSuiAddressStringBufferSize],
    void*)
{
    if (network == nullptr || network[0] == '\0' || account_address == nullptr) {
        return signing::SuiSigningPreparationResult::account_unavailable;
    }
    PersonalMessageAccountCheckContext context{network, account_address};
    return with_sui_zklogin_credential(
               check_personal_message_account_with_credential,
               &context) == SuiZkLoginCredentialAccessResult::consumed
        ? context.result
        : signing::SuiSigningPreparationResult::account_unavailable;
}

signing::SuiSigningPreparationResult check_stopwatch_active_network(
    const char* network,
    void*)
{
    if (network == nullptr || network[0] == '\0') {
        return signing::SuiSigningPreparationResult::account_unavailable;
    }
    NetworkCheckContext context{network};
    return with_sui_zklogin_credential(
               check_network_with_credential,
               &context) == SuiZkLoginCredentialAccessResult::consumed
        ? context.result
        : signing::SuiSigningPreparationResult::account_unavailable;
}

constexpr signing::SuiSigningPreparationOps kStopWatchSigningPreparationOps{
    check_stopwatch_transaction_account,
    check_stopwatch_personal_message_account,
    check_stopwatch_active_network,
    nullptr,
};

const char* signing_error_code(SuiZkLoginSigningResult result)
{
    switch (result) {
        case SuiZkLoginSigningResult::invalid_input:
            return "invalid_params";
        case SuiZkLoginSigningResult::account_unavailable:
            return "account_unavailable";
        case SuiZkLoginSigningResult::signing_error:
        case SuiZkLoginSigningResult::signature_output_too_small:
        case SuiZkLoginSigningResult::zklogin_envelope_error:
            return "signing_failed";
        case SuiZkLoginSigningResult::ok:
        default:
            return "internal_output_error";
    }
}

const char* policy_runtime_code(
    const signing::SignTransactionPolicyRuntimeResult& result)
{
    return result.code != nullptr && result.code[0] != '\0'
               ? result.code
               : "policy_unavailable";
}

signing::PolicySigningExecutionResult make_policy_execution_result(
    signing::PolicySigningExecutionStatus status,
    const char* code,
    const char* message)
{
    signing::PolicySigningExecutionResult result = {};
    result.status = status;
    result.signing_route = signing::Route::sui_sign_transaction;
    result.code = code;
    result.message = message;
    return result;
}

bool copy_policy_execution_metadata(
    signing::PolicySigningExecutionResult* output,
    const signing::SignTransactionPolicyRuntimeResult& input)
{
    if (output == nullptr ||
        input.policy_hash[0] == '\0' ||
        input.rule_ref[0] == '\0') {
        return false;
    }
    strlcpy(output->policy_hash, input.policy_hash, sizeof(output->policy_hash));
    strlcpy(output->rule_ref, input.rule_ref, sizeof(output->rule_ref));
    return output->policy_hash[0] != '\0' && output->rule_ref[0] != '\0';
}

signing::PolicySigningExecutionResult handle_policy_runtime_terminal_result(
    const signing::SignTransactionPolicyRuntimeResult& policy_result)
{
    if (policy_result.status == signing::SignTransactionPolicyRuntimeStatus::policy_rejected) {
        const char* reason_code =
            policy_result.reason_code[0] != '\0'
                ? policy_result.reason_code
                : "policy_rejected";
        if (!append_policy_signing_history(
                signing::HistoryRecordKind::terminal,
                signing::HistoryTerminalResult::policy_rejected,
                reason_code,
                policy_result.payload_digest,
                policy_result.policy_hash,
                policy_result.rule_ref,
                true)) {
            return make_policy_execution_result(
                signing::PolicySigningExecutionStatus::history_error,
                "history_unavailable",
                "Could not record policy signing rejection.");
        }
        signing::PolicySigningExecutionResult result = make_policy_execution_result(
            signing::PolicySigningExecutionStatus::policy_rejected,
            "policy_rejected",
            "The signing request was rejected by device policy.");
        return copy_policy_execution_metadata(&result, policy_result)
                   ? result
                   : make_policy_execution_result(
                         signing::PolicySigningExecutionStatus::history_error,
                         "history_unavailable",
                         "Could not record policy signing rejection.");
    }
    return make_policy_execution_result(
        signing::PolicySigningExecutionStatus::request_error,
        policy_runtime_code(policy_result),
        policy_result.message);
}

signing::PolicySigningExecutionResult execute_policy_sign_transaction_for_common(
    const signing::SignTransactionPolicyRuntimeResult& policy_result)
{
    if (policy_result.status != signing::SignTransactionPolicyRuntimeStatus::policy_authorized) {
        return handle_policy_runtime_terminal_result(policy_result);
    }
    if (!append_policy_signing_history(
            signing::HistoryRecordKind::confirmation,
            signing::HistoryTerminalResult::none,
            "policy_authorized",
            policy_result.payload_digest,
            policy_result.policy_hash,
            policy_result.rule_ref,
            false)) {
        return make_policy_execution_result(
            signing::PolicySigningExecutionStatus::history_error,
            "history_unavailable",
            "Could not record policy signing authorization.");
    }

    signing::PolicySigningExecutionResult result = make_policy_execution_result(
        signing::PolicySigningExecutionStatus::signed_success,
        "policy_signed",
        "Policy authorized signing.");
    if (!copy_policy_execution_metadata(&result, policy_result)) {
        return make_policy_execution_result(
            signing::PolicySigningExecutionStatus::history_error,
            "history_unavailable",
            "Could not record policy signing terminal result.");
    }
    if (policy_result.tx_bytes == nullptr || policy_result.tx_bytes_size == 0) {
        return make_policy_execution_result(
            signing::PolicySigningExecutionStatus::request_error,
            "invalid_params",
            "Policy signing payload is unavailable.");
    }

    const SuiZkLoginSigningResult sign_result =
        sign_sui_zklogin_transaction(
            policy_result.tx_bytes,
            policy_result.tx_bytes_size,
            result.signature,
            &result.signature_size);
    if (sign_result != SuiZkLoginSigningResult::ok) {
        wipe_sensitive_buffer(result.signature, sizeof(result.signature));
        result.signature_size = 0;
        const char* code = signing_error_code(sign_result);
        if (!append_policy_signing_history(
                signing::HistoryRecordKind::terminal,
                signing::HistoryTerminalResult::signing_failed,
                code,
                policy_result.payload_digest,
                policy_result.policy_hash,
                policy_result.rule_ref,
                false)) {
            return make_policy_execution_result(
                signing::PolicySigningExecutionStatus::history_error,
                "history_unavailable",
                "Could not record policy signing terminal result.");
        }
        return make_policy_execution_result(
            signing::PolicySigningExecutionStatus::signing_failed,
            code,
            "The device could not produce a signature.");
    }

    if (!append_policy_signing_history(
            signing::HistoryRecordKind::terminal,
            signing::HistoryTerminalResult::signed_success,
            "policy_signed",
            policy_result.payload_digest,
            policy_result.policy_hash,
            policy_result.rule_ref,
            false)) {
        wipe_sensitive_buffer(result.signature, sizeof(result.signature));
        result.signature_size = 0;
        return make_policy_execution_result(
            signing::PolicySigningExecutionStatus::history_error,
            "history_unavailable",
            "Could not record policy signing terminal result.");
    }
    return result;
}

bool write_policy_execution_response(
    const char* id,
    const uint8_t* request_identity,
    const signing::PolicySigningExecutionResult& result)
{
    const bool written = signing::signing_outcome_write_policy_execution(
        id,
        signing::session_id(),
        request_identity,
        result,
        signing_outcome_writer_ops());
    switch (result.status) {
        case signing::PolicySigningExecutionStatus::request_error:
        case signing::PolicySigningExecutionStatus::history_error:
        case signing::PolicySigningExecutionStatus::account_error: {
            const char* code =
                result.code != nullptr && result.code[0] != '\0'
                    ? result.code
                    : "internal_output_error";
            if (!written) {
                record_error(id, "sign_transaction", "internal_output_error");
                return false;
            }
            record_error(id, "sign_transaction", code);
            return true;
        }
        case signing::PolicySigningExecutionStatus::policy_rejected:
            if (written) {
                record_error(id, "sign_transaction", "policy_rejected");
                return true;
            }
            record_error(id, "sign_transaction", "internal_output_error");
            return false;
        case signing::PolicySigningExecutionStatus::signing_failed: {
            const char* code =
                result.code != nullptr && result.code[0] != '\0'
                    ? result.code
                    : "signing_failed";
            if (written) {
                record_error(id, "sign_transaction", code);
                return true;
            }
            record_error(id, "sign_transaction", "internal_output_error");
            return false;
        }
        case signing::PolicySigningExecutionStatus::signed_success:
            if (written) {
                record_success(id, "sign_transaction");
                return true;
            }
            record_error(id, "sign_transaction", "internal_output_error");
            return false;
    }
    record_error(id, "sign_transaction", "internal_output_error");
    return false;
}

bool prepare_signing_review_label_from_snapshot(
    const signing::UserSigningFlowSnapshot& snapshot,
    char* output,
    size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return false;
    }
    output[0] = '\0';
    if (snapshot.signing_route == signing::SupportedSignRoute::sui_sign_personal_message) {
        strlcpy(output, "Sui message", output_size);
        return true;
    }
    if (snapshot.signing_route != signing::SupportedSignRoute::sui_sign_transaction) {
        return false;
    }
    const bool blind = snapshot.blind_signing_confirmation;
    strlcpy(output, blind ? "Blind Sui tx" : "Sui tx", output_size);
    return append_review_line(
               output,
               output_size,
               "Type",
               snapshot.sui_review.type_summary[0] != '\0'
                   ? snapshot.sui_review.type_summary
                   : "Transaction") &&
           append_review_line(
               output,
               output_size,
               "Risk",
               snapshot.sui_review.risk_label[0] != '\0'
                   ? snapshot.sui_review.risk_label
                   : (blind ? "High" : "Review")) &&
           (!blind ||
            append_review_row(output, output_size, snapshot.sui_review, "Reason", "Reason")) &&
           append_review_row(output, output_size, snapshot.sui_review, "Sender", "Sender") &&
           append_review_row(output, output_size, snapshot.sui_review, "Gas max", "Gas") &&
           append_review_row(output, output_size, snapshot.sui_review, "Commands", "Cmds");
}

bool show_user_signing_review_for_common()
{
    wipe_sensitive_buffer(
        &g_user_signing_snapshot_scratch,
        sizeof(g_user_signing_snapshot_scratch));
    signing::UserSigningFlowSnapshot& snapshot = g_user_signing_snapshot_scratch;
    char review_label[sizeof(g_pending_request.label)] = {};
    if (!signing::user_signing_flow_snapshot_copy(&snapshot) ||
        !prepare_signing_review_label_from_snapshot(
            snapshot,
            review_label,
            sizeof(review_label))) {
        wipe_sensitive_buffer(
            &g_user_signing_snapshot_scratch,
            sizeof(g_user_signing_snapshot_scratch));
        return false;
    }
    if (!remember_current_response_route()) {
        wipe_sensitive_buffer(
            &g_user_signing_snapshot_scratch,
            sizeof(g_user_signing_snapshot_scratch));
        return false;
    }
    g_pending_request.kind =
        snapshot.signing_route == signing::SupportedSignRoute::sui_sign_transaction
            ? PendingRequestKind::sign_transaction
            : PendingRequestKind::sign_personal_message;
    strlcpy(g_pending_request.id, snapshot.request_id, sizeof(g_pending_request.id));
    strlcpy(g_pending_request.label, review_label, sizeof(g_pending_request.label));
    g_pending_request.request_window = snapshot.request_window;
    wipe_sensitive_buffer(
        &g_user_signing_snapshot_scratch,
        sizeof(g_user_signing_snapshot_scratch));
    return true;
}

void clear_user_signing_flow_for_common()
{
    signing::user_signing_flow_clear();
}

void show_user_signing_display_error()
{
    copy_status_text(g_status.last_error, sizeof(g_status.last_error), "ui_error");
}

void record_user_signing_waiting_for_review(
    const char* id,
    signing::Route signing_route)
{
    (void)id;
    (void)signing_route;
}

void log_policy_rejected(
    const char* id,
    const char* chain,
    const char* method,
    const char* rule_ref)
{
    (void)id;
    (void)chain;
    (void)method;
    (void)rule_ref;
}

void log_policy_signing_failed(
    const char* id,
    const char* chain,
    const char* method)
{
    (void)id;
    (void)chain;
    (void)method;
}

void log_policy_signed(
    const char* id,
    const char* chain,
    const char* method,
    const char* rule_ref)
{
    (void)id;
    (void)chain;
    (void)method;
    (void)rule_ref;
}

void log_response_write_failure(const char* response_type, const char* id)
{
    record_error(id, response_type, "internal_output_error");
}

bool write_common_method_error_response(
    const char* id,
    const char* method,
    const char* code)
{
    return reject_line(id, method, code);
}

bool write_common_method_success_response(const char* id, const char* method, JsonObjectConst result)
{
    if (!write_success_response(id, method, result)) {
        return false;
    }
    if (method != nullptr && strcmp(method, "get_status") == 0) {
        ++g_status.status_responses;
    }
    return true;
}

const signing::ResponseWriter& usb_operation_response_writer()
{
    static const signing::ResponseWriter usb_writer(
        write_common_method_error_response,
        write_common_method_success_response,
        write_payload_transfer_success_response,
        log_response_write_failure);
    return usb_writer;
}

signing::ResponseWriter common_method_response_writer()
{
    return current_response_route().response_writer();
}

const signing::SigningHandlerOps& signing_handler_ops()
{
    static const signing::SigningHandlerOps ops = {
        signing_material_ready_for_common_handler,
        user_signing_ingress_busy,
        unrelated_user_signing_ingress_busy,
        current_payload_transfer_ms,
        validate_session_for_user_signing,
        nullptr,
        signing::payload_delivery_admit_operation,
        read_signing_mode_for_preflight,
        nullptr,
        respond_to_signing_retry,
        nullptr,
        g_signing_preflight_retry_stored_response,
        sizeof(g_signing_preflight_retry_stored_response),
        kStopWatchSigningPreparationOps,
        signing::evaluate_sign_transaction_preflight,
        signing::evaluate_sign_personal_message_preflight,
        record_account_unavailable_runtime_failure,
        signing::evaluate_sign_transaction_policy,
        execute_policy_sign_transaction_for_common,
        write_policy_execution_response,
        signing::clear_policy_signing_execution_result,
        signing::clear_sign_transaction_policy_runtime_result,
        make_signing_approval_window,
        signing::user_signing_flow_begin,
        signing::user_signing_flow_begin_personal_message,
        signing::clear_sui_prepared_sign_transaction,
        signing::clear_sui_prepared_personal_message,
        show_user_signing_review_for_common,
        clear_user_signing_flow_for_common,
        show_user_signing_display_error,
        record_user_signing_waiting_for_review,
        show_policy_signing_notice_for_common,
        log_policy_rejected,
        log_policy_signing_failed,
        log_policy_signed,
        log_response_write_failure,
    };
    return ops;
}

bool policy_material_ready_for_common_handler()
{
    if (settings_projection_status() != SettingsProjectionStatus::active) {
        clear_session_scoped_state();
        return false;
    }
    return g_runtime_state.auth_status == LocalAuthProjectionStatus::active;
}

bool write_policy_get_busy_for_common(
    const char* id,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    return !active_auth_allows_session_method(id, "policy_get");
}

bool write_policy_get_admission_error_for_common(
    const char* id,
    signing::OperationType operation,
    const signing::ResponseWriter& writer)
{
    (void)operation;
    (void)writer;
    return reject_if_payload_transfer_blocks_safe_read(id, "policy_get");
}

bool write_policy_propose_busy_for_common(
    const char* id,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    return !active_auth_allows_session_method(id, "policy_propose") ||
           reject_if_payload_transfer_blocks_sensitive_flow(id, "policy_propose");
}

bool show_policy_update_review_for_common()
{
    const signing::PolicyUpdateFlowSnapshot snapshot =
        signing::policy_update_flow_snapshot();
    if (!snapshot.active ||
        snapshot.request_id == nullptr ||
        snapshot.request_id[0] == '\0') {
        return false;
    }
    clear_pending_request();
    if (!remember_current_response_route()) {
        return false;
    }
    g_pending_request.kind = PendingRequestKind::policy_propose;
    strlcpy(g_pending_request.id, snapshot.request_id, sizeof(g_pending_request.id));
    strlcpy(
        g_pending_request.label,
        snapshot.scope_summary != nullptr && snapshot.scope_summary[0] != '\0'
            ? snapshot.scope_summary
            : "Policy update",
        sizeof(g_pending_request.label));
    g_pending_request.request_window = snapshot.review_window;
    return true;
}

bool require_policy_matching_session_for_common(
    const char* id,
    const char* session_id,
    const signing::ResponseWriter& writer)
{
    switch (signing::session_validate(session_id)) {
        case signing::SessionValidationResult::ok:
            if (g_active_session_transport != signing::ProtocolTransport::none &&
                g_current_request_route.transport() != g_active_session_transport) {
                writer.write_error(id, "invalid_session");
                return false;
            }
            return true;
        case signing::SessionValidationResult::missing:
            cancel_pending_credential_proposal_after_session_loss(id);
            writer.write_error(id, "invalid_session");
            return false;
        case signing::SessionValidationResult::invalid_format:
        case signing::SessionValidationResult::mismatch:
        default:
            writer.write_error(id, "invalid_session");
            return false;
    }
}

void record_policy_update_waiting_for_review(const char* id)
{
    (void)id;
}

const signing::PolicyHandlerOps& policy_handler_ops()
{
    static const signing::PolicyHandlerOps ops = {
        policy_material_ready_for_common_handler,
        write_policy_get_busy_for_common,
        write_policy_get_admission_error_for_common,
        write_policy_propose_busy_for_common,
        require_policy_matching_session_for_common,
        nullptr,
        current_payload_transfer_ms,
        make_policy_update_review_window,
        signing::policy_update_flow_begin,
        signing::policy_update_flow_begin_result_reason,
        show_policy_update_review_for_common,
        signing::policy_update_flow_record_ui_error,
        finish_policy_update,
        record_policy_update_waiting_for_review,
    };
    return ops;
}

void handle_policy_get_request(const char* id, JsonDocument& request)
{
    signing::handle_protocol_policy_get_request(
        id,
        request,
        common_method_response_writer().for_method("policy_get"),
        policy_handler_ops());
}

void handle_policy_propose_request(const char* id, JsonDocument& request)
{
    signing::handle_protocol_policy_propose_request(
        id,
        request,
        common_method_response_writer().for_method("policy_propose"),
        policy_handler_ops());
}

void handle_get_approval_history_request(const char* id, JsonDocument& request)
{
    if (!active_auth_allows_session_method(id, "get_approval_history")) {
        return;
    }
    signing::handle_protocol_get_approval_history_request(
        id,
        request,
        common_method_response_writer().for_method("get_approval_history"),
        approval_history_handler_ops());
}

bool resolve_request_payload_ref(const char* id, const char* method, JsonDocument& request)
{
    JsonDocument resolved_payload;
    const signing::RequestEnvelope envelope{
        id,
        method,
        signing::classify_operation_type(method),
    };
    return signing::payload_delivery_resolve_request_payload_ref(
        request,
        resolved_payload,
        current_payload_transfer_ms(),
        envelope,
        common_method_response_writer().for_method(method));
}

bool reject_if_payload_transfer_blocks_sensitive_flow(const char* id, const char* method)
{
    const signing::OperationManifestEntry* entry =
        signing::operation_manifest_entry_for_wire_type(method);
    if (entry == nullptr) {
        reject_line(id, method, "unknown_request");
        return true;
    }
    const PayloadTransferAdmissionDecision admission =
        signing::payload_delivery_admit_operation(
            signing::PayloadDeliveryOperationAdmissionInput{
                current_payload_transfer_ms(),
                entry->payload_delivery_operation,
            });
    if (admission.result == PayloadTransferAdmissionResult::ok) {
        return false;
    }
    if (signing::payload_delivery_admission_blocks_sensitive_flow(admission)) {
        reject_line(id, method, "busy");
        return true;
    }
    reject_line(id, method, "unknown_request");
    return true;
}

bool reject_if_payload_transfer_blocks_safe_read(const char* id, const char* method)
{
    const signing::OperationManifestEntry* entry =
        signing::operation_manifest_entry_for_wire_type(method);
    if (entry == nullptr) {
        reject_line(id, method, "unknown_request");
        return true;
    }
    const PayloadTransferAdmissionDecision admission =
        signing::payload_delivery_admit_operation(
            signing::PayloadDeliveryOperationAdmissionInput{
                current_payload_transfer_ms(),
                entry->payload_delivery_operation,
            });
    if (admission.result == PayloadTransferAdmissionResult::ok ||
        signing::payload_delivery_admission_allows_safe_read(admission)) {
        return false;
    }
    reject_line(id, method, "busy");
    return true;
}

bool write_payload_delivery_safe_read_admission_error_for_common(
    const char* id,
    signing::OperationType operation,
    const signing::ResponseWriter&)
{
    const char* method = signing::operation_type_wire_name(operation);
    return reject_if_payload_transfer_blocks_safe_read(
        id,
        method != nullptr ? method : "get_status");
}

bool write_payload_delivery_identify_device_admission_error_for_common(
    const char* id,
    const signing::ResponseWriter& writer)
{
    if (g_runtime_state.ui_busy) {
        writer.write_error(id, "busy");
        return true;
    }
    return reject_if_payload_transfer_blocks_sensitive_flow(id, "identify_device");
}

bool payload_transfer_material_ready_for_common_handler()
{
    return g_runtime_state.auth_status == LocalAuthProjectionStatus::active;
}

bool write_payload_transfer_busy_or_auth_error_for_common(
    const char* id,
    const signing::ResponseWriter& writer)
{
    if (!g_runtime_state.locally_unlocked) {
        writer.write_error(id, "auth_unavailable");
        return true;
    }
    if (g_pending_request.kind == PendingRequestKind::credential_propose &&
        !signing::session_active()) {
        cancel_pending_credential_proposal_after_session_loss(id);
        writer.write_error(id, "invalid_session");
        return true;
    }
    if (pending_kind_is_signing(g_pending_request.kind) &&
        !signing::session_active()) {
        cancel_pending_signing_after_session_loss(id);
        writer.write_error(id, "invalid_session");
        return true;
    }
    if (g_pending_request.kind == PendingRequestKind::policy_propose &&
        !signing::session_active()) {
        cancel_pending_policy_update_after_session_loss(id);
        writer.write_error(id, "invalid_session");
        return true;
    }
    if (g_runtime_state.ui_busy ||
        any_request_pending()) {
        writer.write_error(id, "busy");
        return true;
    }
    return false;
}

bool require_payload_transfer_session_for_common(
    const char* id,
    const char* session_id,
    const signing::ResponseWriter& writer)
{
    switch (signing::session_validate(session_id)) {
        case signing::SessionValidationResult::ok:
            if (g_active_session_transport != signing::ProtocolTransport::none &&
                g_current_request_route.transport() != g_active_session_transport) {
                writer.write_error(id, "invalid_session");
                return false;
            }
            return true;
        case signing::SessionValidationResult::invalid_format:
        case signing::SessionValidationResult::missing:
        case signing::SessionValidationResult::mismatch:
        default:
            writer.write_error(id, "invalid_session");
            return false;
    }
}

signing::TimeoutWindow payload_transfer_timeout_window_for_size(size_t size_bytes)
{
    const uint32_t now_ms = current_payload_transfer_ms();
    return signing::timeout_window_from_deadline(
        now_ms,
        now_ms + signing::payload_delivery_timeout_window_ms_for_size(size_bytes));
}

const signing::PayloadTransferHandlerOps& payload_transfer_handler_ops()
{
    static const signing::PayloadTransferHandlerOps ops = {
        payload_transfer_material_ready_for_common_handler,
        write_payload_transfer_busy_or_auth_error_for_common,
        require_payload_transfer_session_for_common,
        current_payload_transfer_ms,
        payload_transfer_timeout_window_for_size,
    };
    return ops;
}

bool write_existing_session_connect_response(
    const char* id,
    const signing::ResponseWriter& writer)
{
    if (!signing::session_active()) {
        return false;
    }
    if (g_active_session_transport != signing::ProtocolTransport::none &&
        g_current_request_route.transport() != g_active_session_transport) {
        writer.write_error(id, "invalid_state");
        return true;
    }
    if (write_connect_response_with_writer(id, writer)) {
        record_success(id, "connect");
    } else {
        record_error(id, "connect", "internal_output_error");
    }
    return true;
}

bool connect_material_ready_for_common()
{
    return true;
}

bool write_connect_admission_error_for_common(
    const char* id,
    const signing::ResponseWriter& writer)
{
    if (g_runtime_state.auth_status == LocalAuthProjectionStatus::missing ||
        g_runtime_state.auth_status == LocalAuthProjectionStatus::invalid ||
        g_runtime_state.auth_status == LocalAuthProjectionStatus::storage_error) {
        clear_session_scoped_state();
        writer.write_error(id, "invalid_state");
        return true;
    }
    if (settings_projection_status() != SettingsProjectionStatus::active) {
        clear_session_scoped_state();
        writer.write_error(id, "invalid_state");
        return true;
    }
    if (reject_if_credential_store_error(id, "connect")) {
        return true;
    }
    if (signing::session_active()) {
        return false;
    }
    if (g_runtime_state.auth_status == LocalAuthProjectionStatus::locked) {
        writer.write_error(id, "auth_unavailable");
        return true;
    }
    if (g_runtime_state.auth_status != LocalAuthProjectionStatus::active) {
        clear_session_scoped_state();
        writer.write_error(id, "invalid_state");
        return true;
    }
    if (reject_if_payload_transfer_blocks_sensitive_flow(id, "connect")) {
        return true;
    }
    if (g_runtime_state.ui_busy ||
        any_request_pending()) {
        writer.write_error(id, "busy");
        return true;
    }
    return false;
}

bool begin_connect_approval_for_common(
    const char* request_id,
    const char* client_name,
    signing::TimeoutTick now,
    signing::TimeoutWindow approval_window)
{
    if (!signing::connect_approval_begin(
            request_id,
            client_name,
            now,
            approval_window)) {
        return false;
    }
    if (!remember_current_response_route()) {
        signing::connect_approval_clear();
        return false;
    }
    return true;
}

void reset_connect_review_choice_queue_for_common()
{
}

void show_connect_review_for_common()
{
}

void show_connect_unavailable_for_common()
{
}

void record_connect_waiting_for_review(const char* id, const char* client_name)
{
    (void)id;
    (void)client_name;
}

bool receive_connect_review_choice(signing::ConnectApprovalChoice*)
{
    return false;
}

bool connect_review_human_approval_requires_pin()
{
    return false;
}

bool begin_connect_pin_auth_from_review(signing::TimeoutTick)
{
    return false;
}

bool replace_active_session_for_connect_review()
{
    if (!g_pending_response_route.bound() ||
        signing::session_replace(secure_random_fill_with_context, nullptr) !=
            signing::SessionStartResult::ok) {
        return false;
    }
    g_active_session_transport = g_pending_response_route.transport();
    return true;
}

bool write_connect_error_for_flow(const char* id, const char* code)
{
    const bool written = reject_line(id, "connect", code);
    clear_pending_response_route();
    return written;
}

bool write_connect_rejected_for_flow(const char* id, const char* code)
{
    const bool written = reject_line(id, "connect", code);
    clear_pending_response_route();
    return written;
}

bool write_connect_approved_for_flow(const char* id)
{
    const bool written = write_connect_response_with_writer(
        id,
        common_method_response_writer());
    if (written) {
        record_success(id, "connect");
    } else {
        record_error(id, "connect", "internal_output_error");
    }
    clear_pending_response_route();
    return written;
}

void show_connect_result_for_flow(
    const char*,
    signing::ConnectReviewTerminalUiKind)
{
}

bool connect_review_panel_visible_for_flow()
{
    return true;
}

void log_connect_review_flow_info(const char*, const char*)
{
}

void log_connect_review_flow_error(const char*, const char*)
{
}

void log_connect_review_write_failure(const char* response_type, const char* id)
{
    record_error(id, response_type != nullptr ? response_type : "connect", "internal_output_error");
}

void log_connect_review_recovered(const char*)
{
}

const signing::ConnectReviewResponseFlowOps& connect_review_response_flow_ops()
{
    static const signing::ConnectReviewResponseFlowOps ops = {
        current_payload_transfer_ms,
        nullptr,
        reset_connect_review_choice_queue_for_common,
        receive_connect_review_choice,
        signing::connect_approval_awaiting_choice,
        connect_review_human_approval_requires_pin,
        begin_connect_pin_auth_from_review,
        signing::connect_approval_choose,
        signing::connect_approval_snapshot,
        signing::connect_approval_deadline_reached,
        signing::connect_approval_request_id,
        signing::connect_approval_clear,
        replace_active_session_for_connect_review,
        write_connect_error_for_flow,
        write_connect_approved_for_flow,
        write_connect_rejected_for_flow,
        log_connect_review_flow_info,
        log_connect_review_flow_error,
        log_connect_review_write_failure,
        log_connect_review_recovered,
        show_connect_result_for_flow,
        connect_review_panel_visible_for_flow,
        show_connect_review_for_common,
    };
    return ops;
}

const signing::ConnectHandlerOps& connect_handler_ops()
{
    static const signing::ConnectHandlerOps ops = {
        connect_material_ready_for_common,
        write_connect_admission_error_for_common,
        write_existing_session_connect_response,
        current_payload_transfer_ms,
        make_connect_approval_window,
        begin_connect_approval_for_common,
        show_connect_unavailable_for_common,
        reset_connect_review_choice_queue_for_common,
        show_connect_review_for_common,
        record_connect_waiting_for_review,
    };
    return ops;
}

bool require_active_matching_session_for_common(
    const char* id,
    const char* session_id,
    const signing::ResponseWriter& writer)
{
    switch (signing::session_validate(session_id)) {
        case signing::SessionValidationResult::ok:
            if (g_active_session_transport != signing::ProtocolTransport::none &&
                g_current_request_route.transport() != g_active_session_transport) {
                writer.write_error(id, "invalid_session");
                return false;
            }
            return true;
        case signing::SessionValidationResult::missing:
            cancel_pending_credential_proposal_after_session_loss(id);
            writer.write_error(id, "invalid_session");
            return false;
        case signing::SessionValidationResult::invalid_format:
        case signing::SessionValidationResult::mismatch:
        default:
            writer.write_error(id, "invalid_session");
            return false;
    }
}

bool write_disconnect_success_for_common(const char* id)
{
    clear_session_scoped_state();
    if (write_empty_success_response(id, "disconnect")) {
        return true;
    } else {
        record_error(id, "disconnect", "internal_output_error");
        return false;
    }
}

bool disconnect_pending_credential_proposal_for_common(
    const char* id,
    const char*,
    const signing::ResponseWriter&)
{
    if (g_pending_request.kind != PendingRequestKind::credential_propose) {
        return false;
    }
    cancel_pending_credential_proposal_after_session_loss(id);
    write_disconnect_success_for_common(id);
    return true;
}

bool disconnect_pending_policy_update_for_common(
    const char* id,
    const char*,
    const signing::ResponseWriter&)
{
    if (g_pending_request.kind != PendingRequestKind::policy_propose) {
        return false;
    }
    cancel_pending_policy_update_after_session_loss(id);
    write_disconnect_success_for_common(id);
    return true;
}

bool disconnect_pending_user_signing_for_common(
    const char* id,
    const char*,
    const signing::ResponseWriter&)
{
    if (!pending_kind_is_signing(g_pending_request.kind)) {
        return false;
    }
    cancel_pending_signing_after_session_loss(id);
    write_disconnect_success_for_common(id);
    return true;
}

bool write_busy_if_pending_or_local_flow_active_for_disconnect_common(
    const char* id,
    const signing::ResponseWriter& writer)
{
    if (g_runtime_state.ui_busy ||
        any_request_pending()) {
        writer.write_error(id, "busy");
        return true;
    }
    return false;
}

bool write_payload_delivery_disconnect_admission_error_for_common(
    const char* id,
    signing::OperationType,
    const signing::ResponseWriter& writer)
{
    const signing::PayloadDeliveryAdmissionDecision admission =
        signing::payload_delivery_admit_operation(
            signing::PayloadDeliveryOperationAdmissionInput{
                current_payload_transfer_ms(),
                signing::PayloadDeliveryOperationKind::disconnect,
            });
    if (admission.result == signing::PayloadDeliveryAdmissionResult::ok) {
        return false;
    }
    writer.write_error(
        id,
        admission.result == signing::PayloadDeliveryAdmissionResult::unknown_request
            ? "unknown_request"
            : "busy");
    return true;
}

const signing::DisconnectHandlerOps& disconnect_handler_ops()
{
    static const signing::DisconnectHandlerOps ops = {
        require_active_matching_session_for_common,
        disconnect_pending_policy_update_for_common,
        disconnect_pending_credential_proposal_for_common,
        disconnect_pending_user_signing_for_common,
        write_busy_if_pending_or_local_flow_active_for_disconnect_common,
        write_payload_delivery_disconnect_admission_error_for_common,
        clear_session_scoped_state,
    };
    return ops;
}

bool retained_response_material_ready_for_common()
{
    return g_runtime_state.auth_status == LocalAuthProjectionStatus::active &&
           settings_projection_status() == SettingsProjectionStatus::active;
}

bool write_payload_delivery_retained_response_admission_error_for_common(
    const char* id,
    signing::OperationType,
    const signing::ResponseWriter& writer)
{
    const signing::PayloadDeliveryAdmissionDecision admission =
        signing::payload_delivery_admit_operation(
            signing::PayloadDeliveryOperationAdmissionInput{
                current_payload_transfer_ms(),
                signing::PayloadDeliveryOperationKind::retained_response_read_cleanup,
            });
    if (admission.result == signing::PayloadDeliveryAdmissionResult::ok) {
        return false;
    }
    writer.write_error(
        id,
        admission.result == signing::PayloadDeliveryAdmissionResult::unknown_request
            ? "unknown_request"
            : "busy");
    return true;
}

const signing::RetainedResponseHandlerOps& retained_response_handler_ops()
{
    static const signing::RetainedResponseHandlerOps ops = {
        retained_response_material_ready_for_common,
        write_payload_delivery_retained_response_admission_error_for_common,
        require_active_matching_session_for_common,
    };
    return ops;
}

bool approval_history_busy_for_common(
    const char*,
    const signing::ResponseWriter&)
{
    return false;
}

const signing::ApprovalHistoryHandlerOps& approval_history_handler_ops()
{
    static const signing::ApprovalHistoryHandlerOps ops = {
        retained_response_material_ready_for_common,
        approval_history_busy_for_common,
        write_payload_delivery_retained_response_admission_error_for_common,
        require_active_matching_session_for_common,
        signing::approval_history_read_page,
    };
    return ops;
}

const signing::GetStatusHandlerOps& get_status_handler_ops()
{
    static const signing::GetStatusHandlerOps ops = {
        nullptr,
        write_payload_delivery_safe_read_admission_error_for_common,
        device_status_info,
    };
    return ops;
}

const signing::IdentifyDeviceHandlerOps& identify_device_handler_ops()
{
    static const signing::IdentifyDeviceHandlerOps ops = {
        write_payload_delivery_identify_device_admission_error_for_common,
        identification_code_safe,
        show_identification_code,
        device_status_info,
        kIdentifyDisplayMs,
    };
    return ops;
}

bool session_method_material_ready_for_common()
{
    return true;
}

bool write_session_method_state_error_for_common(
    const char* id,
    const signing::ResponseWriter& writer)
{
    const char* method = writer.method != nullptr ? writer.method : "";
    return !active_auth_allows_session_method(id, method);
}

const signing::ActiveSessionRequestGuardOps& safe_read_session_guard_ops()
{
    static const signing::ActiveSessionRequestGuardOps ops = {
        session_method_material_ready_for_common,
        write_session_method_state_error_for_common,
        write_payload_delivery_safe_read_admission_error_for_common,
        require_active_matching_session_for_common,
    };
    return ops;
}

const signing::ActiveSessionRequestGuardOps& state_only_session_guard_ops()
{
    static const signing::ActiveSessionRequestGuardOps ops = {
        session_method_material_ready_for_common,
        write_session_method_state_error_for_common,
        nullptr,
        require_active_matching_session_for_common,
    };
    return ops;
}

bool read_stopwatch_sui_account_settings(signing::SuiAccountSettings* settings)
{
    if (settings == nullptr) {
        return false;
    }
    *settings = signing::kDefaultSuiAccountSettings;
    return true;
}

bool project_stopwatch_sui_identity_for_session_read(
    signing::SuiSessionReadProjection* projection)
{
    if (projection == nullptr) {
        return false;
    }
    *projection = signing::SuiSessionReadProjection{};
    signing::SuiPublicIdentity& identity = projection->identity;
    identity.kind = signing::SuiActiveIdentityKind::none;
    identity.error = signing::SuiActiveIdentityError::none;

    const SuiZkLoginAccountProjection account_projection = sui_zklogin_account_projection();
    projection->sui_zklogin_credential_available =
        credential_status_allows_install(account_projection.status);
    if (account_projection.status == SuiZkLoginCredentialStatus::missing) {
        return true;
    }
    if (credential_status_is_error(account_projection.status) ||
        !account_projection.active ||
        account_projection.address[0] == '\0' ||
        account_projection.public_key_size == 0 ||
        account_projection.public_key_size > sizeof(identity.public_key)) {
        identity.kind = signing::SuiActiveIdentityKind::error;
        identity.error = signing::SuiActiveIdentityError::proof_storage_error;
        projection->sui_zklogin_credential_available = false;
        return true;
    }

    identity.kind = signing::SuiActiveIdentityKind::zklogin;
    strlcpy(identity.address, account_projection.address, sizeof(identity.address));
    memcpy(identity.public_key, account_projection.public_key, account_projection.public_key_size);
    identity.public_key_size = account_projection.public_key_size;
    return true;
}

const signing::SessionReadHandlerOps& session_read_handler_ops()
{
    static const signing::SessionReadHandlerOps ops = {
        session_method_material_ready_for_common,
        write_session_method_state_error_for_common,
        write_payload_delivery_safe_read_admission_error_for_common,
        require_active_matching_session_for_common,
        signing::read_signing_authorization_mode,
        read_stopwatch_sui_account_settings,
        project_stopwatch_sui_identity_for_session_read,
        nullptr,
    };
    return ops;
}

void handle_connect_request(const char* id, JsonDocument& request)
{
    signing::handle_protocol_connect_request(
        id,
        request,
        common_method_response_writer().for_method("connect"),
        connect_handler_ops());
}

void handle_disconnect_request(const char* id, JsonDocument& request)
{
    signing::handle_protocol_disconnect_request(
        id,
        request,
        common_method_response_writer().for_method("disconnect"),
        disconnect_handler_ops());
}

void handle_get_capabilities_request(const char* id, JsonDocument& request)
{
    signing::handle_protocol_get_capabilities_request(
        id,
        request,
        common_method_response_writer().for_method("get_capabilities"),
        session_read_handler_ops());
}

void handle_get_accounts_request(const char* id, JsonDocument& request)
{
    signing::handle_protocol_get_accounts_request(
        id,
        request,
        common_method_response_writer().for_method("get_accounts"),
        session_read_handler_ops());
}

bool write_credential_prepare_state_error_for_common(
    const char* id,
    const signing::ResponseWriter&)
{
    return !require_credential_install_available(id, "credential_prepare");
}

bool write_credential_propose_state_error_for_common(
    const char* id,
    const signing::ResponseWriter&)
{
    if (any_request_pending() ||
        sui_zklogin_proposal_state_active()) {
        reject_line(id, "credential_propose", "busy");
        return true;
    }
    if (!require_credential_install_available(id, "credential_propose")) {
        return true;
    }
    return reject_if_payload_transfer_blocks_sensitive_flow(id, "credential_propose");
}

signing::SuiZkLoginCredentialPrepareResult prepare_stopwatch_sui_zklogin_credential_for_common(
    const char* session_id,
    signing::SuiZkLoginCredentialPreparation* output)
{
    if (output == nullptr) {
        return signing::SuiZkLoginCredentialPrepareResult::internal_output_error;
    }
    memset(output, 0, sizeof(*output));
    const CredentialPreparationBeginResult result =
        credential_preparation_begin(session_id, secure_random_fill_with_context, nullptr);
    if (result == CredentialPreparationBeginResult::invalid_session) {
        return signing::SuiZkLoginCredentialPrepareResult::invalid_session;
    }
    if (result != CredentialPreparationBeginResult::ok) {
        return signing::SuiZkLoginCredentialPrepareResult::internal_output_error;
    }
    const CredentialPreparationSnapshot snapshot = credential_preparation_snapshot();
    if (!snapshot.active ||
        snapshot.address == nullptr ||
        snapshot.address[0] == '\0' ||
        snapshot.public_key_base64 == nullptr ||
        snapshot.public_key_base64[0] == '\0') {
        return signing::SuiZkLoginCredentialPrepareResult::internal_output_error;
    }
    strlcpy(output->address, snapshot.address, sizeof(output->address));
    strlcpy(
        output->public_key_base64,
        snapshot.public_key_base64,
        sizeof(output->public_key_base64));
    return output->address[0] != '\0' && output->public_key_base64[0] != '\0'
               ? signing::SuiZkLoginCredentialPrepareResult::ok
               : signing::SuiZkLoginCredentialPrepareResult::internal_output_error;
}

signing::SuiZkLoginCredentialProposalBeginResult begin_stopwatch_sui_zklogin_proposal_for_common(
    JsonVariantConst params,
    const char* request_id,
    const char* session_id,
    signing::TimeoutTick now,
    signing::TimeoutWindow request_window)
{
    uint8_t prepared_seed[kSuiEd25519SeedBytes] = {};
    if (!credential_preparation_copy_seed_for_session(session_id, prepared_seed)) {
        return signing::SuiZkLoginCredentialProposalBeginResult::invalid_state;
    }
    const SuiZkLoginProposalBeginResult begin_result =
        sui_zklogin_proposal_state_begin(
            params,
            request_id,
            session_id,
            now,
            request_window,
            prepared_seed);
    wipe_sensitive_buffer(prepared_seed, sizeof(prepared_seed));
    return begin_result == SuiZkLoginProposalBeginResult::ok
               ? signing::SuiZkLoginCredentialProposalBeginResult::ok
               : signing::SuiZkLoginCredentialProposalBeginResult::invalid_proof;
}

void clear_stopwatch_credential_preparation_after_begin_failure()
{
    credential_preparation_state_clear();
}

bool show_stopwatch_sui_zklogin_proposal_review(const char* id)
{
    clear_pending_request();
    if (!remember_current_response_route()) {
        return false;
    }
    g_pending_request.kind = PendingRequestKind::credential_propose;
    strlcpy(g_pending_request.id, id, sizeof(g_pending_request.id));
    strlcpy(g_pending_request.label, "zkLogin proof", sizeof(g_pending_request.label));
    return g_pending_request.id[0] != '\0';
}

const signing::SuiZkLoginCredentialHandlerOps& sui_zklogin_credential_handler_ops()
{
    static const signing::SuiZkLoginCredentialHandlerOps ops = {
        nullptr,
        nullptr,
        write_credential_prepare_state_error_for_common,
        write_credential_propose_state_error_for_common,
        safe_read_session_guard_ops(),
        state_only_session_guard_ops(),
        signing::SessionIdMode::required,
        signing::SessionIdMode::required,
        prepare_stopwatch_sui_zklogin_credential_for_common,
        current_payload_transfer_ms,
        make_sui_zklogin_proposal_window,
        begin_stopwatch_sui_zklogin_proposal_for_common,
        clear_stopwatch_credential_preparation_after_begin_failure,
        show_stopwatch_sui_zklogin_proposal_review,
    };
    return ops;
}

void handle_credential_prepare_request(const char* id, JsonDocument& request)
{
    signing::handle_protocol_credential_prepare_request(
        id,
        request,
        common_method_response_writer().for_method("credential_prepare"),
        sui_zklogin_credential_handler_ops());
}

void finish_credential_proposal(
    const char* id,
    SuiZkLoginProposalTerminalResult terminal_result)
{
    const bool session_ended =
        sui_zklogin_proposal_terminal_ends_session(terminal_result);
    if (signing::write_credential_proposal_outcome_response(
            id,
            common_method_response_writer().for_method("credential_propose"),
            terminal_result,
            session_ended)) {
        record_success(id, "credential_propose");
    } else {
        record_error(id, "credential_propose", "internal_output_error");
    }
    clear_pending_request();
    sui_zklogin_proposal_state_clear();
    credential_preparation_state_clear();
    if (session_ended) {
        clear_session_scoped_state();
    }
}

void handle_credential_propose_request(const char* id, JsonDocument& request)
{
    signing::handle_protocol_credential_propose_request(
        id,
        request,
        common_method_response_writer().for_method("credential_propose"),
        sui_zklogin_credential_handler_ops());
}

void handle_signing_request(
    const char* id,
    const char* method,
    JsonDocument& request,
    signing::SupportedSignRoute route)
{
    if (!active_auth_allows_session_method(id, method)) {
        return;
    }
    const signing::ResponseWriter writer =
        common_method_response_writer().for_method(method);
    if (route == signing::SupportedSignRoute::sui_sign_transaction) {
        signing::handle_protocol_sign_transaction_request(
            id,
            request,
            writer,
            signing_handler_ops());
        return;
    }
    if (route == signing::SupportedSignRoute::sui_sign_personal_message) {
        signing::handle_protocol_sign_personal_message_request(
            id,
            request,
            writer,
            signing_handler_ops());
        return;
    }
    reject_line(id, method, "unsupported_method");
}

void handle_get_result_request(const char* id, JsonDocument& request)
{
    if (!active_auth_allows_session_method(id, "get_result") ||
        !g_runtime_state.locally_unlocked) {
        return;
    }
    signing::handle_protocol_get_result_request(
        id,
        request,
        common_method_response_writer().for_method("get_result"),
        retained_response_handler_ops());
}

void handle_ack_result_request(const char* id, JsonDocument& request)
{
    if (!active_auth_allows_session_method(id, "ack_result") ||
        !g_runtime_state.locally_unlocked) {
        return;
    }
    signing::handle_protocol_ack_result_request(
        id,
        request,
        common_method_response_writer().for_method("ack_result"),
        retained_response_handler_ops());
}

void handle_get_status_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    signing::handle_protocol_get_status_request(
        id,
        request,
        writer.for_method("get_status"),
        get_status_handler_ops());
}

void handle_identify_device_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    signing::handle_protocol_identify_device_request(
        id,
        request,
        writer.for_method("identify_device"),
        identify_device_handler_ops());
}

void handle_connect_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_connect_request(id, request);
}

void handle_sign_transaction_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_signing_request(
        id,
        "sign_transaction",
        request,
        signing::SupportedSignRoute::sui_sign_transaction);
}

void handle_sign_personal_message_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_signing_request(
        id,
        "sign_personal_message",
        request,
        signing::SupportedSignRoute::sui_sign_personal_message);
}

void handle_get_result_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_get_result_request(id, request);
}

void handle_ack_result_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_ack_result_request(id, request);
}

void handle_disconnect_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_disconnect_request(id, request);
}

void handle_get_capabilities_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_get_capabilities_request(id, request);
}

void handle_get_accounts_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_get_accounts_request(id, request);
}

void handle_policy_get_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_policy_get_request(id, request);
}

void handle_get_approval_history_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_get_approval_history_request(id, request);
}

void handle_policy_propose_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_policy_propose_request(id, request);
}

void handle_credential_prepare_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_credential_prepare_request(id, request);
}

void handle_credential_propose_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    (void)writer;
    handle_credential_propose_request(id, request);
}

void handle_payload_transfer_begin_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    signing::handle_protocol_payload_transfer_begin_request(
        id,
        request,
        writer,
        payload_transfer_handler_ops());
}

void handle_payload_transfer_chunk_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    signing::handle_protocol_payload_transfer_chunk_request(
        id,
        request,
        writer,
        payload_transfer_handler_ops());
}

void handle_payload_transfer_finish_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    signing::handle_protocol_payload_transfer_finish_request(
        id,
        request,
        writer,
        payload_transfer_handler_ops());
}

void handle_payload_transfer_abort_operation(
    const char* id,
    JsonDocument& request,
    const signing::ResponseWriter& writer)
{
    signing::handle_protocol_payload_transfer_abort_request(
        id,
        request,
        writer,
        payload_transfer_handler_ops());
}

const signing::OperationHandlers& stopwatch_operation_handlers()
{
    static const signing::OperationHandlers handlers = {
        handle_get_status_operation,
        handle_identify_device_operation,
        handle_connect_operation,
        handle_sign_transaction_operation,
        handle_sign_personal_message_operation,
        handle_get_result_operation,
        handle_ack_result_operation,
        handle_disconnect_operation,
        handle_get_capabilities_operation,
        handle_get_accounts_operation,
        handle_policy_get_operation,
        handle_get_approval_history_operation,
        handle_policy_propose_operation,
        handle_credential_prepare_operation,
        handle_credential_propose_operation,
        handle_payload_transfer_begin_operation,
        handle_payload_transfer_chunk_operation,
        handle_payload_transfer_finish_operation,
        handle_payload_transfer_abort_operation,
    };
    return handlers;
}

bool resolve_payload_ref_for_common_handler(
    JsonDocument& request,
    JsonDocument& resolved_payload,
    signing::TimeoutTick now_tick,
    const signing::RequestEnvelope& envelope,
    const signing::ResponseWriter& writer)
{
    (void)resolved_payload;
    (void)now_tick;
    (void)writer;
    if (envelope.method == nullptr || envelope.method[0] == '\0') {
        return true;
    }
    return resolve_request_payload_ref(envelope.id, envelope.method, request);
}

void handle_protocol_request_line(
    const char* line,
    const signing::ProtocolTransportRoute& route)
{
    ScopedRequestContext request_context(route);
    ++g_status.received_lines;
    signing::handle_protocol_request_line(
        line,
        current_payload_transfer_ms(),
        route,
        stopwatch_operation_handlers(),
        resolve_payload_ref_for_common_handler);
}

void handle_local_transport_request_line(
    const char* line,
    const signing::ProtocolTransportRoute& route)
{
    handle_protocol_request_line(line, route);
}

void clear_local_transport_protocol_state_if_disconnected()
{
    if (local_transport_pairing_established() &&
        local_transport_pairing_connected()) {
        return;
    }
    clear_protocol_state_after_transport_loss(
        signing::ProtocolTransport::local_transport);
}

void enforce_transport_exclusivity(bool usb_connected)
{
    const signing::TransportExclusivityState state{
        usb_connected,
        local_transport_pairing_active() ||
            local_transport_pairing_established(),
    };
    if (signing::transport_exclusivity_action(state) !=
        signing::TransportExclusivityAction::close_secondary_transport) {
        return;
    }

    local_transport_pairing_cancel();
    clear_protocol_state_after_transport_loss(
        signing::ProtocolTransport::local_transport);
}

void feed_byte(char value)
{
    switch (signing::request_line_feed(
        value,
        g_line_buffer,
        sizeof(g_line_buffer),
        &g_line_size,
        &g_discarding_line)) {
        case signing::RequestLineFeedResult::line_ready:
            handle_protocol_request_line(
                g_line_buffer,
                signing::ProtocolTransportRoute(usb_protocol_transport_endpoint()));
            break;
        case signing::RequestLineFeedResult::rejected_nul:
        case signing::RequestLineFeedResult::rejected_too_long:
            ++g_status.invalid_lines;
            {
                const signing::ProtocolTransportRoute route =
                    signing::ProtocolTransportRoute(usb_protocol_transport_endpoint());
                ScopedRequestContext request_context(route);
                reject_line(nullptr, nullptr, "invalid_request");
            }
            break;
        case signing::RequestLineFeedResult::none:
            break;
    }
}

}  // namespace

bool protocol_runtime_projected_device_state_is_error()
{
    return strcmp(stopwatch_device_state(cached_state_projection_input()), "error") == 0;
}

void protocol_runtime_invalidate_projected_state_cache()
{
    invalidate_projected_storage_cache();
}

void protocol_runtime_init()
{
    format_device_id();
    invalidate_projected_storage_cache();
    signing::usb_link_state_clear();
    signing::user_signing_flow_set_session_validator(
        validate_session_for_user_signing,
        nullptr);
    g_usb_session_grace = signing::UsbGraceState{};
    reset_line_receiver_state();
    g_status.usb_ready = init_usb_transport();
}

void protocol_runtime_poll()
{
    const uint32_t now_ms = current_payload_transfer_ms();
    clear_identification_display_if_expired(now_ms);
    clear_signing_notice_if_expired(now_ms);
    signing::payload_delivery_clear_expired(now_ms);
    if (sui_zklogin_proposal_deadline_reached(now_ms)) {
        const SuiZkLoginProposalSnapshot snapshot = sui_zklogin_proposal_state_snapshot();
        finish_credential_proposal(
            snapshot.request_id,
            sui_zklogin_proposal_record_timed_out());
    }
    bool usb_connected = false;
    if (g_status.usb_ready) {
        usb_connected = refresh_usb_connection();
    }
    enforce_transport_exclusivity(usb_connected);
    local_transport_pairing_poll(
        xTaskGetTickCount(),
        handle_local_transport_request_line);
    clear_local_transport_protocol_state_if_disconnected();
    signing::connect_review_response_flow_run(connect_review_response_flow_ops());
    reject_expired_signing_request(now_ms);
    reject_expired_policy_update_request(now_ms);

    if (!usb_connected) {
        return;
    }

    uint8_t buffer[kReadChunkBytes];
    const int read_count = usb_serial_jtag_read_bytes(buffer, sizeof(buffer), 0);
    if (read_count <= 0) {
        return;
    }
    for (int i = 0; i < read_count; ++i) {
        feed_byte(static_cast<char>(buffer[i]));
    }
}

ProtocolStatus protocol_runtime_status()
{
    refresh_usb_connection();
    return g_status;
}

IdentificationDisplay protocol_runtime_identification_display()
{
    clear_identification_display_if_expired(current_payload_transfer_ms());
    return g_identification_display;
}

SigningNotice protocol_runtime_signing_notice()
{
    clear_signing_notice_if_expired(current_payload_transfer_ms());
    return g_signing_notice;
}

void protocol_runtime_set_state(ProtocolRuntimeState state)
{
    g_runtime_state = state;
    if (state.auth_status == LocalAuthProjectionStatus::missing ||
        state.auth_status == LocalAuthProjectionStatus::invalid ||
        state.auth_status == LocalAuthProjectionStatus::storage_error) {
        clear_pending_request();
        clear_session_scoped_state();
    }
}

PendingRequest protocol_runtime_pending_request()
{
    const signing::ConnectApprovalSnapshot approval =
        signing::connect_approval_snapshot();
    if (approval.active) {
        PendingRequest pending = {};
        pending.kind = PendingRequestKind::connect;
        strlcpy(pending.id, approval.request_id, sizeof(pending.id));
        strlcpy(pending.label, approval.client_name, sizeof(pending.label));
        pending.request_window = approval.approval_window;
        return pending;
    }
    return g_pending_request;
}

bool protocol_runtime_approve_pending_request()
{
    if (g_runtime_state.auth_status != LocalAuthProjectionStatus::active ||
        !g_runtime_state.locally_unlocked) {
        return false;
    }

    if (g_pending_request.kind == PendingRequestKind::credential_propose) {
        if (sui_zklogin_proposal_mark_auth_verifying() !=
            SuiZkLoginProposalTransitionResult::ok) {
            return false;
        }
        const SuiZkLoginProposalTerminalResult result =
            sui_zklogin_proposal_commit();
        invalidate_projected_storage_cache();
        finish_credential_proposal(g_pending_request.id, result);
        return result == SuiZkLoginProposalTerminalResult::activated;
    }

    if (pending_kind_is_signing(g_pending_request.kind)) {
        const char* method = pending_signing_method();
        const uint32_t now_ms = current_payload_transfer_ms();
        const signing::UserSigningTransitionResult confirmed =
            signing::user_signing_flow_record_physical_confirmed_and_write_confirmation_history(
                now_ms,
                write_user_signing_confirmation_history,
                nullptr);
        if (confirmed != signing::UserSigningTransitionResult::ok) {
            if (signing::user_signing_flow_terminal_pending()) {
                finish_user_signing_terminal(g_pending_request.id);
            } else {
                const char* code =
                    confirmed == signing::UserSigningTransitionResult::history_error
                        ? "history_unavailable"
                        : "invalid_state";
                reject_line(g_pending_request.id, method, code);
                signing::user_signing_flow_clear();
            }
            clear_pending_request();
            return false;
        }

        UserSigningOutputReadyContext ready_context{g_pending_request.id};
        UserSigningTerminalFinishContext finish_context{g_pending_request.id};
        const signing::UserSigningCriticalSectionOps critical_ops{
            sign_user_signing_payload,
            nullptr,
        };
        const signing::UserSigningHandoffFinishReport report =
            signing::user_signing_execute_critical_section_and_finish(
                user_signing_signed_response_fits,
                &ready_context,
                finish_user_signing_from_common,
                &finish_context,
                critical_ops);
        clear_pending_request();
        return report.terminal_written &&
               report.handoff.result == signing::UserSigningHandoffResult::ok;
    }

    if (g_pending_request.kind == PendingRequestKind::policy_propose) {
        if (signing::policy_update_flow_mark_pin_verifying() !=
            signing::PolicyUpdateFlowTransitionResult::ok) {
            return false;
        }
        const signing::PolicyUpdateFlowTerminalResult result =
            signing::policy_update_flow_commit(current_payload_transfer_ms());
        invalidate_projected_storage_cache();
        finish_policy_update(g_pending_request.id, result);
        return result == signing::PolicyUpdateFlowTerminalResult::applied;
    }

    if (signing::connect_approval_active()) {
        return signing::connect_approval_choose(
            signing::ConnectApprovalChoice::approved,
            current_payload_transfer_ms());
    }

    return false;
}

bool protocol_runtime_reject_pending_request(const char* error_code)
{
    const char* code = error_code != nullptr ? error_code : "user_rejected";
    if (g_pending_request.kind == PendingRequestKind::none) {
        if (!signing::connect_approval_active()) {
            return false;
        }
        if (strcmp(code, "user_rejected") == 0) {
            return signing::connect_approval_choose(
                signing::ConnectApprovalChoice::rejected,
                current_payload_transfer_ms());
        }
        char request_id[signing::kRequestIdSize] = {};
        signing::connect_approval_request_id(request_id, sizeof(request_id));
        signing::connect_approval_clear();
        const bool written = reject_line(request_id, "connect", code);
        clear_pending_response_route();
        return written;
    }
    bool written = false;
    if (g_pending_request.kind == PendingRequestKind::credential_propose) {
        if (strcmp(code, "user_rejected") == 0) {
            finish_credential_proposal(
                g_pending_request.id,
                sui_zklogin_proposal_record_rejected());
            return true;
        }
        if (strcmp(code, "timeout") == 0) {
            finish_credential_proposal(
                g_pending_request.id,
                sui_zklogin_proposal_record_timed_out());
            return true;
        }
        if (strcmp(code, "ui_error") == 0) {
            finish_credential_proposal(
                g_pending_request.id,
                sui_zklogin_proposal_record_ui_error());
            return true;
        }
        if (strcmp(code, "auth_unavailable") == 0 ||
            strcmp(code, "consistency_error") == 0) {
            finish_credential_proposal(
                g_pending_request.id,
                sui_zklogin_proposal_record_consistency_error());
            return true;
        }
        written = reject_line(g_pending_request.id, "credential_propose", code);
        sui_zklogin_proposal_state_clear();
        credential_preparation_state_clear();
        clear_pending_request();
        return written;
    }
    if (pending_kind_is_signing(g_pending_request.kind)) {
        if (strcmp(code, "user_rejected") == 0) {
            signing::user_signing_flow_record_device_rejected();
            finish_user_signing_terminal(g_pending_request.id);
            clear_pending_request();
            return true;
        }
        if (strcmp(code, "timeout") == 0) {
            signing::user_signing_flow_record_timeout(current_payload_transfer_ms());
            finish_user_signing_terminal(g_pending_request.id);
            clear_pending_request();
            return true;
        }
        if (strcmp(code, "auth_unavailable") == 0 ||
            strcmp(code, "consistency_error") == 0 ||
            strcmp(code, "ui_error") == 0) {
            signing::user_signing_flow_cancel_for_ui_loss();
            finish_user_signing_terminal(g_pending_request.id);
            clear_pending_request();
            return true;
        }
        written = reject_line(g_pending_request.id, pending_signing_method(), code);
        signing::user_signing_flow_clear();
        clear_pending_request();
        return written;
    }
    if (g_pending_request.kind == PendingRequestKind::policy_propose) {
        if (strcmp(code, "user_rejected") == 0) {
            finish_policy_update(
                g_pending_request.id,
                signing::policy_update_flow_record_rejected(current_payload_transfer_ms()));
            return true;
        }
        if (strcmp(code, "timeout") == 0) {
            finish_policy_update(
                g_pending_request.id,
                signing::policy_update_flow_record_timed_out(current_payload_transfer_ms()));
            return true;
        }
        finish_policy_update(
            g_pending_request.id,
            signing::policy_update_flow_record_ui_error());
        return true;
    }
    return false;
}

void protocol_runtime_clear_session_scoped_state()
{
    clear_pending_request();
    clear_session_scoped_state();
}

bool protocol_runtime_local_transport_entry_allowed()
{
    const bool usb_connected =
        g_status.usb_ready && refresh_usb_connection();
    const signing::TransportExclusivityState transport_state{
        usb_connected,
        local_transport_pairing_active() ||
            local_transport_pairing_established(),
    };
    return g_runtime_state.auth_status == LocalAuthProjectionStatus::active &&
           g_runtime_state.locally_unlocked &&
           !g_runtime_state.ui_busy &&
           !signing::session_active() &&
           !signing::connect_approval_active() &&
           g_pending_request.kind == PendingRequestKind::none &&
           signing::secondary_transport_entry_allowed(transport_state);
}

}  // namespace stopwatch_target
