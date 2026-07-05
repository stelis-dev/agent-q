#include "usb_transport.h"

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "protocol/device_contract.h"
#include "protocol/device_response.h"
#include "protocol/json_input.h"
#include "numeric/u64_decimal.h"
#include "protocol/protocol_constants.h"
#include "protocol/request_id.h"
#include "protocol/request_line.h"
#include "transport/usb_link_state.h"
#include "transport/usb_session_grace.h"

#include "credential_preparation_state.h"
#include "payload_digest.h"
#include "payload_transfer_request.h"
#include "payload_transfer_state.h"
#include "protocol/base64.h"
#include "protocol_input_encoding.h"
#include "secure_random.h"
#include "sensitive_memory.h"
#include "session_state.h"
#include "sui/zklogin_credential_payload.h"
#include "sui_zklogin_credential_store.h"
#include "sui_zklogin_proposal_state.h"

extern "C" {
#include "byte_conversions.h"
}

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
constexpr size_t kApprovalHistoryPageMax = 4;
constexpr const char* kFirmwareName = "Agent-Q Firmware";
constexpr const char* kHardwareId = "stopwatch-esp32s3";
constexpr const char* kFirmwareVersion = "0.0.0";
constexpr const char* kFallbackDeviceId = "stopwatch-esp32s3-unavailable";
constexpr size_t kZkLoginPublicKeyBase64BufferSize =
    ((kSuiZkLoginPublicKeyMaxBytes + 2) / 3) * 4 + 1;

char g_line_buffer[kLineBufferBytes];
size_t g_line_size = 0;
bool g_discarding_line = false;
UsbStatus g_status = {};
char g_device_id[40] = {};
UsbRuntimeState g_runtime_state{LocalAuthProjectionStatus::missing, false, false};
UsbPendingRequest g_pending_request{
    UsbPendingRequestKind::none,
    {},
    {},
    signing::kTimeoutWindowNone,
};
UsbIdentificationDisplay g_identification_display{false, {}};
uint32_t g_identification_display_deadline_ms = 0;
signing::UsbGraceState g_usb_session_grace;

bool reject_line(const char* id, const char* method, const char* code);
bool device_request_fields_supported_or_reject(
    const char* id,
    const char* method,
    JsonDocument& request,
    const char* const* fields,
    size_t count);
bool payload_has_only_fields(JsonDocument& request, const char* const* fields, size_t count);
PayloadTransferAdmissionOperation payload_transfer_sensitive_operation(const char* method);
bool reject_if_payload_transfer_blocks_sensitive_flow(const char* id, const char* method);
CredentialProjectionStatus credential_projection_status();
StateProjectionInput state_projection_input();

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

StateProjectionInput state_projection_input()
{
    return StateProjectionInput{
        g_runtime_state.auth_status,
        credential_projection_status(),
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

void clear_pending_request()
{
    memset(&g_pending_request, 0, sizeof(g_pending_request));
    g_pending_request.kind = UsbPendingRequestKind::none;
    g_pending_request.request_window = signing::kTimeoutWindowNone;
}

void reject_expired_connect_request(uint32_t now_ms)
{
    if (g_pending_request.kind != UsbPendingRequestKind::connect ||
        !signing::timeout_window_reached(g_pending_request.request_window, now_ms)) {
        return;
    }
    char pending_id[signing::kRequestIdSize] = {};
    strlcpy(pending_id, g_pending_request.id, sizeof(pending_id));
    reject_line(pending_id, "connect", "timeout");
    clear_pending_request();
}

const char* pending_credential_proposal_request_to_notify(const char* current_request_id)
{
    if (g_pending_request.kind != UsbPendingRequestKind::credential_propose ||
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
    if (g_pending_request.kind != UsbPendingRequestKind::credential_propose) {
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

void clear_session_scoped_state()
{
    sui_zklogin_proposal_state_clear();
    credential_preparation_state_clear();
    payload_transfer_clear_all();
    session_state_clear();
}

void reset_line_receiver_state()
{
    g_line_size = 0;
    g_discarding_line = false;
    g_line_buffer[0] = '\0';
}

bool refresh_usb_connection()
{
    const bool connected = g_status.ready && usb_serial_jtag_is_connected();
    g_status.connected = connected;
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
        clear_pending_request();
        clear_session_scoped_state();
    }
    return connected;
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

bool write_json_response(JsonDocument& response, size_t output_size)
{
    char output[1024];
    if (output_size > sizeof(output)) {
        return false;
    }
    const size_t length = serializeJson(response, output, output_size);
    if (length == 0 || length >= output_size) {
        copy_status_text(g_status.last_error, sizeof(g_status.last_error), "internal_output_error");
        return false;
    }
    return write_usb_bytes("\n", 1) &&
           write_usb_bytes(output, length) &&
           write_usb_bytes("\n", 1);
}

bool write_error_response(const char* id, const char* method, const char* code)
{
    JsonDocument response;
    if (!signing::device_response_prepare_method_error(response, id, method, code)) {
        return false;
    }
    return write_json_response(response, 768);
}

bool write_payload_transfer_error_response(const char* id, const char* code)
{
    const signing::DeviceErrorRow* row = signing::device_error_row(code);
    JsonDocument response;
    if (id != nullptr && id[0] != '\0') {
        response["id"] = id;
    }
    response["version"] = signing::kProtocolVersion;
    response["success"] = false;
    JsonObject error = response["error"].to<JsonObject>();
    error["code"] = code != nullptr ? code : "invalid_request";
    error["message"] = row != nullptr ? row->message : "Device request is malformed.";
    error["retryable"] = row != nullptr && row->retryable;
    return write_json_response(response, 768);
}

bool write_success_response(const char* id, const char* method, JsonObjectConst result)
{
    JsonDocument response;
    if (!signing::device_response_prepare_success_result(response, id, method, result)) {
        return false;
    }
    return write_json_response(response, 1024);
}

bool write_empty_success_response(const char* id, const char* method)
{
    JsonDocument result;
    JsonObject object = result.to<JsonObject>();
    return write_success_response(id, method, object);
}

bool write_payload_transfer_success_response(const char* id, JsonObjectConst result)
{
    JsonDocument response;
    if (id != nullptr && id[0] != '\0') {
        response["id"] = id;
    }
    response["version"] = signing::kProtocolVersion;
    response["success"] = true;
    response["result"] = result;
    return write_json_response(response, 768);
}

bool write_status_response(const char* id)
{
    format_device_id();

    const StateProjectionInput projection = state_projection_input();
    const signing::DeviceResponseDeviceFields info{
        g_device_id,
        stopwatch_device_state(projection),
        kFirmwareName,
        kHardwareId,
        kFirmwareVersion,
    };
    JsonDocument result;
    signing::device_response_write_device_fields(result["device"].to<JsonObject>(), info);
    result["provisioning"]["state"] = stopwatch_provisioning_state(projection);

    JsonDocument response;
    if (!signing::device_response_prepare_success_result(
            response,
            id,
            "get_status",
            result.as<JsonObjectConst>())) {
        return false;
    }
    return write_json_response(response, 1024);
}

bool write_identify_device_response(const char* id, const char* code)
{
    format_device_id();

    JsonDocument result;
    result["code"] = code;
    const signing::DeviceResponseDeviceFields info{
        g_device_id,
        device_state(),
        kFirmwareName,
        kHardwareId,
        kFirmwareVersion,
    };
    signing::device_response_write_device_fields(result["device"].to<JsonObject>(), info);
    return write_success_response(id, "identify_device", result.as<JsonObjectConst>());
}

bool write_connect_response(const char* id)
{
    format_device_id();

    JsonDocument result;
    result["sessionId"] = session_state_id();
    result["sessionTtlMs"] = kSessionAdvertisedTtlMs;
    const signing::DeviceResponseDeviceFields info{
        g_device_id,
        device_state(),
        kFirmwareName,
        kHardwareId,
        kFirmwareVersion,
    };
    signing::device_response_write_device_fields(result["device"].to<JsonObject>(), info);
    return write_success_response(id, "connect", result.as<JsonObjectConst>());
}

bool write_capabilities_response(const char* id)
{
    const SuiZkLoginAccountProjection account_projection = sui_zklogin_account_projection();
    if (credential_status_is_error(account_projection.status)) {
        return false;
    }
    JsonDocument result;
    JsonArray chains = result["chains"].to<JsonArray>();
    JsonObject sui = chains.add<JsonObject>();
    sui["id"] = "sui";
    JsonArray accounts = sui["accounts"].to<JsonArray>();
    if (account_projection.active) {
        JsonObject account = accounts.add<JsonObject>();
        account["keyScheme"] = "zklogin";
    }
    sui["methods"].to<JsonArray>();

    JsonArray credentials = result["credentials"].to<JsonArray>();
    if (credential_status_allows_install(account_projection.status)) {
        JsonObject credential = credentials.add<JsonObject>();
        credential["chain"] = "sui";
        credential["credential"] = "zklogin";
        JsonArray operations = credential["operations"].to<JsonArray>();
        operations.add("credential_prepare");
        operations.add("credential_propose");
    }

    return write_success_response(id, "get_capabilities", result.as<JsonObjectConst>());
}

bool write_accounts_response(const char* id)
{
    const SuiZkLoginAccountProjection account_projection = sui_zklogin_account_projection();
    if (credential_status_is_error(account_projection.status)) {
        return false;
    }
    JsonDocument result;
    JsonArray accounts = result["accounts"].to<JsonArray>();
    if (account_projection.active) {
        char public_key_base64[kZkLoginPublicKeyBase64BufferSize] = {};
        if (bytes_to_base64(
                account_projection.public_key,
                account_projection.public_key_size,
                public_key_base64,
                sizeof(public_key_base64)) != 0) {
            return false;
        }
        JsonObject account = accounts.add<JsonObject>();
        account["chain"] = "sui";
        account["address"] = account_projection.address;
        account["publicKey"] = public_key_base64;
        account["keyScheme"] = "zklogin";
        JsonObject sponsored = account["sponsoredTransactions"].to<JsonObject>();
        sponsored["acceptGasSponsor"] = false;
    }
    return write_success_response(id, "get_accounts", result.as<JsonObjectConst>());
}

bool write_credential_preparation_response(const char* id)
{
    const CredentialPreparationSnapshot snapshot = credential_preparation_snapshot();
    if (!snapshot.active) {
        return false;
    }

    JsonDocument result;
    result["chain"] = "sui";
    result["credential"] = "zklogin";
    JsonObject preparation = result["preparation"].to<JsonObject>();
    preparation["publicKey"] = snapshot.public_key_base64;
    preparation["keyScheme"] = "ed25519";
    preparation["address"] = snapshot.address;
    return write_success_response(id, "credential_prepare", result.as<JsonObjectConst>());
}

bool write_credential_proposal_outcome_response(
    const char* id,
    SuiZkLoginProposalTerminalResult terminal_result,
    bool session_ended)
{
    const char* status = sui_zklogin_proposal_terminal_status(terminal_result);
    const char* reason = sui_zklogin_proposal_terminal_reason(terminal_result);
    if (id == nullptr ||
        status == nullptr ||
        status[0] == '\0' ||
        reason == nullptr ||
        reason[0] == '\0') {
        return false;
    }

    JsonDocument result;
    result["status"] = status;
    result["reasonCode"] = reason;
    result["sessionEnded"] = session_ended;
    return write_success_response(id, "credential_propose", result.as<JsonObjectConst>());
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

bool reject_payload_transfer_line(const char* id, const char* code)
{
    record_error(id, "payload_transfer", code);
    if (!write_payload_transfer_error_response(id, code)) {
        record_error(id, "payload_transfer", "internal_output_error");
        return false;
    }
    return true;
}

bool parse_size_string(const char* text, size_t* out)
{
    if (out != nullptr) {
        *out = 0;
    }
    if (text == nullptr || out == nullptr) {
        return false;
    }
    uint64_t parsed = 0;
    if (!signing::parse_canonical_u64_decimal_string(text, &parsed) ||
        parsed > static_cast<uint64_t>(SIZE_MAX)) {
        return false;
    }
    *out = static_cast<size_t>(parsed);
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

void show_identification_code(const char* code)
{
    memset(&g_identification_display, 0, sizeof(g_identification_display));
    g_identification_display.active = true;
    strlcpy(g_identification_display.code, code, sizeof(g_identification_display.code));
    g_identification_display_deadline_ms = current_payload_transfer_ms() + kIdentifyDisplayMs;
}

bool active_auth_allows_session_method(const char* id, const char* method)
{
    if (g_runtime_state.auth_status != LocalAuthProjectionStatus::active) {
        reject_line(id, method, "invalid_state");
        return false;
    }
    if (!g_runtime_state.locally_unlocked) {
        reject_line(id, method, "auth_unavailable");
        return false;
    }
    if (g_pending_request.kind == UsbPendingRequestKind::credential_propose &&
        !session_state_active()) {
        cancel_pending_credential_proposal_after_session_loss(id);
        reject_line(id, method, "invalid_session");
        return false;
    }
    if (g_runtime_state.ui_busy ||
        g_pending_request.kind != UsbPendingRequestKind::none) {
        reject_line(id, method, "busy");
        return false;
    }
    return true;
}

void handle_identify_device_request(const char* id, JsonDocument& request)
{
    if (reject_if_payload_transfer_blocks_sensitive_flow(id, "identify_device")) {
        return;
    }

    const char* const allowed_request_fields[] = {"id", "version", "method", "payload"};
    if (!device_request_fields_supported_or_reject(id, "identify_device", request, allowed_request_fields, 4)) {
        return;
    }

    const char* const allowed_payload_fields[] = {"code"};
    if (!payload_has_only_fields(request, allowed_payload_fields, 1)) {
        reject_line(id, "identify_device", "invalid_params");
        return;
    }

    const char* code = nullptr;
    if (!signing::json_value_c_string(request["payload"]["code"], &code) ||
        !identification_code_safe(code)) {
        reject_line(id, "identify_device", "invalid_params");
        return;
    }

    show_identification_code(code);
    if (write_identify_device_response(id, code)) {
        record_success(id, "identify_device");
    } else {
        record_error(id, "identify_device", "internal_output_error");
    }
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

bool require_matching_session(const char* id, const char* method, JsonDocument& request)
{
    const char* session_id = nullptr;
    if (!signing::json_value_c_string(request["sessionId"], &session_id)) {
        reject_line(id, method, "invalid_session");
        return false;
    }
    switch (session_state_validate(session_id)) {
        case SessionValidationResult::ok:
            return true;
        case SessionValidationResult::invalid_format:
            reject_line(id, method, "invalid_session");
            return false;
        case SessionValidationResult::missing:
            cancel_pending_credential_proposal_after_session_loss(id);
            reject_line(id, method, "invalid_session");
            return false;
        case SessionValidationResult::mismatch:
        default:
            reject_line(id, method, "invalid_session");
            return false;
    }
}

bool require_session_shape(const char* id, const char* method, JsonDocument& request)
{
    const char* session_id = nullptr;
    if (!signing::json_value_c_string(request["sessionId"], &session_id) ||
        !session_id_format_valid(session_id)) {
        reject_line(id, method, "invalid_session");
        return false;
    }
    return true;
}

bool request_has_only_fields(JsonDocument& request, const char* const* fields, size_t count)
{
    return signing::json_object_fields_supported(request.as<JsonObjectConst>(), fields, count);
}

bool request_has_field(JsonDocument& request, const char* field)
{
    if (field == nullptr) {
        return false;
    }
    for (JsonPairConst pair : request.as<JsonObjectConst>()) {
        if (signing::json_string_equals(pair.key(), field)) {
            return true;
        }
    }
    return false;
}

bool device_request_fields_supported_or_reject(
    const char* id,
    const char* method,
    JsonDocument& request,
    const char* const* fields,
    size_t count)
{
    if (request_has_only_fields(request, fields, count)) {
        return true;
    }
    reject_line(id, method, "invalid_request");
    return false;
}

bool required_payload_present_or_reject(const char* id, const char* method, JsonDocument& request)
{
    if (request_has_field(request, "payload")) {
        return true;
    }
    reject_line(id, method, "invalid_params");
    return false;
}

bool device_method_rules_or_reject(const char* id, const char* method, JsonDocument& request)
{
    const signing::DeviceMethodRow* row = signing::device_method_row(method);
    if (row == nullptr) {
        reject_line(id, nullptr, "unsupported_method");
        return false;
    }

    const bool has_session_id = request_has_field(request, "sessionId");
    if (row->session_rule == signing::DeviceSessionRule::forbidden && has_session_id) {
        reject_line(id, method, "invalid_request");
        return false;
    }
    if (row->session_rule == signing::DeviceSessionRule::required && !has_session_id) {
        reject_line(id, method, "invalid_session");
        return false;
    }
    if (has_session_id && !require_session_shape(id, method, request)) {
        return false;
    }

    const bool has_payload = request_has_field(request, "payload");
    if (row->payload_rule == signing::DevicePayloadRule::forbidden && has_payload) {
        reject_line(id, method, "invalid_request");
        return false;
    }
    if (row->payload_rule == signing::DevicePayloadRule::required && !has_payload) {
        reject_line(id, method, "invalid_params");
        return false;
    }
    return true;
}

bool payload_has_only_fields(JsonDocument& request, const char* const* fields, size_t count)
{
    return request["payload"].is<JsonObjectConst>() &&
           signing::json_object_fields_supported(request["payload"].as<JsonObjectConst>(), fields, count);
}

bool retained_request_payload_valid(JsonDocument& request)
{
    const char* const fields[] = {"retainedRequestId"};
    const char* retained_request_id = nullptr;
    return payload_has_only_fields(request, fields, 1) &&
           signing::json_value_c_string(request["payload"]["retainedRequestId"], &retained_request_id) &&
           signing::request_id_format_valid(retained_request_id);
}

bool approval_history_payload_valid(JsonDocument& request)
{
    JsonObjectConst payload = request["payload"].as<JsonObjectConst>();
    if (payload.isNull()) {
        return false;
    }
    for (JsonPairConst pair : payload) {
        if (signing::json_string_equals(pair.key(), "limit")) {
            if (!pair.value().is<unsigned int>()) {
                return false;
            }
            const unsigned int limit = pair.value().as<unsigned int>();
            if (limit == 0 || limit > kApprovalHistoryPageMax) {
                return false;
            }
            continue;
        }
        if (signing::json_string_equals(pair.key(), "beforeSeq")) {
            const char* before_seq = nullptr;
            uint64_t parsed = 0;
            if (!signing::json_value_c_string(pair.value(), &before_seq) ||
                !signing::parse_canonical_u64_decimal_string(before_seq, &parsed)) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

bool policy_propose_payload_wrapper_valid(JsonDocument& request)
{
    const char* const fields[] = {"policy"};
    return payload_has_only_fields(request, fields, 1) &&
           request["payload"]["policy"].is<JsonObjectConst>();
}

bool payload_ref_wrapper(JsonDocument& request, const char** payload_ref)
{
    if (payload_ref != nullptr) {
        *payload_ref = nullptr;
    }
    JsonObjectConst payload = request["payload"].as<JsonObjectConst>();
    if (payload.isNull()) {
        return false;
    }
    const char* const payload_ref_fields[] = {"payloadRef"};
    if (!signing::json_object_fields_supported(payload, payload_ref_fields, 1)) {
        return false;
    }
    const char* ref = nullptr;
    if (!signing::json_value_c_string(payload["payloadRef"], &ref)) {
        return false;
    }
    if (payload_ref != nullptr) {
        *payload_ref = ref;
    }
    return true;
}

const char* payload_resolver_error_code(PayloadTransferResult result)
{
    switch (result) {
        case PayloadTransferResult::invalid_session:
            return "invalid_session";
        case PayloadTransferResult::payload_too_large:
            return "payload_too_large";
        case PayloadTransferResult::allocation_failed:
        case PayloadTransferResult::digest_error:
            return "internal_output_error";
        case PayloadTransferResult::invalid_argument:
            return "invalid_params";
        case PayloadTransferResult::invalid_payload_ref:
        case PayloadTransferResult::invalid_state:
        case PayloadTransferResult::not_found:
            return "payload_unavailable";
        case PayloadTransferResult::ok:
        case PayloadTransferResult::invalid_payload_digest:
        case PayloadTransferResult::invalid_transfer_id:
        case PayloadTransferResult::chunk_too_large:
        case PayloadTransferResult::offset_mismatch:
        case PayloadTransferResult::payload_overflow:
        case PayloadTransferResult::size_mismatch:
        case PayloadTransferResult::digest_mismatch:
        default:
            return "invalid_params";
    }
}

bool resolve_request_payload_ref(const char* id, const char* method, JsonDocument& request)
{
    const char* payload_ref = nullptr;
    if (!payload_ref_wrapper(request, &payload_ref)) {
        return true;
    }

    const char* session_id = nullptr;
    if (!signing::json_value_c_string(request["sessionId"], &session_id)) {
        reject_line(id, method, "invalid_session");
        return false;
    }

    PayloadTransferOwnedPayload owned_payload = {};
    const PayloadTransferResult result =
        payload_transfer_take(current_payload_transfer_ms(), session_id, payload_ref, &owned_payload);
    if (result != PayloadTransferResult::ok) {
        reject_line(id, method, payload_resolver_error_code(result));
        return false;
    }

    JsonDocument resolved_payload;
    const DeserializationError parse_error =
        deserializeJson(resolved_payload, owned_payload.bytes, owned_payload.size_bytes);
    payload_transfer_wipe_owned_payload(&owned_payload);
    if (parse_error || resolved_payload.as<JsonObjectConst>().isNull()) {
        reject_line(id, method, "invalid_params");
        return false;
    }
    request["payload"].set(resolved_payload.as<JsonObjectConst>());
    return true;
}

bool reject_if_payload_transfer_blocks_sensitive_flow(const char* id, const char* method)
{
    const PayloadTransferAdmissionOperation operation =
        payload_transfer_sensitive_operation(method);
    const PayloadTransferAdmissionDecision admission =
        payload_transfer_admit_operation(
            current_payload_transfer_ms(),
            operation);
    if (admission.result == PayloadTransferAdmissionResult::ok) {
        return false;
    }
    if (payload_transfer_admission_blocks_sensitive_flow(admission)) {
        reject_line(id, method, "busy");
        return true;
    }
    reject_line(id, method, "unknown_request");
    return true;
}

bool reject_if_payload_transfer_blocks_safe_read(const char* id, const char* method)
{
    const PayloadTransferAdmissionDecision admission =
        payload_transfer_admit_operation(
            current_payload_transfer_ms(),
            PayloadTransferAdmissionOperation::safe_read);
    if (admission.result == PayloadTransferAdmissionResult::ok) {
        return false;
    }
    reject_line(id, method, "busy");
    return true;
}

PayloadTransferAdmissionOperation payload_transfer_admission_operation(
    PayloadTransferRequestAction action)
{
    switch (action) {
        case PayloadTransferRequestAction::begin:
            return PayloadTransferAdmissionOperation::payload_transfer_begin;
        case PayloadTransferRequestAction::chunk:
            return PayloadTransferAdmissionOperation::payload_transfer_chunk;
        case PayloadTransferRequestAction::finish:
            return PayloadTransferAdmissionOperation::payload_transfer_finish;
        case PayloadTransferRequestAction::abort:
            return PayloadTransferAdmissionOperation::payload_transfer_abort;
    }
    return PayloadTransferAdmissionOperation::payload_transfer_abort;
}

PayloadTransferAdmissionOperation payload_transfer_sensitive_operation(const char* method)
{
    if (method == nullptr) {
        return PayloadTransferAdmissionOperation::credential_propose;
    }
    if (strcmp(method, "connect") == 0) {
        return PayloadTransferAdmissionOperation::connect;
    }
    if (strcmp(method, "identify_device") == 0) {
        return PayloadTransferAdmissionOperation::identify_device;
    }
    if (strcmp(method, "credential_propose") == 0) {
        return PayloadTransferAdmissionOperation::credential_propose;
    }
    if (strcmp(method, "policy_propose") == 0) {
        return PayloadTransferAdmissionOperation::policy_propose;
    }
    if (strcmp(method, "sign_transaction") == 0) {
        return PayloadTransferAdmissionOperation::sign_transaction;
    }
    if (strcmp(method, "sign_personal_message") == 0) {
        return PayloadTransferAdmissionOperation::sign_personal_message;
    }
    return PayloadTransferAdmissionOperation::credential_propose;
}

bool reject_if_payload_transfer_action_unavailable(
    const char* id,
    PayloadTransferRequestAction action,
    uint32_t now_ms)
{
    const PayloadTransferAdmissionDecision admission =
        payload_transfer_admit_operation(
            now_ms,
            payload_transfer_admission_operation(action));
    if (admission.result == PayloadTransferAdmissionResult::ok) {
        return false;
    }
    if (admission.result == PayloadTransferAdmissionResult::busy) {
        reject_payload_transfer_line(id, "busy");
        return true;
    }
    reject_payload_transfer_line(id, "unknown_request");
    return true;
}

bool printable_client_name(const char* value)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }
    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (++length >= sizeof(g_pending_request.label)) {
            return false;
        }
        const unsigned char c = static_cast<unsigned char>(*cursor);
        if (c < 0x20 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

bool write_existing_session_connect_response(const char* id)
{
    if (!session_state_active()) {
        return false;
    }
    if (write_connect_response(id)) {
        record_success(id, "connect");
    } else {
        record_error(id, "connect", "internal_output_error");
    }
    return true;
}

bool connect_material_allows_request(const char* id)
{
    if (g_runtime_state.auth_status == LocalAuthProjectionStatus::missing ||
        g_runtime_state.auth_status == LocalAuthProjectionStatus::invalid ||
        g_runtime_state.auth_status == LocalAuthProjectionStatus::storage_error) {
        clear_session_scoped_state();
        reject_line(id, "connect", "invalid_state");
        return false;
    }
    if (reject_if_credential_store_error(id, "connect")) {
        return false;
    }
    return true;
}

void handle_connect_request(const char* id, JsonDocument& request)
{
    if (!connect_material_allows_request(id)) {
        return;
    }

    const char* const allowed_request_fields[] = {"id", "version", "method", "payload"};
    if (!device_request_fields_supported_or_reject(id, "connect", request, allowed_request_fields, 4)) {
        return;
    }

    const char* const allowed_payload_fields[] = {"clientName"};
    if (!payload_has_only_fields(request, allowed_payload_fields, 1)) {
        reject_line(id, "connect", "invalid_params");
        return;
    }
    const char* client_name = nullptr;
    if (!signing::json_value_c_string(request["payload"]["clientName"], &client_name) ||
        !printable_client_name(client_name)) {
        reject_line(id, "connect", "invalid_params");
        return;
    }

    if (write_existing_session_connect_response(id)) {
        return;
    }

    if (g_runtime_state.auth_status == LocalAuthProjectionStatus::locked) {
        reject_line(id, "connect", "auth_unavailable");
        return;
    }
    if (g_runtime_state.auth_status != LocalAuthProjectionStatus::active) {
        clear_session_scoped_state();
        reject_line(id, "connect", "invalid_state");
        return;
    }
    if (reject_if_payload_transfer_blocks_sensitive_flow(id, "connect")) {
        return;
    }
    if (g_runtime_state.ui_busy ||
        g_pending_request.kind != UsbPendingRequestKind::none) {
        reject_line(id, "connect", "busy");
        return;
    }

    const uint32_t now_ms = current_payload_transfer_ms();
    const signing::TimeoutWindow request_window = make_connect_approval_window(now_ms);
    if (!signing::timeout_window_valid_and_open_at(request_window, now_ms)) {
        reject_line(id, "connect", "internal_output_error");
        return;
    }

    clear_pending_request();
    g_pending_request.kind = UsbPendingRequestKind::connect;
    strlcpy(g_pending_request.id, id, sizeof(g_pending_request.id));
    strlcpy(g_pending_request.label, client_name, sizeof(g_pending_request.label));
    g_pending_request.request_window = request_window;
}

void handle_disconnect_request(const char* id, JsonDocument& request)
{
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId"};
    if (!device_request_fields_supported_or_reject(id, "disconnect", request, allowed_request_fields, 4) ||
        !require_session_shape(id, "disconnect", request)) {
        return;
    }
    if (!require_matching_session(id, "disconnect", request)) {
        return;
    }
    const char* canceled_proposal_id = pending_credential_proposal_request_to_notify(id);
    if (canceled_proposal_id != nullptr) {
        reject_line(canceled_proposal_id, "credential_propose", "invalid_session");
    }
    clear_pending_request();
    clear_session_scoped_state();
    if (write_empty_success_response(id, "disconnect")) {
        record_success(id, "disconnect");
    } else {
        record_error(id, "disconnect", "internal_output_error");
    }
}

void handle_get_capabilities_request(const char* id, JsonDocument& request)
{
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId"};
    if (!device_request_fields_supported_or_reject(id, "get_capabilities", request, allowed_request_fields, 4) ||
        !require_session_shape(id, "get_capabilities", request)) {
        return;
    }
    if (!active_auth_allows_session_method(id, "get_capabilities") ||
        reject_if_payload_transfer_blocks_safe_read(id, "get_capabilities") ||
        !require_matching_session(id, "get_capabilities", request)) {
        return;
    }
    if (write_capabilities_response(id)) {
        record_success(id, "get_capabilities");
    } else {
        reject_line(id, "get_capabilities", "account_unavailable");
    }
}

void handle_get_accounts_request(const char* id, JsonDocument& request)
{
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId"};
    if (!device_request_fields_supported_or_reject(id, "get_accounts", request, allowed_request_fields, 4) ||
        !require_session_shape(id, "get_accounts", request)) {
        return;
    }
    if (!active_auth_allows_session_method(id, "get_accounts") ||
        reject_if_payload_transfer_blocks_safe_read(id, "get_accounts") ||
        !require_matching_session(id, "get_accounts", request)) {
        return;
    }
    if (write_accounts_response(id)) {
        record_success(id, "get_accounts");
    } else {
        reject_line(id, "get_accounts", "account_unavailable");
    }
}

void handle_credential_prepare_request(const char* id, JsonDocument& request)
{
    if (!active_auth_allows_session_method(id, "credential_prepare") ||
        reject_if_payload_transfer_blocks_safe_read(id, "credential_prepare") ||
        !require_matching_session(id, "credential_prepare", request)) {
        return;
    }
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId", "payload"};
    if (!device_request_fields_supported_or_reject(id, "credential_prepare", request, allowed_request_fields, 5) ||
        !required_payload_present_or_reject(id, "credential_prepare", request)) {
        return;
    }
    if (!require_credential_install_available(id, "credential_prepare")) {
        return;
    }
    if (!signing::sui_zklogin_credential_prepare_payload_shape_valid(request["payload"])) {
        reject_line(id, "credential_prepare", "invalid_params");
        return;
    }
    const CredentialPreparationBeginResult result =
        credential_preparation_begin(session_state_id(), secure_random_fill_with_context, nullptr);
    if (result == CredentialPreparationBeginResult::invalid_session) {
        reject_line(id, "credential_prepare", "invalid_session");
        return;
    }
    if (result != CredentialPreparationBeginResult::ok) {
        reject_line(id, "credential_prepare", "internal_output_error");
        return;
    }
    if (write_credential_preparation_response(id)) {
        record_success(id, "credential_prepare");
    } else {
        record_error(id, "credential_prepare", "internal_output_error");
    }
}

void finish_credential_proposal(
    const char* id,
    SuiZkLoginProposalTerminalResult terminal_result)
{
    const bool session_ended =
        sui_zklogin_proposal_terminal_ends_session(terminal_result);
    if (write_credential_proposal_outcome_response(
            id,
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

void finish_credential_proposal_begin_failure(
    const char* id,
    SuiZkLoginProposalBeginResult begin_result)
{
    (void)begin_result;
    if (write_credential_proposal_outcome_response(
            id,
            SuiZkLoginProposalTerminalResult::invalid_proof,
            false)) {
        record_success(id, "credential_propose");
    } else {
        record_error(id, "credential_propose", "internal_output_error");
    }
    credential_preparation_state_clear();
}

void handle_credential_propose_request(const char* id, JsonDocument& request)
{
    if (!active_auth_allows_session_method(id, "credential_propose")) {
        return;
    }
    if (!require_matching_session(id, "credential_propose", request)) {
        return;
    }
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId", "payload"};
    if (!device_request_fields_supported_or_reject(id, "credential_propose", request, allowed_request_fields, 5) ||
        !required_payload_present_or_reject(id, "credential_propose", request)) {
        return;
    }
    if (g_pending_request.kind != UsbPendingRequestKind::none ||
        sui_zklogin_proposal_state_active()) {
        reject_line(id, "credential_propose", "busy");
        return;
    }
    if (!require_credential_install_available(id, "credential_propose")) {
        return;
    }
    if (reject_if_payload_transfer_blocks_sensitive_flow(id, "credential_propose")) {
        return;
    }
    if (!signing::sui_zklogin_credential_propose_payload_shape_valid(request["payload"])) {
        reject_line(id, "credential_propose", "invalid_params");
        return;
    }

    uint8_t prepared_seed[kSuiEd25519SeedBytes] = {};
    if (!credential_preparation_copy_seed_for_session(session_state_id(), prepared_seed)) {
        reject_line(id, "credential_propose", "invalid_state");
        return;
    }
    const uint32_t now_ms = current_payload_transfer_ms();
    const SuiZkLoginProposalBeginResult begin_result =
        sui_zklogin_proposal_state_begin(
            request["payload"],
            id,
            session_state_id(),
            now_ms,
            make_sui_zklogin_proposal_window(now_ms),
            prepared_seed);
    wipe_sensitive_buffer(prepared_seed, sizeof(prepared_seed));
    if (begin_result != SuiZkLoginProposalBeginResult::ok) {
        finish_credential_proposal_begin_failure(id, begin_result);
        return;
    }

    clear_pending_request();
    g_pending_request.kind = UsbPendingRequestKind::credential_propose;
    strlcpy(g_pending_request.id, id, sizeof(g_pending_request.id));
    strlcpy(g_pending_request.label, "zkLogin proof", sizeof(g_pending_request.label));
}

void handle_session_unavailable_method(const char* id, const char* method, JsonDocument& request)
{
    const bool requires_payload =
        strcmp(method, "policy_get") != 0;
    const char* const no_payload_fields[] = {"id", "version", "method", "sessionId"};
    const char* const payload_fields[] = {"id", "version", "method", "sessionId", "payload"};
    if (!device_request_fields_supported_or_reject(
            id,
            method,
            request,
            requires_payload ? payload_fields : no_payload_fields,
            requires_payload ? 5 : 4) ||
        !require_session_shape(id, method, request) ||
        (requires_payload && !required_payload_present_or_reject(id, method, request))) {
        return;
    }
    if (!active_auth_allows_session_method(id, method) ||
        !require_matching_session(id, method, request)) {
        return;
    }
    if (strcmp(method, "policy_get") == 0 ||
        strcmp(method, "get_approval_history") == 0 ||
        strcmp(method, "get_result") == 0 ||
        strcmp(method, "ack_result") == 0) {
        if (reject_if_payload_transfer_blocks_safe_read(id, method)) {
            return;
        }
    } else if (reject_if_payload_transfer_blocks_sensitive_flow(id, method)) {
        return;
    }
    if (strcmp(method, "policy_get") == 0 ||
        strcmp(method, "policy_propose") == 0) {
        if (strcmp(method, "policy_propose") == 0 &&
            !policy_propose_payload_wrapper_valid(request)) {
            reject_line(id, method, "invalid_params");
            return;
        }
        reject_line(id, method, "policy_unavailable");
        return;
    }
    if (strcmp(method, "get_approval_history") == 0) {
        if (!approval_history_payload_valid(request)) {
            reject_line(id, method, "invalid_params");
            return;
        }
        reject_line(id, method, "history_unavailable");
        return;
    }
    if (strcmp(method, "get_result") == 0) {
        if (!retained_request_payload_valid(request)) {
            reject_line(id, method, "invalid_params");
            return;
        }
        reject_line(id, method, "unknown_request");
        return;
    }
    if (strcmp(method, "ack_result") == 0) {
        if (!retained_request_payload_valid(request)) {
            reject_line(id, method, "invalid_params");
            return;
        }
        reject_line(id, method, "unknown_request");
        return;
    }
    reject_line(id, method, "unsupported_method");
}

void handle_payload_transfer_line(JsonDocument& request)
{
    PayloadTransferRequestEnvelope envelope = {};
    const PayloadTransferRequestParseStatus parse_status =
        payload_transfer_request_parse(request, &envelope);
    if (parse_status != PayloadTransferRequestParseStatus::ok) {
        const char* code = payload_transfer_request_error_code(parse_status);
        if (parse_status == PayloadTransferRequestParseStatus::invalid_envelope) {
            ++g_status.invalid_lines;
        }
        reject_payload_transfer_line(envelope.id, code);
        return;
    }

    const char* id = envelope.id;
    const char* session_id = envelope.session_id;

    if (g_runtime_state.auth_status != LocalAuthProjectionStatus::active) {
        reject_payload_transfer_line(id, "invalid_state");
        return;
    }
    if (!g_runtime_state.locally_unlocked) {
        reject_payload_transfer_line(id, "auth_unavailable");
        return;
    }
    if (g_pending_request.kind == UsbPendingRequestKind::credential_propose &&
        !session_state_active()) {
        cancel_pending_credential_proposal_after_session_loss(id);
        reject_payload_transfer_line(id, "invalid_session");
        return;
    }
    if (g_runtime_state.ui_busy ||
        g_pending_request.kind != UsbPendingRequestKind::none) {
        reject_payload_transfer_line(id, "busy");
        return;
    }
    switch (session_state_validate(session_id)) {
        case SessionValidationResult::ok:
            break;
        case SessionValidationResult::invalid_format:
        case SessionValidationResult::missing:
        case SessionValidationResult::mismatch:
        default:
            reject_payload_transfer_line(id, "invalid_session");
            return;
    }
    const uint32_t now_ms = current_payload_transfer_ms();
    if (reject_if_payload_transfer_action_unavailable(id, envelope.action, now_ms)) {
        return;
    }

    if (envelope.action == PayloadTransferRequestAction::begin) {
        const char* total_bytes_text = nullptr;
        const char* digest = nullptr;
        size_t total_bytes = 0;
        if (!signing::json_value_c_string(request["totalBytes"], &total_bytes_text) ||
            !signing::json_value_c_string(request["payloadDigest"], &digest) ||
            !parse_size_string(total_bytes_text, &total_bytes)) {
            reject_payload_transfer_line(id, "invalid_params");
            return;
        }
        PayloadTransferBeginOutput output = {};
        const PayloadTransferResult result =
            payload_transfer_begin(now_ms, session_id, total_bytes, digest, &output);
        if (result != PayloadTransferResult::ok) {
            reject_payload_transfer_line(id, signing::payload_delivery_transfer_error_code(result));
            return;
        }
        JsonDocument response_result;
        response_result["transferId"] = output.transfer_id;
        response_result["receivedBytes"] = "0";
        char chunk_max[12] = {};
        snprintf(chunk_max, sizeof(chunk_max), "%u", static_cast<unsigned>(output.chunk_max_bytes));
        response_result["chunkMaxBytes"] = chunk_max;
        if (write_payload_transfer_success_response(id, response_result.as<JsonObjectConst>())) {
            record_success(id, "payload_transfer_begin");
        } else {
            record_error(id, "payload_transfer_begin", "internal_output_error");
        }
        return;
    }

    if (envelope.action == PayloadTransferRequestAction::chunk) {
        const char* transfer_id = nullptr;
        const char* offset_text = nullptr;
        const char* chunk_base64 = nullptr;
        size_t offset = 0;
        if (!signing::json_value_c_string(request["transferId"], &transfer_id) ||
            !signing::json_value_c_string(request["offsetBytes"], &offset_text) ||
            !signing::json_value_c_string(request["chunk"], &chunk_base64) ||
            !parse_size_string(offset_text, &offset)) {
            reject_payload_transfer_line(id, "invalid_params");
            return;
        }
        size_t decoded_size = 0;
        if (!signing::validate_canonical_base64_syntax(
                chunk_base64,
                signing::kRequestLineMaxBytes,
                &decoded_size)) {
            reject_payload_transfer_line(id, "invalid_params");
            return;
        }
        if (decoded_size > kPayloadTransferChunkMaxBytes) {
            const PayloadTransferResult result =
                payload_transfer_reject_chunk_too_large(now_ms, session_id, transfer_id);
            reject_payload_transfer_line(id, signing::payload_delivery_transfer_error_code(result));
            return;
        }
        uint8_t chunk[kPayloadTransferChunkMaxBytes] = {};
        if (!decode_canonical_base64_input(
                chunk_base64,
                signing::kRequestLineMaxBytes,
                chunk,
                sizeof(chunk),
                &decoded_size)) {
            reject_payload_transfer_line(id, "invalid_params");
            return;
        }
        size_t received = 0;
        const PayloadTransferResult result =
            payload_transfer_append_chunk(now_ms, session_id, transfer_id, offset, chunk, decoded_size, &received);
        wipe_sensitive_buffer(chunk, sizeof(chunk));
        if (result != PayloadTransferResult::ok) {
            reject_payload_transfer_line(id, signing::payload_delivery_transfer_error_code(result));
            return;
        }
        JsonDocument response_result;
        char received_text[16] = {};
        snprintf(received_text, sizeof(received_text), "%u", static_cast<unsigned>(received));
        response_result["receivedBytes"] = received_text;
        if (write_payload_transfer_success_response(id, response_result.as<JsonObjectConst>())) {
            record_success(id, "payload_transfer_chunk");
        } else {
            record_error(id, "payload_transfer_chunk", "internal_output_error");
        }
        return;
    }

    if (envelope.action == PayloadTransferRequestAction::finish) {
        const char* transfer_id = nullptr;
        if (!signing::json_value_c_string(request["transferId"], &transfer_id)) {
            reject_payload_transfer_line(id, "invalid_params");
            return;
        }
        PayloadTransferFinishOutput output = {};
        const PayloadTransferResult result =
            payload_transfer_finish(now_ms, session_id, transfer_id, payload_digest_sha256, &output);
        if (result != PayloadTransferResult::ok) {
            reject_payload_transfer_line(id, signing::payload_delivery_transfer_error_code(result));
            return;
        }
        JsonDocument response_result;
        response_result["payloadRef"] = output.payload_ref;
        if (write_payload_transfer_success_response(id, response_result.as<JsonObjectConst>())) {
            record_success(id, "payload_transfer_finish");
        } else {
            record_error(id, "payload_transfer_finish", "internal_output_error");
        }
        return;
    }

    if (envelope.action == PayloadTransferRequestAction::abort) {
        const char* transfer_id = nullptr;
        const char* payload_ref = nullptr;
        const bool has_transfer_id = request_has_field(request, "transferId");
        const bool has_payload_ref = request_has_field(request, "payloadRef");
        if (has_transfer_id && has_payload_ref) {
            reject_payload_transfer_line(id, "invalid_request");
            return;
        }
        if (has_transfer_id) {
            if (!signing::json_value_c_string(request["transferId"], &transfer_id)) {
                reject_payload_transfer_line(id, "invalid_params");
                return;
            }
        } else if (has_payload_ref) {
            if (!signing::json_value_c_string(request["payloadRef"], &payload_ref)) {
                reject_payload_transfer_line(id, "invalid_params");
                return;
            }
        } else {
            reject_payload_transfer_line(id, "invalid_params");
            return;
        }
        const PayloadTransferResult result =
            payload_transfer_abort(now_ms, session_id, transfer_id, payload_ref);
        if (result != PayloadTransferResult::ok) {
            reject_payload_transfer_line(id, signing::payload_delivery_transfer_error_code(result));
            return;
        }
        JsonDocument response_result;
        if (write_payload_transfer_success_response(id, response_result.as<JsonObjectConst>())) {
            record_success(id, "payload_transfer_abort");
        } else {
            record_error(id, "payload_transfer_abort", "internal_output_error");
        }
        return;
    }

    reject_payload_transfer_line(id, "unsupported_method");
}

void handle_request_line(const char* line)
{
    ++g_status.received_lines;

    JsonDocument request;
    if (!signing::json_line_is_single_object(line)) {
        ++g_status.invalid_lines;
        reject_line(nullptr, nullptr, "invalid_request");
        return;
    }

    const DeserializationError parse_error =
        deserializeJson(request, line, DeserializationOption::NestingLimit(signing::kRequestJsonNestingLimit));
    if (parse_error) {
        ++g_status.invalid_lines;
        reject_line(nullptr, nullptr, "invalid_request");
        return;
    }

    if (!request["type"].isNull()) {
        const char* typed_id = nullptr;
        if (!signing::json_value_c_string(request["id"], &typed_id) ||
            !signing::request_id_format_valid(typed_id)) {
            ++g_status.invalid_lines;
            reject_line(nullptr, nullptr, "invalid_request");
            return;
        }
        if (!request["version"].is<int>()) {
            ++g_status.invalid_lines;
            reject_line(typed_id, nullptr, "invalid_request");
            return;
        }
        if (request["version"].as<int>() != signing::kProtocolVersion) {
            reject_line(typed_id, nullptr, "unsupported_version");
            return;
        }
        const char* type = nullptr;
        if (!signing::json_value_c_string(request["type"], &type)) {
            ++g_status.invalid_lines;
            reject_line(typed_id, nullptr, "invalid_request");
            return;
        }
        if (strcmp(type, "payload_transfer") == 0) {
            handle_payload_transfer_line(request);
            return;
        }
        if (type[0] == '\0') {
            ++g_status.invalid_lines;
            reject_line(typed_id, nullptr, "invalid_request");
            return;
        }
        reject_line(typed_id, nullptr, "unsupported_method");
        return;
    }

    const char* id = nullptr;
    const char* method_text = nullptr;
    const bool has_id = signing::json_value_c_string(request["id"], &id);
    if (!has_id || !signing::request_id_format_valid(id)) {
        ++g_status.invalid_lines;
        reject_line(nullptr, nullptr, "invalid_request");
        return;
    }

    const bool has_method_text = signing::json_value_c_string(request["method"], &method_text);
    const char* method = has_method_text && signing::device_method_row(method_text) != nullptr ? method_text : nullptr;
    if (!has_method_text || !request["version"].is<int>()) {
        ++g_status.invalid_lines;
        reject_line(id, method, "invalid_request");
        return;
    }

    if (request["version"].as<int>() != signing::kProtocolVersion) {
        reject_line(id, method, "unsupported_version");
        return;
    }

    if (method == nullptr) {
        reject_line(id, nullptr, "unsupported_method");
        return;
    }

    const char* const allowed_device_request_fields[] = {
        "id", "version", "method", "sessionId", "payload",
    };
    if (!device_request_fields_supported_or_reject(
            id,
            method,
            request,
            allowed_device_request_fields,
            5)) {
        return;
    }

    if (!device_method_rules_or_reject(id, method, request)) {
        return;
    }
    if (!resolve_request_payload_ref(id, method, request)) {
        return;
    }

    if (strcmp(method, "get_status") == 0) {
        const char* const allowed_status_fields[] = {"id", "version", "method"};
        if (!device_request_fields_supported_or_reject(id, method, request, allowed_status_fields, 3)) {
            return;
        }
        if (reject_if_payload_transfer_blocks_safe_read(id, method)) {
            return;
        }
        if (write_status_response(id)) {
            ++g_status.status_responses;
            record_success(id, method);
        } else {
            record_error(id, method, "internal_output_error");
        }
        return;
    }

    if (strcmp(method, "identify_device") == 0) {
        handle_identify_device_request(id, request);
        return;
    }
    if (strcmp(method, "connect") == 0) {
        handle_connect_request(id, request);
        return;
    }
    if (strcmp(method, "disconnect") == 0) {
        handle_disconnect_request(id, request);
        return;
    }
    if (strcmp(method, "get_capabilities") == 0) {
        handle_get_capabilities_request(id, request);
        return;
    }
    if (strcmp(method, "get_accounts") == 0) {
        handle_get_accounts_request(id, request);
        return;
    }
    if (strcmp(method, "credential_prepare") == 0) {
        handle_credential_prepare_request(id, request);
        return;
    }
    if (strcmp(method, "credential_propose") == 0) {
        handle_credential_propose_request(id, request);
        return;
    }
    if (strcmp(method, "policy_get") == 0 ||
        strcmp(method, "get_approval_history") == 0 ||
        strcmp(method, "policy_propose") == 0 ||
        strcmp(method, "sign_transaction") == 0 ||
        strcmp(method, "sign_personal_message") == 0 ||
        strcmp(method, "get_result") == 0 ||
        strcmp(method, "ack_result") == 0) {
        handle_session_unavailable_method(id, method, request);
        return;
    }

    reject_line(id, method, "invalid_state");
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
            handle_request_line(g_line_buffer);
            break;
        case signing::RequestLineFeedResult::rejected_nul:
        case signing::RequestLineFeedResult::rejected_too_long:
            ++g_status.invalid_lines;
            reject_line(nullptr, nullptr, "invalid_request");
            break;
        case signing::RequestLineFeedResult::none:
            break;
    }
}

}  // namespace

bool usb_transport_init()
{
    format_device_id();
    signing::usb_link_state_clear();
    g_usb_session_grace = signing::UsbGraceState{};
    reset_line_receiver_state();
    if (!usb_serial_jtag_is_driver_installed()) {
        usb_serial_jtag_driver_config_t config = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
        config.tx_buffer_size = 1024;
        config.rx_buffer_size = signing::kRequestLineMaxBytes + kReadChunkBytes;
        const esp_err_t result = usb_serial_jtag_driver_install(&config);
        if (result != ESP_OK) {
            ESP_LOGE(kTag, "USB serial driver install failed: %s", esp_err_to_name(result));
            g_status.ready = false;
            return false;
        }
    }
    usb_serial_jtag_vfs_use_driver();
    g_status.ready = true;
    return true;
}

void usb_transport_poll()
{
    if (!g_status.ready) {
        return;
    }
    const uint32_t now_ms = current_payload_transfer_ms();
    clear_identification_display_if_expired(now_ms);
    payload_transfer_clear_expired(now_ms);
    if (sui_zklogin_proposal_deadline_reached(now_ms)) {
        const SuiZkLoginProposalSnapshot snapshot = sui_zklogin_proposal_state_snapshot();
        finish_credential_proposal(
            snapshot.request_id,
            sui_zklogin_proposal_record_timed_out());
    }
    if (!refresh_usb_connection()) {
        return;
    }
    reject_expired_connect_request(now_ms);

    uint8_t buffer[kReadChunkBytes];
    const int read_count = usb_serial_jtag_read_bytes(buffer, sizeof(buffer), 0);
    if (read_count <= 0) {
        return;
    }
    for (int i = 0; i < read_count; ++i) {
        feed_byte(static_cast<char>(buffer[i]));
    }
}

UsbStatus usb_transport_status()
{
    refresh_usb_connection();
    return g_status;
}

UsbIdentificationDisplay usb_transport_identification_display()
{
    clear_identification_display_if_expired(current_payload_transfer_ms());
    return g_identification_display;
}

void usb_transport_set_runtime_state(UsbRuntimeState state)
{
    g_runtime_state = state;
    if (state.auth_status == LocalAuthProjectionStatus::missing ||
        state.auth_status == LocalAuthProjectionStatus::invalid ||
        state.auth_status == LocalAuthProjectionStatus::storage_error) {
        clear_pending_request();
        clear_session_scoped_state();
    }
}

UsbPendingRequest usb_transport_pending_request()
{
    return g_pending_request;
}

bool usb_transport_approve_pending_request()
{
    if (g_runtime_state.auth_status != LocalAuthProjectionStatus::active ||
        !g_runtime_state.locally_unlocked) {
        return false;
    }

    if (g_pending_request.kind == UsbPendingRequestKind::credential_propose) {
        if (sui_zklogin_proposal_mark_auth_verifying() !=
            SuiZkLoginProposalTransitionResult::ok) {
            return false;
        }
        const SuiZkLoginProposalTerminalResult result =
            sui_zklogin_proposal_commit();
        finish_credential_proposal(g_pending_request.id, result);
        return result == SuiZkLoginProposalTerminalResult::activated;
    }

    if (g_pending_request.kind != UsbPendingRequestKind::connect) {
        return false;
    }

    const SessionStartResult start = session_state_replace(secure_random_fill_with_context, nullptr);
    if (start != SessionStartResult::ok) {
        if (g_pending_request.id[0] != '\0') {
            reject_line(g_pending_request.id, "connect", "internal_output_error");
        }
        clear_pending_request();
        return false;
    }

    const bool written = write_connect_response(g_pending_request.id);
    if (written) {
        record_success(g_pending_request.id, "connect");
    } else {
        record_error(g_pending_request.id, "connect", "internal_output_error");
    }
    clear_pending_request();
    return written;
}

bool usb_transport_reject_pending_request(const char* error_code)
{
    if (g_pending_request.kind == UsbPendingRequestKind::none) {
        return false;
    }
    const char* code = error_code != nullptr ? error_code : "user_rejected";
    bool written = false;
    if (g_pending_request.kind == UsbPendingRequestKind::credential_propose) {
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
    written = reject_line(g_pending_request.id, "connect", code);
    clear_pending_request();
    return written;
}

void usb_transport_clear_session_scoped_state()
{
    clear_pending_request();
    clear_session_scoped_state();
}

}  // namespace stopwatch_target
