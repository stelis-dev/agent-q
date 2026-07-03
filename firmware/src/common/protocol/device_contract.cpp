#include "device_contract.h"

#include <string.h>

namespace signing {
namespace {

constexpr DeviceMethodRow kDeviceMethods[] = {
    {"get_status", DeviceSessionRule::forbidden, DevicePayloadRule::forbidden, "no payload", "StatusResult", "status_material_consistency"},
    {"identify_device", DeviceSessionRule::forbidden, DevicePayloadRule::required, "IdentifyDevicePayload", "IdentifyDeviceResult", "identification_display"},
    {"connect", DeviceSessionRule::forbidden, DevicePayloadRule::required, "ConnectPayload", "ConnectResult", "session_recovery_or_material_bootstrap_approval"},
    {"disconnect", DeviceSessionRule::required, DevicePayloadRule::forbidden, "no payload", "DisconnectResult", "active_session_cleanup"},
    {"get_capabilities", DeviceSessionRule::required, DevicePayloadRule::forbidden, "no payload", "CapabilitiesResult", "active_session_target_capability_state"},
    {"get_accounts", DeviceSessionRule::required, DevicePayloadRule::forbidden, "no payload", "AccountsResult", "active_session_account_availability"},
    {"policy_get", DeviceSessionRule::required, DevicePayloadRule::forbidden, "no payload", "PolicyGetResult", "active_session_policy_store"},
    {"get_approval_history", DeviceSessionRule::required, DevicePayloadRule::required, "ApprovalHistoryPayload", "ApprovalHistoryResult", "active_session_approval_history_store"},
    {"sign_transaction", DeviceSessionRule::required, DevicePayloadRule::required, "SuiSignTransactionPayload", "SignTransactionResult", "active_session_account_binding_signing_authorization"},
    {"sign_personal_message", DeviceSessionRule::required, DevicePayloadRule::required, "SuiSignPersonalMessagePayload", "SignPersonalMessageResult", "active_session_account_binding_user_confirmation"},
    {"policy_propose", DeviceSessionRule::required, DevicePayloadRule::required, "PolicyProposePayload", "PolicyProposalOutcome", "active_session_policy_review_auth_commit"},
    {"credential_prepare", DeviceSessionRule::required, DevicePayloadRule::required, "CredentialPreparePayload", "CredentialPreparation", "active_session_credential_preparation"},
    {"credential_propose", DeviceSessionRule::required, DevicePayloadRule::required, "CredentialProposePayload", "CredentialProposalOutcome", "active_session_credential_review_auth_commit"},
    {"get_result", DeviceSessionRule::required, DevicePayloadRule::required, "RetainedResponsePayload", "retained method response", "active_session_retained_response_lookup"},
    {"ack_result", DeviceSessionRule::required, DevicePayloadRule::required, "RetainedResponsePayload", "AckResult", "active_session_retained_response_cleanup"},
};

constexpr DeviceErrorRow kDeviceErrors[] = {
    {"invalid_request", false, "Device request is malformed.", "Envelope, JSON, id, version, or method shape is invalid."},
    {"invalid_params", false, "Device request payload is invalid.", "Method payload shape or value is invalid."},
    {"invalid_state", false, "Device state does not allow this request.", "Firmware state does not allow the method."},
    {"invalid_session", false, "Session is missing, expired, or does not match.", "Session is missing, expired, or does not match."},
    {"request_id_conflict", false, "Request id is already bound to a different request.", "Request id is already bound to a different retained request identity."},
    {"unknown_request", false, "Requested retained response does not exist.", "Requested retained response does not exist in the current session."},
    {"no_active_device", false, "No active device is configured.", "Host process has no selected active device for the requested scope."},
    {"device_not_found", true, "Requested device is not known to Agent-Q.", "Host process cannot find the requested stored device."},
    {"invalid_device_id", false, "Device id is invalid.", "Host-side device id input is invalid."},
    {"invalid_device", false, "Device identity is unsafe.", "Host process rejected a device identity as unsafe."},
    {"device_mismatch", false, "Connected device does not match the requested device.", "Host process connected to a device whose Firmware identity did not match the requested device id."},
    {"unsupported_method", false, "Device method is not supported.", "Method is not implemented by this Firmware or host boundary."},
    {"unsupported_version", false, "Protocol version is not supported.", "Protocol version is not supported."},
    {"unsupported_chain", false, "Chain is not supported.", "Chain is not supported for the method."},
    {"unsupported_transaction", false, "Transaction shape is not supported.", "Transaction shape is not supported by the current signing path."},
    {"malformed_transaction", false, "Transaction bytes are malformed.", "Transaction bytes or transaction structure are malformed."},
    {"payload_too_large", false, "Payload exceeds the current device payload capacity.", "Payload exceeds the current device payload capacity."},
    {"payload_unavailable", false, "Referenced payload is unavailable.", "Referenced internal payload is missing, expired, consumed, or wrong-session."},
    {"payload_conflict", true, "Another sensitive request blocks this payload.", "Another payload or sensitive flow blocks this request."},
    {"busy", true, "Device is busy with another request.", "Device is already handling another request."},
    {"timeout", true, "The signing request timed out on the device.", "Device or user action timed out."},
    {"user_rejected", false, "The signing request was rejected on the device.", "Device-local user confirmation rejected the request."},
    {"policy_rejected", false, "The signing request was rejected by device policy.", "Firmware policy rejected the request."},
    {"signing_failed", false, "The device could not produce a signature.", "Firmware could not produce the requested signature."},
    {"ui_error", false, "Device could not display or manage required UI.", "Firmware could not display or manage required device UI."},
    {"auth_unavailable", false, "Device-local authentication verifier is unavailable.", "Device-local authentication verifier is unavailable."},
    {"account_unavailable", false, "Device account material is unavailable or does not match the request.", "Device account material is unavailable or does not match the request."},
    {"policy_unavailable", false, "Firmware policy store or active policy is unavailable.", "Firmware policy store or active policy is unavailable."},
    {"history_unavailable", false, "Approval history is unavailable.", "Approval history is unavailable."},
    {"rng_unavailable", true, "Device random generator is unavailable.", "Firmware random generator is unavailable."},
    {"invalid_response", true, "Device response is malformed.", "Firmware response JSON, envelope, or method result shape is invalid."},
    {"handshake_failed", true, "Device status or identification handshake failed.", "Device status or identification handshake failed."},
    {"port_not_found", true, "Requested device port is not connected.", "Requested device port is not connected."},
    {"port_in_use", true, "Requested device port is already in use.", "Requested device port is already in use."},
    {"port_permission_denied", false, "Host process lacks permission to access the device port.", "Host process lacks permission to access the device port."},
    {"unsupported_transport", false, "Host environment does not support the required device transport.", "Host environment does not provide the transport required by the adapter."},
    {"transport_closed", true, "Device connection closed before a valid response.", "Established host-device connection closed before a valid response."},
    {"transport_error", true, "Host-device transport failed before a valid response.", "Host-device transport failed before a valid device response was received."},
    {"local_server_unavailable", true, "Local Agent-Q server is unavailable.", "Local CLI client cannot reach the local Agent-Q server."},
    {"identification_code_exhausted", true, "Identification code could not be allocated.", "Host process could not allocate a unique identification code."},
    {"internal_output_error", false, "Agent-Q produced an unexpected internal result.", "Output sanitization or internal result validation failed."},
    {"unknown_error", false, "Agent-Q request failed.", "Failure did not match a known public code."},
};

constexpr const char* kDeviceResponseSuccessFields[] = {
    "id", "version", "success", "method", "result",
};

constexpr const char* kDeviceResponseFailureFields[] = {
    "id", "version", "success", "method", "error",
};

constexpr const char* kDeviceResponseErrorFields[] = {
    "code", "message", "retryable",
};

}  // namespace

const DeviceMethodRow* device_method_row(const char* method)
{
    if (method == nullptr) {
        return nullptr;
    }
    for (const DeviceMethodRow& row : kDeviceMethods) {
        if (strcmp(row.method, method) == 0) {
            return &row;
        }
    }
    return nullptr;
}

const DeviceErrorRow* device_error_row(const char* code)
{
    if (code == nullptr) {
        return nullptr;
    }
    for (const DeviceErrorRow& row : kDeviceErrors) {
        if (strcmp(row.code, code) == 0) {
            return &row;
        }
    }
    return nullptr;
}

const DeviceMethodRow* device_method_rows(size_t* count)
{
    if (count != nullptr) {
        *count = sizeof(kDeviceMethods) / sizeof(kDeviceMethods[0]);
    }
    return kDeviceMethods;
}

const DeviceErrorRow* device_error_rows(size_t* count)
{
    if (count != nullptr) {
        *count = sizeof(kDeviceErrors) / sizeof(kDeviceErrors[0]);
    }
    return kDeviceErrors;
}

const char* const* device_response_success_fields(size_t* count)
{
    if (count != nullptr) {
        *count = sizeof(kDeviceResponseSuccessFields) / sizeof(kDeviceResponseSuccessFields[0]);
    }
    return kDeviceResponseSuccessFields;
}

const char* const* device_response_failure_fields(size_t* count)
{
    if (count != nullptr) {
        *count = sizeof(kDeviceResponseFailureFields) / sizeof(kDeviceResponseFailureFields[0]);
    }
    return kDeviceResponseFailureFields;
}

const char* const* device_response_error_fields(size_t* count)
{
    if (count != nullptr) {
        *count = sizeof(kDeviceResponseErrorFields) / sizeof(kDeviceResponseErrorFields[0]);
    }
    return kDeviceResponseErrorFields;
}

const char* device_session_rule_name(DeviceSessionRule rule)
{
    switch (rule) {
        case DeviceSessionRule::forbidden:
            return "forbidden";
        case DeviceSessionRule::required:
            return "required";
        case DeviceSessionRule::optional:
            return "optional";
    }
    return "";
}

const char* device_payload_rule_name(DevicePayloadRule rule)
{
    switch (rule) {
        case DevicePayloadRule::forbidden:
            return "forbidden";
        case DevicePayloadRule::required:
            return "required";
        case DevicePayloadRule::optional:
            return "optional";
    }
    return "";
}

}  // namespace signing
