#include "usb_session_read_handlers.h"

#include <stdio.h>

#include "protocol/json_input.h"
#include "transport/payload_delivery_store.h"
#include "protocol/protocol_constants.h"
#include "protocol/sign_route.h"
#include "sui/signing_limits.h"
#include "protocol/usb_active_session_request_guard.h"

extern "C" {
#include "byte_conversions.h"
}

namespace signing {

namespace {

constexpr size_t kSuiActivePublicKeyBase64BufferSize =
    ((kSuiZkLoginPublicKeyMaxBytes + 2) / 3) * 4 + 1;

bool guard_session_read_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSessionReadHandlerOps& ops,
    UsbOperationType operation,
    const char** session_id)
{
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId"};
    const UsbActiveSessionRequestGuardOps guard_ops = {
        ops.material_ready,
        ops.write_busy_if_pending_or_local_flow_active,
        ops.write_payload_delivery_safe_read_admission_error,
        ops.require_active_matching_session,
    };
    return guard_usb_active_session_request(
        id,
        request,
        writer,
        operation,
        guard_ops,
        UsbSessionIdMode::optional_default_empty,
        allowed_request_fields,
        4,
        session_id);
}

const char* active_identity_key_scheme(SuiActiveIdentityKind kind)
{
    switch (kind) {
        case SuiActiveIdentityKind::native:
            return "ed25519";
        case SuiActiveIdentityKind::zklogin:
            return "zklogin";
        case SuiActiveIdentityKind::none:
        case SuiActiveIdentityKind::error:
        default:
            return nullptr;
    }
}

bool write_capability_account(JsonObject account, SuiActiveIdentityKind kind)
{
    const char* key_scheme = active_identity_key_scheme(kind);
    if (key_scheme == nullptr) {
        return false;
    }
    account["keyScheme"] = key_scheme;
    if (kind == SuiActiveIdentityKind::native) {
        account["derivationPath"] = "m/44'/784'/0'/0'/0'";
    }
    return true;
}

bool write_capabilities_response(
    const char* id,
    const UsbOperationResponseWriter& writer,
    AuthorizationMode signing_mode,
    const SuiActiveIdentity& active_identity,
    bool sui_zklogin_credential_available)
{
    JsonDocument result;
    JsonArray chains = result["chains"].to<JsonArray>();
    JsonObject sui = chains.add<JsonObject>();
    sui["id"] = "sui";
    JsonArray accounts = sui["accounts"].to<JsonArray>();
    if (active_identity.kind != SuiActiveIdentityKind::none) {
        JsonObject account = accounts.add<JsonObject>();
        if (!write_capability_account(account, active_identity.kind)) {
            return false;
        }
    }
    sui["methods"].to<JsonArray>();
    if (active_identity.kind != SuiActiveIdentityKind::none) {
        JsonObject signing = result["signing"].to<JsonObject>();
        signing["authorization"] = authorization_mode_name(signing_mode);
        JsonArray signing_routes = signing["methods"].to<JsonArray>();
        if (sign_route_allowed_for_authorization_mode(
                SupportedSignRoute::sui_sign_transaction,
                signing_mode)) {
            JsonObject route_entry = signing_routes.add<JsonObject>();
            route_entry["chain"] = "sui";
            route_entry["method"] = sign_route_wire_method(
                SupportedSignRoute::sui_sign_transaction);
        }
        if (sign_route_allowed_for_authorization_mode(
                SupportedSignRoute::sui_sign_personal_message,
                signing_mode)) {
            JsonObject personal_message_entry = signing_routes.add<JsonObject>();
            personal_message_entry["chain"] = "sui";
            personal_message_entry["method"] = sign_route_wire_method(
                SupportedSignRoute::sui_sign_personal_message);
        }
    }
    JsonArray credentials = result["credentials"].to<JsonArray>();
    if (sui_zklogin_credential_available) {
        JsonObject credential = credentials.add<JsonObject>();
        credential["chain"] = "sui";
        credential["credential"] = "zklogin";
        JsonArray operations = credential["operations"].to<JsonArray>();
        operations.add("credential_prepare");
        operations.add("credential_propose");
    }
    return writer.write_success_result(
        id,
        "get_capabilities",
        result.as<JsonObjectConst>());
}

bool write_accounts_response(
    const char* id,
    const UsbOperationResponseWriter& writer,
    const UsbSessionReadHandlerOps& ops,
    SuiActiveIdentityError* active_identity_error)
{
    if (active_identity_error != nullptr) {
        *active_identity_error = SuiActiveIdentityError::none;
    }
    if (ops.resolve_active_sui_identity == nullptr) {
        return false;
    }

    const SuiActiveIdentity active_identity = ops.resolve_active_sui_identity();
    if (active_identity.kind == SuiActiveIdentityKind::error) {
        if (active_identity_error != nullptr) {
            *active_identity_error = active_identity.error;
        }
        return false;
    }

    JsonDocument result;
    JsonArray accounts = result["accounts"].to<JsonArray>();
    if (active_identity.kind == SuiActiveIdentityKind::none) {
        return writer.write_success_result(
            id,
            "get_accounts",
            result.as<JsonObjectConst>());
    }

    const char* key_scheme = active_identity_key_scheme(active_identity.kind);
    if (key_scheme == nullptr ||
        active_identity.public_key_size == 0 ||
        active_identity.public_key_size > kSuiZkLoginPublicKeyMaxBytes ||
        active_identity.address[0] == '\0') {
        return false;
    }

    SuiAccountSettings account_settings = kDefaultSuiAccountSettings;
    if (ops.read_sui_account_settings == nullptr ||
        !ops.read_sui_account_settings(&account_settings)) {
        return false;
    }

    char public_key_base64[kSuiActivePublicKeyBase64BufferSize] = {};
    if (bytes_to_base64(
            active_identity.public_key,
            active_identity.public_key_size,
            public_key_base64,
            sizeof(public_key_base64)) != 0) {
        return false;
    }

    JsonObject account = accounts.add<JsonObject>();
    account["chain"] = "sui";
    account["address"] = active_identity.address;
    account["publicKey"] = public_key_base64;
    account["keyScheme"] = key_scheme;
    if (active_identity.kind == SuiActiveIdentityKind::native) {
        account["derivationPath"] = "m/44'/784'/0'/0'/0'";
    }
    JsonObject sponsored_transactions = account["sponsoredTransactions"].to<JsonObject>();
    sponsored_transactions["acceptGasSponsor"] = account_settings.accept_gas_sponsor;
    return writer.write_success_result(id, "get_accounts", result.as<JsonObjectConst>());
}

}  // namespace

void handle_usb_get_capabilities_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSessionReadHandlerOps& ops)
{
    const char* session_id = nullptr;
    if (!guard_session_read_request(
            id,
            request,
            writer,
            ops,
            UsbOperationType::get_capabilities,
            &session_id)) {
        return;
    }
    (void)session_id;

    AuthorizationMode signing_mode = AuthorizationMode::user;
    if (ops.read_signing_mode == nullptr || !ops.read_signing_mode(&signing_mode)) {
        writer.write_error(id, "invalid_state");
        return;
    }
    if (ops.resolve_active_sui_identity == nullptr) {
        writer.write_error(id, "account_unavailable");
        return;
    }
    const SuiActiveIdentity active_identity = ops.resolve_active_sui_identity();
    if (active_identity.kind == SuiActiveIdentityKind::error) {
        if (active_identity.error == SuiActiveIdentityError::native_account_unavailable &&
            ops.record_root_material_unreadable != nullptr) {
            ops.record_root_material_unreadable();
        }
        writer.write_error(id, "account_unavailable");
        return;
    }
    const bool sui_zklogin_credential_available =
        ops.sui_zklogin_credential_available != nullptr &&
        ops.sui_zklogin_credential_available();
    if (write_capabilities_response(
            id,
            writer,
            signing_mode,
            active_identity,
            sui_zklogin_credential_available)) {
        return;
    }
    writer.log_write_failure("get_capabilities", id);
}

void handle_usb_get_accounts_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSessionReadHandlerOps& ops)
{
    const char* session_id = nullptr;
    if (!guard_session_read_request(
            id,
            request,
            writer,
            ops,
            UsbOperationType::get_accounts,
            &session_id)) {
        return;
    }
    (void)session_id;

    SuiActiveIdentityError active_identity_error = SuiActiveIdentityError::none;
    if (write_accounts_response(id, writer, ops, &active_identity_error)) {
        return;
    }
    if (active_identity_error == SuiActiveIdentityError::native_account_unavailable &&
        ops.record_root_material_unreadable != nullptr) {
        ops.record_root_material_unreadable();
    }
    writer.write_error(id, "account_unavailable");
}

}  // namespace signing
