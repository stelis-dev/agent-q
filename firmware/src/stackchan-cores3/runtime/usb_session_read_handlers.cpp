#include "usb_session_read_handlers.h"

#include <stdio.h>

#include "protocol/json_input.h"
#include "payload_delivery_store.h"
#include "protocol/protocol_constants.h"
#include "signing_route.h"
#include "sign_transaction_limits.h"
#include "usb_active_session_request_guard.h"
#include "usb_response_writer.h"

extern "C" {
#include "byte_conversions.h"
}

namespace signing {

namespace {

constexpr size_t kPolicyIdBufferSize = 80;
constexpr size_t kSuiActivePublicKeyBase64BufferSize =
    ((kSuiZkLoginPublicKeyMaxBytes + 2) / 3) * 4 + 1;

struct SessionReadPolicyDocument {
    const char* schema = nullptr;
    char policy_id[kPolicyIdBufferSize] = {};
    const char* default_action = nullptr;
    size_t blockchain_count = 0;
    size_t network_count = 0;
    size_t policy_count = 0;
    size_t condition_count = 0;
    const CurrentPolicyDocument* document = nullptr;
};

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
    AuthorizationMode signing_mode,
    const SuiActiveIdentity& active_identity,
    bool sui_zklogin_credential_available)
{
    JsonDocument result;
    JsonArray chains = result["chains"].to<JsonArray>();
    JsonObject sui = chains.add<JsonObject>();
    sui["id"] = "sui";
    JsonArray accounts = sui["accounts"].to<JsonArray>();
    JsonObject account = accounts.add<JsonObject>();
    if (!write_capability_account(account, active_identity.kind)) {
        return false;
    }
    sui["methods"].to<JsonArray>();
    JsonObject signing = result["signing"].to<JsonObject>();
    signing["authorization"] = authorization_mode_name(signing_mode);
    JsonArray signing_routes = signing["methods"].to<JsonArray>();
    if (signing_route_allowed_for_authorization_mode(
            Route::sui_sign_transaction,
            signing_mode)) {
        JsonObject route_entry = signing_routes.add<JsonObject>();
        route_entry["chain"] = "sui";
        route_entry["method"] = signing_route_wire_method(
            Route::sui_sign_transaction);
    }
    if (signing_route_allowed_for_authorization_mode(
            Route::sui_sign_personal_message,
            signing_mode)) {
        JsonObject personal_message_entry = signing_routes.add<JsonObject>();
        personal_message_entry["chain"] = "sui";
        personal_message_entry["method"] = signing_route_wire_method(
            Route::sui_sign_personal_message);
    }
    if (sui_zklogin_credential_available) {
        JsonArray credentials = result["credentials"].to<JsonArray>();
        JsonObject credential = credentials.add<JsonObject>();
        credential["chain"] = "sui";
        credential["credential"] = "zklogin";
        JsonArray operations = credential["operations"].to<JsonArray>();
        operations.add("credential_prepare");
        operations.add("credential_propose");
    }
    return usb_response_write_success_result(id, "get_capabilities", result.as<JsonObjectConst>());
}

bool write_accounts_response(
    const char* id,
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

    JsonDocument result;
    JsonArray accounts = result["accounts"].to<JsonArray>();
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
    return usb_response_write_success_result(id, "get_accounts", result.as<JsonObjectConst>());
}

bool write_policy_response(
    const char* id,
    const SessionReadPolicyDocument& policy)
{
    if (policy.document == nullptr) {
        return false;
    }

    JsonDocument result;
    JsonObject policy_json = result["policy"].to<JsonObject>();
    policy_json["schema"] = policy.schema;
    policy_json["policyId"] = policy.policy_id;
    policy_json["defaultAction"] = policy.default_action;
    policy_json["blockchainCount"] = policy.blockchain_count;
    policy_json["networkCount"] = policy.network_count;
    policy_json["policyCount"] = policy.policy_count;
    policy_json["conditionCount"] = policy.condition_count;
    JsonArray blockchains = policy_json["blockchains"].to<JsonArray>();
    const CurrentPolicyDocument& document = *policy.document;
    for (size_t blockchain_index = 0; blockchain_index < document.blockchain_count; ++blockchain_index) {
        const CurrentPolicyBlockchainScope& source_blockchain =
            document.blockchains[blockchain_index];
        JsonObject blockchain = blockchains.add<JsonObject>();
        blockchain["blockchain"] = source_blockchain.blockchain;
        JsonArray networks = blockchain["networks"].to<JsonArray>();
        for (size_t network_index = 0; network_index < source_blockchain.network_count; ++network_index) {
            const CurrentPolicyNetworkScope& source_network =
                source_blockchain.networks[network_index];
            JsonObject network = networks.add<JsonObject>();
            network["network"] = source_network.network;
            JsonArray policies = network["policies"].to<JsonArray>();
            for (size_t policy_index = 0; policy_index < source_network.policy_count; ++policy_index) {
                const CurrentPolicy& source_policy =
                    source_network.policies[policy_index];
                JsonObject policy_json_object = policies.add<JsonObject>();
                policy_json_object["id"] = source_policy.id;
                policy_json_object["action"] =
                    current_policy_action_name(source_policy.action);
                JsonArray conditions = policy_json_object["conditions"].to<JsonArray>();
                for (size_t condition_index = 0; condition_index < source_policy.condition_count; ++condition_index) {
                    const CurrentPolicyCondition& source_condition =
                        source_policy.conditions[condition_index];
                    JsonObject condition = conditions.add<JsonObject>();
                    condition["field"] = source_condition.field;
                    if (source_condition.where_type != nullptr &&
                        source_condition.where_type[0] != '\0') {
                        JsonObject where = condition["where"].to<JsonObject>();
                        where["type"] = source_condition.where_type;
                    }
                    condition["op"] = current_policy_operator_name(source_condition.op);
                    if (current_policy_operator_uses_value_list(source_condition.op)) {
                        JsonArray values = condition["values"].to<JsonArray>();
                        for (size_t value_index = 0; value_index < source_condition.value_count; ++value_index) {
                            values.add(source_condition.values[value_index]);
                        }
                    } else if (source_condition.value_count == 1) {
                        condition["value"] = source_condition.values[0];
                    } else {
                        return false;
                    }
                }
            }
        }
    }
    return usb_response_write_success_result(id, "policy_get", result.as<JsonObjectConst>());
}

bool read_active_policy(
    const UsbSessionReadHandlerOps& ops,
    SessionReadPolicyDocument* policy)
{
    if (policy == nullptr || ops.read_active_policy == nullptr) {
        return false;
    }
    return ops.read_active_policy(
        &policy->schema,
        policy->policy_id,
        sizeof(policy->policy_id),
        &policy->default_action,
        &policy->blockchain_count,
        &policy->network_count,
        &policy->policy_count,
        &policy->condition_count,
        &policy->document);
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
    if (write_accounts_response(id, ops, &active_identity_error)) {
        return;
    }
    if (active_identity_error == SuiActiveIdentityError::native_account_unavailable &&
        ops.record_root_material_unreadable != nullptr) {
        ops.record_root_material_unreadable();
    }
    writer.write_error(id, "account_unavailable");
}

void handle_usb_policy_get_request(
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
            UsbOperationType::policy_get,
            &session_id)) {
        return;
    }
    (void)session_id;

    SessionReadPolicyDocument policy;
    if (!read_active_policy(ops, &policy) ||
        policy.document == nullptr) {
        if (ops.record_active_policy_unavailable != nullptr) {
            ops.record_active_policy_unavailable();
        }
        writer.write_error(id, "policy_unavailable");
        return;
    }
    if (write_policy_response(id, policy)) {
        return;
    }
    writer.log_write_failure("policy_get", id);
}

}  // namespace signing
