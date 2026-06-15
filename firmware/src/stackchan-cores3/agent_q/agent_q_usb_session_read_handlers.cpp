#include "agent_q_usb_session_read_handlers.h"

#include <stdio.h>

#include "agent_q_json_input.h"
#include "agent_q_payload_delivery_store.h"
#include "agent_q_protocol_constants.h"
#include "agent_q_signing_route.h"
#include "agent_q_sign_transaction_limits.h"
#include "agent_q_usb_response_writer.h"

extern "C" {
#include "byte_conversions.h"
}

namespace agent_q {

namespace {

constexpr size_t kPolicyIdBufferSize = 80;
constexpr size_t kSuiActivePublicKeyBase64BufferSize =
    ((kAgentQSuiZkLoginPublicKeyMaxBytes + 2) / 3) * 4 + 1;

struct SessionReadPolicyDocument {
    const char* schema = nullptr;
    char policy_id[kPolicyIdBufferSize] = {};
    const char* default_action = nullptr;
    size_t blockchain_count = 0;
    size_t network_count = 0;
    size_t policy_count = 0;
    size_t condition_count = 0;
    const AgentQCurrentPolicyDocument* document = nullptr;
};

bool session_read_material_ready(const AgentQUsbSessionReadHandlerOps& ops)
{
    return ops.material_ready != nullptr && ops.material_ready();
}

bool session_read_busy(const AgentQUsbSessionReadHandlerOps& ops, const char* id)
{
    return ops.write_busy_if_pending_or_local_flow_active != nullptr &&
           ops.write_busy_if_pending_or_local_flow_active(id);
}

bool session_read_payload_delivery_admission_error(
    const AgentQUsbSessionReadHandlerOps& ops,
    const char* id,
    AgentQUsbOperationType operation)
{
    return ops.write_payload_delivery_safe_read_admission_error != nullptr &&
           ops.write_payload_delivery_safe_read_admission_error(id, operation);
}

bool session_read_session_valid(
    const AgentQUsbSessionReadHandlerOps& ops,
    const char* id,
    const char* session_id)
{
    return ops.require_active_matching_session != nullptr &&
           ops.require_active_matching_session(id, session_id);
}

bool parse_session_id_or_write_error(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const char** session_id)
{
    if (agent_q_json_optional_c_string(request["sessionId"], "", session_id)) {
        return true;
    }
    writer.write_error(id, "invalid_session", "Invalid session.");
    return false;
}

bool session_read_request_fields_supported(JsonDocument& request)
{
    const char* const allowed_request_fields[] = {"id", "version", "type", "sessionId"};
    return agent_q_json_object_fields_supported(
        request.as<JsonVariantConst>(),
        allowed_request_fields,
        4);
}

bool guard_session_read_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSessionReadHandlerOps& ops,
    AgentQUsbOperationType operation,
    const char* invalid_state_message,
    const char* unsupported_fields_message,
    const char** session_id)
{
    if (!session_read_material_ready(ops)) {
        writer.write_error(id, "invalid_state", invalid_state_message);
        return false;
    }
    if (session_read_busy(ops, id)) {
        return false;
    }
    if (session_read_payload_delivery_admission_error(ops, id, operation)) {
        return false;
    }
    if (!parse_session_id_or_write_error(id, request, writer, session_id)) {
        return false;
    }
    if (!session_read_session_valid(ops, id, *session_id)) {
        return false;
    }
    if (!session_read_request_fields_supported(request)) {
        writer.write_error(id, "invalid_params", unsupported_fields_message);
        return false;
    }
    return true;
}

const char* active_identity_key_scheme(AgentQSuiActiveIdentityKind kind)
{
    switch (kind) {
        case AgentQSuiActiveIdentityKind::native:
            return "ed25519";
        case AgentQSuiActiveIdentityKind::zklogin:
            return "zklogin";
        case AgentQSuiActiveIdentityKind::error:
        default:
            return nullptr;
    }
}

bool write_capability_account(JsonObject account, AgentQSuiActiveIdentityKind kind)
{
    const char* key_scheme = active_identity_key_scheme(kind);
    if (key_scheme == nullptr) {
        return false;
    }
    account["keyScheme"] = key_scheme;
    if (kind == AgentQSuiActiveIdentityKind::native) {
        account["derivationPath"] = "m/44'/784'/0'/0'/0'";
    }
    return true;
}

bool write_capabilities_response(
    const char* id,
    AgentQSigningAuthorizationMode signing_mode,
    const AgentQSuiActiveIdentity& active_identity,
    bool sui_zklogin_credential_available)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "capabilities";
    JsonArray chains = response["chains"].to<JsonArray>();
    JsonObject sui = chains.add<JsonObject>();
    sui["id"] = "sui";
    JsonArray accounts = sui["accounts"].to<JsonArray>();
    JsonObject account = accounts.add<JsonObject>();
    if (!write_capability_account(account, active_identity.kind)) {
        return false;
    }
    sui["methods"].to<JsonArray>();
    JsonObject signing = response["signing"].to<JsonObject>();
    signing["authorization"] = signing_authorization_mode_name(signing_mode);
    JsonArray signing_routes = signing["methods"].to<JsonArray>();
    if (signing_route_allowed_for_authorization_mode(
            AgentQSigningRoute::sui_sign_transaction,
            signing_mode)) {
        JsonObject signing_entry = signing_routes.add<JsonObject>();
        signing_entry["chain"] = "sui";
        signing_entry["method"] = signing_route_wire_method(
            AgentQSigningRoute::sui_sign_transaction);
        char inline_max_bytes[24] = {};
        char chunk_max_bytes[24] = {};
        char payload_max_bytes[24] = {};
        snprintf(
            inline_max_bytes,
            sizeof(inline_max_bytes),
            "%u",
            static_cast<unsigned>(kAgentQSuiSignTransactionInlineTxBytesMaxBytes));
        snprintf(
            chunk_max_bytes,
            sizeof(chunk_max_bytes),
            "%u",
            static_cast<unsigned>(kAgentQPayloadDeliveryDefaultChunkMaxBytes));
        snprintf(
            payload_max_bytes,
            sizeof(payload_max_bytes),
            "%u",
            static_cast<unsigned>(kAgentQPayloadDeliveryDefaultMaxBytes));
        JsonObject payload = signing_entry["payload"].to<JsonObject>();
        payload["kind"] = "transaction";
        payload["inlineMaxBytes"] = inline_max_bytes;
        payload["chunkMaxBytes"] = chunk_max_bytes;
        payload["payloadMaxBytes"] = payload_max_bytes;
    }
    if (signing_route_allowed_for_authorization_mode(
            AgentQSigningRoute::sui_sign_personal_message,
            signing_mode)) {
        JsonObject personal_message_entry = signing_routes.add<JsonObject>();
        personal_message_entry["chain"] = "sui";
        personal_message_entry["method"] = signing_route_wire_method(
            AgentQSigningRoute::sui_sign_personal_message);
    }
    if (sui_zklogin_credential_available) {
        JsonArray credentials = response["credentials"].to<JsonArray>();
        JsonObject credential = credentials.add<JsonObject>();
        credential["chain"] = "sui";
        credential["credential"] = "zklogin";
        JsonArray operations = credential["operations"].to<JsonArray>();
        operations.add("credential_prepare");
        operations.add("credential_propose");
    }
    return usb_response_write_json(response);
}

bool write_accounts_response(
    const char* id,
    const AgentQUsbSessionReadHandlerOps& ops,
    AgentQSuiActiveIdentityError* active_identity_error)
{
    if (active_identity_error != nullptr) {
        *active_identity_error = AgentQSuiActiveIdentityError::none;
    }
    if (ops.resolve_active_sui_identity == nullptr) {
        return false;
    }

    const AgentQSuiActiveIdentity active_identity = ops.resolve_active_sui_identity();
    if (active_identity.kind == AgentQSuiActiveIdentityKind::error) {
        if (active_identity_error != nullptr) {
            *active_identity_error = active_identity.error;
        }
        return false;
    }
    const char* key_scheme = active_identity_key_scheme(active_identity.kind);
    if (key_scheme == nullptr ||
        active_identity.public_key_size == 0 ||
        active_identity.public_key_size > kAgentQSuiZkLoginPublicKeyMaxBytes ||
        active_identity.address[0] == '\0') {
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

    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "accounts";
    JsonArray accounts = response["accounts"].to<JsonArray>();
    JsonObject account = accounts.add<JsonObject>();
    account["chain"] = "sui";
    account["address"] = active_identity.address;
    account["publicKey"] = public_key_base64;
    account["keyScheme"] = key_scheme;
    if (active_identity.kind == AgentQSuiActiveIdentityKind::native) {
        account["derivationPath"] = "m/44'/784'/0'/0'/0'";
    }
    return usb_response_write_json(response);
}

bool write_policy_response(
    const char* id,
    const SessionReadPolicyDocument& policy)
{
    if (policy.document == nullptr) {
        return false;
    }

    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "policy";
    JsonObject policy_json = response["policy"].to<JsonObject>();
    policy_json["schema"] = policy.schema;
    policy_json["policyId"] = policy.policy_id;
    policy_json["defaultAction"] = policy.default_action;
    policy_json["blockchainCount"] = policy.blockchain_count;
    policy_json["networkCount"] = policy.network_count;
    policy_json["policyCount"] = policy.policy_count;
    policy_json["conditionCount"] = policy.condition_count;
    JsonArray blockchains = policy_json["blockchains"].to<JsonArray>();
    const AgentQCurrentPolicyDocument& document = *policy.document;
    for (size_t blockchain_index = 0; blockchain_index < document.blockchain_count; ++blockchain_index) {
        const AgentQCurrentPolicyBlockchainScope& source_blockchain =
            document.blockchains[blockchain_index];
        JsonObject blockchain = blockchains.add<JsonObject>();
        blockchain["blockchain"] = source_blockchain.blockchain;
        JsonArray networks = blockchain["networks"].to<JsonArray>();
        for (size_t network_index = 0; network_index < source_blockchain.network_count; ++network_index) {
            const AgentQCurrentPolicyNetworkScope& source_network =
                source_blockchain.networks[network_index];
            JsonObject network = networks.add<JsonObject>();
            network["network"] = source_network.network;
            JsonArray policies = network["policies"].to<JsonArray>();
            for (size_t policy_index = 0; policy_index < source_network.policy_count; ++policy_index) {
                const AgentQCurrentPolicy& source_policy =
                    source_network.policies[policy_index];
                JsonObject policy_json_object = policies.add<JsonObject>();
                policy_json_object["id"] = source_policy.id;
                policy_json_object["action"] =
                    agent_q_current_policy_action_name(source_policy.action);
                JsonArray conditions = policy_json_object["conditions"].to<JsonArray>();
                for (size_t condition_index = 0; condition_index < source_policy.condition_count; ++condition_index) {
                    const AgentQCurrentPolicyCondition& source_condition =
                        source_policy.conditions[condition_index];
                    JsonObject condition = conditions.add<JsonObject>();
                    condition["field"] = source_condition.field;
                    if (source_condition.where_type != nullptr &&
                        source_condition.where_type[0] != '\0') {
                        JsonObject where = condition["where"].to<JsonObject>();
                        where["type"] = source_condition.where_type;
                    }
                    condition["op"] = agent_q_current_policy_operator_name(source_condition.op);
                    if (agent_q_current_policy_operator_uses_value_list(source_condition.op)) {
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
    return usb_response_write_json(response);
}

bool read_active_policy(
    const AgentQUsbSessionReadHandlerOps& ops,
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
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSessionReadHandlerOps& ops)
{
    const char* session_id = nullptr;
    if (!guard_session_read_request(
            id,
            request,
            writer,
            ops,
            AgentQUsbOperationType::get_capabilities,
            "Capabilities are available only after provisioning is complete.",
            "get_capabilities request contains unsupported fields.",
            &session_id)) {
        return;
    }
    (void)session_id;

    AgentQSigningAuthorizationMode signing_mode = AgentQSigningAuthorizationMode::user;
    if (ops.read_signing_mode == nullptr || !ops.read_signing_mode(&signing_mode)) {
        writer.write_error(id, "invalid_state", "Signing authorization mode is unavailable.");
        return;
    }
    if (ops.resolve_active_sui_identity == nullptr) {
        writer.write_error(id, "account_error", "Could not derive accounts.");
        return;
    }
    const AgentQSuiActiveIdentity active_identity = ops.resolve_active_sui_identity();
    if (active_identity.kind == AgentQSuiActiveIdentityKind::error) {
        if (active_identity.error == AgentQSuiActiveIdentityError::native_account_unavailable &&
            ops.record_root_material_unreadable != nullptr) {
            ops.record_root_material_unreadable();
        }
        writer.write_error(id, "account_error", "Could not derive accounts.");
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
    writer.log_write_failure("capabilities", id);
}

void handle_usb_get_accounts_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSessionReadHandlerOps& ops)
{
    const char* session_id = nullptr;
    if (!guard_session_read_request(
            id,
            request,
            writer,
            ops,
            AgentQUsbOperationType::get_accounts,
            "Accounts are available only after provisioning is complete.",
            "get_accounts request contains unsupported fields.",
            &session_id)) {
        return;
    }
    (void)session_id;

    AgentQSuiActiveIdentityError active_identity_error = AgentQSuiActiveIdentityError::none;
    if (write_accounts_response(id, ops, &active_identity_error)) {
        return;
    }
    if (active_identity_error == AgentQSuiActiveIdentityError::native_account_unavailable &&
        ops.record_root_material_unreadable != nullptr) {
        ops.record_root_material_unreadable();
    }
    writer.write_error(id, "account_error", "Could not derive accounts.");
}

void handle_usb_policy_get_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSessionReadHandlerOps& ops)
{
    const char* session_id = nullptr;
    if (!guard_session_read_request(
            id,
            request,
            writer,
            ops,
            AgentQUsbOperationType::policy_get,
            "Policy is available only after provisioning is complete.",
            "policy_get request contains unsupported fields.",
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
        writer.write_error(id, "policy_error", "Active policy is unavailable.");
        return;
    }
    if (write_policy_response(id, policy)) {
        return;
    }
    writer.log_write_failure("policy", id);
}

}  // namespace agent_q
