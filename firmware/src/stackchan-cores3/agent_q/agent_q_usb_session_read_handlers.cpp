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

struct SessionReadPolicyDocument {
    const char* schema = nullptr;
    char policy_id[kPolicyIdBufferSize] = {};
    const char* default_action = nullptr;
    size_t rule_count = 0;
    const AgentQPolicyDocument* document = nullptr;
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
    const char* id)
{
    return ops.write_payload_delivery_safe_read_admission_error != nullptr &&
           ops.write_payload_delivery_safe_read_admission_error(id);
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
    if (session_read_payload_delivery_admission_error(ops, id)) {
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

bool write_capabilities_response(
    const char* id,
    AgentQSigningAuthorizationMode signing_mode)
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
    account["keyScheme"] = "ed25519";
    account["derivationPath"] = "m/44'/784'/0'/0'/0'";
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
    return usb_response_write_json(response);
}

bool write_accounts_response(
    const char* id,
    const AgentQUsbSessionReadHandlerOps& ops,
    bool* root_material_unavailable)
{
    if (root_material_unavailable != nullptr) {
        *root_material_unavailable = false;
    }
    if (ops.derive_sui_account == nullptr) {
        return false;
    }

    uint8_t public_key[kSuiEd25519PublicKeyBytes] = {};
    char address[kSuiAddressBufferSize] = {};
    const SuiAccountDerivationResult account_result =
        ops.derive_sui_account(public_key, address, sizeof(address));
    if (account_result == SuiAccountDerivationResult::root_material_unavailable) {
        if (root_material_unavailable != nullptr) {
            *root_material_unavailable = true;
        }
        return false;
    }
    if (account_result != SuiAccountDerivationResult::ok) {
        return false;
    }

    char public_key_base64[48] = {};
    if (bytes_to_base64(public_key, sizeof(public_key), public_key_base64, sizeof(public_key_base64)) != 0) {
        return false;
    }

    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "accounts";
    JsonArray accounts = response["accounts"].to<JsonArray>();
    JsonObject account = accounts.add<JsonObject>();
    account["chain"] = "sui";
    account["address"] = address;
    account["publicKey"] = public_key_base64;
    account["keyScheme"] = "ed25519";
    account["derivationPath"] = "m/44'/784'/0'/0'/0'";
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
    policy_json["ruleCount"] = policy.rule_count;
    JsonArray rules = policy_json["rules"].to<JsonArray>();
    const AgentQPolicyDocument& document = *policy.document;
    for (size_t rule_index = 0; rule_index < document.rule_count; ++rule_index) {
        const AgentQPolicyRule& source_rule = document.rules[rule_index];
        JsonObject rule = rules.add<JsonObject>();
        rule["id"] = source_rule.id;
        rule["chain"] = source_rule.chain;
        rule["method"] = source_rule.operation;
        rule["action"] = agent_q_policy_action_name(source_rule.action);
        JsonArray criteria = rule["criteria"].to<JsonArray>();
        for (size_t criterion_index = 0; criterion_index < source_rule.criterion_count; ++criterion_index) {
            const AgentQPolicyCriterion& source_criterion =
                source_rule.criteria[criterion_index];
            JsonObject criterion = criteria.add<JsonObject>();
            criterion["field"] = source_criterion.field;
            criterion["op"] = agent_q_policy_operator_name(source_criterion.op);
            if (source_criterion.op == AgentQPolicyOperator::in) {
                JsonArray values = criterion["values"].to<JsonArray>();
                for (size_t value_index = 0; value_index < source_criterion.value_count; ++value_index) {
                    values.add(source_criterion.values[value_index]);
                }
            } else {
                criterion["value"] = source_criterion.value;
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
        &policy->rule_count,
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
    if (write_capabilities_response(id, signing_mode)) {
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
            "Accounts are available only after provisioning is complete.",
            "get_accounts request contains unsupported fields.",
            &session_id)) {
        return;
    }
    (void)session_id;

    bool root_material_unavailable = false;
    if (write_accounts_response(id, ops, &root_material_unavailable)) {
        return;
    }
    if (root_material_unavailable && ops.record_root_material_unreadable != nullptr) {
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
