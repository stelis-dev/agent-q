#include "agent_q_usb_session_read_handlers.h"

#include "agent_q_json_input.h"
#include "agent_q_protocol_constants.h"
#include "agent_q_signing_route.h"
#include "agent_q_usb_response_writer.h"

namespace agent_q {

namespace {

bool session_read_material_ready(const AgentQUsbSessionReadHandlerOps& ops)
{
    return ops.material_ready != nullptr && ops.material_ready();
}

bool session_read_busy(const AgentQUsbSessionReadHandlerOps& ops, const char* id)
{
    return ops.write_busy_if_pending_or_local_flow_active != nullptr &&
           ops.write_busy_if_pending_or_local_flow_active(id);
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

    if (ops.write_accounts_response != nullptr &&
        ops.write_accounts_response(id)) {
        return;
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

    if (ops.write_policy_response == nullptr) {
        writer.log_write_failure("policy", id);
        return;
    }
    switch (ops.write_policy_response(id)) {
        case AgentQUsbPolicyResponseWriteResult::ok:
            return;
        case AgentQUsbPolicyResponseWriteResult::active_policy_unavailable:
            if (ops.record_active_policy_unavailable != nullptr) {
                ops.record_active_policy_unavailable();
            }
            writer.write_error(id, "policy_error", "Active policy is unavailable.");
            return;
        case AgentQUsbPolicyResponseWriteResult::response_write_failed:
            writer.log_write_failure("policy", id);
            return;
    }
}

}  // namespace agent_q
