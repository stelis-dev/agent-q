#include "agent_q_usb_sui_zklogin_credential_handlers.h"

#include <string.h>

#include "agent_q_json_input.h"
#include "agent_q_usb_sui_zklogin_credential_outcome_writer.h"

namespace agent_q {
namespace {

bool require_common_request_fields(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer)
{
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId", "payload"};
    if (agent_q_json_object_fields_supported(
            request.as<JsonVariantConst>(),
            allowed_request_fields,
            5)) {
        return true;
    }
    writer.write_error(id, "invalid_params");
    return false;
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
    writer.write_error(id, "invalid_session");
    return false;
}

bool parse_supported_credential_params(
    const char* id,
    JsonVariantConst params,
    const AgentQUsbOperationResponseWriter& writer,
    bool prepare_only)
{
    if (!params.is<JsonObjectConst>()) {
        writer.write_error(id, "invalid_params");
        return false;
    }
    JsonObjectConst object = params.as<JsonObjectConst>();
    const char* const prepare_keys[] = {"chain", "credential"};
    const char* const propose_keys[] = {
        "chain",
        "credential",
        "network",
        "address",
        "publicKey",
        "maxEpoch",
        "inputs",
    };
    if (!agent_q_json_object_fields_supported(
            params,
            prepare_only ? prepare_keys : propose_keys,
            prepare_only ? 2 : 7)) {
        writer.write_error(id, "invalid_params");
        return false;
    }
    const char* chain = nullptr;
    const char* credential = nullptr;
    if (!agent_q_json_value_c_string(object["chain"], &chain) ||
        !agent_q_json_value_c_string(object["credential"], &credential) ||
        strcmp(chain, "sui") != 0 ||
        strcmp(credential, "zklogin") != 0) {
        writer.write_error(id, "invalid_params");
        return false;
    }
    return true;
}

bool guard_common(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSuiZkLoginCredentialHandlerOps& ops,
    const char** session_id)
{
    if (ops.material_ready == nullptr || !ops.material_ready()) {
        writer.write_error(id, "invalid_state");
        return false;
    }
    if (!parse_session_id_or_write_error(id, request, writer, session_id)) {
        return false;
    }
    if (ops.require_active_matching_session == nullptr ||
        !ops.require_active_matching_session(id, *session_id, writer)) {
        return false;
    }
    if (!require_common_request_fields(id, request, writer)) {
        return false;
    }
    return true;
}

bool active_identity_allows_preparation(
    const char* id,
    const AgentQSuiActiveIdentity& identity,
    const AgentQUsbOperationResponseWriter& writer)
{
    switch (identity.kind) {
        case AgentQSuiActiveIdentityKind::native:
            return true;
        case AgentQSuiActiveIdentityKind::zklogin:
            writer.write_error(
                id,
                "invalid_state");
            return false;
        case AgentQSuiActiveIdentityKind::error:
        default:
            writer.write_error(
                id,
                "invalid_state");
            return false;
    }
}

}  // namespace

void handle_usb_credential_prepare_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSuiZkLoginCredentialHandlerOps& ops)
{
    if (ops.write_credential_prepare_admission_error != nullptr &&
        ops.write_credential_prepare_admission_error(id, writer)) {
        return;
    }
    if (ops.write_payload_delivery_safe_read_admission_error != nullptr &&
        ops.write_payload_delivery_safe_read_admission_error(
            id,
            AgentQUsbOperationType::credential_prepare,
            writer)) {
        return;
    }

    const char* session_id = nullptr;
    if (!guard_common(
            id,
            request,
            writer,
            ops,
            &session_id)) {
        return;
    }
    (void)session_id;
    if (!parse_supported_credential_params(id, request["payload"], writer, true)) {
        return;
    }
    if (ops.resolve_active_identity == nullptr) {
        writer.write_error(id, "internal_output_error");
        return;
    }
    const AgentQSuiActiveIdentity identity = ops.resolve_active_identity();
    if (!active_identity_allows_preparation(id, identity, writer)) {
        return;
    }
    if (!usb_sui_zklogin_credential_preparation_write(
            id,
            identity.address,
            identity.public_key,
            identity.public_key_size)) {
        writer.log_write_failure("credential_prepare", id);
    }
}

void handle_usb_credential_propose_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSuiZkLoginCredentialHandlerOps& ops)
{
    if (ops.write_credential_propose_admission_error != nullptr &&
        ops.write_credential_propose_admission_error(id, writer)) {
        return;
    }

    const char* session_id = nullptr;
    if (!guard_common(
            id,
            request,
            writer,
            ops,
            &session_id)) {
        return;
    }
    if (!parse_supported_credential_params(id, request["payload"], writer, false)) {
        return;
    }
    if (ops.resolve_active_identity == nullptr ||
        ops.current_tick == nullptr ||
        ops.make_proposal_window == nullptr ||
        ops.begin_proposal == nullptr ||
        ops.begin_result_reason == nullptr ||
        ops.show_proposal_review == nullptr) {
        writer.write_error(id, "internal_output_error");
        return;
    }

    const AgentQSuiActiveIdentity identity = ops.resolve_active_identity();
    if (!active_identity_allows_preparation(id, identity, writer)) {
        return;
    }

    const AgentQTimeoutTick now = ops.current_tick();
    const AgentQTimeoutWindow request_window = ops.make_proposal_window(now);
    const AgentQSuiZkLoginProposalBeginResult begin_result =
            ops.begin_proposal(
            request["payload"],
            id,
            session_id,
            now,
            request_window);
    if (begin_result != AgentQSuiZkLoginProposalBeginResult::ok) {
        const bool written = usb_sui_zklogin_credential_proposal_outcome_write(
            id,
            AgentQSuiZkLoginProposalTerminalResult::invalid_proof,
            false);
        if (!written) {
            writer.log_write_failure("credential_propose", id);
        }
        return;
    }

    ops.show_proposal_review(id);
}

}  // namespace agent_q
