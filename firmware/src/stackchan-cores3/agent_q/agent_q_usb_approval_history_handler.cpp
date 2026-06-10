#include "agent_q_usb_approval_history_handler.h"

#include "agent_q_approval_history.h"
#include "agent_q_json_input.h"

namespace agent_q {

namespace {

bool parse_approval_history_params(JsonDocument& request, size_t* limit, uint64_t* before_sequence)
{
    if (limit == nullptr || before_sequence == nullptr) {
        return false;
    }
    *limit = kAgentQApprovalHistoryPageMax;
    *before_sequence = 0;

    JsonVariant params = request["params"];
    if (params.isNull()) {
        return true;
    }
    if (!params.is<JsonObject>()) {
        return false;
    }

    JsonObject params_object = params.as<JsonObject>();
    for (JsonPair pair : params_object) {
        JsonVariant value = pair.value();
        if (agent_q_json_string_equals(pair.key(), "limit")) {
            if (!value.is<unsigned int>()) {
                return false;
            }
            const unsigned int requested_limit = value.as<unsigned int>();
            if (requested_limit == 0 ||
                requested_limit > kAgentQApprovalHistoryPageMax) {
                return false;
            }
            *limit = requested_limit;
            continue;
        }
        if (agent_q_json_string_equals(pair.key(), "beforeSeq")) {
            const char* before_value = nullptr;
            if (!agent_q_json_value_c_string(value, &before_value)) {
                return false;
            }
            if (!approval_history_parse_sequence(before_value, before_sequence)) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

}  // namespace

void handle_usb_get_approval_history_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbApprovalHistoryHandlerOps& ops)
{
    if (ops.material_ready == nullptr || !ops.material_ready()) {
        writer.write_error(id, "invalid_state", "Approval history is available only after provisioning is complete.");
        return;
    }
    if (ops.write_busy_if_pending_or_local_flow_active != nullptr &&
        ops.write_busy_if_pending_or_local_flow_active(id)) {
        return;
    }

    const char* session_id = nullptr;
    if (!agent_q_json_optional_c_string(request["sessionId"], "", &session_id)) {
        writer.write_error(id, "invalid_session", "Invalid session.");
        return;
    }
    if (ops.require_active_matching_session == nullptr ||
        !ops.require_active_matching_session(id, session_id)) {
        return;
    }

    const char* const allowed_request_fields[] = {"id", "version", "type", "sessionId", "params"};
    if (!agent_q_json_object_fields_supported(
            request.as<JsonVariantConst>(),
            allowed_request_fields,
            5)) {
        writer.write_error(id, "invalid_params", "get_approval_history request contains unsupported fields.");
        return;
    }

    size_t limit = kAgentQApprovalHistoryPageMax;
    uint64_t before_sequence = 0;
    if (!parse_approval_history_params(request, &limit, &before_sequence)) {
        writer.write_error(id, "invalid_params", "Approval history params are invalid.");
        return;
    }

    if (ops.write_approval_history_response != nullptr &&
        ops.write_approval_history_response(id, before_sequence, limit)) {
        return;
    }
    writer.write_error(id, "history_error", "Approval history is unavailable.");
}

}  // namespace agent_q
