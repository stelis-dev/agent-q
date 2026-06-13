#include "agent_q_usb_policy_propose_handler.h"

#include "agent_q_json_input.h"
#include "agent_q_usb_policy_propose_result_writer.h"

namespace agent_q {

void handle_usb_policy_propose_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPolicyProposeHandlerOps& ops)
{
    if (ops.material_ready == nullptr || !ops.material_ready()) {
        writer.write_error(id, "invalid_state", "Policy update is available only after provisioning is complete.");
        return;
    }
    if (ops.write_policy_propose_admission_error != nullptr &&
        ops.write_policy_propose_admission_error(id)) {
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
        writer.write_error(id, "invalid_params", "policy_propose request contains unsupported fields.");
        return;
    }

    JsonVariant params = request["params"];
    if (!params.is<JsonObject>()) {
        writer.write_error(id, "invalid_params", "Policy update params must be an object.");
        return;
    }
    JsonObject params_object = params.as<JsonObject>();
    const char* const allowed_policy_params[] = {"policy"};
    if (!agent_q_json_object_fields_supported(params, allowed_policy_params, 1) ||
        params_object["policy"].isNull()) {
        writer.write_error(id, "invalid_params", "Policy update params require policy.");
        return;
    }

    if (ops.make_review_window == nullptr ||
        ops.begin_policy_update == nullptr ||
        ops.begin_result_reason == nullptr ||
        ops.show_policy_update_review == nullptr ||
        ops.record_ui_error == nullptr ||
        ops.finish_policy_update_terminal == nullptr) {
        writer.write_error(id, "protocol_error", "Policy update handler is unavailable.");
        return;
    }

    const AgentQTimeoutWindow review_window = ops.make_review_window();
    const AgentQPolicyUpdateFlowBeginResult begin_result =
        ops.begin_policy_update(
            params_object["policy"],
            id,
            session_id,
            review_window);
    if (begin_result != AgentQPolicyUpdateFlowBeginResult::ok) {
        if (!usb_policy_propose_result_write(
                id,
                "invalid_policy",
                ops.begin_result_reason(begin_result),
                nullptr)) {
            writer.log_write_failure("policy_propose_result", id);
        }
        return;
    }

    if (!ops.show_policy_update_review()) {
        ops.finish_policy_update_terminal(id, ops.record_ui_error());
        return;
    }
    if (ops.record_review_waiting != nullptr) {
        ops.record_review_waiting(id);
    }
}

}  // namespace agent_q
