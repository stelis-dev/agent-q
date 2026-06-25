#include "agent_q_usb_policy_propose_handler.h"

#include "agent_q_json_input.h"
#include "agent_q_usb_policy_propose_outcome_writer.h"

namespace agent_q {

void handle_usb_policy_propose_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbPolicyProposeHandlerOps& ops)
{
    if (ops.material_ready == nullptr || !ops.material_ready()) {
        writer.write_error(id, "invalid_state");
        return;
    }
    if (ops.write_policy_propose_admission_error != nullptr &&
        ops.write_policy_propose_admission_error(id, writer)) {
        return;
    }

    const char* session_id = nullptr;
    if (!agent_q_json_optional_c_string(request["sessionId"], "", &session_id)) {
        writer.write_error(id, "invalid_session");
        return;
    }
    if (ops.require_active_matching_session == nullptr ||
        !ops.require_active_matching_session(id, session_id, writer)) {
        return;
    }

    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId", "payload"};
    if (!agent_q_json_object_fields_supported(
            request.as<JsonVariantConst>(),
            allowed_request_fields,
            5)) {
        writer.write_error(id, "invalid_params");
        return;
    }

    JsonVariant payload = request["payload"];
    if (!payload.is<JsonObject>()) {
        writer.write_error(id, "invalid_params");
        return;
    }
    JsonObject payload_object = payload.as<JsonObject>();
    const char* const allowed_policy_params[] = {"policy"};
    if (!agent_q_json_object_fields_supported(payload, allowed_policy_params, 1) ||
        payload_object["policy"].isNull()) {
        writer.write_error(id, "invalid_params");
        return;
    }

    if (ops.current_tick == nullptr ||
        ops.make_review_window == nullptr ||
        ops.begin_policy_update == nullptr ||
        ops.begin_result_reason == nullptr ||
        ops.show_policy_update_review == nullptr ||
        ops.record_ui_error == nullptr ||
        ops.finish_policy_update_terminal == nullptr) {
        writer.write_error(id, "internal_output_error");
        return;
    }

    const AgentQTimeoutTick now = ops.current_tick();
    const AgentQTimeoutWindow review_window = ops.make_review_window(now);
    const AgentQPolicyUpdateFlowBeginResult begin_result =
        ops.begin_policy_update(
            payload_object["policy"],
            id,
            session_id,
            now,
            review_window);
    if (begin_result != AgentQPolicyUpdateFlowBeginResult::ok) {
        if (!usb_policy_propose_outcome_write(
                id,
                "invalid_policy",
                ops.begin_result_reason(begin_result),
                nullptr)) {
            writer.log_write_failure("policy_propose", id);
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
