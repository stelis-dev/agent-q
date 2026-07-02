#include "usb_policy_propose_handler.h"

#include "protocol/json_input.h"
#include "usb_active_session_request_guard.h"
#include "usb_policy_propose_outcome_writer.h"

namespace signing {

void handle_usb_policy_propose_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbPolicyProposeHandlerOps& ops)
{
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId", "payload"};
    const char* session_id = nullptr;
    const UsbActiveSessionRequestGuardOps guard_ops = {
        ops.material_ready,
        ops.write_policy_propose_busy,
        nullptr,
        ops.require_active_matching_session,
    };
    if (!guard_usb_active_session_request(
            id,
            request,
            writer,
            UsbOperationType::policy_propose,
            guard_ops,
            UsbSessionIdMode::optional_default_empty,
            allowed_request_fields,
            5,
            &session_id)) {
        return;
    }

    JsonVariant payload = request["payload"];
    if (!payload.is<JsonObject>()) {
        writer.write_error(id, "invalid_params");
        return;
    }
    JsonObject payload_object = payload.as<JsonObject>();
    const char* const allowed_policy_params[] = {"policy"};
    if (!json_object_fields_supported(payload, allowed_policy_params, 1) ||
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

    const TimeoutTick now = ops.current_tick();
    const TimeoutWindow review_window = ops.make_review_window(now);
    const PolicyUpdateFlowBeginResult begin_result =
        ops.begin_policy_update(
            payload_object["policy"],
            id,
            session_id,
            now,
            review_window);
    if (begin_result != PolicyUpdateFlowBeginResult::ok) {
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

}  // namespace signing
