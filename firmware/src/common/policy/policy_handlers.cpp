#include "policy/policy_handlers.h"

#include "policy/policy_json_writer.h"
#include "policy/policy_store.h"
#include "protocol/json_input.h"
#include "protocol/active_session_request_guard.h"

namespace signing {
namespace {

bool guard_policy_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PolicyHandlerOps& ops,
    OperationType operation,
    const char* const* allowed_request_fields,
    size_t allowed_request_field_count,
    const char** session_id)
{
    const ActiveSessionRequestGuardOps guard_ops = {
        ops.material_ready,
        operation == OperationType::policy_get
            ? ops.write_policy_get_busy
            : ops.write_policy_propose_busy,
        operation == OperationType::policy_get
            ? ops.write_policy_get_admission_error
            : nullptr,
        ops.require_active_matching_session,
    };
    return guard_active_session_request(
        id,
        request,
        writer,
        operation,
        guard_ops,
        SessionIdMode::optional_default_empty,
        allowed_request_fields,
        allowed_request_field_count,
        session_id);
}

}  // namespace

bool policy_propose_outcome_write(
    const char* id,
    const char* status,
    const char* reason_code,
    const PolicyUpdateFlowSnapshot* policy,
    const ResponseWriter& writer)
{
    JsonDocument result;
    result["status"] = status;
    result["reasonCode"] = reason_code;
    if (policy != nullptr) {
        JsonObject policy_json = result["policy"].to<JsonObject>();
        policy_json["policyHash"] = policy->policy_hash;
        policy_json["blockchainCount"] = policy->blockchain_count;
        policy_json["networkCount"] = policy->network_count;
        policy_json["policyCount"] = policy->policy_count;
        policy_json["conditionCount"] = policy->condition_count;
        policy_json["highestAction"] = policy->highest_action;
    }
    return writer.write_success_result(
        id,
        "policy_propose",
        result.as<JsonObjectConst>());
}

void handle_protocol_policy_get_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PolicyHandlerOps& ops)
{
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId"};
    const char* session_id = nullptr;
    if (!guard_policy_request(
            id,
            request,
            writer,
            ops,
            OperationType::policy_get,
            allowed_request_fields,
            4,
            &session_id)) {
        return;
    }
    (void)session_id;

    StoredPolicyDocument policy = {};
    if (!read_active_policy_document(&policy) ||
        policy.document == nullptr) {
        if (ops.record_active_policy_unavailable != nullptr) {
            ops.record_active_policy_unavailable();
        }
        writer.write_error(id, "policy_unavailable");
        return;
    }
    JsonDocument result;
    if (policy_store_write_policy_json(result["policy"].to<JsonObject>(), policy) &&
        writer.write_success_result(id, "policy_get", result.as<JsonObjectConst>())) {
        return;
    }
    if (writer.log_write_failure != nullptr) {
        writer.log_write_failure("policy_get", id);
    }
}

void handle_protocol_policy_propose_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PolicyHandlerOps& ops)
{
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId", "payload"};
    const char* session_id = nullptr;
    if (!guard_policy_request(
            id,
            request,
            writer,
            ops,
            OperationType::policy_propose,
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
        if (!policy_propose_outcome_write(
                id,
                "invalid_policy",
                ops.begin_result_reason(begin_result),
                nullptr,
                writer) &&
            writer.log_write_failure != nullptr) {
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
