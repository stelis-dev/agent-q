#include "usb_approval_history_handler.h"

#include "protocol/json_input.h"
#include "protocol/protocol_constants.h"
#include "usb_active_session_request_guard.h"
#include "usb_response_writer.h"

namespace signing {

namespace {

bool parse_approval_history_params(JsonDocument& request, size_t* limit, uint64_t* before_sequence)
{
    if (limit == nullptr || before_sequence == nullptr) {
        return false;
    }
    *limit = kApprovalHistoryPageMax;
    *before_sequence = 0;

    JsonVariant payload = request["payload"];
    if (!payload.is<JsonObject>()) {
        return false;
    }

    JsonObject params_object = payload.as<JsonObject>();
    for (JsonPair pair : params_object) {
        JsonVariant value = pair.value();
        if (json_string_equals(pair.key(), "limit")) {
            if (!value.is<unsigned int>()) {
                return false;
            }
            const unsigned int requested_limit = value.as<unsigned int>();
            if (requested_limit == 0 ||
                requested_limit > kApprovalHistoryPageMax) {
                return false;
            }
            *limit = requested_limit;
            continue;
        }
        if (json_string_equals(pair.key(), "beforeSeq")) {
            const char* before_value = nullptr;
            if (!json_value_c_string(value, &before_value)) {
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
    const UsbOperationResponseWriter& writer,
    const UsbApprovalHistoryHandlerOps& ops)
{
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId", "payload"};
    const char* session_id = nullptr;
    const UsbActiveSessionRequestGuardOps guard_ops = {
        ops.material_ready,
        ops.write_busy_if_pending_or_local_flow_active,
        ops.write_payload_delivery_safe_read_admission_error,
        ops.require_active_matching_session,
    };
    if (!guard_usb_active_session_request(
            id,
            request,
            writer,
            UsbOperationType::get_approval_history,
            guard_ops,
            UsbSessionIdMode::optional_default_empty,
            allowed_request_fields,
            5,
            &session_id)) {
        return;
    }

    size_t limit = kApprovalHistoryPageMax;
    uint64_t before_sequence = 0;
    if (!parse_approval_history_params(request, &limit, &before_sequence)) {
        writer.write_error(id, "invalid_params");
        return;
    }

    ApprovalHistoryPage page = {};
    if (ops.read_approval_history_page != nullptr &&
        ops.read_approval_history_page(before_sequence, limit, &page) == ApprovalHistoryReadResult::ok) {
        JsonDocument result;
        if (approval_history_write_page_json(result.to<JsonObject>(), page) &&
            usb_response_write_success_result(id, "get_approval_history", result.as<JsonObjectConst>())) {
            return;
        }
    }
    writer.write_error(id, "history_unavailable");
}

}  // namespace signing
