#include "usb_approval_history_handler.h"

#include "json_input.h"
#include "protocol_constants.h"
#include "numeric/u64_decimal.h"
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

bool write_approval_history_response(const char* id, const ApprovalHistoryPage& page)
{
    JsonDocument result;
    result["hasMore"] = page.has_more;
    JsonArray records = result["records"].to<JsonArray>();
    for (size_t index = 0; index < page.count; ++index) {
        const ApprovalHistoryRecord& source = page.records[index];
        JsonObject record = records.add<JsonObject>();
        char sequence[kU64DecimalBufferBytes] = {};
        char uptime_ms[kU64DecimalBufferBytes] = {};
        if (!format_u64_decimal(source.sequence, sequence, sizeof(sequence)) ||
            !format_u64_decimal(source.uptime_ms, uptime_ms, sizeof(uptime_ms))) {
            return false;
        }
        record["seq"] = sequence;
        record["uptimeMs"] = uptime_ms;
        record["timeSource"] = "uptime";
        record["reasonCode"] = source.reason_code;
        if (source.event_kind == ApprovalHistoryEventKind::policy_update) {
            record["eventKind"] = "policy_update";
            record["result"] = source.policy_result;
            record["policyHash"] = source.policy_hash;
            record["policyCount"] = source.policy_count;
            record["highestAction"] = source.highest_action;
        } else if (source.event_kind == ApprovalHistoryEventKind::signing) {
            record["eventKind"] = "signing";
            record["recordKind"] =
                approval_history_signing_record_kind_to_string(source.signing_record_kind);
            record["authorization"] =
                source.confirmation_kind == ApprovalHistoryConfirmationKind::policy
                    ? "policy"
                    : "user";
            record["chain"] = source.chain;
            record["method"] = source.method;
            if (source.signing_record_kind == HistoryRecordKind::confirmation &&
                source.confirmation_kind != ApprovalHistoryConfirmationKind::none) {
                record["confirmationKind"] =
                    approval_history_confirmation_kind_to_string(source.confirmation_kind);
            }
            if (source.signing_terminal_result != HistoryTerminalResult::none) {
                record["terminalResult"] =
                    approval_history_signing_terminal_result_to_string(source.signing_terminal_result);
            }
            if (source.payload_digest[0] != '\0') {
                record["payloadDigest"] = source.payload_digest;
            }
            if (source.policy_hash[0] != '\0') {
                record["policyHash"] = source.policy_hash;
            }
            if (source.rule_ref[0] != '\0') {
                record["ruleRef"] = source.rule_ref;
            }
        }
    }
    return usb_response_write_success_result(id, "get_approval_history", result.as<JsonObjectConst>());
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
        ops.read_approval_history_page(before_sequence, limit, &page) == ApprovalHistoryReadResult::ok &&
        write_approval_history_response(id, page)) {
        return;
    }
    writer.write_error(id, "history_unavailable");
}

}  // namespace signing
