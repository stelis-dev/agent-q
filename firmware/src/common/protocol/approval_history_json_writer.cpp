#include "protocol/approval_history.h"

#include "numeric/u64_decimal.h"

namespace signing {

bool approval_history_write_page_json(JsonObject result, const ApprovalHistoryPage& page)
{
    if (result.isNull()) {
        return false;
    }
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
            continue;
        }
        if (source.event_kind != ApprovalHistoryEventKind::signing) {
            return false;
        }
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
    return true;
}

}  // namespace signing
