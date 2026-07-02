#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_approval_history_handler.sh

Compiles the extracted USB approval-history handler and verifies state/session,
field, paging parameter, and history response behavior. It does not require
hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${RUNTIME_DIR}/usb_active_session_request_guard.cpp" \
  "${RUNTIME_DIR}/usb_active_session_request_guard.h" \
  "${RUNTIME_DIR}/usb_approval_history_handler.cpp" \
  "${RUNTIME_DIR}/usb_approval_history_handler.h" \
  "${RUNTIME_DIR}/usb_operation_response_writer.h" \
  "${RUNTIME_DIR}/usb_response_writer.h" \
  "${COMMON_ROOT}/numeric/u64_decimal.h" \
  "${RUNTIME_DIR}/approval_history.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-usb-approval-history-handler.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/firmware_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ArduinoJson.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "usb_approval_history_handler.h"

namespace signing {

bool approval_history_parse_sequence(const char* value, uint64_t* output)
{
    if (value == nullptr || output == nullptr || value[0] == '\0') {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == nullptr || *end != '\0') {
        return false;
    }
    *output = static_cast<uint64_t>(parsed);
    return true;
}

const char* approval_history_confirmation_kind_to_string(ApprovalHistoryConfirmationKind value)
{
    return value == ApprovalHistoryConfirmationKind::policy ? "policy" : "physical_confirm";
}

const char* approval_history_signing_record_kind_to_string(HistoryRecordKind value)
{
    return value == HistoryRecordKind::terminal ? "terminal" : "confirmation";
}

const char* approval_history_signing_terminal_result_to_string(
    HistoryTerminalResult value)
{
    return value == HistoryTerminalResult::signed_success ? "signed_success" : "signing_failed";
}

}  // namespace signing

namespace {

int g_write_error_calls = 0;
int g_log_write_failure_calls = 0;
int g_material_calls = 0;
int g_busy_calls = 0;
int g_payload_admission_calls = 0;
int g_require_session_calls = 0;
int g_read_history_calls = 0;
int g_json_write_calls = 0;
bool g_material_ready = true;
bool g_busy = false;
bool g_payload_admission_error = false;
bool g_session_valid = true;
signing::ApprovalHistoryReadResult g_read_history_result = signing::ApprovalHistoryReadResult::ok;
bool g_json_write_ok = true;
size_t g_last_limit = 0;
uint64_t g_last_before = 0;
const char* g_last_id = nullptr;
const char* g_last_session = nullptr;
const char* g_last_error_code = nullptr;
char g_last_response_id[32] = {};
char g_last_response_type[32] = {};
bool g_last_has_more = false;
size_t g_last_record_count = 0;
char g_last_record_seq[32] = {};
char g_last_record_uptime[32] = {};
char g_last_record_event_kind[32] = {};
char g_last_record_reason_code[32] = {};
char g_last_record_chain[16] = {};
char g_last_record_method[40] = {};
char g_last_record_terminal_result[32] = {};

void reset_state()
{
    g_write_error_calls = 0;
    g_log_write_failure_calls = 0;
    g_material_calls = 0;
    g_busy_calls = 0;
    g_payload_admission_calls = 0;
    g_require_session_calls = 0;
    g_read_history_calls = 0;
    g_json_write_calls = 0;
    g_material_ready = true;
    g_busy = false;
    g_payload_admission_error = false;
    g_session_valid = true;
    g_read_history_result = signing::ApprovalHistoryReadResult::ok;
    g_json_write_ok = true;
    g_last_limit = 0;
    g_last_before = 0;
    g_last_id = nullptr;
    g_last_session = nullptr;
    g_last_error_code = nullptr;
    g_last_response_id[0] = '\0';
    g_last_response_type[0] = '\0';
    g_last_has_more = false;
    g_last_record_count = 0;
    g_last_record_seq[0] = '\0';
    g_last_record_uptime[0] = '\0';
    g_last_record_event_kind[0] = '\0';
    g_last_record_reason_code[0] = '\0';
    g_last_record_chain[0] = '\0';
    g_last_record_method[0] = '\0';
    g_last_record_terminal_result[0] = '\0';
}

bool write_error(const char* id, const char* code)
{
    g_write_error_calls += 1;
    g_last_id = id;
    g_last_error_code = code;
    return true;
}

void log_write_failure(const char* response_type, const char* id)
{
    (void)response_type;
    g_log_write_failure_calls += 1;
    g_last_id = id;
}

bool material_ready()
{
    g_material_calls += 1;
    return g_material_ready;
}

bool write_busy(const char* id, const signing::UsbOperationResponseWriter& writer)
{
    g_busy_calls += 1;
    g_last_id = id;
    if (g_busy) {
        writer.write_error(id, "busy");
    }
    return g_busy;
}

bool write_payload_admission_error(
    const char* id,
    signing::UsbOperationType operation,
    const signing::UsbOperationResponseWriter& writer)
{
    assert(operation == signing::UsbOperationType::get_approval_history);
    g_payload_admission_calls += 1;
    g_last_id = id;
    if (!g_payload_admission_error) {
        return false;
    }
    return writer.write_error(id, "busy");
}

bool require_session(
    const char* id,
    const char* session_id,
    const signing::UsbOperationResponseWriter& writer)
{
    g_require_session_calls += 1;
    g_last_id = id;
    g_last_session = session_id;
    if (!g_session_valid) {
        writer.write_error(id, "invalid_session");
    }
    return g_session_valid;
}

signing::ApprovalHistoryReadResult read_history_page(
    uint64_t before_sequence,
    size_t limit,
    signing::ApprovalHistoryPage* output)
{
    g_read_history_calls += 1;
    g_last_before = before_sequence;
    g_last_limit = limit;
    if (output != nullptr && g_read_history_result == signing::ApprovalHistoryReadResult::ok) {
        memset(output, 0, sizeof(*output));
        output->count = 1;
        output->has_more = true;
        output->records[0].sequence = 7;
        output->records[0].uptime_ms = 1234;
        output->records[0].event_kind = signing::ApprovalHistoryEventKind::signing;
        output->records[0].confirmation_kind = signing::ApprovalHistoryConfirmationKind::policy;
        output->records[0].signing_record_kind = signing::HistoryRecordKind::terminal;
        output->records[0].signing_terminal_result =
            signing::HistoryTerminalResult::signed_success;
        snprintf(output->records[0].reason_code, sizeof(output->records[0].reason_code), "signed");
        snprintf(output->records[0].chain, sizeof(output->records[0].chain), "sui");
        snprintf(output->records[0].method, sizeof(output->records[0].method), "sign_transaction");
    }
    return g_read_history_result;
}

signing::UsbOperationResponseWriter make_writer()
{
    return signing::UsbOperationResponseWriter{
        write_error,
        log_write_failure,
    };
}

signing::UsbApprovalHistoryHandlerOps make_ops()
{
    return signing::UsbApprovalHistoryHandlerOps{
        material_ready,
        write_busy,
        write_payload_admission_error,
        require_session,
        read_history_page,
    };
}

JsonDocument parse_request(const char* json)
{
    JsonDocument request;
    const DeserializationError error = deserializeJson(request, json);
    assert(!error);
    return request;
}

}  // namespace

namespace signing {

bool usb_response_write_json(JsonDocument& response)
{
    g_json_write_calls += 1;
    JsonObjectConst result = response["result"].as<JsonObjectConst>();
    snprintf(g_last_response_id, sizeof(g_last_response_id), "%s", response["id"].as<const char*>());
    snprintf(g_last_response_type, sizeof(g_last_response_type), "%s", response["method"] | "");
    g_last_has_more = result["hasMore"].as<bool>();
    JsonArrayConst records = result["records"].as<JsonArrayConst>();
    g_last_record_count = records.size();
    if (g_last_record_count > 0) {
        JsonObjectConst record = records[0].as<JsonObjectConst>();
        snprintf(g_last_record_seq, sizeof(g_last_record_seq), "%s", record["seq"].as<const char*>());
        snprintf(g_last_record_uptime, sizeof(g_last_record_uptime), "%s", record["uptimeMs"].as<const char*>());
        snprintf(g_last_record_event_kind, sizeof(g_last_record_event_kind), "%s", record["eventKind"].as<const char*>());
        snprintf(g_last_record_reason_code, sizeof(g_last_record_reason_code), "%s", record["reasonCode"].as<const char*>());
        snprintf(g_last_record_chain, sizeof(g_last_record_chain), "%s", record["chain"].as<const char*>());
        snprintf(g_last_record_method, sizeof(g_last_record_method), "%s", record["method"].as<const char*>());
        snprintf(g_last_record_terminal_result, sizeof(g_last_record_terminal_result), "%s", record["terminalResult"].as<const char*>());
    }
    return g_json_write_ok;
}

bool usb_response_write_success_result(const char* id, const char* method, JsonObjectConst result)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = 1;
    response["success"] = true;
    response["method"] = method;
    response["result"].set(result);
    return usb_response_write_json(response);
}

}  // namespace signing

int main()
{
    {
        reset_state();
        g_material_ready = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session\",\"payload\":{}}");
        signing::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_state") == 0);
        assert(g_busy_calls == 0);
        assert(g_payload_admission_calls == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_history_calls == 0);
        assert(g_json_write_calls == 0);
    }

    {
        reset_state();
        g_busy = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session\",\"payload\":{}}");
        signing::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_material_calls == 1);
        assert(g_busy_calls == 1);
        assert(g_payload_admission_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_history_calls == 0);
        assert(g_json_write_calls == 0);
    }

    {
        reset_state();
        g_payload_admission_error = true;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session\",\"payload\":{}}");
        signing::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_material_calls == 1);
        assert(g_busy_calls == 1);
        assert(g_payload_admission_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "busy") == 0);
        assert(g_require_session_calls == 0);
        assert(g_read_history_calls == 0);
        assert(g_json_write_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":7}");
        signing::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_payload_admission_calls == 1);
        assert(g_require_session_calls == 0);
        assert(g_read_history_calls == 0);
        assert(g_json_write_calls == 0);
    }

    {
        reset_state();
        g_session_valid = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session\",\"payload\":{}}");
        signing::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_require_session_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_session") == 0);
        assert(g_read_history_calls == 0);
        assert(g_json_write_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session\",\"extra\":1}");
        signing::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_read_history_calls == 0);
        assert(g_json_write_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session\",\"payload\":7}");
        signing::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_read_history_calls == 0);
        assert(g_json_write_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session\",\"payload\":{\"limit\":0}}");
        signing::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_read_history_calls == 0);
        assert(g_json_write_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session\",\"payload\":{\"beforeSeq\":7}}");
        signing::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "invalid_params") == 0);
        assert(g_read_history_calls == 0);
        assert(g_json_write_calls == 0);
    }

    {
        reset_state();
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session\",\"payload\":{\"limit\":2,\"beforeSeq\":\"42\"}}");
        signing::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_write_error_calls == 0);
        assert(g_read_history_calls == 1);
        assert(g_json_write_calls == 1);
        assert(g_last_limit == 2);
        assert(g_last_before == 42);
        assert(strcmp(g_last_response_id, "req") == 0);
        assert(strcmp(g_last_response_type, "get_approval_history") == 0);
        assert(g_last_has_more);
        assert(g_last_record_count == 1);
        assert(strcmp(g_last_record_seq, "7") == 0);
        assert(strcmp(g_last_record_uptime, "1234") == 0);
        assert(strcmp(g_last_record_event_kind, "signing") == 0);
        assert(strcmp(g_last_record_reason_code, "signed") == 0);
        assert(strcmp(g_last_record_chain, "sui") == 0);
        assert(strcmp(g_last_record_method, "sign_transaction") == 0);
        assert(strcmp(g_last_record_terminal_result, "signed_success") == 0);
    }

    {
        reset_state();
        g_read_history_result = signing::ApprovalHistoryReadResult::storage_error;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session\",\"payload\":{}}");
        signing::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_read_history_calls == 1);
        assert(g_json_write_calls == 0);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "history_unavailable") == 0);
    }

    {
        reset_state();
        g_json_write_ok = false;
        JsonDocument request = parse_request("{\"id\":\"req\",\"version\":1,\"method\":\"get_approval_history\",\"sessionId\":\"session\",\"payload\":{}}");
        signing::handle_usb_get_approval_history_request("req", request, make_writer(), make_ops());
        assert(g_read_history_calls == 1);
        assert(g_json_write_calls == 1);
        assert(g_write_error_calls == 1);
        assert(strcmp(g_last_error_code, "history_unavailable") == 0);
    }

    printf("USB approval-history handler tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${COMMON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  -I"${TMP_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/usb_active_session_request_guard.cpp" \
  "${RUNTIME_DIR}/usb_approval_history_handler.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
