#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_policy_update_flow.sh

Compiles the StackChan CoreS3 policy-update flow with real proposal parsing and
canonicalization plus host stubs for policy storage, terminal marker, and
approval-history persistence. This test does not require ESP-IDF, but it uses
the pinned StackChan ArduinoJson source by default. Set ARDUINOJSON_ROOT to
override the ArduinoJson source root.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET_ROOT="${REPO_ROOT}/firmware/src/stackchan-cores3"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${COMMON_ROOT}/numeric/u64_decimal.h" \
  "${REPO_ROOT}/firmware/src/common/policy/policy_update_flow.cpp" \
  "${REPO_ROOT}/firmware/src/common/policy/policy_update_flow.h" \
  "${REPO_ROOT}/firmware/src/common/policy/policy_proposal_parser.cpp" \
  "${REPO_ROOT}/firmware/src/common/policy/policy_proposal_parser.h" \
  "${COMMON_POLICY_DIR}/document.cpp" \
  "${COMMON_POLICY_DIR}/document.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-policy-update-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/firmware_common"
mkdir -p "${TMP_DIR}/freertos"
ln -s "${COMMON_POLICY_DIR}" "${TMP_DIR}/firmware_common/policy"
ln -s "${COMMON_SUI_DIR}" "${TMP_DIR}/firmware_common/sui"

cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/policy_update_flow_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ArduinoJson.h>

#include "protocol/approval_history.h"
#include "policy/policy_store.h"
#include "policy/policy_update_flow.h"
#include "policy/policy_update_marker.h"

namespace {

int failures = 0;

signing::PolicyStoreWriteResult g_store_result =
    signing::PolicyStoreWriteResult::applied;
signing::PolicyUpdateMarkerBeginResult g_marker_begin_result =
    signing::PolicyUpdateMarkerBeginResult::written;
bool g_marker_clear_result = true;
bool g_digest_result = true;
bool g_policy_id_result = true;
bool g_history_result = true;
int g_store_calls = 0;
int g_marker_begin_calls = 0;
int g_marker_clear_calls = 0;
int g_history_calls = 0;
char g_last_history_result[32] = {};
char g_last_history_reason[32] = {};
char g_last_history_policy_hash[72] = {};
char g_last_highest_action[8] = {};
char g_last_marker_highest_action[8] = {};
size_t g_last_policy_count = 0;
uint64_t g_last_uptime_ms = 0;

constexpr const char* kTestRequestId = "policy-test-request";
constexpr const char* kTestSessionId = "ABCDEFGHIJKLMNOPQRSTUVWXY";

signing::TimeoutWindow test_review_window(TickType_t started_at = 10, TickType_t deadline = 110)
{
    return signing::timeout_window_from_deadline(started_at, deadline);
}

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void reset_stubs()
{
    signing::policy_update_flow_clear();
    g_store_result = signing::PolicyStoreWriteResult::applied;
    g_marker_begin_result = signing::PolicyUpdateMarkerBeginResult::written;
    g_marker_clear_result = true;
    g_digest_result = true;
    g_policy_id_result = true;
    g_history_result = true;
    g_store_calls = 0;
    g_marker_begin_calls = 0;
    g_marker_clear_calls = 0;
    g_history_calls = 0;
    memset(g_last_history_result, 0, sizeof(g_last_history_result));
    memset(g_last_history_reason, 0, sizeof(g_last_history_reason));
    memset(g_last_history_policy_hash, 0, sizeof(g_last_history_policy_hash));
    memset(g_last_highest_action, 0, sizeof(g_last_highest_action));
    memset(g_last_marker_highest_action, 0, sizeof(g_last_marker_highest_action));
    g_last_policy_count = 0;
    g_last_uptime_ms = 0;
}

JsonDocument parse_policy_json()
{
    JsonDocument document;
    const char* json =
        "{"
        "\"schema\":\"signing.policy\","
        "\"defaultAction\":\"reject\","
        "\"blockchains\":[{"
        "\"blockchain\":\"sui\","
        "\"networks\":[{"
        "\"network\":\"testnet\","
        "\"policies\":[]"
        "}]"
        "}]"
        "}";
    const DeserializationError error = deserializeJson(document, json);
    expect(!error, "test policy JSON parses");
    return document;
}

bool begin_valid_policy()
{
    JsonDocument document = parse_policy_json();
    return signing::policy_update_flow_begin(
               document.as<JsonVariantConst>(),
               kTestRequestId,
               kTestSessionId,
               10,
               test_review_window()) ==
           signing::PolicyUpdateFlowBeginResult::ok;
}

bool continue_valid_policy_to_pin()
{
    return signing::policy_update_flow_continue_to_pin(20) ==
           signing::PolicyUpdateFlowTransitionResult::ok;
}

bool mark_valid_policy_pin_verifying()
{
    return signing::policy_update_flow_mark_pin_verifying() ==
           signing::PolicyUpdateFlowTransitionResult::ok;
}

bool begin_valid_policy_ready_to_commit()
{
    return begin_valid_policy() &&
           continue_valid_policy_to_pin() &&
           mark_valid_policy_pin_verifying();
}

JsonDocument parse_sign_policy_json()
{
    JsonDocument document;
    const char* json =
        "{"
        "\"schema\":\"signing.policy\","
        "\"defaultAction\":\"reject\","
        "\"blockchains\":[{"
        "\"blockchain\":\"sui\","
        "\"networks\":[{"
        "\"network\":\"testnet\","
        "\"policies\":[{"
        "\"id\":\"sign-max-one-sui\","
        "\"action\":\"sign\","
        "\"conditions\":["
        "{\"field\":\"sui.token_totals_by_type.amount_raw\",\"where\":{\"type\":\"0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI\"},\"op\":\"lte\",\"value\":\"1000000000\"},"
        "{\"field\":\"sui.token_sources.type\",\"op\":\"in\",\"values\":[\"0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI\"]},"
        "{\"field\":\"sui.gas_budget_raw\",\"op\":\"lte\",\"value\":\"10000000\"}"
        "]"
        "}]"
        "}]"
        "}]"
        "}";
    const DeserializationError error = deserializeJson(document, json);
    expect(!error, "test sign policy JSON parses");
    return document;
}

signing::PolicyUpdateFlowBeginResult begin_sign_policy()
{
    JsonDocument document = parse_sign_policy_json();
    return signing::policy_update_flow_begin(
               document.as<JsonVariantConst>(),
               kTestRequestId,
               kTestSessionId,
               10,
               test_review_window());
}

JsonDocument parse_multi_sign_policy_json()
{
    JsonDocument document;
    const char* json =
        "{"
        "\"schema\":\"signing.policy\","
        "\"defaultAction\":\"reject\","
        "\"blockchains\":[{"
        "\"blockchain\":\"sui\","
        "\"networks\":[{"
        "\"network\":\"testnet\","
        "\"policies\":["
        "{"
        "\"id\":\"sign-one\","
        "\"action\":\"sign\","
        "\"conditions\":["
        "{\"field\":\"sui.move_call_packages\",\"op\":\"contains\",\"value\":\"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}"
        "]"
        "},"
        "{"
        "\"id\":\"sign-two\","
        "\"action\":\"sign\","
        "\"conditions\":["
        "{\"field\":\"sui.move_call_packages\",\"op\":\"contains\",\"value\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}"
        "]"
        "}"
        "]"
        "}]"
        "}]"
        "}";
    const DeserializationError error = deserializeJson(document, json);
    expect(!error, "test multiple sign policy JSON parses");
    return document;
}

}  // namespace

namespace signing {

PolicyStoreWriteResult store_active_policy_record(const uint8_t*, size_t)
{
    ++g_store_calls;
    return g_store_result;
}

bool policy_store_digest_for_record(const uint8_t*, size_t, uint8_t* output, size_t output_size)
{
    if (!g_digest_result || output == nullptr || output_size != kPolicyUpdateDigestBytes) {
        return false;
    }
    memset(output, 0xa5, output_size);
    return true;
}

bool policy_store_policy_id_for_record(const uint8_t*, size_t, char* output, size_t output_size)
{
    if (!g_policy_id_result || output == nullptr || output_size < 72) {
        return false;
    }
    strlcpy(output, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", output_size);
    return true;
}

bool approval_history_append_required_policy_update(
    const PolicyUpdateHistoryAppendInput& input,
    uint64_t uptime_ms)
{
    ++g_history_calls;
    strlcpy(g_last_history_result, input.result != nullptr ? input.result : "", sizeof(g_last_history_result));
    strlcpy(g_last_history_reason, input.reason_code != nullptr ? input.reason_code : "", sizeof(g_last_history_reason));
    strlcpy(g_last_history_policy_hash, input.policy_hash != nullptr ? input.policy_hash : "", sizeof(g_last_history_policy_hash));
    strlcpy(g_last_highest_action, input.highest_action != nullptr ? input.highest_action : "", sizeof(g_last_highest_action));
    g_last_policy_count = input.policy_count;
    g_last_uptime_ms = uptime_ms;
    return g_history_result;
}

PolicyUpdateMarkerBeginResult policy_update_marker_begin(
    const uint8_t* policy_digest,
    size_t policy_digest_size,
    size_t policy_count,
    PolicyUpdateHighestAction highest_action)
{
    ++g_marker_begin_calls;
    if (policy_digest == nullptr ||
        policy_digest_size != kPolicyUpdateDigestBytes ||
        policy_count > signing::kCurrentPolicyMaxTotalPolicies) {
        return PolicyUpdateMarkerBeginResult::invalid_input;
    }
    strlcpy(
        g_last_marker_highest_action,
        highest_action == PolicyUpdateHighestAction::sign ? "sign" : "reject",
        sizeof(g_last_marker_highest_action));
    return g_marker_begin_result;
}

bool policy_update_marker_clear()
{
    ++g_marker_clear_calls;
    return g_marker_clear_result;
}

}  // namespace signing

int main()
{
    reset_stubs();
    expect(begin_valid_policy(), "valid policy begins flow");
    signing::PolicyUpdateFlowSnapshot snapshot = signing::policy_update_flow_snapshot();
    expect(snapshot.active, "snapshot reports active proposal");
    expect(snapshot.stage == signing::PolicyUpdateFlowStage::reviewing,
           "snapshot starts in review stage");
    expect(strcmp(snapshot.request_id, kTestRequestId) == 0, "snapshot exposes request id");
    expect(strcmp(snapshot.session_id, kTestSessionId) == 0, "snapshot exposes session id");
    expect(signing::timeout_window_valid(snapshot.review_window), "snapshot exposes review window");
    expect(strcmp(snapshot.policy_hash, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0,
           "snapshot exposes policy hash");
    expect(snapshot.blockchain_count == 1, "snapshot exposes blockchain count");
    expect(snapshot.network_count == 1, "snapshot exposes network count");
    expect(snapshot.policy_count == 0, "snapshot exposes policy count");
    expect(snapshot.condition_count == 0, "snapshot exposes condition count");
    expect(strcmp(snapshot.highest_action, "reject") == 0, "snapshot exposes highest action");
    expect(strcmp(snapshot.default_action, "reject") == 0, "snapshot exposes default action");
    expect(strcmp(snapshot.scope_summary, "scopes=1/1 policies=0 conditions=0") == 0, "snapshot exposes scope summary");
    expect(strcmp(snapshot.review_summary,
                  "sha256:aaaaaaaa b1 n1 p0 c0 reject->reject\n"
                  "scopes=1/1 policies=0 conditions=0\n"
                  "scope sui\n"
                  "  network testnet\n"
                  "    no policy entries\n") == 0,
           "snapshot exposes scoped empty policy review summary");

    reset_stubs();
    expect(begin_valid_policy(), "begin before transition checks");
    expect(signing::policy_update_flow_commit(50) ==
               signing::PolicyUpdateFlowTerminalResult::invalid_state,
           "commit is unavailable before PIN verification");
    expect(signing::policy_update_flow_continue_to_pin(20) ==
               signing::PolicyUpdateFlowTransitionResult::ok,
           "review continue enters PIN stage");
    snapshot = signing::policy_update_flow_snapshot();
    expect(snapshot.stage == signing::PolicyUpdateFlowStage::pin_entry,
           "snapshot reports PIN entry after continue");
    expect(signing::policy_update_flow_record_rejected(60) ==
               signing::PolicyUpdateFlowTerminalResult::invalid_state,
           "PIN stage cancel is not terminal rejected by flow");
    expect(signing::policy_update_flow_return_to_review(30, test_review_window(30, 130)) ==
               signing::PolicyUpdateFlowTransitionResult::ok,
           "PIN Back returns to review with a new window");
    snapshot = signing::policy_update_flow_snapshot();
    expect(snapshot.stage == signing::PolicyUpdateFlowStage::reviewing &&
               snapshot.review_window.started_at == 30 &&
               snapshot.review_window.deadline == 130,
           "review return stores fresh review window");
    expect(signing::policy_update_flow_continue_to_pin(40) ==
               signing::PolicyUpdateFlowTransitionResult::ok &&
               signing::policy_update_flow_mark_pin_verifying() ==
                   signing::PolicyUpdateFlowTransitionResult::ok,
           "PIN submit enters verifying stage");
    snapshot = signing::policy_update_flow_snapshot();
    expect(snapshot.stage == signing::PolicyUpdateFlowStage::pin_verifying,
           "snapshot reports PIN verifying");
    expect(signing::policy_update_flow_return_to_pin_entry() ==
               signing::PolicyUpdateFlowTransitionResult::ok,
           "wrong PIN returns flow to PIN entry");
    snapshot = signing::policy_update_flow_snapshot();
    expect(snapshot.stage == signing::PolicyUpdateFlowStage::pin_entry,
           "snapshot reports PIN entry after wrong PIN transition");
    expect(signing::policy_update_flow_return_to_review(50, test_review_window(30, 40)) ==
               signing::PolicyUpdateFlowTransitionResult::invalid_deadline,
           "PIN Back rejects stale review window at state owner boundary");
    expect(signing::policy_update_flow_return_to_review(20, test_review_window(30, 130)) ==
               signing::PolicyUpdateFlowTransitionResult::invalid_deadline,
           "PIN Back rejects future review window at state owner boundary");

    reset_stubs();
    {
        JsonDocument document = parse_policy_json();
        expect(signing::policy_update_flow_begin(
                   document.as<JsonVariantConst>(),
                   kTestRequestId,
                   kTestSessionId,
                   25,
                   test_review_window(10, 20)) ==
                   signing::PolicyUpdateFlowBeginResult::invalid_argument,
               "begin rejects stale review window at state owner boundary");
        expect(!signing::policy_update_flow_active(), "stale begin leaves no active proposal");
        expect(signing::policy_update_flow_begin(
                   document.as<JsonVariantConst>(),
                   kTestRequestId,
                   kTestSessionId,
                   5,
                   test_review_window(10, 20)) ==
                   signing::PolicyUpdateFlowBeginResult::invalid_argument,
               "begin rejects future review window at state owner boundary");
        expect(!signing::policy_update_flow_active(), "future begin leaves no active proposal");
        expect(signing::policy_update_flow_begin(
                   document.as<JsonVariantConst>(),
                   kTestRequestId,
                   kTestSessionId,
                   10,
                   test_review_window(10, 20)) ==
                   signing::PolicyUpdateFlowBeginResult::ok,
               "begin before expired review continue");
        expect(signing::policy_update_flow_continue_to_pin(21) ==
                   signing::PolicyUpdateFlowTransitionResult::timed_out,
               "expired review cannot continue to PIN");
        expect(signing::policy_update_flow_record_timed_out(210) ==
                   signing::PolicyUpdateFlowTerminalResult::timed_out,
               "expired review can record timeout terminal");
    }

    reset_stubs();
    expect(begin_valid_policy(), "begin before rejected terminal");
    expect(signing::policy_update_flow_record_rejected(100) ==
               signing::PolicyUpdateFlowTerminalResult::rejected,
           "rejected terminal records history");
    expect(g_history_calls == 1 &&
               strcmp(g_last_history_result, "rejected") == 0 &&
               strcmp(g_last_history_reason, "device_rejected") == 0 &&
               g_last_uptime_ms == 100,
           "rejected terminal history metadata");
    expect(g_marker_begin_calls == 0 && g_store_calls == 0, "rejected terminal does not touch storage");

    reset_stubs();
    expect(begin_valid_policy(), "begin before timeout terminal");
    g_history_result = false;
    expect(signing::policy_update_flow_record_timed_out(200) ==
               signing::PolicyUpdateFlowTerminalResult::history_error,
           "timeout history failure returns history_error");
    expect(!signing::policy_update_flow_active(), "history failure clears volatile proposal");

    reset_stubs();
    expect(begin_valid_policy(), "begin before UI error terminal");
    expect(signing::policy_update_flow_record_ui_error() ==
               signing::PolicyUpdateFlowTerminalResult::ui_error,
           "UI error terminal is distinct from timeout");
    expect(g_history_calls == 0 && g_marker_begin_calls == 0 && g_store_calls == 0,
           "UI error terminal does not write history or storage");

    reset_stubs();
    expect(begin_valid_policy_ready_to_commit(), "begin before applied commit");
    expect(signing::policy_update_flow_commit(300) ==
               signing::PolicyUpdateFlowTerminalResult::applied,
           "applied commit returns applied");
    expect(g_marker_begin_calls == 1 && g_store_calls == 1 && g_history_calls == 1 && g_marker_clear_calls == 1,
           "applied commit uses marker store history clear");
    expect(strcmp(g_last_history_result, "applied") == 0 &&
               strcmp(g_last_history_reason, "device_confirmed") == 0 &&
               strcmp(g_last_highest_action, "reject") == 0 &&
               g_last_policy_count == 0,
           "applied commit history metadata");

    reset_stubs();
    expect(begin_sign_policy() == signing::PolicyUpdateFlowBeginResult::ok,
           "non-empty sign policy begins flow");
    snapshot = signing::policy_update_flow_snapshot();
    expect(snapshot.active, "non-empty sign policy is pending review");
    expect(snapshot.policy_count == 1, "sign policy count");
    expect(snapshot.condition_count == 3, "sign policy condition count");
    expect(strcmp(snapshot.highest_action, "sign") == 0, "sign policy highest action");
    expect(strstr(snapshot.review_summary, "policy sign-max-one-sui sign") != nullptr,
           "sign policy summary includes policy id and action");
    expect(strstr(snapshot.review_summary,
                  "- sui.token_totals_by_type.amount_raw lte where.type=0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI 1000000000") != nullptr,
           "sign policy summary includes type-bound amount condition");
    expect(strstr(snapshot.review_summary, "- sui.token_sources.type in [0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI]") != nullptr,
           "sign policy summary includes token type condition");
    expect(strstr(snapshot.review_summary, "- sui.gas_budget_raw lte 10000000") != nullptr,
           "sign policy summary includes gas condition");
    expect(signing::policy_update_flow_continue_to_pin(20) ==
               signing::PolicyUpdateFlowTransitionResult::ok &&
               signing::policy_update_flow_mark_pin_verifying() ==
                   signing::PolicyUpdateFlowTransitionResult::ok,
           "sign policy reaches commit stage");
    expect(signing::policy_update_flow_commit(900) ==
               signing::PolicyUpdateFlowTerminalResult::applied,
           "sign policy commit applies");
    expect(strcmp(g_last_history_result, "applied") == 0 &&
               strcmp(g_last_history_reason, "device_confirmed") == 0 &&
               strcmp(g_last_highest_action, "sign") == 0 &&
               g_last_policy_count == 1 &&
               strcmp(g_last_marker_highest_action, "sign") == 0,
           "sign policy commit history and marker metadata");

    reset_stubs();
    {
        JsonDocument multi_sign = parse_multi_sign_policy_json();
        expect(signing::policy_update_flow_begin(
                   multi_sign.as<JsonVariantConst>(),
                   kTestRequestId,
                   kTestSessionId,
                   10,
                   test_review_window()) ==
               signing::PolicyUpdateFlowBeginResult::ok,
               "multiple current policies begin review");
        snapshot = signing::policy_update_flow_snapshot();
        expect(snapshot.active, "multiple current policies leave an active proposal");
        expect(snapshot.policy_count == 2, "multiple current policy count");
        expect(snapshot.condition_count == 2, "multiple current condition count");
        expect(strstr(snapshot.review_summary, "policy sign-one sign") != nullptr,
               "multi-policy summary includes first policy");
        expect(strstr(snapshot.review_summary, "policy sign-two sign") != nullptr,
               "multi-policy summary includes second policy");
    }

    reset_stubs();
    expect(begin_valid_policy_ready_to_commit(), "begin before unchanged failure commit");
    g_store_result = signing::PolicyStoreWriteResult::unchanged_failure;
    expect(signing::policy_update_flow_commit(400) ==
               signing::PolicyUpdateFlowTerminalResult::storage_error,
           "unchanged store failure returns storage_error");
    expect(strcmp(g_last_history_result, "storage_error") == 0 &&
               strcmp(g_last_history_reason, "storage_error") == 0 &&
               g_marker_clear_calls == 1,
           "storage_error terminal records history and clears marker");

    reset_stubs();
    expect(begin_valid_policy_ready_to_commit(), "begin before store consistency error");
    g_store_result = signing::PolicyStoreWriteResult::consistency_error;
    expect(signing::policy_update_flow_commit(500) ==
               signing::PolicyUpdateFlowTerminalResult::consistency_error,
           "store consistency propagates consistency_error");
    expect(g_history_calls == 0, "consistency error is not stored as history result");

    reset_stubs();
    expect(begin_valid_policy_ready_to_commit(), "begin before marker storage failure");
    g_marker_begin_result = signing::PolicyUpdateMarkerBeginResult::storage_error;
    expect(signing::policy_update_flow_commit(600) ==
               signing::PolicyUpdateFlowTerminalResult::storage_error,
           "pre-commit marker storage failure returns storage_error");
    expect(g_store_calls == 0 &&
               g_marker_clear_calls == 0 &&
               strcmp(g_last_history_result, "storage_error") == 0,
           "marker storage failure does not store policy");

    reset_stubs();
    expect(begin_valid_policy_ready_to_commit(), "begin before marker pending after error");
    g_marker_begin_result = signing::PolicyUpdateMarkerBeginResult::pending_after_error;
    expect(signing::policy_update_flow_commit(700) ==
               signing::PolicyUpdateFlowTerminalResult::consistency_error,
           "ambiguous marker begin returns consistency_error");
    expect(g_store_calls == 0 && g_history_calls == 0, "ambiguous marker begin is not recorded as durable history");

    reset_stubs();
    expect(begin_valid_policy_ready_to_commit(), "begin before applied history failure");
    g_history_result = false;
    expect(signing::policy_update_flow_commit(800) ==
               signing::PolicyUpdateFlowTerminalResult::consistency_error,
           "post-commit applied history failure becomes consistency_error");
    expect(g_marker_clear_calls == 0, "post-commit history failure leaves terminal marker for fail-closed state");

    reset_stubs();
    JsonDocument invalid;
    deserializeJson(invalid, "{\"schema\":\"bad\",\"defaultAction\":\"reject\",\"blockchains\":[]}");
    expect(signing::policy_update_flow_begin(
               invalid.as<JsonVariantConst>(),
               kTestRequestId,
               kTestSessionId,
               10,
               test_review_window()) ==
               signing::PolicyUpdateFlowBeginResult::invalid_policy,
           "invalid policy is rejected before flow activation");
    expect(!signing::policy_update_flow_active(), "invalid policy leaves no active proposal");

    reset_stubs();
    JsonDocument valid_but_undigestable = parse_policy_json();
    g_policy_id_result = false;
    expect(signing::policy_update_flow_begin(
               valid_but_undigestable.as<JsonVariantConst>(),
               kTestRequestId,
               kTestSessionId,
               10,
               test_review_window()) ==
               signing::PolicyUpdateFlowBeginResult::encode_error,
           "canonical digest/id failure is reported as encode_error");
    expect(!signing::policy_update_flow_active(), "encode error leaves no active proposal");

    if (failures != 0) {
        fprintf(stderr, "%d policy update flow test(s) failed\n", failures);
        return 1;
    }
    printf("Policy update flow tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${TARGET_ROOT}/runtime" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_POLICY_DIR}" \
  -I"${COMMON_SUI_DIR}" \
  "${TMP_DIR}/policy_update_flow_test.cpp" \
  "${REPO_ROOT}/firmware/src/common/policy/policy_update_flow.cpp" \
  "${REPO_ROOT}/firmware/src/common/policy/policy_proposal_parser.cpp" \
  "${COMMON_POLICY_DIR}/document.cpp" \
  -o "${TMP_DIR}/policy_update_flow_test"

"${TMP_DIR}/policy_update_flow_test"
