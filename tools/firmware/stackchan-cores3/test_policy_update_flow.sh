#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_policy_update_flow.sh

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
TARGET_ROOT="${REPO_ROOT}/products/firmware/src/stackchan-cores3"
COMMON_ROOT="${REPO_ROOT}/products/firmware/src/common/agent_q"
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_update_flow.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_update_flow.h" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_proposal_parser.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_proposal_parser.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_canonical.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_canonical.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.h" \
  "${COMMON_SUI_DIR}/agent_q_sui_method_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_method_adapter.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-policy-update-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_POLICY_DIR}" "${TMP_DIR}/agent_q_common/policy"
ln -s "${COMMON_SUI_DIR}" "${TMP_DIR}/agent_q_common/sui"

cat >"${TMP_DIR}/policy_update_flow_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ArduinoJson.h>

#include "agent_q_approval_history.h"
#include "agent_q_policy_store.h"
#include "agent_q_policy_update_flow.h"
#include "agent_q_policy_update_marker.h"

namespace {

int failures = 0;

agent_q::AgentQPolicyStoreWriteResult g_store_result =
    agent_q::AgentQPolicyStoreWriteResult::applied;
agent_q::AgentQPolicyUpdateMarkerBeginResult g_marker_begin_result =
    agent_q::AgentQPolicyUpdateMarkerBeginResult::written;
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
size_t g_last_rule_count = 0;
uint64_t g_last_uptime_ms = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void reset_stubs()
{
    agent_q::policy_update_flow_clear();
    g_store_result = agent_q::AgentQPolicyStoreWriteResult::applied;
    g_marker_begin_result = agent_q::AgentQPolicyUpdateMarkerBeginResult::written;
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
    g_last_rule_count = 0;
    g_last_uptime_ms = 0;
}

JsonDocument parse_policy_json()
{
    JsonDocument document;
    const char* json =
        "{"
        "\"schema\":\"agentq.policy.v0\","
        "\"defaultAction\":\"reject\","
        "\"rules\":[{"
        "\"id\":\"reject_devnet\","
        "\"chain\":\"sui\","
        "\"method\":\"sign_transaction\","
        "\"action\":\"reject\","
        "\"criteria\":[{\"field\":\"common.network\",\"op\":\"eq\",\"value\":\"devnet\"}]"
        "}]"
        "}";
    const DeserializationError error = deserializeJson(document, json);
    expect(!error, "test policy JSON parses");
    return document;
}

bool begin_valid_policy()
{
    JsonDocument document = parse_policy_json();
    return agent_q::policy_update_flow_begin(document.as<JsonVariantConst>()) ==
           agent_q::AgentQPolicyUpdateFlowBeginResult::ok;
}

}  // namespace

namespace agent_q {

AgentQPolicyStoreWriteResult store_active_policy_record(const uint8_t*, size_t)
{
    ++g_store_calls;
    return g_store_result;
}

bool policy_store_digest_for_record(const uint8_t*, size_t, uint8_t* output, size_t output_size)
{
    if (!g_digest_result || output == nullptr || output_size != kAgentQPolicyUpdateDigestBytes) {
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
    const AgentQPolicyUpdateHistoryAppendInput& input,
    uint64_t uptime_ms)
{
    ++g_history_calls;
    strlcpy(g_last_history_result, input.result != nullptr ? input.result : "", sizeof(g_last_history_result));
    strlcpy(g_last_history_reason, input.reason_code != nullptr ? input.reason_code : "", sizeof(g_last_history_reason));
    strlcpy(g_last_history_policy_hash, input.policy_hash != nullptr ? input.policy_hash : "", sizeof(g_last_history_policy_hash));
    strlcpy(g_last_highest_action, input.highest_action != nullptr ? input.highest_action : "", sizeof(g_last_highest_action));
    g_last_rule_count = input.rule_count;
    g_last_uptime_ms = uptime_ms;
    return g_history_result;
}

AgentQPolicyUpdateMarkerBeginResult policy_update_marker_begin(
    const uint8_t* policy_digest,
    size_t policy_digest_size,
    size_t rule_count,
    AgentQPolicyUpdateHighestAction highest_action)
{
    ++g_marker_begin_calls;
    if (policy_digest == nullptr ||
        policy_digest_size != kAgentQPolicyUpdateDigestBytes ||
        rule_count != 1 ||
        highest_action != AgentQPolicyUpdateHighestAction::reject) {
        return AgentQPolicyUpdateMarkerBeginResult::invalid_input;
    }
    return g_marker_begin_result;
}

bool policy_update_marker_clear()
{
    ++g_marker_clear_calls;
    return g_marker_clear_result;
}

}  // namespace agent_q

int main()
{
    reset_stubs();
    expect(begin_valid_policy(), "valid policy begins flow");
    agent_q::AgentQPolicyUpdateFlowSnapshot snapshot = agent_q::policy_update_flow_snapshot();
    expect(snapshot.active, "snapshot reports active proposal");
    expect(strcmp(snapshot.policy_hash, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0,
           "snapshot exposes policy hash");
    expect(snapshot.rule_count == 1, "snapshot exposes rule count");
    expect(strcmp(snapshot.highest_action, "reject") == 0, "snapshot exposes highest action");
    expect(strcmp(snapshot.default_action, "reject") == 0, "snapshot exposes default action");
    expect(strcmp(snapshot.method_summary, "sui/sign_transaction") == 0, "snapshot exposes method summary");

    reset_stubs();
    expect(begin_valid_policy(), "begin before rejected terminal");
    expect(agent_q::policy_update_flow_record_rejected(100) ==
               agent_q::AgentQPolicyUpdateFlowTerminalResult::rejected,
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
    expect(agent_q::policy_update_flow_record_timed_out(200) ==
               agent_q::AgentQPolicyUpdateFlowTerminalResult::history_error,
           "timeout history failure returns history_error");
    expect(!agent_q::policy_update_flow_active(), "history failure clears volatile proposal");

    reset_stubs();
    expect(begin_valid_policy(), "begin before UI error terminal");
    expect(agent_q::policy_update_flow_record_ui_error() ==
               agent_q::AgentQPolicyUpdateFlowTerminalResult::ui_error,
           "UI error terminal is distinct from timeout");
    expect(g_history_calls == 0 && g_marker_begin_calls == 0 && g_store_calls == 0,
           "UI error terminal does not write history or storage");

    reset_stubs();
    expect(begin_valid_policy(), "begin before applied commit");
    expect(agent_q::policy_update_flow_commit(300) ==
               agent_q::AgentQPolicyUpdateFlowTerminalResult::applied,
           "applied commit returns applied");
    expect(g_marker_begin_calls == 1 && g_store_calls == 1 && g_history_calls == 1 && g_marker_clear_calls == 1,
           "applied commit uses marker store history clear");
    expect(strcmp(g_last_history_result, "applied") == 0 &&
               strcmp(g_last_history_reason, "device_confirmed") == 0 &&
               strcmp(g_last_highest_action, "reject") == 0 &&
               g_last_rule_count == 1,
           "applied commit history metadata");

    reset_stubs();
    expect(begin_valid_policy(), "begin before unchanged failure commit");
    g_store_result = agent_q::AgentQPolicyStoreWriteResult::unchanged_failure;
    expect(agent_q::policy_update_flow_commit(400) ==
               agent_q::AgentQPolicyUpdateFlowTerminalResult::storage_error,
           "unchanged store failure returns storage_error");
    expect(strcmp(g_last_history_result, "storage_error") == 0 &&
               strcmp(g_last_history_reason, "storage_error") == 0 &&
               g_marker_clear_calls == 1,
           "storage_error terminal records history and clears marker");

    reset_stubs();
    expect(begin_valid_policy(), "begin before store consistency error");
    g_store_result = agent_q::AgentQPolicyStoreWriteResult::consistency_error;
    expect(agent_q::policy_update_flow_commit(500) ==
               agent_q::AgentQPolicyUpdateFlowTerminalResult::consistency_error,
           "store consistency propagates consistency_error");
    expect(g_history_calls == 0, "consistency error is not stored as history result");

    reset_stubs();
    expect(begin_valid_policy(), "begin before marker storage failure");
    g_marker_begin_result = agent_q::AgentQPolicyUpdateMarkerBeginResult::storage_error;
    expect(agent_q::policy_update_flow_commit(600) ==
               agent_q::AgentQPolicyUpdateFlowTerminalResult::storage_error,
           "pre-commit marker storage failure returns storage_error");
    expect(g_store_calls == 0 &&
               g_marker_clear_calls == 0 &&
               strcmp(g_last_history_result, "storage_error") == 0,
           "marker storage failure does not store policy");

    reset_stubs();
    expect(begin_valid_policy(), "begin before marker pending after error");
    g_marker_begin_result = agent_q::AgentQPolicyUpdateMarkerBeginResult::pending_after_error;
    expect(agent_q::policy_update_flow_commit(700) ==
               agent_q::AgentQPolicyUpdateFlowTerminalResult::consistency_error,
           "ambiguous marker begin returns consistency_error");
    expect(g_store_calls == 0 && g_history_calls == 0, "ambiguous marker begin is not recorded as durable history");

    reset_stubs();
    expect(begin_valid_policy(), "begin before applied history failure");
    g_history_result = false;
    expect(agent_q::policy_update_flow_commit(800) ==
               agent_q::AgentQPolicyUpdateFlowTerminalResult::consistency_error,
           "post-commit applied history failure becomes consistency_error");
    expect(g_marker_clear_calls == 0, "post-commit history failure leaves terminal marker for fail-closed state");

    reset_stubs();
    JsonDocument invalid;
    deserializeJson(invalid, "{\"schema\":\"bad\",\"defaultAction\":\"reject\",\"rules\":[]}");
    expect(agent_q::policy_update_flow_begin(invalid.as<JsonVariantConst>()) ==
               agent_q::AgentQPolicyUpdateFlowBeginResult::invalid_policy,
           "invalid policy is rejected before flow activation");
    expect(!agent_q::policy_update_flow_active(), "invalid policy leaves no active proposal");

    reset_stubs();
    JsonDocument valid_but_undigestable = parse_policy_json();
    g_policy_id_result = false;
    expect(agent_q::policy_update_flow_begin(valid_but_undigestable.as<JsonVariantConst>()) ==
               agent_q::AgentQPolicyUpdateFlowBeginResult::encode_error,
           "canonical digest/id failure is reported as encode_error");
    expect(!agent_q::policy_update_flow_active(), "encode error leaves no active proposal");

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
  -I"${TARGET_ROOT}/agent_q" \
  -I"${COMMON_POLICY_DIR}" \
  -I"${COMMON_SUI_DIR}" \
  "${TMP_DIR}/policy_update_flow_test.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_update_flow.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_proposal_parser.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_canonical.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_method_adapter.cpp" \
  -o "${TMP_DIR}/policy_update_flow_test"

"${TMP_DIR}/policy_update_flow_test"
