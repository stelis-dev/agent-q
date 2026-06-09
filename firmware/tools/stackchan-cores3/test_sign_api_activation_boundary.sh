#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sign_api_activation_boundary.sh

Checks the Sign API activation boundary:
Firmware USB and Agent-Q core expose public sign_transaction and
sign_personal_message requests. Firmware reads local signing mode and enters
the supported policy or user authorization branch without host-selectable
authorization request types. Provider-sui and Agent-Q MCP expose the same
signing method names and must not expose host-selectable authorization APIs.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
USB_SERVER="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_request_server.cpp"
SIGNING_PREFLIGHT_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_signing_preflight.cpp"
POLICY_SIGNING_EXECUTION_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_policy_signing_execution.cpp"
USER_REVIEW_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_user_signing_review_view_model.cpp"
USER_SIGNING_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_user_signing_critical_section.cpp"
USER_FLOW_HEADER="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_user_signing_flow.h"
USER_SIGNING_HEADER="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_user_signing_critical_section.h"
SIGN_TRANSACTION_INGRESS_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_sign_transaction_user_ingress.cpp"
SIGN_PERSONAL_MESSAGE_INGRESS_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_sign_personal_message_user_ingress.cpp"
MCP_SOURCE="${REPO_ROOT}/packages/agent-q/src/mcp.ts"
PROVIDER_SOURCE="${REPO_ROOT}/packages/provider-sui/src/provider-sui.ts"
CORE_SOURCE="${REPO_ROOT}/packages/core/src"

failures=0
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sign-api-boundary.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

expect_absent() {
  local file="$1"
  local pattern="$2"
  local label="$3"
  local matches="${TMP_DIR}/matches"

  if grep -En "${pattern}" "${file}" >"${matches}"; then
    echo "FAILED: ${label}" >&2
    cat "${matches}" >&2
    failures=$((failures + 1))
  fi
  rm -f "${matches}"
}

expect_present() {
  local file="$1"
  local pattern="$2"
  local label="$3"

  if ! grep -Eq "${pattern}" "${file}"; then
    echo "FAILED: ${label}" >&2
    failures=$((failures + 1))
  fi
}

expect_order() {
  local file="$1"
  local first_pattern="$2"
  local second_pattern="$3"
  local label="$4"
  local first_line
  local second_line

  first_line="$(grep -En "${first_pattern}" "${file}" | head -n 1 | cut -d: -f1 || true)"
  second_line="$(grep -En "${second_pattern}" "${file}" | head -n 1 | cut -d: -f1 || true)"

  if [[ -z "${first_line}" || -z "${second_line}" || ${first_line} -ge ${second_line} ]]; then
    echo "FAILED: ${label}" >&2
    failures=$((failures + 1))
  fi
}

expect_tree_absent() {
  local dir="$1"
  local pattern="$2"
  local label="$3"
  local matches="${TMP_DIR}/tree-matches"

  while IFS= read -r source_file; do
    grep -En "${pattern}" "${source_file}" >>"${matches}" || true
  done < <(find "${dir}" -type f \( -name '*.ts' -o -name '*.mjs' -o -name '*.sh' -o -name '*.cpp' -o -name '*.h' \))

  if [[ -s "${matches}" ]]; then
    echo "FAILED: ${label}" >&2
    cat "${matches}" >&2
    failures=$((failures + 1))
  fi
  rm -f "${matches}"
}

expect_tree_present() {
  local dir="$1"
  local pattern="$2"
  local label="$3"
  local matches="${TMP_DIR}/tree-present"

  while IFS= read -r source_file; do
    grep -En "${pattern}" "${source_file}" >>"${matches}" || true
  done < <(find "${dir}" -type f \( -name '*.ts' -o -name '*.mts' -o -name '*.cts' \))

  if [[ ! -s "${matches}" ]]; then
    echo "FAILED: ${label}" >&2
    failures=$((failures + 1))
  fi
  rm -f "${matches}"
}

expect_present "${USB_SERVER}" '"sign_transaction"' \
  "USB request server must accept public sign_transaction messages"
expect_absent "${USB_SERVER}" '"sign_transaction_user"|"sign_transaction_policy"' \
  "USB request server must not accept host-selected authorization request types"
expect_present "${USB_SERVER}" '"sign_result"|write_sign_result' \
  "USB request server must write public sign_result responses"
expect_present "${USB_SERVER}" '"signing"' \
  "USB request server must advertise shared signing capabilities"
expect_present "${USB_SERVER}" 'user_signing_(flow|confirmation)|user_signing_execute_critical_section' \
  "USB request server must call user-confirmed authorization state owners"
expect_present "${USB_SERVER}" 'evaluate_sign_transaction_policy' \
  "USB request server must call policy authorization runtime"
expect_present "${USB_SERVER}" 'execute_policy_sign_transaction' \
  "USB request server must delegate policy signing execution to the execution owner"
expect_present "${POLICY_SIGNING_EXECUTION_SOURCE}" 'write_policy_signing_confirmation_history' \
  "policy signing execution owner must own policy confirmation history writes"
expect_present "${POLICY_SIGNING_EXECUTION_SOURCE}" 'sign_sui_ed25519_transaction_from_stored_root' \
  "policy signing execution owner must own policy signing critical section"
expect_absent "${USB_SERVER}" 'write_policy_signing_confirmation_history|write_policy_signing_terminal_history|sign_sui_ed25519_transaction_from_stored_root' \
  "USB request server must not assemble policy signing history/signing directly"
expect_present "${USB_SERVER}" 'read_signing_authorization_mode' \
  "USB request server must read Firmware-local signing authorization mode"
expect_present "${USB_SERVER}" 'user_signing_flow_begin' \
  "USB request server user branch must enter user-confirmed flow"

SIGN_TRANSACTION_BRANCH_SNIPPET="${TMP_DIR}/sign-transaction-branch.cpp"
SIGN_TRANSACTION_PREFLIGHT_SNIPPET="${TMP_DIR}/sign-transaction-preflight.cpp"
awk '
  /AgentQSigningPreflightResult evaluate_sign_transaction_preflight/ { capture = 1 }
  capture { print }
  /AgentQSigningPreflightResult evaluate_sign_personal_message_preflight/ { capture = 0 }
' "${SIGNING_PREFLIGHT_SOURCE}" >"${SIGN_TRANSACTION_PREFLIGHT_SNIPPET}"
awk '
  /if \(strcmp\(type, "sign_transaction"\) == 0\)/ { capture = 1 }
  capture { print }
  /ESP_LOGI\(kTag, "sign_transaction waiting for device review/ { capture = 0 }
' "${USB_SERVER}" >"${SIGN_TRANSACTION_BRANCH_SNIPPET}"
expect_present "${SIGN_TRANSACTION_BRANCH_SNIPPET}" 'read_signing_mode_for_preflight' \
  "USB request server sign_transaction branch snippet must be captured"
expect_present "${SIGN_TRANSACTION_BRANCH_SNIPPET}" 'evaluate_sign_transaction_preflight' \
  "sign_transaction branch must delegate signing preflight to the extracted helper"
expect_order "${SIGN_TRANSACTION_BRANCH_SNIPPET}" 'evaluate_sign_transaction_preflight' 'handle_sign_transaction_policy_mode' \
  "sign_transaction policy authorization must consume prepared Sui transaction data"
expect_order "${SIGN_TRANSACTION_BRANCH_SNIPPET}" 'evaluate_sign_transaction_preflight' 'user_signing_flow_begin' \
  "sign_transaction user authorization must consume prepared Sui transaction data"
expect_order "${SIGN_TRANSACTION_PREFLIGHT_SNIPPET}" 'classify_sign_route\(AgentQSignOperation::sign_transaction' 'evaluate_sign_transaction_user_ingress' \
  "sign_transaction preflight must identify the route before state/session work"
expect_order "${SIGN_TRANSACTION_PREFLIGHT_SNIPPET}" 'evaluate_sign_transaction_user_ingress' 'sign_request_identity' \
  "sign_transaction preflight must complete before request identity"
expect_order "${SIGN_TRANSACTION_PREFLIGHT_SNIPPET}" 'sign_request_identity' 'retry_allows_preflight_to_continue' \
  "sign_transaction must bind request identity before stored-result replay"
expect_order "${SIGN_TRANSACTION_PREFLIGHT_SNIPPET}" 'retry_allows_preflight_to_continue' 'read_signing_mode' \
  "sign_transaction replay must complete before reading signing mode"
expect_order "${SIGN_TRANSACTION_PREFLIGHT_SNIPPET}" 'retry_allows_preflight_to_continue' 'prepare_sui_sign_transaction' \
  "sign_transaction replay must complete before Sui adapter preparation"
expect_order "${SIGN_TRANSACTION_INGRESS_SOURCE}" 'if \(!state\.material_ready\)' 'validate_sign_transaction_user_session_format' \
  "sign_transaction preflight must check state before session format"
expect_order "${SIGN_TRANSACTION_INGRESS_SOURCE}" 'validate_sign_transaction_user_session_format' 'validate_sign_transaction_user_envelope' \
  "sign_transaction preflight must check session before exact envelope"
expect_order "${SIGN_TRANSACTION_INGRESS_SOURCE}" 'validate_sign_transaction_user_envelope' 'validate_sign_transaction_user_params' \
  "sign_transaction preflight must exact-check the request before shallow params"

SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET="${TMP_DIR}/sign-personal-message-branch.cpp"
SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET="${TMP_DIR}/sign-personal-message-preflight.cpp"
awk '
  /AgentQSigningPreflightResult evaluate_sign_personal_message_preflight/ { capture = 1 }
  capture { print }
  /^\}  \/\/ namespace agent_q/ { capture = 0 }
' "${SIGNING_PREFLIGHT_SOURCE}" >"${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}"
awk '
  /if \(strcmp\(type, "sign_personal_message"\) == 0\)/ { capture = 1 }
  capture { print }
  /show_user_signing_review\(\)/ { capture = 0 }
' "${USB_SERVER}" >"${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}"
expect_present "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'read_signing_mode_for_preflight' \
  "USB request server sign_personal_message branch snippet must be captured"
expect_present "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'evaluate_sign_personal_message_preflight' \
  "sign_personal_message branch must delegate signing preflight to the extracted helper"
expect_order "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'evaluate_sign_personal_message_preflight' 'user_signing_flow_begin_personal_message' \
  "sign_personal_message user authorization must consume prepared Sui message data"
expect_order "${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}" 'classify_sign_route\(AgentQSignOperation::sign_personal_message' 'evaluate_sign_personal_message_user_ingress' \
  "sign_personal_message must identify the route before state/session work"
expect_order "${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}" 'evaluate_sign_personal_message_user_ingress' 'sign_request_identity' \
  "sign_personal_message preflight must complete before request identity"
expect_order "${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}" 'sign_request_identity' 'retry_allows_preflight_to_continue' \
  "sign_personal_message must bind request identity before stored-result replay"
expect_order "${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}" 'retry_allows_preflight_to_continue' 'read_signing_mode' \
  "sign_personal_message replay must complete before reading signing mode"
expect_order "${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}" 'retry_allows_preflight_to_continue' 'prepare_sui_sign_personal_message' \
  "sign_personal_message replay must complete before Sui adapter preparation"
expect_order "${SIGN_PERSONAL_MESSAGE_INGRESS_SOURCE}" 'if \(!state\.material_ready\)' 'validate_sign_personal_message_user_session_format' \
  "sign_personal_message preflight must check state before session format"
expect_order "${SIGN_PERSONAL_MESSAGE_INGRESS_SOURCE}" 'validate_sign_personal_message_user_session_format' 'validate_sign_personal_message_user_envelope' \
  "sign_personal_message preflight must check session before exact envelope"
expect_order "${SIGN_PERSONAL_MESSAGE_INGRESS_SOURCE}" 'validate_sign_personal_message_user_envelope' 'validate_sign_personal_message_user_params' \
  "sign_personal_message preflight must exact-check the request before shallow params"
expect_present "${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}" 'AgentQSigningAuthorizationMode::policy' \
  "sign_personal_message branch must explicitly handle policy mode"
expect_present "${USB_SERVER}" 'sign_personal_message is not available in policy authorization mode' \
  "sign_personal_message policy mode must fail closed as unsupported"
expect_present "${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}" 'evaluate_sign_personal_message_user_ingress' \
  "sign_personal_message user mode must use the method-specific ingress owner"
expect_absent "${USB_SERVER}" 'decode_sign_personal_message_request' \
  "USB request server must not inline-decode sign_personal_message params"
expect_present "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'user_signing_flow_begin_personal_message' \
  "sign_personal_message user mode must enter the user-confirmed flow owner"

expect_present "${USER_FLOW_HEADER}" 'AgentQSigningMethod signing_method' \
  "user signing flow snapshot must carry verified signing method identity"
expect_present "${USER_SIGNING_HEADER}" 'AgentQSigningMethod signing_method' \
  "user signing output must carry verified signing method identity"
expect_present "${USER_REVIEW_SOURCE}" 'snapshot\.signing_method' \
  "clear-signing review must branch on verified signing method identity"
expect_absent "${USER_REVIEW_SOURCE}" 'strcmp\(snapshot\.method' \
  "clear-signing review must not branch on raw snapshot method strings"
expect_absent "${USER_REVIEW_SOURCE}" 'classify_signing_method' \
  "clear-signing review must not reclassify raw method strings"
expect_present "${USER_SIGNING_SOURCE}" 'snapshot\.signing_method' \
  "signing critical section must branch on verified signing method identity"
expect_absent "${USER_SIGNING_SOURCE}" 'strcmp\(snapshot\.method' \
  "signing critical section must not branch on raw snapshot method strings"
expect_absent "${USER_SIGNING_SOURCE}" 'classify_signing_method' \
  "signing critical section must not reclassify raw method strings"
expect_absent "${USB_SERVER}" 'classify_signing_method' \
  "sign_result writer must not reclassify raw method strings"
expect_absent "${POLICY_SIGNING_EXECUTION_SOURCE}" 'classify_sui_sign_transaction|base64_to_bytes|approval_history_digest_payload' \
  "policy signing execution must consume prepared signing data, not re-prepare transaction bytes"
expect_absent "${USER_SIGNING_SOURCE}" 'classify_sui_sign_transaction|base64_to_bytes|approval_history_digest_payload|derive_sui_ed25519_account_from_stored_root' \
  "user signing critical section must consume prepared signing data, not re-prepare payloads"

USER_BRANCH_SNIPPET="${TMP_DIR}/sign-transaction-user-branch.cpp"
awk '
  /evaluate_sign_transaction_preflight/ { capture = 1 }
  capture { print }
  /show_user_signing_review\(\)/ { capture = 0 }
' "${USB_SERVER}" >"${USER_BRANCH_SNIPPET}"
expect_present "${USER_BRANCH_SNIPPET}" 'user_signing_flow_begin' \
  "USB request server user branch snippet must be captured"
expect_absent "${USER_BRANCH_SNIPPET}" 'evaluate_sign_transaction_policy|write_policy_signing_confirmation_history' \
  "USB request server user branch must not apply or record policy authorization"

for request_name in \
  get_status \
  identify_device \
  connect \
  disconnect \
  get_capabilities \
  get_accounts \
  policy_get \
  get_approval_history \
  policy_propose; do
  expect_present "${USB_SERVER}" "${request_name} request contains unsupported fields" \
    "USB request server must exact-check ${request_name} top-level request fields"
done

expect_tree_present "${CORE_SOURCE}" 'signTransaction|sign_transaction|sign_result' \
  "Agent-Q core source must expose the Sign API"
expect_tree_present "${CORE_SOURCE}" 'signPersonalMessage|sign_personal_message|messageBytes' \
  "Agent-Q core source must expose Sui personal-message signing"
expect_present "${PROVIDER_SOURCE}" 'signTransaction' \
  "Provider must expose signTransaction"
expect_present "${PROVIDER_SOURCE}" 'signPersonalMessage' \
  "Provider must expose signPersonalMessage"
expect_absent "${PROVIDER_SOURCE}" 'signByUser|signByPolicy|policyPropose' \
  "Provider must not expose host-selected authorization or Admin policy update"
expect_present "${MCP_SOURCE}" '"sign_transaction"' \
  "MCP must expose sign_transaction"
expect_present "${MCP_SOURCE}" '"sign_personal_message"' \
  "MCP must expose sign_personal_message"
expect_present "${MCP_SOURCE}" '"policy_propose"' \
  "MCP must expose top-level policy_propose"
expect_absent "${MCP_SOURCE}" 'signByUser|signByPolicy|"sign_transaction_user"|"sign_transaction_policy"' \
  "MCP source must not expose host-selected authorization request types"

for source_dir in \
  "${REPO_ROOT}/packages/core/src" \
  "${REPO_ROOT}/packages/provider-sui/src" \
  "${REPO_ROOT}/packages/agent-q/src" \
  "${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q" \
  "${REPO_ROOT}/firmware/src/common/agent_q"; do
  expect_tree_absent "${source_dir}" 'common\.network' \
    "Production source must not retain Sui network policy facts"
done

while IFS= read -r source_file; do
  expect_absent "${source_file}" 'approvalTimeoutMs|durationMs|timeoutMs' \
    "Production signing source must not accept caller-controlled timing fields"
done < <(find "${REPO_ROOT}/packages/core/src" "${REPO_ROOT}/packages/provider-sui/src" "${REPO_ROOT}/packages/agent-q/src" -type f \( -name '*.ts' -o -name '*.mts' -o -name '*.cts' \))

if [[ ${failures} -ne 0 ]]; then
  echo "${failures} Sign API activation boundary check(s) failed" >&2
  exit 1
fi

echo "Sign API activation boundary checks passed"
