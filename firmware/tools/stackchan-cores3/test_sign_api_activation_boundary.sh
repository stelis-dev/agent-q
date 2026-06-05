#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sign_api_activation_boundary.sh

Checks the Sign API activation boundary:
Firmware USB and Gateway client expose public sign_transaction and
sign_personal_message requests. Firmware reads local signing mode and enters
the supported policy or user authorization branch without host-selectable
authorization request types. Provider-sui and MCP expose the same signing
method names and must not expose host-selectable authorization APIs.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
USB_SERVER="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_request_server.cpp"
USER_REVIEW_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_user_signing_review_view_model.cpp"
USER_SIGNING_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_user_signing_critical_section.cpp"
USER_FLOW_HEADER="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_user_signing_flow.h"
USER_SIGNING_HEADER="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_user_signing_critical_section.h"
MCP_SOURCE="${REPO_ROOT}/packages/mcp/src/mcp.ts"
PROVIDER_SOURCE="${REPO_ROOT}/packages/provider-sui/src/provider-sui.ts"
CLIENT_SOURCE="${REPO_ROOT}/packages/client/src"

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
expect_present "${USB_SERVER}" 'read_signing_authorization_mode' \
  "USB request server must read Firmware-local signing authorization mode"
expect_present "${USB_SERVER}" 'user_signing_flow_begin' \
  "USB request server user branch must enter user-confirmed flow"

SIGN_TRANSACTION_BRANCH_SNIPPET="${TMP_DIR}/sign-transaction-branch.cpp"
awk '
  /if \(strcmp\(type, "sign_transaction"\) == 0\)/ { capture = 1 }
  capture { print }
  /ESP_LOGI\(kTag, "sign_transaction waiting for device review/ { capture = 0 }
' "${USB_SERVER}" >"${SIGN_TRANSACTION_BRANCH_SNIPPET}"
expect_present "${SIGN_TRANSACTION_BRANCH_SNIPPET}" 'read_signing_authorization_mode' \
  "USB request server sign_transaction branch snippet must be captured"
expect_order "${SIGN_TRANSACTION_BRANCH_SNIPPET}" 'provisioned_material_ready\(\)' 'read_signing_authorization_mode' \
  "USB request server must check material state before reading signing mode"
expect_order "${SIGN_TRANSACTION_BRANCH_SNIPPET}" 'write_busy_if_pending_or_local_flow_active' 'read_signing_authorization_mode' \
  "USB request server must check busy state before reading signing mode"
expect_order "${SIGN_TRANSACTION_BRANCH_SNIPPET}" 'require_active_matching_session' 'read_signing_authorization_mode' \
  "USB request server must check active session before reading signing mode"

SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET="${TMP_DIR}/sign-personal-message-branch.cpp"
awk '
  /if \(strcmp\(type, "sign_personal_message"\) == 0\)/ { capture = 1 }
  capture { print }
  /show_user_signing_review\(\)/ { capture = 0 }
' "${USB_SERVER}" >"${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}"
expect_present "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'read_signing_authorization_mode' \
  "USB request server sign_personal_message branch snippet must be captured"
expect_order "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'provisioned_material_ready\(\)' 'read_signing_authorization_mode' \
  "sign_personal_message must check material state before reading signing mode"
expect_order "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'write_busy_if_pending_or_local_flow_active' 'read_signing_authorization_mode' \
  "sign_personal_message must check busy state before reading signing mode"
expect_order "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'require_active_matching_session' 'read_signing_authorization_mode' \
  "sign_personal_message must check active session before reading signing mode"
expect_present "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'AgentQSigningAuthorizationMode::policy' \
  "sign_personal_message branch must explicitly handle policy mode"
expect_present "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'unsupported_method' \
  "sign_personal_message policy mode must fail closed as unsupported"
expect_present "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'evaluate_sign_personal_message_user_ingress' \
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

USER_BRANCH_SNIPPET="${TMP_DIR}/sign-transaction-user-branch.cpp"
awk '
  /AgentQSignTransactionUserIngressOutput ingress/ { capture = 1 }
  capture { print }
  /show_user_signing_review\(\)/ { capture = 0 }
' "${USB_SERVER}" >"${USER_BRANCH_SNIPPET}"
expect_present "${USER_BRANCH_SNIPPET}" 'user_signing_flow_begin' \
  "USB request server user branch snippet must be captured"
expect_absent "${USER_BRANCH_SNIPPET}" 'evaluate_sign_transaction_policy|write_policy_signing_confirmation_history' \
  "USB request server user branch must not apply or record policy authorization"

expect_tree_present "${CLIENT_SOURCE}" 'signTransaction|sign_transaction|sign_result' \
  "Gateway client source must expose the new Sign API"
expect_tree_present "${CLIENT_SOURCE}" 'signPersonalMessage|sign_personal_message|messageBytes' \
  "Gateway client source must expose Sui personal-message signing"
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
  "${REPO_ROOT}/packages/client/src" \
  "${REPO_ROOT}/packages/provider-sui/src" \
  "${REPO_ROOT}/packages/mcp/src" \
  "${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q" \
  "${REPO_ROOT}/firmware/src/common/agent_q"; do
  expect_tree_absent "${source_dir}" 'common\.network' \
    "Production source must not retain Sui network policy facts"
done

while IFS= read -r source_file; do
  expect_absent "${source_file}" 'approvalTimeoutMs|durationMs|timeoutMs' \
    "Production signing source must not accept caller-controlled timing fields"
done < <(find "${REPO_ROOT}/packages/client/src" "${REPO_ROOT}/packages/provider-sui/src" "${REPO_ROOT}/packages/mcp/src" -type f \( -name '*.ts' -o -name '*.mts' -o -name '*.cts' \))

if [[ ${failures} -ne 0 ]]; then
  echo "${failures} Sign API activation boundary check(s) failed" >&2
  exit 1
fi

echo "Sign API activation boundary checks passed"
