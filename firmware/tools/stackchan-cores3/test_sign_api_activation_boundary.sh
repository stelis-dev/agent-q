#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sign_api_activation_boundary.sh

Checks the Sign API activation boundary:
Firmware USB and Gateway client expose sign_by_user/sign_by_policy through the
shared Sign API, provider exposes only signByUser, and MCP exposes only
sign_by_policy plus propose_policy_update.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
USB_SERVER="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_request_server.cpp"
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

expect_present "${USB_SERVER}" '"sign_by_user"' \
  "USB request server must accept public sign_by_user messages"
expect_present "${USB_SERVER}" '"sign_by_policy"' \
  "USB request server must accept public sign_by_policy messages"
expect_present "${USB_SERVER}" '"sign_result"|write_sign_result' \
  "USB request server must write public sign_result responses"
expect_present "${USB_SERVER}" '"signing"' \
  "USB request server must advertise shared signing capabilities"
expect_present "${USB_SERVER}" 'sign_by_user_(flow|confirmation|signing)_' \
  "USB request server must call user-confirmed signing state owners"

expect_tree_present "${CLIENT_SOURCE}" 'signByUser|signByPolicy|sign_by_user|sign_by_policy|sign_result' \
  "Gateway client source must expose the new Sign API"
expect_present "${PROVIDER_SOURCE}" 'signByUser' \
  "Provider must expose signByUser"
expect_absent "${PROVIDER_SOURCE}" 'signByPolicy|proposePolicyUpdate' \
  "Provider must not expose policy signing or Admin policy update"
expect_present "${MCP_SOURCE}" '"sign_by_policy"' \
  "MCP must expose sign_by_policy"
expect_present "${MCP_SOURCE}" '"propose_policy_update"' \
  "MCP must expose top-level propose_policy_update"
expect_absent "${MCP_SOURCE}" 'signByUser|"sign_by_user"' \
  "MCP source must not expose user-confirmed provider signing"

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
