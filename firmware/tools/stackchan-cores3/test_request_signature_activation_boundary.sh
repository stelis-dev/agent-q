#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_request_signature_activation_boundary.sh

Checks the provider-facing request_signature activation boundary:
Firmware USB, client, and provider expose the device-confirmed signing path;
MCP still has no signing ingress/tool and fails closed on provider-facing
signatureRequests metadata.
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
PROVIDER_SOURCE="${REPO_ROOT}/packages/provider/src/provider.ts"

failures=0
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-signing-boundary.XXXXXX")"
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

expect_tree_present() {
  local dir="$1"
  local pattern="$2"
  local label="$3"
  local matches="${TMP_DIR}/tree-matches"

  while IFS= read -r source_file; do
    grep -En "${pattern}" "${source_file}" >>"${matches}" || true
  done < <(find "${dir}" -type f \( -name '*.ts' -o -name '*.mts' -o -name '*.cts' \))

  if [[ ! -s "${matches}" ]]; then
    echo "FAILED: ${label}" >&2
    failures=$((failures + 1))
  fi
  rm -f "${matches}"
}

expect_present "${USB_SERVER}" '"request_signature"' \
  "USB request server must accept public request_signature messages"
expect_present "${USB_SERVER}" '"signature_result"|write_signature_result' \
  "USB request server must write public signature_result responses"
expect_present "${USB_SERVER}" 'signatureRequests' \
  "USB request server must advertise provider-facing signatureRequests"
expect_present "${USB_SERVER}" 'signature_request_(flow|confirmation|signing)_' \
  "USB request server must call signature request state owners"
expect_present "${USB_SERVER}" 'handle_signature_review_|on_signature_review_|modal_draw_signature_request_review_panel' \
  "USB request server must wire signature review UI callbacks"

for source_dir in \
  "${REPO_ROOT}/packages/client/src" \
  "${REPO_ROOT}/packages/provider/src"; do
  expect_tree_present "${source_dir}" 'requestSignature|request_signature|signature_result|signatureRequests' \
    "Gateway client/provider source must expose provider-facing signing"
done

expect_present "${PROVIDER_SOURCE}" 'requestSignature' \
  "Provider must expose requestSignature"
expect_absent "${PROVIDER_SOURCE}" 'callMethod|proposePolicyUpdate' \
  "Provider must not expose raw callMethod or Admin policy update"

while IFS= read -r source_file; do
  expect_absent "${source_file}" 'requestSignature|request_signature|signature_result' \
    "MCP source must not expose signing ingress or signature results"
  expect_absent "${source_file}" 'delete[[:space:]]+[^;]*signatureRequests' \
    "MCP source must not silently strip provider-facing signatureRequests"
done < <(find "${REPO_ROOT}/packages/mcp/src" -type f \( -name '*.ts' -o -name '*.mts' -o -name '*.cts' \))

expect_present "${MCP_SOURCE}" \
  'MCP get_capabilities must not expose provider-facing signatureRequests' \
  "MCP get_capabilities must fail closed on provider-facing signatureRequests"

while IFS= read -r source_file; do
  expect_absent "${source_file}" 'approvalTimeoutMs|durationMs|timeoutMs' \
    "Production signing source must not accept caller-controlled timing fields"
done < <(find "${REPO_ROOT}/packages/client/src" "${REPO_ROOT}/packages/provider/src" "${REPO_ROOT}/packages/mcp/src" -type f \( -name '*.ts' -o -name '*.mts' -o -name '*.cts' \))

if [[ ${failures} -ne 0 ]]; then
  echo "${failures} request_signature activation boundary check(s) failed" >&2
  exit 1
fi

echo "request_signature activation boundary checks passed"
