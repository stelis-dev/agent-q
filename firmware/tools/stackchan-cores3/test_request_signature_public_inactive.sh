#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_request_signature_public_inactive.sh

Checks that the current request_signature status remains public-inactive:
internal partial runtime modules may exist, but public Firmware USB runtime
wiring, client/provider API/parser wiring, and provider-facing capability
advertisement must stay inactive until a full product activation gate is
completed.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
USB_SERVER="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_request_server.cpp"
USB_SESSION_LOSS_H="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_session_loss.h"
USB_SESSION_LOSS_CPP="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_session_loss.cpp"

failures=0
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-public-inactive.XXXXXX")"
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

expect_absent "${USB_SERVER}" 'agent_q_signature_request_(confirmation|flow|review_view_model|signing)\.h' \
  "USB request server must not include signature request runtime owners"
expect_absent "${USB_SERVER}" '"request_signature"' \
  "USB request server must not accept public request_signature messages"
expect_absent "${USB_SERVER}" '"signature_result"|write_signature_result' \
  "USB request server must not write public signature_result responses"
expect_absent "${USB_SERVER}" 'signatureRequests' \
  "USB request server must not advertise provider-facing signatureRequests"
expect_absent "${USB_SERVER}" 'signature_request_(flow|confirmation|signing)_' \
  "USB request server must not call signature request flow/confirmation/signing helpers"
expect_absent "${USB_SERVER}" 'handle_signature_review_|on_signature_review_|modal_draw_signature_request_review_panel' \
  "USB request server must not own signature review UI callbacks"

for session_loss_file in "${USB_SESSION_LOSS_H}" "${USB_SESSION_LOSS_CPP}"; do
  expect_absent "${session_loss_file}" \
    'signature_request_active|signature_request_critical|cancel_signature_request|clear_signature_review_panel' \
    "USB session-loss classifier must not own signature request cleanup"
done

for source_dir in \
  "${REPO_ROOT}/packages/client/src" \
  "${REPO_ROOT}/packages/provider/src"; do
  while IFS= read -r source_file; do
    expect_absent "${source_file}" 'requestSignature|request_signature|signature_result|signatureRequests' \
      "Gateway client/provider source must not expose provider-facing signing"
  done < <(find "${source_dir}" -type f \( -name '*.ts' -o -name '*.mts' -o -name '*.cts' \))
done

while IFS= read -r source_file; do
  expect_absent "${source_file}" 'requestSignature|request_signature|signature_result' \
    "MCP source must not expose signing ingress or signature results"
  expect_absent "${source_file}" 'delete[[:space:]]+[^;]*signatureRequests' \
    "MCP source must not silently strip provider-facing signatureRequests"
done < <(find "${REPO_ROOT}/packages/mcp/src" -type f \( -name '*.ts' -o -name '*.mts' -o -name '*.cts' \))

expect_present "${REPO_ROOT}/packages/mcp/src/mcp.ts" \
  'MCP get_capabilities must not expose provider-facing signatureRequests' \
  "MCP get_capabilities must fail closed on provider-facing signatureRequests"

if [[ ${failures} -ne 0 ]]; then
  echo "${failures} public-inactive boundary check(s) failed" >&2
  exit 1
fi

echo "request_signature public-inactive boundary checks passed"
