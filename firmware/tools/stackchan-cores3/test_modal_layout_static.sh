#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_modal_layout_static.sh

Checks static layout invariants for StackChan CoreS3 modal drawing code.
This test does not require ESP-IDF or LVGL headers.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
MODAL_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_modal_drawing.cpp"

fail() {
  printf 'FAILED: %s\n' "$1" >&2
  exit 1
}

const_int() {
  local name="$1"
  sed -n "s/.*${name} = \\([0-9][0-9]*\\);.*/\\1/p" "${MODAL_SOURCE}" | head -n 1
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-modal-layout.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

SNIPPET="${TMP_DIR}/connect_review.cpp"
sed -n '/bool modal_draw_connect_review_panel(/,/^}/p' "${MODAL_SOURCE}" >"${SNIPPET}"

grep -Fq 'lv_label_set_text(subtitle, "Connect only, not signing");' "${SNIPPET}" ||
  fail "connect review must state that connection is not signing approval"
grep -Fq 'lv_label_set_text(client_label, "Requester");' "${SNIPPET}" ||
  fail "connect review client label must say Requester"
if grep -Fq 'lv_label_set_text(client_label, "Agent-Q");' "${SNIPPET}"; then
  fail "connect review client label must not duplicate the default Agent-Q client name"
fi
grep -Fq 'lv_label_set_text(mode_label, "Requires");' "${SNIPPET}" ||
  fail "connect review approval row must explain the required local input"

grep -Fq 'lv_label_set_long_mode(client_value, LV_LABEL_LONG_CLIP);' "${SNIPPET}" ||
  fail "connect review agent-q value must use bounded long mode"

if grep -Fq 'lv_label_set_long_mode(client_value, LV_LABEL_LONG_WRAP);' "${SNIPPET}"; then
  fail "connect review agent-q value must not wrap into following rows"
fi

grep -Fq 'lv_obj_set_size(' "${SNIPPET}" ||
  fail "connect review agent-q value must have a fixed display region"
grep -Fq 'kConnectReviewClientNameValueWidth' "${SNIPPET}" ||
  fail "connect review agent-q value width must use the bounded layout constant"
grep -Fq 'kConnectReviewClientNameValueHeight' "${SNIPPET}" ||
  fail "connect review agent-q value height must use the bounded layout constant"
grep -Fq 'kConnectReviewApprovalRowY' "${SNIPPET}" ||
  fail "connect review approval row must use a named layout constant"

client_name_y="$(const_int kConnectReviewClientNameValueY)"
client_name_height="$(const_int kConnectReviewClientNameValueHeight)"
approval_y="$(const_int kConnectReviewApprovalRowY)"

if [[ -z "${client_name_y}" || -z "${client_name_height}" || -z "${approval_y}" ]]; then
  fail "connect review layout constants must be parseable"
fi

if (( client_name_y + client_name_height > approval_y )); then
  fail "connect review agent-q value region overlaps the approval row"
fi

grep -Fq 'AgentQUserSigningReviewRowKind::wrapped_value' "${MODAL_SOURCE}" ||
  fail "signing review layout must use row kind for wrapped-value rows"

grep -Fq 'kUserSigningReviewWrappedValueRowHeight' "${MODAL_SOURCE}" ||
  fail "signing review wrapped rows must use a named layout height"

if grep -Fq 'strcmp(model.rows[index].label, "Recipient")' "${MODAL_SOURCE}"; then
  fail "signing review layout must not depend on the visible Recipient label"
fi

printf 'Modal layout static checks passed\n'
