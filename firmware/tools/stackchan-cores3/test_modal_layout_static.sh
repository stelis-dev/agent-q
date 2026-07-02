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
MODAL_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime/modal_drawing.cpp"

fail() {
  printf 'FAILED: %s\n' "$1" >&2
  exit 1
}

const_int() {
  local name="$1"
  sed -n "s/.*${name} = \\([0-9][0-9]*\\);.*/\\1/p" "${MODAL_SOURCE}" | head -n 1
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/modal-layout.XXXXXX")"
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
  fail "connect review client value must use bounded long mode"

if grep -Fq 'lv_label_set_long_mode(client_value, LV_LABEL_LONG_WRAP);' "${SNIPPET}"; then
  fail "connect review client value must not wrap into following rows"
fi

grep -Fq 'lv_obj_set_size(' "${SNIPPET}" ||
  fail "connect review client value must have a fixed display region"
grep -Fq 'kConnectReviewClientNameValueWidth' "${SNIPPET}" ||
  fail "connect review client value width must use the bounded layout constant"
grep -Fq 'kConnectReviewClientNameValueHeight' "${SNIPPET}" ||
  fail "connect review client value height must use the bounded layout constant"
grep -Fq 'kConnectReviewApprovalRowY' "${SNIPPET}" ||
  fail "connect review approval row must use a named layout constant"

client_name_y="$(const_int kConnectReviewClientNameValueY)"
client_name_height="$(const_int kConnectReviewClientNameValueHeight)"
approval_y="$(const_int kConnectReviewApprovalRowY)"

if [[ -z "${client_name_y}" || -z "${client_name_height}" || -z "${approval_y}" ]]; then
  fail "connect review layout constants must be parseable"
fi

if (( client_name_y + client_name_height > approval_y )); then
  fail "connect review client value region overlaps the approval row"
fi

grep -Fq 'UserSigningReviewRowKind::wrapped_value' "${MODAL_SOURCE}" ||
  fail "signing review layout must use row kind for wrapped-value rows"

grep -Fq 'kUserSigningReviewWrappedValueRowHeight' "${MODAL_SOURCE}" ||
  fail "signing review wrapped rows must use a named layout height"

if grep -Fq 'strcmp(model.rows[index].label, "Recipient")' "${MODAL_SOURCE}"; then
  fail "signing review layout must not depend on the visible Recipient label"
fi

SUI_SNIPPET="${TMP_DIR}/sui_settings.cpp"
sed -n '/bool modal_draw_sui_settings_panel(/,/^}/p' "${MODAL_SOURCE}" >"${SUI_SNIPPET}"

grep -Fq '"Gas sponsor"' "${SUI_SNIPPET}" ||
  fail "Sui settings must display the gas sponsor account setting"
grep -Fq 'g_callbacks.on_sui_settings_gas_sponsor_clicked' "${SUI_SNIPPET}" ||
  fail "Sui settings gas sponsor row must be a local UI action"
grep -Fq 'model.gas_sponsor_toggle_available' "${SUI_SNIPPET}" ||
  fail "Sui settings gas sponsor action must be disableable when settings cannot be read"
grep -Fq 'lv_obj_add_flag(content, LV_OBJ_FLAG_SCROLLABLE);' "${SUI_SNIPPET}" ||
  fail "Sui settings account content must be scrollable"
grep -Fq 'lv_obj_set_scroll_dir(content, LV_DIR_VER);' "${SUI_SNIPPET}" ||
  fail "Sui settings account content must scroll vertically"
grep -Fq 'make_settings_section_divider(content, kSuiSettingsActionDividerY)' "${SUI_SNIPPET}" ||
  fail "Sui settings must visually separate account facts from actions"
grep -Fq 'make_settings_action_row_at(' "${SUI_SNIPPET}" ||
  fail "Sui settings gas sponsor action must use the settings action row"

gas_sponsor_y="$(const_int kSuiSettingsGasSponsorRowY)"
clear_y="$(const_int kSuiSettingsClearButtonY)"
settings_action_height="$(const_int kSettingsMenuActionButtonHeight)"
if [[ -z "${gas_sponsor_y}" || -z "${clear_y}" || -z "${settings_action_height}" ]]; then
  fail "Sui settings gas sponsor layout constants must be parseable"
fi

if (( gas_sponsor_y + settings_action_height > clear_y )); then
  fail "Sui settings gas sponsor row overlaps the clear button"
fi

printf 'Modal layout static checks passed\n'
