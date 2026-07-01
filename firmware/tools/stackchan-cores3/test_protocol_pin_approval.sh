#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_protocol_pin_approval.sh

Compiles the StackChan CoreS3 protocol-backed local PIN approval state owner
against host stubs and verifies request id, session id, purpose, and deadline
ownership. This test uses only a host C++ compiler and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
LOCAL_PIN_AUTH_UI_HEADER="${AGENT_Q_DIR}/agent_q_local_pin_auth_ui_flow.h"
LOCAL_PIN_AUTH_UI_SOURCE="${AGENT_Q_DIR}/agent_q_local_pin_auth_ui_flow.cpp"
MODAL_TRANSITION_SOURCE="${AGENT_Q_DIR}/agent_q_modal_transition.cpp"
USB_REQUEST_SERVER_SOURCE="${AGENT_Q_DIR}/agent_q_usb_request_server.cpp"
CXX_BIN="${CXX:-c++}"

check_modal_transition_owner_present() {
  if [[ ! -f "${MODAL_TRANSITION_SOURCE}" ]]; then
    echo "FAILED: ModalTransitionOwner source is missing" >&2
    exit 1
  fi
  if ! grep -q 'modal_transition_complete_processing_to_result' "${MODAL_TRANSITION_SOURCE}" ||
     ! grep -q 'modal_transition_complete_to_next_panel' "${MODAL_TRANSITION_SOURCE}" ||
     ! grep -q 'modal_transition_run_work_then_clear_panel' "${MODAL_TRANSITION_SOURCE}"; then
    echo "FAILED: ModalTransitionOwner must own next-panel, processing-to-result, and work-then-clear transitions" >&2
    exit 1
  fi
  if ! grep -q 'agent_q_modal_transition.h' "${LOCAL_PIN_AUTH_UI_SOURCE}"; then
    echo "FAILED: local PIN UI flow must use ModalTransitionOwner" >&2
    exit 1
  fi
}

check_modal_transition_next_panel_order() {
  local snippet="${TMP_DIR}/modal_transition_complete_to_next_panel.cpp"
  local draw_line
  local clear_line

  awk '
    /bool modal_transition_complete_to_next_panel\(/ { in_fn = 1 }
    in_fn { print }
    in_fn && /^}/ { exit }
  ' "${MODAL_TRANSITION_SOURCE}" >"${snippet}"

  draw_line="$(grep -En 'draw_next\(context\)' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  clear_line="$(grep -En 'modal_transition_clear_panel_after_work' "${snippet}" | head -n 1 | cut -d: -f1 || true)"

  if [[ -z "${draw_line}" || -z "${clear_line}" || "${draw_line}" -ge "${clear_line}" ]]; then
    echo "FAILED: next-panel transition must prepare the next panel before clearing the current panel" >&2
    echo "draw_line=${draw_line:-missing} clear_line=${clear_line:-missing}" >&2
    exit 1
  fi
}

check_settings_completion_uses_transition_owner() {
  local settings_snippet="${TMP_DIR}/complete_local_pin_processing_to_settings.cpp"
  local commit_snippet="${TMP_DIR}/local_pin_auth_ui_commit_setting_if_ready.cpp"
  local prepare_snippet="${TMP_DIR}/local_pin_auth_ui_handle_prepare_worker_result.cpp"

  awk '
    /void complete_local_pin_processing_to_settings\(/ { in_fn = 1 }
    in_fn { print }
    in_fn && /^}/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${settings_snippet}"

  if ! grep -q 'modal_transition_complete_to_next_panel' "${settings_snippet}"; then
    echo "FAILED: Settings return must route through ModalTransitionOwner next-panel transition" >&2
    exit 1
  fi

  awk '
    /void local_pin_auth_ui_commit_setting_if_ready\(/ { in_fn = 1 }
    in_fn { print }
    in_fn && /^}/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${commit_snippet}"

  awk '
    /void local_pin_auth_ui_handle_prepare_worker_result\(/ { in_fn = 1 }
    in_fn { print }
    in_fn && /^}/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${prepare_snippet}"

  if grep -q 'modal_transition_clear_panel_after_work' "${commit_snippet}" ||
     grep -q 'modal_transition_clear_panel_after_work' "${prepare_snippet}"; then
    echo "FAILED: Settings commit completion must not clear the PIN panel before preparing Settings/result UI" >&2
    exit 1
  fi
}

check_no_flow_local_pin_clear_helper() {
  if grep -Eq '(^|[[:space:]])clear_local_pin_panel\(' "${LOCAL_PIN_AUTH_UI_SOURCE}"; then
    echo "FAILED: local PIN UI flow must not reintroduce flow-local panel clearing" >&2
    exit 1
  fi
}

check_local_pin_ui_deadline_order() {
  local snippet="${TMP_DIR}/clear_waiting_local_pin_input_if_needed.cpp"
  local deadline_line
  local lockout_line

  awk '
    /void clear_waiting_local_pin_input_if_needed\(/ { in_fn = 1 }
    in_fn { print }
    in_fn && /^}/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${snippet}"

  deadline_line="$(grep -En 'finish_request_backed_local_pin_input_timeout_if_reached' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  lockout_line="$(grep -En 'local_pin_auth_release_lockout_if_elapsed' "${snippet}" | head -n 1 | cut -d: -f1 || true)"

  if [[ -z "${deadline_line}" || -z "${lockout_line}" || "${deadline_line}" -ge "${lockout_line}" ]]; then
    echo "FAILED: protocol-backed PIN input timeout must be handled before lockout retry UI recovery" >&2
    echo "deadline_line=${deadline_line:-missing} lockout_line=${lockout_line:-missing}" >&2
    exit 1
  fi
}

check_local_pin_clear_if_needed_dispatches_to_cleanup_helpers() {
  local snippet="${TMP_DIR}/local_pin_auth_ui_clear_if_needed.cpp"
  local processing_line
  local waiting_line

  awk '
    /void local_pin_auth_ui_clear_if_needed\(/ { in_fn = 1 }
    in_fn { print }
    in_fn && /^}/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${snippet}"

  processing_line="$(grep -En 'clear_processing_local_pin_if_needed' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  waiting_line="$(grep -En 'clear_waiting_local_pin_input_if_needed' "${snippet}" | head -n 1 | cut -d: -f1 || true)"

  if [[ -z "${processing_line}" || -z "${waiting_line}" || "${processing_line}" -ge "${waiting_line}" ]]; then
    echo "FAILED: local PIN cleanup frame must delegate processing and waiting-input cleanup in order" >&2
    echo "processing_line=${processing_line:-missing} waiting_line=${waiting_line:-missing}" >&2
    exit 1
  fi
  if grep -Eq 'write_connect_rejected_from_pin|finish_policy_update_terminal|finish_user_signing_error_terminal|record_policy_update_timed_out_from_pin|record_sui_zklogin_timed_out_from_pin' "${snippet}"; then
    echo "FAILED: local PIN cleanup frame must not inline purpose-specific terminal cleanup" >&2
    exit 1
  fi
}

check_local_pin_ui_handler_timeout_order() {
  local function_name="$1"
  local second_pattern="$2"
  local label="$3"
  local snippet="${TMP_DIR}/${function_name}.cpp"
  local timeout_line
  local second_line

  awk -v fn="${function_name}" '
    $0 ~ "void " fn "\\(" { in_fn = 1 }
    in_fn { print }
    in_fn && /^}/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${snippet}"

  timeout_line="$(grep -En 'finish_request_backed_local_pin_input_timeout_if_reached' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  second_line="$(grep -En "${second_pattern}" "${snippet}" | head -n 1 | cut -d: -f1 || true)"

  if [[ -z "${timeout_line}" || -z "${second_line}" || "${timeout_line}" -ge "${second_line}" ]]; then
    echo "FAILED: ${label}" >&2
    echo "timeout_line=${timeout_line:-missing} second_line=${second_line:-missing}" >&2
    exit 1
  fi
}

check_local_pin_worker_timeout_order() {
  local snippet="${TMP_DIR}/handle_local_pin_auth_verify_worker_result.cpp"
  local timeout_line
  local complete_line

  awk '
    /void local_pin_auth_ui_handle_verify_worker_result\(/ { in_fn = 1 }
    in_fn { print }
    in_fn && /^}/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${snippet}"

  complete_line="$(grep -En 'local_pin_auth_complete_verify_job\(' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  timeout_line="$(grep -En 'finish_request_backed_local_pin_input_timeout_if_reached' "${snippet}" | awk -F: -v complete="${complete_line:-0}" '$1 < complete { line = $1 } END { print line }')"

  if [[ -z "${timeout_line}" || -z "${complete_line}" || "${timeout_line}" -ge "${complete_line}" ]]; then
    echo "FAILED: protocol-backed PIN worker completion must check input timeout before local PIN verify result" >&2
    echo "timeout_line=${timeout_line:-missing} complete_line=${complete_line:-missing}" >&2
    exit 1
  fi
}

check_settings_policy_reset_keeps_panel_until_completion() {
  local snippet="${TMP_DIR}/settings_policy_reset_case.cpp"
  local complete_setting_line
  local raw_store_line
  local clear_before_complete_line
  local restore_line

  awk '
    /case AgentQLocalPinAuthVerifyResult::verified_settings_policy_reset:/ { in_case = 1 }
    in_case { print }
    in_case && /return;/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${snippet}"

  complete_setting_line="$(grep -En 'complete_policy_reset_setting' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  raw_store_line="$(grep -En 'store_default_policy' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  restore_line="$(grep -En 'complete_local_pin_settings_completion|complete_local_pin_processing_to_settings|restore_settings_menu_after_pin' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  clear_before_complete_line="$(
    grep -En 'clear_local_pin_panel' "${snippet}" |
      awk -F: -v complete="${complete_setting_line:-0}" '$1 < complete { print $1; exit }' || true
  )"

  if [[ -n "${raw_store_line}" ]]; then
    echo "FAILED: settings policy reset UI must not call the raw policy store callback" >&2
    echo "raw_store_line=${raw_store_line}" >&2
    exit 1
  fi
  if [[ -z "${complete_setting_line}" || -z "${restore_line}" || "${complete_setting_line}" -ge "${restore_line}" ]]; then
    echo "FAILED: settings policy reset must complete the setting action before restoring Settings" >&2
    echo "complete_setting_line=${complete_setting_line:-missing} restore_line=${restore_line:-missing}" >&2
    exit 1
  fi
  if [[ -n "${clear_before_complete_line}" ]]; then
    echo "FAILED: settings policy reset must keep the processing panel visible until policy reset completes" >&2
    echo "clear_before_complete_line=${clear_before_complete_line} complete_setting_line=${complete_setting_line}" >&2
    exit 1
  fi
}

check_settings_sui_clear_keeps_panel_until_completion() {
  local snippet="${TMP_DIR}/settings_sui_clear_case.cpp"
  local complete_setting_line
  local raw_clear_line
  local clear_before_complete_line
  local restore_line

  awk '
    /case AgentQLocalPinAuthVerifyResult::verified_settings_sui_zklogin_clear:/ { in_case = 1 }
    in_case { print }
    in_case && /return;/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${snippet}"

  complete_setting_line="$(grep -En 'complete_sui_zklogin_clear_setting' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  raw_clear_line="$(grep -En 'clear_sui_zklogin_proof' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  restore_line="$(grep -En 'complete_local_pin_settings_completion|complete_local_pin_processing_to_sui_settings|restore_sui_settings_after_pin' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  clear_before_complete_line="$(
    grep -En 'clear_local_pin_panel' "${snippet}" |
      awk -F: -v complete="${complete_setting_line:-0}" '$1 < complete { print $1; exit }' || true
  )"

  if [[ -n "${raw_clear_line}" ]]; then
    echo "FAILED: Sui zkLogin Settings clear UI must not call the raw proof clear callback" >&2
    echo "raw_clear_line=${raw_clear_line}" >&2
    exit 1
  fi
  if [[ -z "${complete_setting_line}" || -z "${restore_line}" || "${complete_setting_line}" -ge "${restore_line}" ]]; then
    echo "FAILED: Sui zkLogin Settings clear must complete the setting action before restoring Settings" >&2
    echo "complete_setting_line=${complete_setting_line:-missing} restore_line=${restore_line:-missing}" >&2
    exit 1
  fi
  if [[ -n "${clear_before_complete_line}" ]]; then
    echo "FAILED: Sui zkLogin Settings clear must keep the processing panel visible until proof clear completes" >&2
    echo "clear_before_complete_line=${clear_before_complete_line} complete_setting_line=${complete_setting_line}" >&2
    exit 1
  fi
}

check_connect_pin_completion_uses_connect_callbacks() {
  if grep -Eq 'protocol_pin_approval_begin_connect\(|local_pin_auth_begin_connect\(' "${LOCAL_PIN_AUTH_UI_SOURCE}"; then
    echo "FAILED: local PIN UI flow must use a semantic connect PIN begin callback instead of direct protocol/local PIN begin owner calls" >&2
    exit 1
  fi

  if grep -Eq 'ops\.(write_connect_rejected\(|write_connect_approved|replace_active_session|clear_connect_approval|connect_approval_return_to_review|log_connect_session_creation_failed|log_connect_pin_approved)' "${LOCAL_PIN_AUTH_UI_SOURCE}"; then
    echo "FAILED: local PIN UI flow must use semantic connect completion callbacks instead of raw connect response/session/approval ops" >&2
    exit 1
  fi

  for required in \
    'begin_connect_pin_auth(' \
    'write_connect_rejected_from_pin(' \
    'finish_connect_rejection_cleanup(' \
    'return_connect_review_from_pin(' \
    'replace_connect_session_from_pin(' \
    'finish_connect_session_error(' \
    'finish_connect_approved('; do
    if ! grep -q "${required}" "${LOCAL_PIN_AUTH_UI_SOURCE}"; then
      echo "FAILED: local PIN UI flow is missing semantic connect callback ${required}" >&2
      exit 1
    fi
  done

  for required in \
    'begin_connect_pin_auth_for_local_pin_auth' \
    'write_connect_rejected_from_pin_for_local_pin_auth' \
    'finish_connect_rejection_cleanup_for_local_pin_auth' \
    'return_connect_review_from_pin_for_local_pin_auth' \
    'replace_connect_session_from_pin_for_local_pin_auth' \
    'finish_connect_session_error_for_local_pin_auth' \
    'finish_connect_approved_for_local_pin_auth'; do
    if ! grep -q "${required}" "${USB_REQUEST_SERVER_SOURCE}"; then
      echo "FAILED: StackChan request server is missing connect PIN callback ${required}" >&2
      exit 1
    fi
  done

  local begin_connect_draw_failure="${TMP_DIR}/local_pin_auth_ui_begin_connect_draw_failure.cpp"
  local write_line
  local wipe_line
  local cleanup_line

  awk '
    /if \(!draw_local_pin_panel\(ops\)\)/ { in_block = 1 }
    in_block { print }
    in_block && /return false;/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${begin_connect_draw_failure}"

  write_line="$(grep -En 'write_connect_rejected_from_pin' "${begin_connect_draw_failure}" | head -n 1 | cut -d: -f1 || true)"
  wipe_line="$(grep -En 'wipe_local_pin_auth_scratch' "${begin_connect_draw_failure}" | head -n 1 | cut -d: -f1 || true)"
  cleanup_line="$(grep -En 'finish_connect_rejection_cleanup' "${begin_connect_draw_failure}" | head -n 1 | cut -d: -f1 || true)"

  if [[ -z "${write_line}" || -z "${wipe_line}" || -z "${cleanup_line}" ||
        "${write_line}" -ge "${wipe_line}" || "${wipe_line}" -ge "${cleanup_line}" ]]; then
    echo "FAILED: connect PIN display-allocation failure must write rejection before wiping scratch and clear pending state after wiping scratch" >&2
    echo "write_line=${write_line:-missing} wipe_line=${wipe_line:-missing} cleanup_line=${cleanup_line:-missing}" >&2
    exit 1
  fi
}

check_local_pin_request_id_lookup_uses_app_callback() {
  if grep -Eq 'protocol_pin_approval_request_id_for_local_pin_purpose\(|request_backed_local_pin_request_id\(|pending_request_id_for_local_pin_purpose\(|policy_update_request_id_for_pin\(' "${LOCAL_PIN_AUTH_UI_SOURCE}"; then
    echo "FAILED: local PIN UI flow must use the app-provided request-id callback for terminal/rejection decisions" >&2
    exit 1
  fi

  if ! grep -q 'request_id_for_pin(' "${LOCAL_PIN_AUTH_UI_SOURCE}"; then
    echo "FAILED: local PIN UI flow is missing the semantic request-id callback" >&2
    exit 1
  fi
  if ! grep -q 'request_id_for_local_pin_auth' "${USB_REQUEST_SERVER_SOURCE}"; then
    echo "FAILED: StackChan request server is missing the local PIN request-id callback" >&2
    exit 1
  fi
}

check_policy_sui_pin_completion_uses_owner_callbacks() {
  if grep -Eq 'policy_update_flow_(clear|return_to_review|return_to_pin_entry|record_|commit)|sui_zklogin_proposal_flow_(return_to_review|return_to_pin_entry|record_|commit)|write_policy_propose_outcome_with_current_policy|protocol_pin_approval_begin_sui_zklogin_proposal|protocol_pin_approval_clear\(\)' "${LOCAL_PIN_AUTH_UI_SOURCE}"; then
    echo "FAILED: local PIN UI flow must use semantic policy/Sui callbacks instead of direct policy, Sui, or protocol PIN owner calls" >&2
    exit 1
  fi

  for required in \
    'return_policy_update_review_from_pin(' \
    'return_policy_update_pin_entry_from_pin(' \
    'record_policy_update_ui_error_from_pin(' \
    'record_policy_update_timed_out_from_pin(' \
    'commit_policy_update_from_pin(' \
    'finish_policy_update_unavailable_from_pin(' \
    'begin_sui_zklogin_proposal_pin_from_review' \
    'return_sui_zklogin_review_from_pin(' \
    'return_sui_zklogin_pin_entry_from_pin(' \
    'record_sui_zklogin_ui_error_from_pin(' \
    'record_sui_zklogin_timed_out_from_pin(' \
    'record_sui_zklogin_rejected_from_pin(' \
    'record_sui_zklogin_consistency_error_from_pin(' \
    'commit_sui_zklogin_from_pin('; do
    if ! grep -q "${required}" "${LOCAL_PIN_AUTH_UI_SOURCE}"; then
      echo "FAILED: local PIN UI flow is missing semantic policy/Sui callback ${required}" >&2
      exit 1
    fi
  done

  for required in \
    'return_policy_update_review_from_pin_for_local_pin_auth' \
    'finish_policy_update_unavailable_from_pin_for_local_pin_auth' \
    'begin_sui_zklogin_proposal_pin_from_review_for_local_pin_auth' \
    'return_sui_zklogin_review_from_pin_for_local_pin_auth' \
    'record_sui_zklogin_consistency_error_from_pin_for_local_pin_auth'; do
    if ! grep -q "${required}" "${USB_REQUEST_SERVER_SOURCE}"; then
      echo "FAILED: StackChan request server is missing policy/Sui PIN callback ${required}" >&2
      exit 1
    fi
  done

  if grep -Eq 'return_policy_update_pin_entry_from_pin_for_local_pin_auth|record_policy_update_ui_error_from_pin_for_local_pin_auth|record_policy_update_timed_out_from_pin_for_local_pin_auth|commit_policy_update_from_pin_for_local_pin_auth|return_sui_zklogin_pin_entry_from_pin_for_local_pin_auth|record_sui_zklogin_ui_error_from_pin_for_local_pin_auth|record_sui_zklogin_timed_out_from_pin_for_local_pin_auth|record_sui_zklogin_rejected_from_pin_for_local_pin_auth|commit_sui_zklogin_from_pin_for_local_pin_auth' "${USB_REQUEST_SERVER_SOURCE}"; then
    echo "FAILED: StackChan request server must not reintroduce one-line policy/Sui local PIN wrappers that can bind owner functions directly" >&2
    exit 1
  fi

  local ops_snippet="${TMP_DIR}/local_pin_auth_ops.cpp"
  awk '
    /^agent_q::AgentQLocalPinAuthUiFlowOps local_pin_auth_ui_flow_ops\(\)$/ { in_ops = 1 }
    in_ops { print }
    in_ops && /^}/ { exit }
  ' "${USB_REQUEST_SERVER_SOURCE}" >"${ops_snippet}"

  for required in \
    'agent_q::policy_update_flow_return_to_pin_entry' \
    'agent_q::policy_update_flow_record_ui_error' \
    'agent_q::policy_update_flow_record_timed_out' \
    'agent_q::policy_update_flow_commit' \
    'agent_q::sui_zklogin_proposal_flow_return_to_pin_entry' \
    'agent_q::sui_zklogin_proposal_flow_record_ui_error' \
    'agent_q::sui_zklogin_proposal_flow_record_timed_out' \
    'agent_q::sui_zklogin_proposal_flow_record_rejected' \
    'agent_q::sui_zklogin_proposal_flow_commit'; do
    if ! grep -q "${required}" "${ops_snippet}"; then
      echo "FAILED: StackChan local PIN ops must bind direct owner function ${required}" >&2
      exit 1
    fi
  done
}

check_policy_update_keeps_panel_until_commit() {
  local snippet="${TMP_DIR}/verified_policy_update_case.cpp"
  local approved_line
  local commit_line
  local raw_commit_line
  local clear_between_approved_and_commit_line
  local transition_line
  local finish_line

  awk '
    /case AgentQLocalPinAuthVerifyResult::verified_policy_update:/ { in_case = 1 }
    in_case && /case AgentQLocalPinAuthVerifyResult::started_setting_commit:/ { exit }
    in_case { print }
  ' "${LOCAL_PIN_AUTH_UI_SOURCE}" >"${snippet}"

  approved_line="$(grep -En 'policy update PIN approved"' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  commit_line="$(grep -En 'commit_policy_update_from_pin' "${snippet}" | awk -F: -v approved="${approved_line:-0}" '$1 > approved { print $1; exit }' || true)"
  raw_commit_line="$(grep -En 'policy_update_flow_commit' "${snippet}" | head -n 1 | cut -d: -f1 || true)"
  transition_line="$(grep -En 'complete_local_pin_processing_to_policy_terminal' "${snippet}" | awk -F: -v commit="${commit_line:-0}" '$1 > commit { print $1; exit }' || true)"
  finish_line="$(grep -En 'complete_local_pin_processing_to_policy_terminal|finish_policy_update_terminal' "${snippet}" | tail -n 1 | cut -d: -f1 || true)"
  clear_between_approved_and_commit_line="$(
    grep -En 'clear_local_pin_panel' "${snippet}" |
      awk -F: -v approved="${approved_line:-0}" -v commit="${commit_line:-0}" '$1 > approved && $1 < commit { print $1; exit }' || true
  )"

  if [[ -z "${approved_line}" || -z "${commit_line}" || -z "${transition_line}" || "${commit_line}" -ge "${transition_line}" ]]; then
    echo "FAILED: policy update PIN approval must commit policy before ModalTransitionOwner finishes the terminal result" >&2
    echo "approved_line=${approved_line:-missing} commit_line=${commit_line:-missing} transition_line=${transition_line:-missing}" >&2
    exit 1
  fi
  if [[ -n "${raw_commit_line}" ]]; then
    echo "FAILED: local PIN UI flow must use the policy commit callback instead of calling the policy flow owner directly" >&2
    echo "raw_commit_line=${raw_commit_line}" >&2
    exit 1
  fi
  if [[ -n "${clear_between_approved_and_commit_line}" ]]; then
    echo "FAILED: policy update PIN approval must keep the processing panel visible until policy commit completes" >&2
    echo "clear_between_approved_and_commit_line=${clear_between_approved_and_commit_line} commit_line=${commit_line}" >&2
    exit 1
  fi
  if [[ -z "${finish_line}" || "${transition_line}" -gt "${finish_line}" ]]; then
    echo "FAILED: policy update PIN approval must finish through ModalTransitionOwner" >&2
    echo "transition_line=${transition_line:-missing} finish_line=${finish_line:-missing}" >&2
    exit 1
  fi
}

check_user_signing_keeps_panel_until_signing_work() {
  local work_line
  local raw_execute_line
  local helper_line
  local raw_confirmation_line
  local raw_flow_line

  helper_line="$(grep -En 'run_user_signing_then_clear_local_pin_panel' "${LOCAL_PIN_AUTH_UI_SOURCE}" | head -n 1 | cut -d: -f1 || true)"
  work_line="$(grep -En 'modal_transition_run_work_then_clear_panel' "${LOCAL_PIN_AUTH_UI_SOURCE}" | head -n 1 | cut -d: -f1 || true)"
  raw_execute_line="$(grep -En 'execute_user_signing_critical_section_and_finish\\(request_id\\)' "${LOCAL_PIN_AUTH_UI_SOURCE}" | head -n 1 | cut -d: -f1 || true)"
  raw_confirmation_line="$(
    grep -En 'user_signing_confirmation_(cancel_for_pin_loss|record_timeout|return_to_review_from_pin|complete_pin_verify_job_and_write_history)\(' "${LOCAL_PIN_AUTH_UI_SOURCE}" |
      head -n 1 |
      cut -d: -f1 || true
  )"
  raw_flow_line="$(
    grep -En 'user_signing_flow_(terminal_pending|cancel_for_ui_loss)\(' "${LOCAL_PIN_AUTH_UI_SOURCE}" |
      head -n 1 |
      cut -d: -f1 || true
  )"

  if [[ -z "${helper_line}" || -z "${work_line}" ]]; then
    echo "FAILED: user signing local PIN approval must route signing work through ModalTransitionOwner" >&2
    echo "helper_line=${helper_line:-missing} work_line=${work_line:-missing}" >&2
    exit 1
  fi
  if [[ -n "${raw_execute_line}" ]]; then
    echo "FAILED: local PIN user signing must not call signing work directly from the verified path" >&2
    echo "raw_execute_line=${raw_execute_line}" >&2
    exit 1
  fi
  if [[ -n "${raw_confirmation_line}" || -n "${raw_flow_line}" ]]; then
    echo "FAILED: local PIN user signing must use app-level user-signing callbacks instead of direct owner calls" >&2
    echo "raw_confirmation_line=${raw_confirmation_line:-none} raw_flow_line=${raw_flow_line:-none}" >&2
    exit 1
  fi

  if grep -Eq 'cancel_user_signing_for_pin_loss_from_local_pin_auth|record_user_signing_timeout_from_pin_for_local_pin_auth|return_user_signing_review_from_pin_for_local_pin_auth|user_signing_terminal_pending_from_local_pin_auth|execute_user_signing_for_local_pin_auth|finish_user_signing_error_terminal_for_local_pin_auth' "${USB_REQUEST_SERVER_SOURCE}"; then
    echo "FAILED: StackChan request server must not reintroduce one-line user-signing local PIN wrappers that can bind owner functions directly" >&2
    exit 1
  fi

  local ops_snippet="${TMP_DIR}/local_pin_auth_user_signing_ops.cpp"
  awk '
    /^agent_q::AgentQLocalPinAuthUiFlowOps local_pin_auth_ui_flow_ops\(\)$/ { in_ops = 1 }
    in_ops { print }
    in_ops && /^}/ { exit }
  ' "${USB_REQUEST_SERVER_SOURCE}" >"${ops_snippet}"

  for required in \
    'agent_q::user_signing_confirmation_cancel_for_pin_loss' \
    'agent_q::user_signing_confirmation_record_timeout' \
    'agent_q::user_signing_confirmation_return_to_review_from_pin' \
    'agent_q::user_signing_flow_terminal_pending' \
    'execute_user_signing_critical_section_and_finish' \
    'finish_user_signing_error_terminal'; do
    if ! grep -q "${required}" "${ops_snippet}"; then
      echo "FAILED: StackChan local PIN ops must bind direct owner function ${required}" >&2
      exit 1
    fi
  done
}

check_local_pin_ops_surface_is_grouped() {
  local ops_struct="${TMP_DIR}/AgentQLocalPinAuthUiFlowOps.h"
  local ops_builder="${TMP_DIR}/local_pin_auth_grouped_ops.cpp"

  awk '
    /^struct AgentQLocalPinAuthUiFlowOps / { in_struct = 1 }
    in_struct { print }
    in_struct && /^};/ { exit }
  ' "${LOCAL_PIN_AUTH_UI_HEADER}" >"${ops_struct}"

  if grep -q '(\*' "${ops_struct}"; then
    echo "FAILED: AgentQLocalPinAuthUiFlowOps must expose responsibility groups, not flat callback fields" >&2
    exit 1
  fi

  for required in \
    'AgentQLocalPinAuthTimingOps timing' \
    'AgentQLocalPinAuthDisplayOps display' \
    'AgentQLocalPinAuthMaterialSettingsOps material_settings' \
    'AgentQLocalPinAuthRequestOps request' \
    'AgentQLocalPinAuthConnectOps connect' \
    'AgentQLocalPinAuthPolicyUpdateOps policy_update' \
    'AgentQLocalPinAuthSuiZkLoginOps sui_zklogin' \
    'AgentQLocalPinAuthUserSigningOps user_signing'; do
    if ! grep -q "${required}" "${ops_struct}"; then
      echo "FAILED: local PIN ops surface is missing responsibility group ${required}" >&2
      exit 1
    fi
  done

  awk '
    /^agent_q::AgentQLocalPinAuthUiFlowOps local_pin_auth_ui_flow_ops\(\)$/ { in_ops = 1 }
    in_ops { print }
    in_ops && /^}/ { exit }
  ' "${USB_REQUEST_SERVER_SOURCE}" >"${ops_builder}"

  for required in \
    'ops.timing.' \
    'ops.display.' \
    'ops.material_settings.' \
    'ops.request.' \
    'ops.connect.' \
    'ops.policy_update.' \
    'ops.sui_zklogin.' \
    'ops.user_signing.'; do
    if ! grep -q "${required}" "${ops_builder}"; then
      echo "FAILED: StackChan local PIN ops builder is missing grouped assignment ${required}" >&2
      exit 1
    fi
  done

  if grep -Eq 'ops\.(now|wall_clock_ms|provisioned_material_ready|human_approval_requires_pin|read_human_approval_input_mode|read_signing_authorization_mode|read_sui_account_settings|begin_connect_pin_auth|request_id_for_pin|show_policy_update_review|show_sui_zklogin_review|show_user_signing_review|connect_approval_ms)[[:space:]]*=' "${ops_builder}"; then
    echo "FAILED: StackChan local PIN ops builder must not assign flat operation fields" >&2
    exit 1
  fi
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-protocol-pin-approval.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/protocol_pin_approval_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_protocol_pin_approval.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

bool random_bytes(void* output, size_t size, void*)
{
    if (output == nullptr) {
        return false;
    }
    unsigned char* bytes = static_cast<unsigned char*>(output);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = static_cast<unsigned char>(index + 1);
    }
    return true;
}

agent_q::AgentQTimeoutWindow timeout_window(TickType_t started_at, TickType_t deadline)
{
    return agent_q::timeout_window_from_deadline(started_at, deadline);
}

}  // namespace

namespace agent_q {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

}  // namespace agent_q

int main()
{
    using Purpose = agent_q::AgentQProtocolPinApprovalPurpose;
    using LocalPurpose = agent_q::AgentQLocalPinAuthPurpose;
    using SessionValidation = agent_q::AgentQSessionValidationResult;

    agent_q::session_init();
    agent_q::protocol_pin_approval_clear();
    expect(!agent_q::protocol_pin_approval_active(), "clear leaves state inactive");
    char request_id[agent_q::kAgentQProtocolPinRequestIdSize] = {};
    expect(!agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
               LocalPurpose::connect,
               request_id,
               sizeof(request_id)),
           "inactive state has no connect request id");
    expect(request_id[0] == '\0', "inactive request id output is cleared");
    expect(agent_q::protocol_pin_approval_begin_connect("connect-1", 10, timeout_window(10, 100)),
           "connect protocol PIN approval begins");
    agent_q::AgentQProtocolPinApprovalSnapshot snapshot =
        agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.active, "connect snapshot is active");
    expect(snapshot.purpose == Purpose::connect, "connect snapshot purpose");
    expect(strcmp(snapshot.request_id, "connect-1") == 0, "connect request id stored");
    expect(snapshot.session_id[0] == '\0', "connect stores no session id");
    expect(snapshot.request_window.started_at == 10 &&
               snapshot.request_window.deadline == 100,
           "connect request window stored");
    expect(snapshot.pin_input_window.started_at == 10 &&
               snapshot.pin_input_window.deadline == 100,
           "connect PIN input window stored");
    expect(agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
               LocalPurpose::connect,
               request_id,
               sizeof(request_id)) &&
               strcmp(request_id, "connect-1") == 0,
           "connect request id maps from local PIN purpose");
    expect(!agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
               LocalPurpose::policy_update,
               request_id,
               sizeof(request_id)),
           "connect state does not map policy update purpose");
    expect(!agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               99),
           "deadline not reached before deadline");
    expect(agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               100),
           "deadline reached at deadline");
    expect(agent_q::protocol_pin_approval_pause_deadline_for_local_pin_purpose(
               LocalPurpose::connect,
               90),
           "connect local PIN verification pauses PIN input deadline");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.request_window.deadline == 100, "connect request admission window remains recorded while PIN verifies");
    expect(snapshot.pin_input_window.started_at == 0 &&
               snapshot.pin_input_window.deadline == 0,
           "connect PIN input deadline is hidden while verification runs");
    expect(!agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               1000),
           "paused connect PIN input deadline does not keep request deadline running");
    expect(agent_q::protocol_pin_approval_refresh_deadline_for_local_pin_purpose(
               LocalPurpose::connect,
               120),
           "connect local PIN retry resumes after processing");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.pin_input_window.started_at == 40 &&
               snapshot.pin_input_window.deadline == 130,
           "connect retry resumes remaining time without resetting timer fill");
    expect(!agent_q::protocol_pin_approval_refresh_deadline_for_local_pin_purpose(
               LocalPurpose::connect,
               121),
           "connect retry cannot resume twice without a new pause");
    expect(agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               130),
           "resumed connect retry expires after remaining input time");
    expect(agent_q::protocol_pin_approval_pause_deadline_for_local_pin_purpose(
               LocalPurpose::connect,
               125),
           "connect local PIN verification can pause a resumed input window");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.request_window.deadline == 100, "connect request window remains immutable");
    expect(snapshot.pin_input_window.deadline == 0, "connect paused PIN input deadline stored");
    expect(!agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               1000),
           "paused connect PIN input deadline stays paused after resumed retry");

    char too_long[agent_q::kAgentQProtocolPinRequestIdSize + 4] = {};
    memset(too_long, 'a', sizeof(too_long) - 1);
    expect(!agent_q::protocol_pin_approval_begin_connect(too_long, 20, timeout_window(20, 200)),
           "overlong request id is rejected");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(strcmp(snapshot.request_id, "connect-1") == 0,
           "failed begin does not overwrite existing state");
    expect(!agent_q::protocol_pin_approval_begin_policy_update(
               "policy-overwrite",
               "session_aaaaaaaaaaaaaaaa",
               20,
               timeout_window(20, 225)),
           "active protocol PIN approval cannot be overwritten");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.purpose == Purpose::connect &&
               strcmp(snapshot.request_id, "connect-1") == 0,
           "rejected active overwrite leaves current state intact");

    expect(agent_q::session_replace(random_bytes, nullptr) ==
               agent_q::AgentQSessionStartResult::ok,
           "test session starts");
    const char* session_id = agent_q::session_id();
    agent_q::protocol_pin_approval_clear();
    expect(!agent_q::protocol_pin_approval_begin_connect(
               "connect-stale",
               30,
               timeout_window(10, 20)),
           "connect protocol PIN rejects stale request window");
    expect(!agent_q::protocol_pin_approval_begin_connect(
               "connect-future",
               10,
               timeout_window(20, 40)),
           "connect protocol PIN rejects future request window");
    expect(!agent_q::protocol_pin_approval_begin_policy_update(
               "policy-stale",
               session_id,
               30,
               timeout_window(10, 20)),
           "policy protocol PIN rejects stale request window");
    expect(!agent_q::protocol_pin_approval_begin_policy_update(
               "policy-future",
               session_id,
               10,
               timeout_window(20, 40)),
           "policy protocol PIN rejects future request window");
    expect(!agent_q::protocol_pin_approval_begin_sui_zklogin_proposal(
               "zklogin-stale",
               session_id,
               30,
               timeout_window(10, 20)),
           "Sui zkLogin protocol PIN rejects stale request window");
    expect(!agent_q::protocol_pin_approval_begin_sui_zklogin_proposal(
               "zklogin-future",
               session_id,
               10,
               timeout_window(20, 40)),
           "Sui zkLogin protocol PIN rejects future request window");
    expect(agent_q::protocol_pin_approval_begin_policy_update(
               "policy-1",
               session_id,
               20,
               timeout_window(20, 250)),
           "policy update protocol PIN approval begins");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.active, "policy update snapshot is active");
    expect(snapshot.purpose == Purpose::policy_update, "policy update snapshot purpose");
    expect(strcmp(snapshot.request_id, "policy-1") == 0, "policy update request id stored");
    expect(strcmp(snapshot.session_id, session_id) == 0, "policy update session id stored");
    expect(snapshot.request_window.started_at == 20 &&
               snapshot.request_window.deadline == 250,
           "policy update stores request window");
    expect(snapshot.pin_input_window.started_at == 20 &&
               snapshot.pin_input_window.deadline == 250,
           "policy update stores PIN input window");
    expect(agent_q::protocol_pin_approval_policy_update_session_matches(session_id),
           "matching policy update session recognized");
    expect(!agent_q::protocol_pin_approval_policy_update_session_matches(
               "session_aaaaaaaaaaaaaaaa"),
           "mismatched policy update session rejected");
    expect(agent_q::protocol_pin_approval_policy_update_request_id(
               request_id,
               sizeof(request_id)) &&
               strcmp(request_id, "policy-1") == 0,
           "policy update request id is available");
    expect(agent_q::protocol_pin_approval_validate_policy_update_session() ==
               SessionValidation::ok,
           "active matching session validates");

    agent_q::protocol_pin_approval_clear();
    expect(agent_q::protocol_pin_approval_begin_sui_zklogin_proposal(
               "zklogin-1",
               session_id,
               40,
               timeout_window(40, 260)),
           "Sui zkLogin protocol PIN approval begins");
    snapshot = agent_q::protocol_pin_approval_snapshot();
    expect(snapshot.active, "Sui zkLogin snapshot is active");
    expect(snapshot.purpose == Purpose::sui_zklogin_proposal, "Sui zkLogin snapshot purpose");
    expect(strcmp(snapshot.request_id, "zklogin-1") == 0, "Sui zkLogin request id stored");
    expect(strcmp(snapshot.session_id, session_id) == 0, "Sui zkLogin session id stored");
    expect(agent_q::protocol_pin_approval_request_id_for_local_pin_purpose(
               LocalPurpose::sui_zklogin_proposal,
               request_id,
               sizeof(request_id)) &&
               strcmp(request_id, "zklogin-1") == 0,
           "Sui zkLogin request id maps from local PIN purpose");
    expect(agent_q::protocol_pin_approval_sui_zklogin_proposal_session_matches(session_id),
           "matching Sui zkLogin session recognized");
    expect(!agent_q::protocol_pin_approval_sui_zklogin_proposal_session_matches(
               "session_aaaaaaaaaaaaaaaa"),
           "mismatched Sui zkLogin session rejected");
    expect(agent_q::protocol_pin_approval_sui_zklogin_proposal_request_id(
               request_id,
               sizeof(request_id)) &&
               strcmp(request_id, "zklogin-1") == 0,
           "Sui zkLogin request id is available");
    expect(agent_q::protocol_pin_approval_validate_sui_zklogin_proposal_session() ==
               SessionValidation::ok,
           "active matching Sui zkLogin session validates");
    agent_q::session_clear();
    expect(agent_q::protocol_pin_approval_validate_sui_zklogin_proposal_session() ==
               SessionValidation::missing,
           "cleared session invalidates pending Sui zkLogin proposal");

    agent_q::protocol_pin_approval_clear();
    expect(!agent_q::protocol_pin_approval_policy_update_request_id(
               request_id,
               sizeof(request_id)),
           "cleared state has no policy update request id");
    expect(!agent_q::protocol_pin_approval_sui_zklogin_proposal_request_id(
               request_id,
               sizeof(request_id)),
           "cleared state has no Sui zkLogin request id");
    expect(!agent_q::protocol_pin_approval_deadline_reached_for_local_pin_purpose(
               LocalPurpose::connect,
               1000),
           "cleared state has no reached protocol deadline");

    if (failures != 0) {
        fprintf(stderr, "%d protocol PIN approval test(s) failed\n", failures);
        return 1;
    }
    printf("Protocol PIN approval tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/protocol_pin_approval_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_protocol_pin_approval.cpp" \
  "${AGENT_Q_DIR}/agent_q_session.cpp" \
  -o "${TMP_DIR}/protocol_pin_approval_test"

"${TMP_DIR}/protocol_pin_approval_test"
check_modal_transition_owner_present
check_local_pin_ui_deadline_order
check_local_pin_clear_if_needed_dispatches_to_cleanup_helpers
check_local_pin_ui_handler_timeout_order \
  local_pin_auth_ui_handle_digit \
  'local_pin_auth_add_digit' \
  "request-backed PIN digit handler must timeout before local PIN mutation"
check_local_pin_ui_handler_timeout_order \
  local_pin_auth_ui_handle_clear \
  'local_pin_auth_clear_pin' \
  "request-backed PIN clear handler must timeout before local PIN mutation"
check_local_pin_ui_handler_timeout_order \
  local_pin_auth_ui_handle_backspace \
  'local_pin_auth_backspace_pin' \
  "request-backed PIN backspace handler must timeout before local PIN mutation"
check_local_pin_ui_handler_timeout_order \
  local_pin_auth_ui_handle_submit \
  'local_pin_auth_submit' \
  "request-backed PIN submit handler must timeout before verification start"
check_local_pin_ui_handler_timeout_order \
  local_pin_auth_ui_cancel \
  'return_policy_update_review_from_pin|usb_response_write_connect_rejected|user_signing_confirmation_return_to_review_from_pin' \
  "request-backed PIN cancel handler must timeout before cancel/back action"
check_local_pin_worker_timeout_order
check_settings_policy_reset_keeps_panel_until_completion
check_settings_sui_clear_keeps_panel_until_completion
check_connect_pin_completion_uses_connect_callbacks
check_local_pin_request_id_lookup_uses_app_callback
check_policy_sui_pin_completion_uses_owner_callbacks
check_policy_update_keeps_panel_until_commit
check_user_signing_keeps_panel_until_signing_work
check_local_pin_ops_surface_is_grouped
check_modal_transition_next_panel_order
check_settings_completion_uses_transition_owner
check_no_flow_local_pin_clear_helper
