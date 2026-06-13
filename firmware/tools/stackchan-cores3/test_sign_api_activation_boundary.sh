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
signing route names and must not expose host-selectable authorization APIs.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
USB_SERVER="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_request_server.cpp"
USB_APPROVAL_HISTORY_HANDLER_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_approval_history_handler.cpp"
USB_CONNECT_HANDLER_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_connect_handler.cpp"
USB_OPERATION_TYPE_HEADER="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_operation_type.h"
USB_OPERATION_RESPONSE_WRITER_HEADER="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_operation_response_writer.h"
USB_OPERATION_DISPATCH_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_operation_dispatch.cpp"
USB_ENVELOPE_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_request_envelope.cpp"
USB_LINE_RECEIVER_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_line_receiver.cpp"
UI_EVENT_BRIDGE_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_ui_event_bridge.cpp"
USB_LINE_HANDLER_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_request_line_handler.cpp"
USB_DEVICE_HANDLERS_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_device_handlers.cpp"
USB_DISCONNECT_HANDLER_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_disconnect_handler.cpp"
USB_SIGNING_RESULT_WRITER_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_signing_result_writer.cpp"
USB_RETAINED_RESULT_HANDLERS_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_retained_result_handlers.cpp"
USB_SESSION_READ_HANDLERS_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_session_read_handlers.cpp"
USB_POLICY_PROPOSE_HANDLER_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_policy_propose_handler.cpp"
USB_POLICY_PROPOSE_RESULT_WRITER_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_policy_propose_result_writer.cpp"
USB_SIGNING_HANDLER_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_usb_signing_handlers.cpp"
CONNECT_REVIEW_RESPONSE_FLOW_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_connect_review_response_flow.cpp"
LOCAL_SETTINGS_RESET_UI_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_local_settings_reset_ui_flow.cpp"
LOCAL_PIN_AUTH_UI_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_local_pin_auth_ui_flow.cpp"
POLICY_UPDATE_REVIEW_UI_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_policy_update_review_ui_flow.cpp"
USER_SIGNING_REVIEW_UI_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_user_signing_review_ui_flow.cpp"
REQUEST_BACKED_LOCAL_PIN_CONTEXT_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_request_backed_local_pin_context.cpp"
TRANSIENT_UI_FLOW_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_transient_ui_flow.cpp"
SIGNING_PREFLIGHT_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_signing_preflight.cpp"
POLICY_SIGNING_EXECUTION_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_policy_signing_execution.cpp"
USER_REVIEW_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_user_signing_review_view_model.cpp"
USER_SIGNING_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_user_signing_critical_section.cpp"
USER_SIGNING_CONFIRMATION_SOURCE="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q/agent_q_user_signing_confirmation.cpp"
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

usb_stack_expr="$(sed -n 's/.*kUsbRequestTaskStackBytes = \(.*\);/\1/p' "${USB_SERVER}" | head -n 1)"
if [[ -z "${usb_stack_expr}" ]]; then
  echo "FAILED: USB request task stack size must be declared" >&2
  failures=$((failures + 1))
else
  usb_stack_bytes=$((usb_stack_expr))
  if (( usb_stack_bytes < 32768 )); then
    echo "FAILED: USB request task stack must be at least 32768 bytes" >&2
    failures=$((failures + 1))
  fi
fi

expect_present "${USB_SIGNING_HANDLER_SOURCE}" 'g_sign_transaction_preflight_scratch' \
  "USB signing handler must keep large transaction preflight scratch off the USB task stack"
expect_absent "${USB_SIGNING_HANDLER_SOURCE}" 'AgentQSignTransactionPreflightOutput[[:space:]]+preflight[[:space:]]*(=|;)' \
  "USB signing handler must not allocate transaction preflight output as a stack local"
expect_present "${USER_FLOW_HEADER}" 'AgentQUserSigningFlowCoreSnapshot' \
  "user signing flow must expose a small core snapshot for non-review lifecycle paths"
expect_present "${USER_FLOW_HEADER}" 'user_signing_flow_snapshot_copy' \
  "user signing flow must expose caller-owned review snapshot copying for large review details"
expect_present "${USER_SIGNING_REVIEW_UI_SOURCE}" 'g_review_snapshot_scratch' \
  "user signing review UI must keep large review snapshots off the task stack"
expect_absent "${USER_SIGNING_REVIEW_UI_SOURCE}" 'AgentQUserSigningFlowSnapshot[[:space:]]+[A-Za-z_]+[[:space:]]*=' \
  "user signing review UI must not allocate large review snapshots as stack locals"
expect_absent "${USB_SERVER}" 'AgentQUserSigningFlowSnapshot[[:space:]]+[A-Za-z_]+[[:space:]]*=' \
  "USB request server must use the small user-signing core snapshot outside review rendering"
expect_absent "${USER_SIGNING_SOURCE}" 'AgentQUserSigningFlowSnapshot' \
  "user signing critical section must not copy large review snapshots"
expect_absent "${USER_SIGNING_CONFIRMATION_SOURCE}" 'AgentQUserSigningFlowSnapshot' \
  "user signing confirmation must not bind or copy large review snapshots"
expect_absent "${REQUEST_BACKED_LOCAL_PIN_CONTEXT_SOURCE}" 'AgentQUserSigningFlowSnapshot' \
  "request-backed local PIN context must not copy large review snapshots"

expect_present "${USB_OPERATION_TYPE_HEADER}" '"sign_transaction"' \
  "USB operation classifier must accept public sign_transaction messages"
expect_absent "${USB_OPERATION_TYPE_HEADER}" '"sign_transaction_user"|"sign_transaction_policy"' \
  "USB operation classifier must not accept host-selected authorization request types"
expect_present "${USB_SIGNING_RESULT_WRITER_SOURCE}" '"sign_result"|usb_signing_result_write' \
  "USB signing result writer must own public sign_result responses"
expect_absent "${USB_SERVER}" 'response\["type"\][[:space:]]*=[[:space:]]*"sign_result"|write_sign_result_signed|write_sign_result_user_terminal|write_sign_result_policy_rejected|write_sign_result_signing_failed' \
  "USB request server must not own public sign_result response JSON"
expect_present "${USB_SESSION_READ_HANDLERS_SOURCE}" '"signing"' \
  "session-read handler must advertise shared signing capabilities"
expect_present "${USB_OPERATION_RESPONSE_WRITER_HEADER}" 'AgentQUsbOperationResponseWriter' \
  "USB operation response writer boundary must be shared outside the USB server"
expect_present "${USB_OPERATION_DISPATCH_SOURCE}" 'dispatch_usb_operation' \
  "USB operation dispatch boundary must live outside the USB server"
expect_present "${USB_OPERATION_DISPATCH_SOURCE}" 'AgentQUsbOperationHandlers' \
  "USB operation dispatch boundary must route through an explicit handler table"
expect_present "${USB_SERVER}" 'usb_operation_handlers' \
  "USB request server must provide its public operation handler table"
expect_present "${USB_SERVER}" 'handle_usb_request_line' \
  "USB request server must route public request lines through the extracted line handler"
expect_present "${USB_LINE_RECEIVER_SOURCE}" 'usb_serial_jtag_read_bytes' \
  "USB line receiver must own physical USB serial reads"
expect_present "${USB_SERVER}" 'usb_line_receiver_poll' \
  "USB request server must delegate physical line receive to the extracted line receiver"
expect_absent "${USB_SERVER}" 'usb_request_line_feed|g_line_buffer|g_line_size|g_discarding_invalid_line' \
  "USB request server must not own line-framing accumulator state"
expect_present "${UI_EVENT_BRIDGE_SOURCE}" 'modal_drawing_set_callbacks' \
  "UI event bridge must own modal callback registration"
expect_present "${UI_EVENT_BRIDGE_SOURCE}" 'xQueueCreate' \
  "UI event bridge must own UI input queues"
expect_present "${USB_SERVER}" 'ui_event_bridge_receive' \
  "USB request server must consume UI events through the bridge"
expect_present "${LOCAL_SETTINGS_RESET_UI_SOURCE}" 'local_settings_reset_ui_clear_if_needed' \
  "local settings/reset UI flow must own reset timeout and panel-loss cleanup"
expect_present "${LOCAL_SETTINGS_RESET_UI_SOURCE}" 'local_settings_reset_ui_handle_auth_worker_result' \
  "local settings/reset UI flow must own reset PIN worker-result handling"
expect_present "${LOCAL_SETTINGS_RESET_UI_SOURCE}" 'local_settings_reset_ui_commit_if_ready' \
  "local settings/reset UI flow must own destructive reset commit handling"
expect_present "${USB_SERVER}" 'local_settings_reset_ui_clear_if_needed' \
  "USB request server maintenance phase must delegate local settings/reset cleanup"
expect_present "${USB_SERVER}" 'local_settings_reset_ui_handle_auth_worker_result' \
  "USB request server must delegate local reset auth worker results"
expect_absent "${USB_SERVER}" 'local_reset_submit_pin_for_verification|local_reset_complete_pin_verify_job|local_reset_commit_material' \
  "USB request server must not own local reset PIN verification or destructive reset commit logic"
expect_present "${LOCAL_PIN_AUTH_UI_SOURCE}" 'local_pin_auth_ui_handle_verify_worker_result' \
  "local PIN auth UI flow must own PIN verifier worker-result handling"
expect_present "${LOCAL_PIN_AUTH_UI_SOURCE}" 'local_pin_auth_ui_clear_if_needed' \
  "local PIN auth UI flow must own timeout and panel-loss cleanup"
expect_present "${LOCAL_PIN_AUTH_UI_SOURCE}" 'local_pin_auth_ui_commit_setting_if_ready' \
  "local PIN auth UI flow must own local PIN setting commit handling"
expect_present "${LOCAL_PIN_AUTH_UI_SOURCE}" 'local_pin_auth_ui_cancel' \
  "local PIN auth UI flow must own local PIN cancellation terminal effects"
expect_present "${USB_SERVER}" 'local_pin_auth_ui_handle_verify_worker_result' \
  "USB request server must delegate local PIN auth verifier worker results"
expect_present "${USB_SERVER}" 'local_pin_auth_ui_clear_if_needed' \
  "USB request server maintenance phase must delegate local PIN auth cleanup"
expect_absent "${USB_SERVER}" 'local_pin_auth_complete_verify_job|user_signing_confirmation_complete_pin_verify_job_and_write_history|local_pin_auth_fail_processing_if_expired|local_pin_auth_release_lockout_if_elapsed|request_backed_local_pin_deadline_reached|request_backed_local_pin_resume_input_window|request_backed_local_pin_pause_input_window' \
  "USB request server must not own local PIN verification, lockout, timeout, or request-backed input-window effects"
expect_present "${POLICY_UPDATE_REVIEW_UI_SOURCE}" 'policy_update_review_ui_continue' \
  "policy update review UI flow must own continue-to-PIN lifecycle effects"
expect_present "${POLICY_UPDATE_REVIEW_UI_SOURCE}" 'policy_update_review_ui_reject' \
  "policy update review UI flow must own reject terminal effects"
expect_present "${POLICY_UPDATE_REVIEW_UI_SOURCE}" 'policy_update_review_ui_clear_if_needed' \
  "policy update review UI flow must own timeout and panel-recovery effects"
expect_present "${USER_SIGNING_REVIEW_UI_SOURCE}" 'user_signing_review_ui_accept' \
  "user signing review UI flow must own accept/PIN/signing entry effects"
expect_present "${USER_SIGNING_REVIEW_UI_SOURCE}" 'user_signing_review_ui_reject' \
  "user signing review UI flow must own reject terminal effects"
expect_present "${USER_SIGNING_REVIEW_UI_SOURCE}" 'user_signing_review_ui_clear_if_needed' \
  "user signing review UI flow must own timeout and panel-recovery effects"
expect_present "${USB_SERVER}" 'policy_update_review_ui_continue' \
  "USB request server must delegate policy update review continue handling"
expect_present "${USB_SERVER}" 'policy_update_review_ui_clear_if_needed' \
  "USB request server maintenance phase must delegate policy update review cleanup"
expect_present "${USB_SERVER}" 'user_signing_review_ui_accept' \
  "USB request server must delegate user signing review accept handling"
expect_present "${USB_SERVER}" 'user_signing_review_ui_clear_if_needed' \
  "USB request server maintenance phase must delegate user signing review cleanup"
expect_present "${REQUEST_BACKED_LOCAL_PIN_CONTEXT_SOURCE}" 'request_backed_local_pin_owner_for_purpose' \
  "request-backed local PIN context must own purpose-to-owner classification"
expect_present "${REQUEST_BACKED_LOCAL_PIN_CONTEXT_SOURCE}" 'request_backed_local_pin_cap_input_window' \
  "request-backed local PIN context must own request-window capping"
expect_present "${REQUEST_BACKED_LOCAL_PIN_CONTEXT_SOURCE}" 'request_backed_local_pin_pause_input_window' \
  "request-backed local PIN context must own request-backed pause delegation"
expect_present "${REQUEST_BACKED_LOCAL_PIN_CONTEXT_SOURCE}" 'request_backed_local_pin_resume_input_window' \
  "request-backed local PIN context must own request-backed resume delegation"
expect_absent "${USB_SERVER}" 'RequestBackedPinOwner|request_backed_pin_owner_for_purpose|protocol_pin_approval_refresh_deadline_for_local_pin_purpose|protocol_pin_approval_pause_deadline_for_local_pin_purpose|user_signing_flow_refresh_pin_deadline|user_signing_confirmation_mark_pin_verification_started' \
  "USB request server must not own request-backed local PIN owner/deadline delegation"
expect_absent "${USB_SERVER}" 'g_ui_event_queue|g_connect_review_choice_queue|modal_drawing_set_callbacks|drawing_surface_set_panel_deleted_callback|xQueueCreate|xQueueSend|xQueueReceive|on_(connect_review|user_signing_review|policy_update_review|setup|settings|error_recovery|reset|backup_phrase|pin|import).*clicked' \
  "USB request server must not own LVGL callback or UI input queue wiring"
expect_present "${USB_LINE_HANDLER_SOURCE}" 'parse_usb_request_envelope' \
  "USB line handler must parse request envelopes through the extracted helper"
expect_present "${USB_LINE_HANDLER_SOURCE}" 'dispatch_usb_operation' \
  "USB line handler must delegate to the extracted dispatch helper"
expect_present "${USB_ENVELOPE_SOURCE}" 'classify_usb_operation_type' \
  "USB envelope parser must use the public operation classifier"
expect_present "${USB_LINE_HANDLER_SOURCE}" 'operation_type' \
  "USB line handler dispatch must use typed operation ids from the parsed envelope"
expect_present "${USB_DEVICE_HANDLERS_SOURCE}" 'handle_usb_get_status_request' \
  "get_status operation handler must live outside the USB server"
expect_present "${USB_SERVER}" 'handle_usb_get_status_request' \
  "USB request server handler table must route get_status to the extracted handler"
expect_present "${USB_SERVER}" 'handle_identify_device_request' \
  "USB request server must route identify_device through an injected operation wrapper"
expect_present "${USB_DEVICE_HANDLERS_SOURCE}" 'handle_usb_identify_device_request' \
  "identify_device operation handler must live outside the USB server"
expect_present "${USB_SERVER}" 'handle_connect_request' \
  "USB request server must route connect through an operation handler"
expect_present "${USB_CONNECT_HANDLER_SOURCE}" 'handle_usb_connect_request' \
  "connect operation handler must live outside the USB server"
expect_present "${USB_SERVER}" 'handle_get_result_request' \
  "USB request server must route get_result through an injected operation wrapper"
expect_present "${USB_RETAINED_RESULT_HANDLERS_SOURCE}" 'handle_usb_get_result_request' \
  "get_result operation handler must live outside the USB server"
expect_present "${USB_RETAINED_RESULT_HANDLERS_SOURCE}" 'signing_result_find' \
  "retained-result handler must own stored-result lookup"
expect_present "${USB_SERVER}" 'handle_ack_result_request' \
  "USB request server must route ack_result through an injected operation wrapper"
expect_present "${USB_RETAINED_RESULT_HANDLERS_SOURCE}" 'handle_usb_ack_result_request' \
  "ack_result operation handler must live outside the USB server"
expect_present "${USB_RETAINED_RESULT_HANDLERS_SOURCE}" 'signing_result_ack' \
  "retained-result handler must own stored-result ack"
expect_absent "${USB_SERVER}" 'try_deliver_stored_result_by_id|ack_stored_result_by_id' \
  "USB request server must not own retained signing-result store adapters"
expect_present "${USB_SERVER}" 'handle_get_capabilities_request' \
  "USB request server must route get_capabilities through an operation handler"
expect_present "${USB_SESSION_READ_HANDLERS_SOURCE}" 'handle_usb_get_capabilities_request' \
  "get_capabilities operation handler must live outside the USB server"
expect_present "${USB_SERVER}" 'handle_get_accounts_request' \
  "USB request server must route get_accounts through an operation handler"
expect_present "${USB_SESSION_READ_HANDLERS_SOURCE}" 'handle_usb_get_accounts_request' \
  "get_accounts operation handler must live outside the USB server"
expect_present "${USB_SERVER}" 'handle_policy_get_request' \
  "USB request server must route policy_get through an operation handler"
expect_present "${USB_SESSION_READ_HANDLERS_SOURCE}" 'handle_usb_policy_get_request' \
  "policy_get operation handler must live outside the USB server"
expect_present "${USB_SERVER}" 'handle_disconnect_request' \
  "USB request server must route disconnect through an operation handler"
expect_present "${USB_DISCONNECT_HANDLER_SOURCE}" 'handle_usb_disconnect_request' \
  "disconnect operation handler must live outside the USB server"
expect_present "${USB_SERVER}" 'handle_get_approval_history_request' \
  "USB request server must route get_approval_history through an operation handler"
expect_present "${USB_APPROVAL_HISTORY_HANDLER_SOURCE}" 'handle_usb_get_approval_history_request' \
  "get_approval_history operation handler must live outside the USB server"
expect_present "${USB_APPROVAL_HISTORY_HANDLER_SOURCE}" 'response\["type"\][[:space:]]*=[[:space:]]*"approval_history"' \
  "get_approval_history handler must own approval_history response JSON"
expect_present "${USB_APPROVAL_HISTORY_HANDLER_SOURCE}" 'read_approval_history_page' \
  "get_approval_history handler must own approval-history page read dispatch"
expect_absent "${USB_SERVER}" 'response\["type"\][[:space:]]*=[[:space:]]*"approval_history"|write_approval_history_response' \
  "USB request server must not own approval_history response JSON"
expect_present "${USB_SERVER}" 'handle_policy_propose_request' \
  "USB request server must route policy_propose through an operation handler"
expect_present "${USB_POLICY_PROPOSE_HANDLER_SOURCE}" 'handle_usb_policy_propose_request' \
  "policy_propose operation handler must live outside the USB server"
expect_present "${USB_POLICY_PROPOSE_RESULT_WRITER_SOURCE}" 'response\["type"\][[:space:]]*=[[:space:]]*"policy_propose_result"' \
  "policy_propose result writer must own policy_propose_result response JSON"
expect_absent "${USB_SERVER}" 'response\["type"\][[:space:]]*=[[:space:]]*"policy_propose_result"|write_policy_propose_result_response' \
  "USB request server must not own policy_propose_result response JSON"
expect_present "${USB_SERVER}" 'handle_sign_transaction_request' \
  "USB request server must route sign_transaction through an operation handler"
expect_present "${USB_SERVER}" 'handle_sign_personal_message_request' \
  "USB request server must route sign_personal_message through an operation handler"
expect_present "${USB_SIGNING_HANDLER_SOURCE}" 'handle_usb_sign_transaction_request' \
  "sign_transaction operation handler must live outside the USB server"
expect_present "${USB_SIGNING_HANDLER_SOURCE}" 'handle_usb_sign_personal_message_request' \
  "sign_personal_message operation handler must live outside the USB server"
expect_present "${USB_SIGNING_HANDLER_SOURCE}" 'begin_transaction_user_signing|begin_personal_message_user_signing' \
  "extracted signing handler must enter user-confirmed authorization through injected state owners"
expect_present "${USB_SIGNING_HANDLER_SOURCE}" 'evaluate_transaction_policy' \
  "extracted signing handler must call policy authorization runtime through injected dependencies"
expect_present "${USB_SIGNING_HANDLER_SOURCE}" 'execute_policy_transaction' \
  "extracted signing handler must delegate policy signing execution through injected dependencies"
expect_present "${POLICY_SIGNING_EXECUTION_SOURCE}" 'write_policy_signing_confirmation_history' \
  "policy signing execution owner must own policy confirmation history writes"
expect_present "${POLICY_SIGNING_EXECUTION_SOURCE}" 'sign_sui_ed25519_transaction_from_stored_root' \
  "policy signing execution owner must own policy signing critical section"
expect_absent "${USB_SERVER}" 'write_policy_signing_confirmation_history|write_policy_signing_terminal_history|sign_sui_ed25519_transaction_from_stored_root' \
  "USB request server must not assemble policy signing history/signing directly"
expect_present "${USB_SERVER}" 'read_signing_authorization_mode' \
  "USB request server must supply Firmware-local signing authorization mode"
expect_present "${USB_SERVER}" 'user_signing_flow_begin' \
  "USB request server must supply user-confirmed flow dependencies"

SIGN_TRANSACTION_BRANCH_SNIPPET="${TMP_DIR}/sign-transaction-branch.cpp"
SIGN_TRANSACTION_PREFLIGHT_SNIPPET="${TMP_DIR}/sign-transaction-preflight.cpp"
COMMON_POST_INGRESS_PREFLIGHT_SNIPPET="${TMP_DIR}/common-post-ingress-preflight.cpp"
POST_IDENTITY_PREFLIGHT_SNIPPET="${TMP_DIR}/post-identity-preflight.cpp"
awk '
  /AgentQSigningPreflightResult evaluate_post_identity_preflight/ { capture = 1 }
  capture { print }
  /AgentQSigningPreflightResult evaluate_common_post_ingress_preflight/ { capture = 0 }
' "${SIGNING_PREFLIGHT_SOURCE}" >"${POST_IDENTITY_PREFLIGHT_SNIPPET}"
awk '
  /AgentQSigningPreflightResult evaluate_common_post_ingress_preflight/ { capture = 1 }
  capture { print }
  /^}  \/\/ namespace/ { capture = 0 }
' "${SIGNING_PREFLIGHT_SOURCE}" >"${COMMON_POST_INGRESS_PREFLIGHT_SNIPPET}"
awk '
  /AgentQSigningPreflightResult evaluate_sign_transaction_preflight/ { capture = 1 }
  capture { print }
  /AgentQSigningPreflightResult evaluate_sign_personal_message_preflight/ { capture = 0 }
' "${SIGNING_PREFLIGHT_SOURCE}" >"${SIGN_TRANSACTION_PREFLIGHT_SNIPPET}"
awk '
  /void handle_usb_sign_transaction_request/ { capture = 1 }
  capture { print }
  /void handle_usb_sign_personal_message_request/ { capture = 0 }
' "${USB_SIGNING_HANDLER_SOURCE}" >"${SIGN_TRANSACTION_BRANCH_SNIPPET}"
expect_present "${SIGN_TRANSACTION_BRANCH_SNIPPET}" 'make_preflight_runtime\(ops\)' \
  "sign_transaction handler snippet must be captured"
expect_present "${SIGN_TRANSACTION_BRANCH_SNIPPET}" 'evaluate_transaction_preflight' \
  "sign_transaction handler must delegate signing preflight to the extracted helper"
expect_order "${SIGN_TRANSACTION_BRANCH_SNIPPET}" 'evaluate_transaction_preflight' 'handle_sign_transaction_policy_mode' \
  "sign_transaction policy authorization must consume prepared Sui transaction data"
expect_order "${SIGN_TRANSACTION_BRANCH_SNIPPET}" 'evaluate_transaction_preflight' 'begin_transaction_user_signing' \
  "sign_transaction user authorization must consume prepared Sui transaction data"
expect_order "${SIGN_TRANSACTION_PREFLIGHT_SNIPPET}" 'classify_sign_route\(AgentQSignOperation::sign_transaction' 'evaluate_sign_transaction_user_ingress' \
  "sign_transaction preflight must identify the route before state/session work"
expect_order "${SIGN_TRANSACTION_PREFLIGHT_SNIPPET}" 'evaluate_sign_transaction_user_ingress' 'evaluate_common_post_ingress_preflight' \
  "sign_transaction preflight must complete before common request identity/retry work"
expect_order "${COMMON_POST_INGRESS_PREFLIGHT_SNIPPET}" 'sign_request_identity' 'evaluate_post_identity_preflight' \
  "common signing preflight must bind request identity before post-identity replay work"
expect_order "${POST_IDENTITY_PREFLIGHT_SNIPPET}" 'retry_allows_preflight_to_continue' 'read_signing_mode' \
  "common signing preflight replay must complete before reading signing mode"
expect_order "${SIGN_TRANSACTION_PREFLIGHT_SNIPPET}" 'evaluate_common_post_ingress_preflight' 'prepare_sui_sign_transaction' \
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
  /void handle_usb_sign_personal_message_request/ { capture = 1 }
  capture { print }
  /^}  \/\/ namespace agent_q/ { capture = 0 }
' "${USB_SIGNING_HANDLER_SOURCE}" >"${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}"
expect_present "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'make_preflight_runtime\(ops\)' \
  "sign_personal_message handler snippet must be captured"
expect_present "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'evaluate_personal_message_preflight' \
  "sign_personal_message handler must delegate signing preflight to the extracted helper"
expect_order "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'evaluate_personal_message_preflight' 'begin_personal_message_user_signing' \
  "sign_personal_message user authorization must consume prepared Sui message data"
expect_order "${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}" 'classify_sign_route\(AgentQSignOperation::sign_personal_message' 'evaluate_sign_personal_message_user_ingress' \
  "sign_personal_message must identify the route before state/session work"
expect_order "${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}" 'evaluate_sign_personal_message_user_ingress' 'evaluate_common_post_ingress_preflight' \
  "sign_personal_message preflight must complete before common request identity/retry work"
expect_order "${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}" 'evaluate_common_post_ingress_preflight' 'prepare_sui_sign_personal_message' \
  "sign_personal_message replay must complete before Sui adapter preparation"
expect_order "${SIGN_PERSONAL_MESSAGE_INGRESS_SOURCE}" 'if \(!state\.material_ready\)' 'validate_sign_personal_message_user_session_format' \
  "sign_personal_message preflight must check state before session format"
expect_order "${SIGN_PERSONAL_MESSAGE_INGRESS_SOURCE}" 'validate_sign_personal_message_user_session_format' 'validate_sign_personal_message_user_envelope' \
  "sign_personal_message preflight must check session before exact envelope"
expect_order "${SIGN_PERSONAL_MESSAGE_INGRESS_SOURCE}" 'validate_sign_personal_message_user_envelope' 'validate_sign_personal_message_user_params' \
  "sign_personal_message preflight must exact-check the request before shallow params"
expect_present "${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}" 'AgentQSigningAuthorizationMode::policy' \
  "sign_personal_message branch must explicitly handle policy mode"
expect_present "${USB_SIGNING_HANDLER_SOURCE}" 'sign_personal_message is not available in policy authorization mode' \
  "sign_personal_message policy mode must fail closed as unsupported"
expect_present "${SIGN_PERSONAL_MESSAGE_PREFLIGHT_SNIPPET}" 'evaluate_sign_personal_message_user_ingress' \
  "sign_personal_message user mode must use the method-specific ingress owner"
expect_absent "${USB_SERVER}" 'decode_sign_personal_message_request' \
  "USB request server must not inline-decode sign_personal_message params"
expect_present "${SIGN_PERSONAL_MESSAGE_BRANCH_SNIPPET}" 'begin_personal_message_user_signing' \
  "sign_personal_message user mode must enter the user-confirmed flow owner"

expect_present "${USER_FLOW_HEADER}" 'AgentQSigningRoute signing_route' \
  "user signing flow snapshot must carry verified signing route identity"
expect_present "${USER_SIGNING_HEADER}" 'AgentQSigningRoute signing_route' \
  "user signing output must carry verified signing route identity"
expect_present "${USER_REVIEW_SOURCE}" 'snapshot\.signing_route' \
  "clear-signing review must branch on verified signing route identity"
expect_absent "${USER_REVIEW_SOURCE}" 'strcmp\(snapshot\.method' \
  "clear-signing review must not branch on raw snapshot method strings"
expect_absent "${USER_REVIEW_SOURCE}" 'classify_signing_route' \
  "clear-signing review must not reclassify raw method strings"
expect_present "${USER_SIGNING_SOURCE}" 'snapshot\.signing_route' \
  "signing critical section must branch on verified signing route identity"
expect_absent "${USER_SIGNING_SOURCE}" 'strcmp\(snapshot\.method' \
  "signing critical section must not branch on raw snapshot method strings"
expect_absent "${USER_SIGNING_SOURCE}" 'classify_signing_route' \
  "signing critical section must not reclassify raw method strings"
expect_absent "${USB_SERVER}" 'classify_signing_route' \
  "sign_result writer must not reclassify raw method strings"
expect_absent "${POLICY_SIGNING_EXECUTION_SOURCE}" 'classify_sui_sign_transaction|base64_to_bytes|approval_history_digest_payload' \
  "policy signing execution must consume prepared signing data, not re-prepare transaction bytes"
expect_absent "${USER_SIGNING_SOURCE}" 'classify_sui_sign_transaction|base64_to_bytes|approval_history_digest_payload|derive_sui_ed25519_account_from_stored_root' \
  "user signing critical section must consume prepared signing data, not re-prepare payloads"

USER_BRANCH_SNIPPET="${TMP_DIR}/sign-transaction-user-branch.cpp"
awk '
  /evaluate_transaction_preflight/ { capture = 1 }
  capture { print }
  /show_user_signing_review/ { capture = 0 }
' "${USB_SIGNING_HANDLER_SOURCE}" >"${USER_BRANCH_SNIPPET}"
expect_present "${USER_BRANCH_SNIPPET}" 'begin_transaction_user_signing' \
  "extracted signing handler user branch snippet must be captured"
expect_absent "${USER_BRANCH_SNIPPET}" 'write_policy_signing_confirmation_history' \
  "extracted signing handler user branch must not record policy authorization"

HANDLE_LINE_SNIPPET="${TMP_DIR}/handle-line.cpp"
awk '
  /void handle_line/ { capture = 1 }
  capture { print }
  /void poll_usb_input/ { capture = 0 }
' "${USB_SERVER}" >"${HANDLE_LINE_SNIPPET}"
expect_present "${HANDLE_LINE_SNIPPET}" 'handle_usb_request_line' \
  "handle_line must delegate line-level envelope parsing and operation dispatch"
expect_absent "${HANDLE_LINE_SNIPPET}" 'classify_usb_operation_type' \
  "handle_line must not directly classify raw type strings"
expect_absent "${HANDLE_LINE_SNIPPET}" 'parse_usb_request_envelope|dispatch_usb_operation' \
  "handle_line must not own envelope parsing or operation dispatch"
expect_absent "${HANDLE_LINE_SNIPPET}" 'strcmp\(type' \
  "handle_line must not own request-specific operation branching"
expect_absent "${HANDLE_LINE_SNIPPET}" 'handle_(get_status|identify_device|connect|sign_transaction|sign_personal_message|get_result|ack_result|disconnect|get_capabilities|get_accounts|policy_get|get_approval_history|policy_propose)_request' \
  "handle_line must not call operation handlers directly"

USB_TICK_SNIPPET="${TMP_DIR}/usb-request-server-tick.cpp"
awk '
  /void run_usb_request_server_tick/ { capture = 1 }
  capture { print }
  /void usb_request_task/ { capture = 0 }
' "${USB_SERVER}" >"${USB_TICK_SNIPPET}"
expect_order "${USB_TICK_SNIPPET}" 'run_usb_request_server_maintenance_phase' 'run_usb_request_server_local_ui_phase' \
  "USB request server tick must run maintenance before local UI events"
expect_order "${USB_TICK_SNIPPET}" 'run_usb_request_server_local_ui_phase' 'run_usb_request_server_connect_response_phase' \
  "USB request server tick must process local UI state before connect responses"
expect_order "${USB_TICK_SNIPPET}" 'run_usb_request_server_connect_response_phase' 'run_usb_request_server_transport_phase' \
  "USB request server tick must resolve connect responses before USB transport polling"

USB_CONNECT_RESPONSE_PHASE_SNIPPET="${TMP_DIR}/usb-connect-response-phase.cpp"
awk '
  /void run_usb_request_server_connect_response_phase/ { capture = 1 }
  capture { print }
  /void run_usb_request_server_transport_phase/ { capture = 0 }
' "${USB_SERVER}" >"${USB_CONNECT_RESPONSE_PHASE_SNIPPET}"
expect_present "${USB_CONNECT_RESPONSE_PHASE_SNIPPET}" 'run_connect_review_response_flow' \
  "USB connect-response phase must delegate connect review terminal response and recovery"
expect_absent "${USB_CONNECT_RESPONSE_PHASE_SNIPPET}" 'send_connect_review_response_if_needed|ensure_connect_review_ui|connect_approval_deadline_reached|replace_active_session' \
  "USB connect-response phase must not inline connect review terminal response logic"
expect_present "${CONNECT_REVIEW_RESPONSE_FLOW_SOURCE}" 'connect_review_response_flow_run' \
  "connect review response flow must own the connect response phase"
expect_present "${CONNECT_REVIEW_RESPONSE_FLOW_SOURCE}" 'drain_connect_review_choice_events' \
  "connect review response flow must drain connect review choices"
expect_present "${CONNECT_REVIEW_RESPONSE_FLOW_SOURCE}" 'send_connect_terminal_response_if_needed' \
  "connect review response flow must send terminal connect responses"
expect_present "${CONNECT_REVIEW_RESPONSE_FLOW_SOURCE}" 'ensure_connect_review_ui' \
  "connect review response flow must recover missing connect review UI after response handling"
expect_order "${CONNECT_REVIEW_RESPONSE_FLOW_SOURCE}" 'send_connect_terminal_response_if_needed' 'ensure_connect_review_ui' \
  "connect review response flow must write terminal response before recovering connect review UI"

USB_TRANSPORT_PHASE_SNIPPET="${TMP_DIR}/usb-transport-phase.cpp"
awk '
  /void run_usb_request_server_transport_phase/ { capture = 1 }
  capture { print }
  /void run_usb_request_server_tick/ { capture = 0 }
' "${USB_SERVER}" >"${USB_TRANSPORT_PHASE_SNIPPET}"
expect_present "${USB_TRANSPORT_PHASE_SNIPPET}" 'poll_usb_host_connection' \
  "USB transport phase must poll host-link state before line input"
expect_present "${USB_TRANSPORT_PHASE_SNIPPET}" 'poll_usb_input' \
  "USB transport phase must poll request-line input"
expect_order "${USB_TRANSPORT_PHASE_SNIPPET}" 'poll_usb_host_connection' 'poll_usb_input' \
  "USB transport phase must poll host-link state before reading new input"

expect_present "${TRANSIENT_UI_FLOW_SOURCE}" 'transient_ui_show_identification_code' \
  "temporary identification display lifecycle must live in transient UI flow"
expect_present "${TRANSIENT_UI_FLOW_SOURCE}" 'transient_ui_clear_identification_if_needed' \
  "temporary identification expiry must live in transient UI flow"
expect_present "${TRANSIENT_UI_FLOW_SOURCE}" 'transient_ui_clear_message_if_needed' \
  "temporary message expiry must live in transient UI flow"
expect_present "${USB_SERVER}" 'transient_ui_show_identification_code' \
  "USB request server must delegate identification display to transient UI flow"
expect_present "${USB_SERVER}" 'transient_ui_clear_identification_if_needed' \
  "USB request server must delegate identification expiry to transient UI flow"
expect_present "${USB_SERVER}" 'transient_ui_clear_message_if_needed' \
  "USB request server must delegate message expiry to transient UI flow"
USB_CLEAR_IDENTIFICATION_SNIPPET="${TMP_DIR}/usb-clear-identification.cpp"
awk '
  /void clear_identification_if_needed/ { capture = 1 }
  capture { print }
  /void clear_agent_q_message_if_needed/ { capture = 0 }
' "${USB_SERVER}" >"${USB_CLEAR_IDENTIFICATION_SNIPPET}"
expect_absent "${USB_CLEAR_IDENTIFICATION_SNIPPET}" 'identification_display_deadline_reached|avatar_overlay_mode\(\)|avatar_overlay_clear' \
  "USB clear_identification_if_needed must not inline temporary identification expiry logic"
USB_CLEAR_MESSAGE_SNIPPET="${TMP_DIR}/usb-clear-message.cpp"
awk '
  /void clear_agent_q_message_if_needed/ { capture = 1 }
  capture { print }
  /void clear_connect_review_state/ { capture = 0 }
' "${USB_SERVER}" >"${USB_CLEAR_MESSAGE_SNIPPET}"
expect_absent "${USB_CLEAR_MESSAGE_SNIPPET}" 'avatar_overlay_message_deadline_reached|avatar_overlay_clear' \
  "USB clear_agent_q_message_if_needed must not inline temporary message expiry logic"

expect_present "${USB_CONNECT_HANDLER_SOURCE}" "connect request contains unsupported fields" \
  "extracted connect handler must exact-check top-level request fields"
expect_present "${USB_POLICY_PROPOSE_HANDLER_SOURCE}" "policy_propose request contains unsupported fields" \
  "extracted policy_propose handler must exact-check top-level request fields"
expect_present "${USB_DEVICE_HANDLERS_SOURCE}" "get_status request contains unsupported fields" \
  "extracted get_status handler must exact-check top-level request fields"
expect_present "${USB_DEVICE_HANDLERS_SOURCE}" "identify_device request contains unsupported fields" \
  "extracted identify_device handler must exact-check top-level request fields"
expect_present "${USB_RETAINED_RESULT_HANDLERS_SOURCE}" "get_result request contains unsupported fields" \
  "extracted get_result handler must exact-check top-level request fields"
expect_present "${USB_RETAINED_RESULT_HANDLERS_SOURCE}" "ack_result request contains unsupported fields" \
  "extracted ack_result handler must exact-check top-level request fields"
expect_present "${USB_DISCONNECT_HANDLER_SOURCE}" "disconnect request contains unsupported fields" \
  "extracted disconnect handler must exact-check top-level request fields"
expect_present "${USB_APPROVAL_HISTORY_HANDLER_SOURCE}" "get_approval_history request contains unsupported fields" \
  "extracted get_approval_history handler must exact-check top-level request fields"
expect_present "${USB_SESSION_READ_HANDLERS_SOURCE}" "get_capabilities request contains unsupported fields" \
  "extracted get_capabilities handler must exact-check top-level request fields"
expect_present "${USB_SESSION_READ_HANDLERS_SOURCE}" "get_accounts request contains unsupported fields" \
  "extracted get_accounts handler must exact-check top-level request fields"
expect_present "${USB_SESSION_READ_HANDLERS_SOURCE}" "policy_get request contains unsupported fields" \
  "extracted policy_get handler must exact-check top-level request fields"

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
