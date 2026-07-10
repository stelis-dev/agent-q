#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON="${REPO_ROOT}/firmware/src/common"
STACKCHAN="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
STOPWATCH="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/overlay/main"
PREPARE="${REPO_ROOT}/firmware/tools/stopwatch-esp32s3/prepare.sh"

expect_present() {
  local file="$1"
  local text="$2"
  local message="$3"
  if ! grep -Fq "${text}" "${file}"; then
    echo "Missing ${message}: ${text} in ${file}" >&2
    exit 1
  fi
}

expect_absent() {
  local file="$1"
  local text="$2"
  local message="$3"
  if grep -Fq "${text}" "${file}"; then
    echo "Unexpected ${message}: ${text} in ${file}" >&2
    exit 1
  fi
}

for common_source in \
  protocol/protocol_transport.h \
  transport/local_transport_identity_store.cpp \
  transport/local_transport_mbedtls_crypto.cpp \
  transport/local_transport_nimble_peripheral.cpp \
  transport/local_transport_nimble_pairing_session.cpp \
  transport/local_transport_pairing_session.cpp; do
  [[ -f "${COMMON}/${common_source}" ]] || {
    echo "Missing common local transport owner: ${common_source}" >&2
    exit 1
  }
done

if grep -En "StackChan|StopWatch|stackchan|stopwatch|M5|lv_|pairing_id|static_priv|static_pub|EXT_RAM" \
  "${COMMON}/transport/local_transport_identity_store.cpp" \
  "${COMMON}/transport/local_transport_identity_store.h" \
  "${COMMON}/transport/local_transport_mbedtls_crypto.cpp" \
  "${COMMON}/transport/local_transport_mbedtls_crypto.h" \
  "${COMMON}/transport/local_transport_nimble_peripheral.cpp" \
  "${COMMON}/transport/local_transport_nimble_peripheral.h"; then
  echo "Target, UI, storage-layout, or memory-placement detail leaked into common local transport" >&2
  exit 1
fi
if grep -En "draw_pairing_panel|modal_|lv_" \
  "${COMMON}/transport/local_transport_pairing_session.cpp" \
  "${COMMON}/transport/local_transport_pairing_session.h"; then
  echo "Common pairing state must expose snapshots and events, not own target UI" >&2
  exit 1
fi

[[ ! -e "${STACKCHAN}/local_transport_ble.cpp" ]] || {
  echo "StackChan-local BLE implementation remains beside the common owner" >&2
  exit 1
}
expect_present "${STACKCHAN}/local_transport_pairing.cpp" \
  'transport/local_transport_nimble_pairing_session.h' \
  "StackChan common NimBLE pairing-session consumer"
expect_present "${STOPWATCH}/runtime/local_transport_pairing.cpp" \
  'transport/local_transport_nimble_pairing_session.h' \
  "StopWatch common NimBLE pairing-session consumer"
for target_pairing in \
  "${STACKCHAN}/local_transport_pairing.cpp" \
  "${STOPWATCH}/runtime/local_transport_pairing.cpp"; do
  expect_present "${target_pairing}" \
    'local_transport_nimble_pairing_session_ops({' \
    "shared NimBLE pairing-session composition"
  expect_absent "${target_pairing}" \
    'local_transport_ble_receive(' \
    "target-local BLE receive process"
  expect_absent "${target_pairing}" \
    'local_transport_ble_send_indication(' \
    "target-local BLE send process"
done
expect_present "${STOPWATCH}/runtime/local_transport_pairing.cpp" \
  'local_transport_identity_load_secret(identity_store_ops(), identity)' \
  "private identity read constrained to pairing composition"
if grep -R "load_identity_secret" "${STOPWATCH}/runtime"/*.h; then
  echo "StopWatch target header exposes a private-identity read function" >&2
  exit 1
fi

expect_present "${STOPWATCH}/runtime/app.cpp" \
  'case input::KeyEvent::GoPrevious:' \
  "physical KEYA entry event"
expect_present "${STOPWATCH}/runtime/app.cpp" \
  'local_transport_pairing_cancel();' \
  "physical cancel cleanup"

key_handler="$(sed -n '/void RuntimeApp::handle_key_event/,/void RuntimeApp::handle_touch_poll/p' "${STOPWATCH}/runtime/app.cpp")"
keya_block="$(sed -n '/case input::KeyEvent::GoPrevious:/,/case input::KeyEvent::GoNext:/p' <<<"${key_handler}")"
chord_block="$(sed -n '/case input::KeyEvent::GoHome:/,/case input::KeyEvent::None:/p' <<<"${key_handler}")"
if ! grep -Fq 'begin_local_transport_pairing(now_ms);' <<<"${keya_block}"; then
  echo "KEYA must enter local transport from the guarded idle state" >&2
  exit 1
fi
if grep -Fq 'begin_local_transport_pairing(now_ms);' <<<"${chord_block}" ||
   ! grep -Fq 'transition_to(RuntimeState::signing_mode_review);' <<<"${chord_block}"; then
  echo "KEYA+KEYB must retain signing-mode access without a second pairing entry" >&2
  exit 1
fi
expect_present "${STOPWATCH}/runtime/app.h" \
  'enum class RuntimeState {' \
  "target interaction state owner"
expect_absent "${STOPWATCH}/runtime/app.h" \
  'ScreenMode' \
  "screen-owned workflow state"
expect_absent "${STOPWATCH}/runtime/app.cpp" \
  'screen_mode_' \
  "screen-owned workflow state"
expect_present "${STOPWATCH}/runtime/local_transport_pairing_scene.cpp" \
  'lv_qrcode_update(qr_code_, payload, strlen(payload))' \
  "QR payload rendering"
expect_present "${STOPWATCH}/runtime/local_transport_pairing_scene.cpp" \
  'lv_obj_set_style_bg_opa(scene_root_, LV_OPA_COVER' \
  "opaque scene isolation"

expect_present "${STOPWATCH}/runtime/protocol_runtime.cpp" \
  'ScopedRequestContext request_context(route);' \
  "transport-bound request scope"
expect_present "${STOPWATCH}/runtime/protocol_runtime.cpp" \
  'g_pending_response_route = g_current_request_route;' \
  "asynchronous response-route ownership"
expect_present "${STOPWATCH}/runtime/protocol_runtime.cpp" \
  'stopwatch_operation_handlers()' \
  "single operation table consumption"
expect_present "${STOPWATCH}/runtime/protocol_runtime.cpp" \
  'g_status.usb_ready = init_usb_transport();' \
  "USB initialization isolated from protocol runtime state"
expect_absent "${STOPWATCH}/runtime/protocol_runtime.cpp" \
  'stopwatch_local_transport_operation_handlers' \
  "transport-specific operation table"
expect_present "${STOPWATCH}/runtime/device_reset.cpp" \
  'local_transport_pairing_wipe_identity()' \
  "Device reset identity wipe"

state_sync_block="$(sed -n '/void RuntimeApp::sync_local_transport_state/,/void RuntimeApp::project_local_transport_scene/p' "${STOPWATCH}/runtime/app.cpp")"
if grep -Fq 'local_transport_pairing_scene_' <<<"${state_sync_block}"; then
  echo "Local transport state synchronization must not draw target UI" >&2
  exit 1
fi

scene_projection_block="$(sed -n '/void RuntimeApp::project_local_transport_scene/,/void RuntimeApp::refresh_auth_mode/p' "${STOPWATCH}/runtime/app.cpp")"
if grep -Eq 'transition_to|cancel_local_transport_carrier' <<<"${scene_projection_block}"; then
  echo "Local transport scene projection must not command runtime transitions" >&2
  exit 1
fi

auth_transport_guard="$(sed -n '/const bool auth_allows_local_transport/,/if (protocol_runtime_projected_device_state_is_error/p' "${STOPWATCH}/runtime/app.cpp")"
if grep -Fq 'runtime_state_' <<<"${auth_transport_guard}"; then
  echo "Carrier cleanup must be driven by carrier/auth state, not displayed interaction state" >&2
  exit 1
fi

protocol_poll_block="$(sed -n '/void protocol_runtime_poll/,/ProtocolStatus protocol_runtime_status/p' "${STOPWATCH}/runtime/protocol_runtime.cpp")"
local_transport_poll_line="$(grep -n 'local_transport_pairing_poll' <<<"${protocol_poll_block}" | head -n 1 | cut -d: -f1)"
usb_return_line="$(grep -n 'if (!usb_connected)' <<<"${protocol_poll_block}" | head -n 1 | cut -d: -f1)"
if [[ -z "${local_transport_poll_line}" || -z "${usb_return_line}" || "${local_transport_poll_line}" -ge "${usb_return_line}" ]]; then
  echo "Protocol runtime must poll local transport before any USB-unavailable return" >&2
  exit 1
fi

expect_present "${PREPARE}" \
  '"CONFIG_LV_USE_QRCODE": "y"' \
  "StopWatch QR build config"
for config in \
  '"CONFIG_BT_NIMBLE_ROLE_CENTRAL": "n"' \
  '"CONFIG_BT_NIMBLE_ROLE_PERIPHERAL": "y"' \
  '"CONFIG_BT_NIMBLE_GATT_CLIENT": "n"' \
  '"CONFIG_BT_NIMBLE_GATT_SERVER": "y"'; do
  expect_present "${REPO_ROOT}/firmware/tools/common/configure_local_transport_sdkconfig.py" \
    "${config}" \
    "bounded common local transport config"
done

echo "StopWatch local transport structure tests passed"
