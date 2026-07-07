#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 /path/to/M5StopWatch-UserDemo" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SOURCE_ROOT="${REPO_ROOT}/firmware/src/stopwatch-esp32s3"
OVERLAY_MAIN="${SOURCE_ROOT}/overlay/main"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_NUMERIC="${COMMON_ROOT}/numeric"
COMMON_POLICY="${COMMON_ROOT}/policy"
COMMON_PROTOCOL="${COMMON_ROOT}/protocol"
COMMON_SIGNING="${COMMON_ROOT}/signing"
COMMON_SUI="${COMMON_ROOT}/sui"
COMMON_TRANSPORT="${COMMON_ROOT}/transport"
CHECKOUT_DIR="$(cd "$1" && pwd)"

if [[ ! -f "${CHECKOUT_DIR}/CMakeLists.txt" || ! -f "${CHECKOUT_DIR}/main/CMakeLists.txt" || ! -f "${CHECKOUT_DIR}/main/main.cpp" ]]; then
  echo "Expected a M5StopWatch-UserDemo ESP-IDF project: ${CHECKOUT_DIR}" >&2
  exit 1
fi

if [[ ! -d "${CHECKOUT_DIR}/components/M5GFX" || ! -d "${CHECKOUT_DIR}/components/lvgl" || ! -d "${CHECKOUT_DIR}/components/M5PM1" || ! -d "${CHECKOUT_DIR}/components/M5IOE1" ]]; then
  echo "Missing pinned StopWatch dependencies under ${CHECKOUT_DIR}/components. Run fetch.sh first." >&2
  exit 1
fi

if [[ ! -f "${CHECKOUT_DIR}/sdkconfig.defaults" ]]; then
  echo "Missing StopWatch sdkconfig.defaults in ${CHECKOUT_DIR}" >&2
  exit 1
fi

if [[ ! -f "${OVERLAY_MAIN}/main.cpp" || ! -f "${OVERLAY_MAIN}/CMakeLists.txt" || ! -d "${OVERLAY_MAIN}/runtime" ]]; then
  echo "Missing tracked StopWatch overlay source: ${OVERLAY_MAIN}" >&2
  exit 1
fi
for required_common_protocol in \
  approval_history.cpp \
  approval_history_json_writer.cpp \
  approval_history_json_writer.h \
  approval_history.h \
  device_contract.cpp \
  device_contract.h \
  device_response.cpp \
  device_response.h \
  json_input.h \
  protocol_constants.h \
  protocol_input_copy.h \
  request_id.cpp \
  request_id.h \
  request_line.cpp \
  request_line.h \
  session_id.h \
  signing_mode.cpp \
  signing_mode.h \
  sign_request_identity.cpp \
  sign_request_identity.h \
  signing_response_store.cpp \
  signing_response_store.h \
  usb_active_session_request_guard.cpp \
  usb_active_session_request_guard.h \
  usb_session_read_handlers.cpp \
  usb_session_read_handlers.h \
  usb_sui_zklogin_credential_handlers.cpp \
  usb_sui_zklogin_credential_handlers.h \
  usb_operation_response_writer.h \
  usb_operation_type.cpp \
  usb_operation_type.h; do
  if [[ ! -f "${COMMON_PROTOCOL}/${required_common_protocol}" ]]; then
    echo "Missing tracked common protocol source: ${COMMON_PROTOCOL}/${required_common_protocol}" >&2
    exit 1
  fi
done
for required_common_signing in \
  policy_signing_execution_result.cpp \
  policy_signing_execution_result.h \
	  signing_preflight.cpp \
	  signing_preflight.h \
	  signing_retry_delivery.cpp \
	  signing_retry_delivery.h \
	  signing_retry_response.cpp \
	  signing_retry_response.h \
	  sign_personal_message_user_ingress.cpp \
	  sign_personal_message_user_ingress.h \
  sign_personal_message_user_validation.cpp \
  sign_personal_message_user_validation.h \
  sign_transaction_policy_runtime.cpp \
  sign_transaction_policy_runtime.h \
  sign_transaction_user_ingress.cpp \
  sign_transaction_user_ingress.h \
  sign_transaction_user_validation.cpp \
  sign_transaction_user_validation.h \
	  usb_signing_handlers.cpp \
	  usb_signing_handlers.h \
	  usb_signing_outcome_writer.cpp \
	  usb_signing_outcome_writer.h \
	  user_signing_flow.cpp \
  user_signing_flow.h \
  user_signing_critical_section.cpp \
  user_signing_critical_section.h \
  user_signing_limits.h \
  user_signing_review_timer_state.h; do
  if [[ ! -f "${COMMON_SIGNING}/${required_common_signing}" ]]; then
    echo "Missing tracked common signing source: ${COMMON_SIGNING}/${required_common_signing}" >&2
    exit 1
  fi
done
if [[ ! -f "${COMMON_NUMERIC}/u64_decimal.h" ]]; then
  echo "Missing tracked common numeric source: ${COMMON_NUMERIC}/u64_decimal.h" >&2
  exit 1
fi
for required_common_policy in \
  document.cpp \
  document.h \
  evaluator.cpp \
  evaluator.h \
  policy_json_writer.cpp \
  policy_json_writer.h \
  policy_proposal_parser.cpp \
  policy_proposal_parser.h \
  policy_store.cpp \
  policy_store.h \
  policy_update_flow.cpp \
  policy_update_flow.h \
  policy_update_marker.cpp \
  policy_update_marker.h \
  usb_policy_handlers.cpp \
  usb_policy_handlers.h \
  u64.h; do
  if [[ ! -f "${COMMON_POLICY}/${required_common_policy}" ]]; then
    echo "Missing tracked common policy source: ${COMMON_POLICY}/${required_common_policy}" >&2
    exit 1
  fi
done
if [[ ! -d "${SOURCE_ROOT}/components/signing_crypto" ]]; then
  echo "Missing tracked StopWatch signing crypto component: ${SOURCE_ROOT}/components/signing_crypto" >&2
  exit 1
fi
if [[ ! -f "${COMMON_SUI}/network.h" ]]; then
  echo "Missing tracked common Sui network source: ${COMMON_SUI}/network.h" >&2
  exit 1
fi
for required_common_sui in \
  account_settings_types.h \
  active_identity.h \
  account_binding.cpp \
  account_binding.h \
  offline_policy_facts.cpp \
  offline_policy_facts.h \
  personal_message_intent.cpp \
  personal_message_intent.h \
  signing_preparation.cpp \
  signing_preparation.h \
  signing_preparation_types.h \
  signing_limits.h \
  signing_payload.cpp \
  signing_payload.h \
  signature_scheme.h \
  zklogin_credential_outcome.cpp \
  zklogin_credential_outcome.h \
  zklogin_credential_payload.cpp \
  zklogin_credential_payload.h \
  zklogin_proof_payload.cpp \
  zklogin_proof_payload.h \
  zklogin_proof_record.cpp \
  zklogin_proof_record.h \
  zklogin_signature.cpp \
  zklogin_signature.h; do
  if [[ ! -f "${COMMON_SUI}/${required_common_sui}" ]]; then
    echo "Missing tracked common Sui source: ${COMMON_SUI}/${required_common_sui}" >&2
    exit 1
  fi
done
for required_common_transport in \
  connect_approval.cpp \
  connect_approval.h \
  connect_review_response_flow.cpp \
  connect_review_response_flow.h \
  payload_delivery_admission.cpp \
  payload_delivery_admission.h \
  payload_delivery_operation_kind.h \
  payload_delivery_primitives.cpp \
  payload_delivery_primitives.h \
  payload_delivery_resolution.cpp \
  payload_delivery_resolution.h \
  payload_delivery_store.cpp \
  payload_delivery_store.h \
  timeout_window.h \
  usb_link_state.cpp \
  usb_link_state.h \
  usb_session_grace.cpp \
  usb_session_grace.h; do
  if [[ ! -f "${COMMON_TRANSPORT}/${required_common_transport}" ]]; then
    echo "Missing tracked common transport source: ${COMMON_TRANSPORT}/${required_common_transport}" >&2
    exit 1
  fi
done

git -C "${CHECKOUT_DIR}" clean -fd -- main >/dev/null
cp "${OVERLAY_MAIN}/main.cpp" "${CHECKOUT_DIR}/main/main.cpp"
cp "${OVERLAY_MAIN}/CMakeLists.txt" "${CHECKOUT_DIR}/main/CMakeLists.txt"
rm -rf "${CHECKOUT_DIR}/main/assets/dial"
mkdir -p "${CHECKOUT_DIR}/main/assets/dial"
for required_dial_asset in \
  dial_assets_generated.h \
  1_baseplate.rgb565a8.bin \
  2_dial_frames.idx8.deflate.bin; do
  if [[ ! -f "${OVERLAY_MAIN}/assets/dial/${required_dial_asset}" ]]; then
    echo "Missing generated StopWatch dial asset: ${OVERLAY_MAIN}/assets/dial/${required_dial_asset}" >&2
    echo "Run firmware/tools/stopwatch-esp32s3/generate_dial_assets.mjs after updating dial PNG sources." >&2
    exit 1
  fi
  cp "${OVERLAY_MAIN}/assets/dial/${required_dial_asset}" "${CHECKOUT_DIR}/main/assets/dial/${required_dial_asset}"
done
rm -rf "${CHECKOUT_DIR}/main/runtime"
mkdir -p "${CHECKOUT_DIR}/main/runtime"
cp -R "${OVERLAY_MAIN}/runtime/." "${CHECKOUT_DIR}/main/runtime/"
if [[ -d "${OVERLAY_MAIN}/hal" ]]; then
  cp -R "${OVERLAY_MAIN}/hal/." "${CHECKOUT_DIR}/main/hal/"
fi
python3 - "${CHECKOUT_DIR}/main/hal/hal.cpp" <<'PY'
from __future__ import annotations

import sys
import re
from pathlib import Path

hal_path = Path(sys.argv[1])
text = hal_path.read_text()
old_init = """    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
"""
new_init = """    // Initialize NVS. Storage consistency is handled by Agent-Q runtime gates;
    // startup must never erase persistent signing material automatically.
    ESP_ERROR_CHECK(nvs_flash_init());
"""
if old_init not in text:
    raise SystemExit(f"Expected upstream NVS init block not found in {hal_path}")
text = text.replace(old_init, new_init, 1)

factory_reset_pattern = re.compile(
    r"\nvoid Hal::factoryReset\(\)\n"
    r"\{\n"
    r"    mclog::tagInfo\(_tag, \"start factory reset\"\);\n"
    r"    ESP_ERROR_CHECK\(nvs_flash_erase\(\)\);\n"
    r"    reboot\(\);\n"
    r"\}\n*"
)
text, factory_reset_count = factory_reset_pattern.subn("\n", text, count=1)
if factory_reset_count != 1:
    raise SystemExit(f"Expected upstream factoryReset block not found in {hal_path}")
hal_path.write_text(text)
PY
python3 - "${CHECKOUT_DIR}/main/hal/utils/config_ap/config_ap.cpp" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

config_ap_path = Path(sys.argv[1])
if not config_ap_path.exists():
    raise SystemExit(f"Expected upstream config AP source not found in {config_ap_path}")
text = config_ap_path.read_text()
old_init = """    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
"""
new_init = """    esp_err_t ret = nvs_flash_init();
"""
if old_init not in text:
    raise SystemExit(f"Expected upstream config AP NVS erase fallback not found in {config_ap_path}")
text = text.replace(old_init, new_init, 1)
config_ap_path.write_text(text)
PY
if grep -R "nvs_flash_erase" "${CHECKOUT_DIR}/main" "${CHECKOUT_DIR}/components" >/dev/null; then
  echo "Unsafe nvs_flash_erase remains in prepared StopWatch firmware tree." >&2
  exit 1
fi
rm -rf "${CHECKOUT_DIR}/main/firmware_common/protocol"
mkdir -p "${CHECKOUT_DIR}/main/firmware_common/protocol"
cp -R "${COMMON_PROTOCOL}/." "${CHECKOUT_DIR}/main/firmware_common/protocol/"
rm -rf "${CHECKOUT_DIR}/main/firmware_common/signing"
mkdir -p "${CHECKOUT_DIR}/main/firmware_common/signing"
cp -R "${COMMON_SIGNING}/." "${CHECKOUT_DIR}/main/firmware_common/signing/"
rm -rf "${CHECKOUT_DIR}/main/firmware_common/numeric"
mkdir -p "${CHECKOUT_DIR}/main/firmware_common/numeric"
cp -R "${COMMON_NUMERIC}/." "${CHECKOUT_DIR}/main/firmware_common/numeric/"
rm -rf "${CHECKOUT_DIR}/main/firmware_common/policy"
mkdir -p "${CHECKOUT_DIR}/main/firmware_common/policy"
cp -R "${COMMON_POLICY}/." "${CHECKOUT_DIR}/main/firmware_common/policy/"
rm -rf "${CHECKOUT_DIR}/main/firmware_common/sui"
mkdir -p "${CHECKOUT_DIR}/main/firmware_common/sui"
cp -R "${COMMON_SUI}/." "${CHECKOUT_DIR}/main/firmware_common/sui/"
rm -rf "${CHECKOUT_DIR}/main/firmware_common/transport"
mkdir -p "${CHECKOUT_DIR}/main/firmware_common/transport"
cp -R "${COMMON_TRANSPORT}/." "${CHECKOUT_DIR}/main/firmware_common/transport/"
rm -rf "${CHECKOUT_DIR}/components/signing_crypto"
mkdir -p "${CHECKOUT_DIR}/components/signing_crypto"
cp -R "${SOURCE_ROOT}/components/signing_crypto/." "${CHECKOUT_DIR}/components/signing_crypto/"

python3 - "${CHECKOUT_DIR}/sdkconfig.defaults" "${CHECKOUT_DIR}/sdkconfig" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path


def set_config_value(config_path: Path, key: str, value: str) -> None:
    if not config_path.exists():
        return
    if config_path.is_symlink() or not config_path.is_file():
        raise SystemExit(f"Refusing to write through non-regular config path: {config_path}")

    desired = f"{key}={value}"
    lines = config_path.read_text().splitlines()
    updated: list[str] = []
    replaced = False
    for line in lines:
        if line.startswith(f"{key}=") or line == f"# {key} is not set":
            if not replaced:
                updated.append(desired)
                replaced = True
            continue
        updated.append(line)
    if not replaced:
        updated.append(desired)
    config_path.write_text("\n".join(updated) + "\n")


for arg in sys.argv[1:]:
    set_config_value(Path(arg), "CONFIG_ESP_MAIN_TASK_STACK_SIZE", "32768")
PY

echo "Prepared StopWatch ESP32-S3 firmware at ${CHECKOUT_DIR}"
