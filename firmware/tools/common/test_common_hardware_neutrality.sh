#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
NIMBLE_PERIPHERAL="${COMMON_ROOT}/transport/local_transport_nimble_peripheral.cpp"
STACKCHAN_PREPARE="${REPO_ROOT}/firmware/tools/stackchan-cores3/prepare.sh"
STOPWATCH_PREPARE="${REPO_ROOT}/firmware/tools/stopwatch-esp32s3/prepare.sh"
LOCAL_TRANSPORT_CONFIG="${REPO_ROOT}/firmware/tools/common/configure_local_transport_sdkconfig.py"

if grep -R -nE \
  'StackChan|stackchan|StopWatch|stopwatch|CoreS3|cores3|M5Stack|m5stack|M5Unified' \
  "${COMMON_ROOT}"; then
  echo "Hardware-target name leaked into common Firmware source" >&2
  exit 1
fi

unexpected_usb_file="$(
  find "${COMMON_ROOT}" -type f -name 'usb_*' \
    ! -path '*/transport/usb_link_state.cpp' \
    ! -path '*/transport/usb_link_state.h' \
    ! -path '*/transport/usb_session_grace.cpp' \
    ! -path '*/transport/usb_session_grace.h' \
    -print -quit
)"
if [[ -n "${unexpected_usb_file}" ]]; then
  echo "Transport-independent common source retains a USB-specific filename: ${unexpected_usb_file}" >&2
  exit 1
fi

while IFS= read -r source; do
  case "${source}" in
    */protocol/protocol_transport.h|\
    */transport/usb_link_state.cpp|\
    */transport/usb_link_state.h|\
    */transport/usb_session_grace.cpp|\
    */transport/usb_session_grace.h)
      continue
      ;;
  esac
  if grep -nE 'USB|Usb|(^|[^[:alnum:]])usb_' "${source}"; then
    echo "Transport-independent common source retains USB-specific vocabulary: ${source}" >&2
    exit 1
  fi
done < <(find "${COMMON_ROOT}" -type f \( -name '*.cpp' -o -name '*.h' \) -print)

if grep -Fq 'memset(&g_inbound_frame' "${NIMBLE_PERIPHERAL}"; then
  echo "Common BLE carrier must clear the injected frame, not its owner pointer" >&2
  exit 1
fi
if ! grep -Fq 'clear_inbound_frame_locked();' "${NIMBLE_PERIPHERAL}"; then
  echo "Common BLE carrier is missing its injected-frame lifecycle owner" >&2
  exit 1
fi

PAIRING_SESSION="${COMMON_ROOT}/transport/local_transport_pairing_session.cpp"
if [[ "$(grep -c 'g_pairing\.clear();' "${PAIRING_SESSION}")" -ne 3 ]] ||
   ! grep -Fq 'clear_pairing_session_state(ops);' "${PAIRING_SESSION}"; then
  echo "Common pairing terminal paths must use the complete session cleanup owner" >&2
  exit 1
fi

for memory_config in \
  '--malloc-always-internal 512' \
  '--malloc-reserve-internal 65536' \
  '--prefer-network-psram'; do
  for target_prepare in "${STACKCHAN_PREPARE}" "${STOPWATCH_PREPARE}"; do
    if ! grep -Fq -- "${memory_config}" "${target_prepare}"; then
      echo "Target local-transport build does not preserve internal controller memory: ${target_prepare}" >&2
      exit 1
    fi
  done
done

tmp_config="$(mktemp "${TMPDIR:-/tmp}/local-transport-sdkconfig.XXXXXX")"
trap 'rm -f "${tmp_config}"' EXIT
printf '%s\n' \
  'CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=16384' \
  'CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL=32768' \
  '# CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP is not set' >"${tmp_config}"
python3 "${LOCAL_TRANSPORT_CONFIG}" \
  --malloc-always-internal 512 \
  --malloc-reserve-internal 65536 \
  --prefer-network-psram \
  "${tmp_config}"
for expected_config in \
  'CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=512' \
  'CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL=65536' \
  'CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP=y' \
  'CONFIG_BT_NIMBLE_ROLE_CENTRAL is not set' \
  'CONFIG_BT_NIMBLE_ROLE_PERIPHERAL=y'; do
  if ! grep -Fq "${expected_config}" "${tmp_config}"; then
    echo "Common local-transport sdkconfig owner did not apply: ${expected_config}" >&2
    exit 1
  fi
done

echo "Common Firmware hardware-neutrality tests passed"
