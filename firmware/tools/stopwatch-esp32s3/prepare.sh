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
COMMON_PROTOCOL="${COMMON_ROOT}/protocol"
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
  device_contract.cpp \
  device_contract.h \
  device_response.cpp \
  device_response.h \
  json_input.h \
  protocol_constants.h \
  request_id.cpp \
  request_id.h \
  request_line.cpp \
  request_line.h \
  session_id.h; do
  if [[ ! -f "${COMMON_PROTOCOL}/${required_common_protocol}" ]]; then
    echo "Missing tracked common protocol source: ${COMMON_PROTOCOL}/${required_common_protocol}" >&2
    exit 1
  fi
done
if [[ ! -f "${COMMON_NUMERIC}/u64_decimal.h" ]]; then
  echo "Missing tracked common numeric source: ${COMMON_NUMERIC}/u64_decimal.h" >&2
  exit 1
fi
if [[ ! -d "${SOURCE_ROOT}/components/signing_crypto" ]]; then
  echo "Missing tracked StopWatch signing crypto component: ${SOURCE_ROOT}/components/signing_crypto" >&2
  exit 1
fi
if [[ ! -f "${COMMON_SUI}/network.h" ]]; then
  echo "Missing tracked common Sui network source: ${COMMON_SUI}/network.h" >&2
  exit 1
fi
for required_common_sui in \
  zklogin_credential_outcome.cpp \
  zklogin_credential_outcome.h \
  zklogin_credential_payload.cpp \
  zklogin_credential_payload.h \
  zklogin_proof_record.cpp \
  zklogin_proof_record.h; do
  if [[ ! -f "${COMMON_SUI}/${required_common_sui}" ]]; then
    echo "Missing tracked common Sui source: ${COMMON_SUI}/${required_common_sui}" >&2
    exit 1
  fi
done
for required_common_transport in \
  payload_delivery_admission.cpp \
  payload_delivery_admission.h \
  payload_delivery_operation_kind.h \
  payload_delivery_primitives.cpp \
  payload_delivery_primitives.h \
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
rm -rf "${CHECKOUT_DIR}/main/firmware_common/protocol"
mkdir -p "${CHECKOUT_DIR}/main/firmware_common/protocol"
cp -R "${COMMON_PROTOCOL}/." "${CHECKOUT_DIR}/main/firmware_common/protocol/"
rm -rf "${CHECKOUT_DIR}/main/firmware_common/numeric"
mkdir -p "${CHECKOUT_DIR}/main/firmware_common/numeric"
cp -R "${COMMON_NUMERIC}/." "${CHECKOUT_DIR}/main/firmware_common/numeric/"
rm -rf "${CHECKOUT_DIR}/main/firmware_common/sui"
mkdir -p "${CHECKOUT_DIR}/main/firmware_common/sui"
cp -R "${COMMON_SUI}/." "${CHECKOUT_DIR}/main/firmware_common/sui/"
rm -rf "${CHECKOUT_DIR}/main/firmware_common/transport"
mkdir -p "${CHECKOUT_DIR}/main/firmware_common/transport"
cp -R "${COMMON_TRANSPORT}/." "${CHECKOUT_DIR}/main/firmware_common/transport/"
rm -rf "${CHECKOUT_DIR}/components/signing_crypto"
mkdir -p "${CHECKOUT_DIR}/components/signing_crypto"
cp -R "${SOURCE_ROOT}/components/signing_crypto/." "${CHECKOUT_DIR}/components/signing_crypto/"
