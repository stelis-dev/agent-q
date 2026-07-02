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
COMMON_PROTOCOL="${REPO_ROOT}/firmware/src/common/protocol"
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
  json_input.h \
  protocol_constants.h \
  request_id.cpp \
  request_id.h \
  usb_request_line.cpp \
  usb_request_line.h; do
  if [[ ! -f "${COMMON_PROTOCOL}/${required_common_protocol}" ]]; then
    echo "Missing tracked common protocol source: ${COMMON_PROTOCOL}/${required_common_protocol}" >&2
    exit 1
  fi
done

git -C "${CHECKOUT_DIR}" clean -fd -- main >/dev/null
cp "${OVERLAY_MAIN}/main.cpp" "${CHECKOUT_DIR}/main/main.cpp"
cp "${OVERLAY_MAIN}/CMakeLists.txt" "${CHECKOUT_DIR}/main/CMakeLists.txt"
rm -rf "${CHECKOUT_DIR}/main/runtime"
mkdir -p "${CHECKOUT_DIR}/main/runtime"
cp -R "${OVERLAY_MAIN}/runtime/." "${CHECKOUT_DIR}/main/runtime/"
if [[ -d "${OVERLAY_MAIN}/hal" ]]; then
  cp -R "${OVERLAY_MAIN}/hal/." "${CHECKOUT_DIR}/main/hal/"
fi
rm -rf "${CHECKOUT_DIR}/main/firmware_common/protocol"
mkdir -p "${CHECKOUT_DIR}/main/firmware_common/protocol"
cp -R "${COMMON_PROTOCOL}/." "${CHECKOUT_DIR}/main/firmware_common/protocol/"
