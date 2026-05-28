#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 /path/to/StackChan/firmware" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
FIRMWARE_DIR="$(cd "$1" && pwd)"
TARGET_ROOT="${REPO_ROOT}/products/firmware/src/stackchan-cores3"

if [[ ! -f "${FIRMWARE_DIR}/main/CMakeLists.txt" || ! -f "${FIRMWARE_DIR}/main/main.cpp" ]]; then
  echo "Expected a StackChan firmware directory with main/CMakeLists.txt and main/main.cpp: ${FIRMWARE_DIR}" >&2
  exit 1
fi

if [[ ! -d "${TARGET_ROOT}/agent_q" || ! -d "${TARGET_ROOT}/components/signing_crypto" ]]; then
  echo "Missing tracked StackChan CoreS3 firmware overlay under ${TARGET_ROOT}" >&2
  exit 1
fi

rm -rf "${FIRMWARE_DIR}/main/agent_q"
cp -R "${TARGET_ROOT}/agent_q" "${FIRMWARE_DIR}/main/agent_q"

mkdir -p "${FIRMWARE_DIR}/components"
rm -rf "${FIRMWARE_DIR}/components/signing_crypto"
cp -R "${TARGET_ROOT}/components/signing_crypto" "${FIRMWARE_DIR}/components/signing_crypto"

python3 - "${FIRMWARE_DIR}/main/CMakeLists.txt" "${FIRMWARE_DIR}/main/main.cpp" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path


def insert_after_once(text: str, needle: str, insert: str, label: str) -> str:
    if insert.strip() in text:
        return text
    if needle not in text:
        raise SystemExit(f"Could not patch {label}; expected anchor not found.")
    return text.replace(needle, needle + insert, 1)


cmake_path = Path(sys.argv[1])
main_path = Path(sys.argv[2])

cmake = cmake_path.read_text()
cmake = insert_after_once(
    cmake,
    '    "hal/*.cpp"\n',
    '    "agent_q/*.c"\n    "agent_q/*.cc"\n    "agent_q/*.cpp"\n',
    "main/CMakeLists.txt sources",
)
cmake = insert_after_once(
    cmake,
    "                        esp_driver_uart\n",
    "                        esp_driver_usb_serial_jtag\n",
    "main/CMakeLists.txt usb dependency",
)
cmake = insert_after_once(
    cmake,
    "                        mooncake_log\n",
    "                        signing_crypto\n",
    "main/CMakeLists.txt signing dependency",
)
cmake_path.write_text(cmake)

main_cpp = main_path.read_text()
main_cpp = insert_after_once(
    main_cpp,
    "#include <hal/hal.h>\n",
    "#include <agent_q/agent_q_signing_self_test.h>\n#include <agent_q/agent_q_usb_request_server.h>\n",
    "main.cpp includes",
)
main_cpp = insert_after_once(
    main_cpp,
    "    GetHAL().init();\n",
    "\n    // Agent-Q smoke checks\n    agent_q::run_signing_self_test();\n    agent_q::init_usb_request_server();\n",
    "main.cpp startup",
)
main_path.write_text(main_cpp)
PY

echo "Prepared StackChan CoreS3 firmware at ${FIRMWARE_DIR}"
