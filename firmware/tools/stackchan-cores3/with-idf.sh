#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  FIRMWARE_IDF_PATH=/path/to/esp-idf-v5.5.4 firmware/tools/stackchan-cores3/with-idf.sh <command> [args...]

Runs a command after activating ESP-IDF with a stable Python interpreter.

Environment:
  FIRMWARE_IDF_PATH      Required unless IDF_PATH is already set.
  FIRMWARE_IDF_PYTHON    Optional. Defaults to python3.11.

Examples:
  FIRMWARE_IDF_PATH=/path/to/esp-idf-v5.5.4 \
    firmware/tools/stackchan-cores3/with-idf.sh \
    firmware/tools/stackchan-cores3/build.sh

  FIRMWARE_IDF_PATH=/path/to/esp-idf-v5.5.4 \
    firmware/tools/stackchan-cores3/with-idf.sh \
    firmware/tools/stackchan-cores3/test_policy_store.sh
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

IDF_ROOT="${FIRMWARE_IDF_PATH:-${IDF_PATH:-}}"
if [[ -z "${IDF_ROOT}" ]]; then
  echo "FIRMWARE_IDF_PATH is required unless IDF_PATH is already set." >&2
  usage
  exit 2
fi

if [[ ! -f "${IDF_ROOT}/tools/activate.py" ]]; then
  echo "FIRMWARE_IDF_PATH does not point to an ESP-IDF checkout: ${IDF_ROOT}" >&2
  exit 1
fi

IDF_PYTHON="${FIRMWARE_IDF_PYTHON:-python3.11}"
if [[ "${IDF_PYTHON}" == */* ]]; then
  if [[ ! -x "${IDF_PYTHON}" ]]; then
    echo "FIRMWARE_IDF_PYTHON is not executable: ${IDF_PYTHON}" >&2
    exit 1
  fi
else
  if ! command -v "${IDF_PYTHON}" >/dev/null 2>&1; then
    echo "Python interpreter not found: ${IDF_PYTHON}" >&2
    echo "Install Python 3.11 or set FIRMWARE_IDF_PYTHON=/path/to/python." >&2
    exit 1
  fi
fi

# ESP-IDF export.sh chooses the first acceptable python on PATH, which can vary
# across shells. Calling activate.py with an explicit interpreter keeps
# IDF_PYTHON_ENV_PATH and the CMake PYTHON cache stable for one build dir.
idf_exports="$("${IDF_PYTHON}" "${IDF_ROOT}/tools/activate.py" --export --shell bash)"
eval "${idf_exports}"

exec "$@"
