#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stopwatch-esp32s3/build.sh [path-to-M5StopWatch-UserDemo] [build-dir]

ESP-IDF must already be installed and active in the shell, so idf.py is on PATH.
By default, the script downloads the pinned M5Stack StopWatch ESP32-S3 firmware
host project and pinned Git component dependencies into the ignored
.firmware-cache directory, applies the tracked target overlay, and builds the
result. It does not depend on .WORK paths.
EOF
}

if [[ $# -gt 2 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_SOURCE_ENV="${REPO_ROOT}/firmware/source.env"
TARGET_SOURCE_ENV="${REPO_ROOT}/firmware/src/stopwatch-esp32s3/source.env"
DEFAULT_CHECKOUT_DIR="${REPO_ROOT}/.firmware-cache/stopwatch-esp32s3/M5StopWatch-UserDemo"
DEFAULT_SIGNING_CRYPTO_DIR="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib"
INPUT_PATH="${1:-${DEFAULT_CHECKOUT_DIR}}"
BUILD_DIR="${2:-build-stopwatch-esp32s3}"

# shellcheck source=/dev/null
source "${COMMON_SOURCE_ENV}"
# shellcheck source=/dev/null
source "${TARGET_SOURCE_ENV}"

CHECKOUT_DIR="${INPUT_PATH}"
"${SCRIPT_DIR}/fetch.sh" "${CHECKOUT_DIR}" >/dev/null
CHECKOUT_DIR="$(cd "${CHECKOUT_DIR}" && pwd)"

if [[ "${BUILD_DIR}" != /* ]]; then
  BUILD_DIR="${CHECKOUT_DIR}/${BUILD_DIR}"
fi

BUILD_PARENT="$(dirname "${BUILD_DIR}")"
BUILD_NAME="$(basename "${BUILD_DIR}")"
if [[ ! -d "${BUILD_PARENT}" ]]; then
  mkdir -p "${BUILD_PARENT}"
fi
BUILD_DIR="$(cd "${BUILD_PARENT}" && pwd)/${BUILD_NAME}"

case "${BUILD_DIR}" in
  "${CHECKOUT_DIR}"/*)
    ;;
  *)
    echo "StopWatch build directory must be inside the checkout: ${BUILD_DIR}" >&2
    exit 1
    ;;
esac

if [[ -z "${BUILD_NAME}" || "${BUILD_NAME}" == "." || "${BUILD_NAME}" == ".." || "${BUILD_DIR}" == "/" || "${BUILD_DIR}" == "${CHECKOUT_DIR}" ]]; then
  echo "Refusing unsafe StopWatch build directory: ${BUILD_DIR}" >&2
  exit 1
fi
rm -rf "${BUILD_DIR}"

fetch_pinned_repo() {
  local repo_url="$1"
  local commit="$2"
  local checkout_dir="$3"

  if [[ -e "${checkout_dir}" && ! -d "${checkout_dir}/.git" ]]; then
    echo "Destination exists but is not a git checkout: ${checkout_dir}" >&2
    exit 1
  fi

  if [[ ! -d "${checkout_dir}/.git" ]]; then
    mkdir -p "$(dirname "${checkout_dir}")"
    git clone "${repo_url}" "${checkout_dir}"
  fi

  if ! git -C "${checkout_dir}" cat-file -e "${commit}^{commit}" 2>/dev/null; then
    git -C "${checkout_dir}" fetch --tags origin
  fi
  git -C "${checkout_dir}" checkout --force "${commit}"
  git -C "${checkout_dir}" clean -fdx >/dev/null
}

if [[ -z "${SIGNING_CRYPTO_ROOT:-}" ]]; then
  fetch_pinned_repo "${SIGNING_CRYPTO_REPOSITORY}" "${SIGNING_CRYPTO_COMMIT}" "${DEFAULT_SIGNING_CRYPTO_DIR}"
  export SIGNING_CRYPTO_ROOT="${DEFAULT_SIGNING_CRYPTO_DIR}"
else
  export SIGNING_CRYPTO_ROOT
fi

if [[ ! -f "${SIGNING_CRYPTO_ROOT}/src/microsui_core/key_management.c" ]]; then
  echo "SIGNING_CRYPTO_ROOT does not point to the pinned signing key-derivation source: ${SIGNING_CRYPTO_ROOT}" >&2
  exit 1
fi

"${SCRIPT_DIR}/prepare.sh" "${CHECKOUT_DIR}"

if ! command -v idf.py >/dev/null 2>&1; then
  echo "idf.py is not on PATH. Install ESP-IDF ${ESP_IDF_VERSION} and source its export.sh first." >&2
  exit 127
fi

cd "${CHECKOUT_DIR}"
idf.py -B "${BUILD_DIR}" build
