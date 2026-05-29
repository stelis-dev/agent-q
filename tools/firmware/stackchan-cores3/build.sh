#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/build.sh [path-to-StackChan-or-firmware] [build-dir]

ESP-IDF must already be installed and active in the shell, so idf.py is on PATH.
By default, the script downloads the pinned StackChan host firmware into the
ignored .firmware-cache directory, applies the tracked Agent-Q overlay, and
downloads the pinned signing and BIP-39 wordlist sources into .firmware-cache
before building. It does not depend on .WORK paths.
EOF
}

if [[ $# -gt 2 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_SOURCE_ENV="${REPO_ROOT}/products/firmware/source.env"
TARGET_SOURCE_ENV="${REPO_ROOT}/products/firmware/src/stackchan-cores3/source.env"
DEFAULT_CHECKOUT_DIR="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan"
DEFAULT_SIGNING_DIR="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib"
DEFAULT_BIP39_WORDLIST_DIR="${REPO_ROOT}/.firmware-cache/bip39/bips"
INPUT_PATH="${1:-${DEFAULT_CHECKOUT_DIR}}"
BUILD_DIR="${2:-build-agentq-stackchan-cores3}"

# shellcheck source=/dev/null
source "${COMMON_SOURCE_ENV}"
# shellcheck source=/dev/null
source "${TARGET_SOURCE_ENV}"

if [[ "${INPUT_PATH}" == */firmware && -f "${INPUT_PATH}/CMakeLists.txt" ]]; then
  FIRMWARE_DIR="$(cd "${INPUT_PATH}" && pwd)"
  CHECKOUT_DIR="$(cd "${FIRMWARE_DIR}/.." && pwd)"
else
  CHECKOUT_DIR="${INPUT_PATH}"
  "${SCRIPT_DIR}/fetch.sh" "${CHECKOUT_DIR}" >/dev/null
  FIRMWARE_DIR="$(cd "${CHECKOUT_DIR}/firmware" && pwd)"
fi

if [[ "${BUILD_DIR}" != /* ]]; then
  BUILD_DIR="${FIRMWARE_DIR}/${BUILD_DIR}"
fi

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
}

if [[ -z "${AGENT_Q_SIGNING_CRYPTO_ROOT:-}" ]]; then
  fetch_pinned_repo "${AGENT_Q_SIGNING_CRYPTO_REPOSITORY}" "${AGENT_Q_SIGNING_CRYPTO_COMMIT}" "${DEFAULT_SIGNING_DIR}"
  export AGENT_Q_SIGNING_CRYPTO_ROOT="${DEFAULT_SIGNING_DIR}"
else
  export AGENT_Q_SIGNING_CRYPTO_ROOT
fi

if [[ ! -f "${AGENT_Q_SIGNING_CRYPTO_ROOT}/src/microsui_core/sign.c" ]]; then
  echo "AGENT_Q_SIGNING_CRYPTO_ROOT does not point to the pinned signing source: ${AGENT_Q_SIGNING_CRYPTO_ROOT}" >&2
  exit 1
fi

if [[ -z "${AGENT_Q_BIP39_WORDLIST_ROOT:-}" ]]; then
  fetch_pinned_repo "${AGENT_Q_BIP39_WORDLIST_REPOSITORY}" "${AGENT_Q_BIP39_WORDLIST_COMMIT}" "${DEFAULT_BIP39_WORDLIST_DIR}"
  export AGENT_Q_BIP39_WORDLIST_ROOT="${DEFAULT_BIP39_WORDLIST_DIR}"
else
  export AGENT_Q_BIP39_WORDLIST_ROOT
fi

AGENT_Q_BIP39_ENGLISH_WORDLIST_FILE="${AGENT_Q_BIP39_WORDLIST_ROOT}/${AGENT_Q_BIP39_ENGLISH_WORDLIST_PATH}"
if [[ ! -f "${AGENT_Q_BIP39_ENGLISH_WORDLIST_FILE}" ]]; then
  echo "AGENT_Q_BIP39_WORDLIST_ROOT does not point to the pinned BIP-39 wordlist source: ${AGENT_Q_BIP39_WORDLIST_ROOT}" >&2
  exit 1
fi
export AGENT_Q_BIP39_ENGLISH_WORDLIST_FILE

"${SCRIPT_DIR}/prepare.sh" "${FIRMWARE_DIR}"

if ! command -v idf.py >/dev/null 2>&1; then
  echo "idf.py is not on PATH. Install ESP-IDF ${AGENT_Q_ESP_IDF_VERSION} and source its export.sh first." >&2
  exit 127
fi

cd "${FIRMWARE_DIR}"
idf.py -B "${BUILD_DIR}" build
