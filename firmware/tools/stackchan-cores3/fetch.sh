#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/fetch.sh /path/to/StackChan

Fetches the pinned StackChan host firmware repository and its firmware
dependencies into the given directory. The destination is not .WORK-specific;
GitHub Actions should use a temporary directory inside the runner workspace.
EOF
}

if [[ $# -gt 1 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SOURCE_ENV="${REPO_ROOT}/firmware/src/stackchan-cores3/source.env"
DEFAULT_CHECKOUT_DIR="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan"

# shellcheck source=/dev/null
source "${SOURCE_ENV}"

CHECKOUT_DIR="${1:-${DEFAULT_CHECKOUT_DIR}}"

if [[ -e "${CHECKOUT_DIR}" && ! -d "${CHECKOUT_DIR}/.git" ]]; then
  echo "Destination exists but is not a git checkout: ${CHECKOUT_DIR}" >&2
  exit 1
fi

if [[ ! -d "${CHECKOUT_DIR}/.git" ]]; then
  mkdir -p "$(dirname "${CHECKOUT_DIR}")"
  git clone "${AGENT_Q_STACKCHAN_REPOSITORY}" "${CHECKOUT_DIR}"
fi

if ! git -C "${CHECKOUT_DIR}" cat-file -e "${AGENT_Q_STACKCHAN_COMMIT}^{commit}" 2>/dev/null; then
  git -C "${CHECKOUT_DIR}" fetch --tags origin
fi
git -C "${CHECKOUT_DIR}" checkout --force "${AGENT_Q_STACKCHAN_COMMIT}"

cd "${CHECKOUT_DIR}/firmware"
python3 ./fetch_repos.py

echo "${CHECKOUT_DIR}"
