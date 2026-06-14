#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_prepare_sync.sh

Checks that prepare.sh materializes tracked files and directories into a
generated StackChan firmware tree, replacing stale or broken symlinks left by a
previous polluted checkout, including kept generated files.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET_ROOT="${REPO_ROOT}/firmware/src/stackchan-cores3"
FIRMWARE_DIR="${AGENT_Q_STACKCHAN_FIRMWARE_DIR:-${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-prepare-sync.XXXXXX")"

if [[ ! -f "${FIRMWARE_DIR}/main/CMakeLists.txt" ||
      ! -f "${FIRMWARE_DIR}/main/main.cpp" ||
      ! -f "${FIRMWARE_DIR}/main/hal/hal.cpp" ||
      ! -f "${FIRMWARE_DIR}/xiaozhi-esp32/main/mcp_server.cc" ]]; then
  echo "Missing prepared StackChan firmware tree: ${FIRMWARE_DIR}" >&2
  echo "Run firmware/tools/stackchan-cores3/build.sh first, or set AGENT_Q_STACKCHAN_FIRMWARE_DIR." >&2
  rm -rf "${TMP_DIR}"
  exit 1
fi

GENERATED_WORDLIST="${FIRMWARE_DIR}/main/agent_q/agent_q_bip39_wordlist.cpp"
WORDLIST_BACKUP="${TMP_DIR}/agent_q_bip39_wordlist.cpp"
TARGET_FILE=""
TARGET_FILE_BACKUP="${TMP_DIR}/agent_q_entropy.cpp"
TARGET_DIR=""
TARGET_DIR_BACKUP="${TMP_DIR}/policy"
SYNC_ROOT_DIR=""
SYNC_ROOT_BACKUP="${TMP_DIR}/signing_crypto"
HAD_WORDLIST=0
if [[ -f "${GENERATED_WORDLIST}" && ! -L "${GENERATED_WORDLIST}" ]]; then
  cp "${GENERATED_WORDLIST}" "${WORDLIST_BACKUP}"
  HAD_WORDLIST=1
fi

restore_generated_tree() {
  if [[ -n "${TARGET_FILE}" && -f "${TARGET_FILE_BACKUP}" ]]; then
    rm -f "${TARGET_FILE}"
    cp "${TARGET_FILE_BACKUP}" "${TARGET_FILE}"
  fi
  if [[ -n "${TARGET_DIR}" && -d "${TARGET_DIR_BACKUP}" ]]; then
    rm -rf "${TARGET_DIR}"
    cp -R "${TARGET_DIR_BACKUP}" "${TARGET_DIR}"
  fi
  if [[ -n "${SYNC_ROOT_DIR}" && -d "${SYNC_ROOT_BACKUP}" ]]; then
    rm -rf "${SYNC_ROOT_DIR}"
    mkdir -p "$(dirname "${SYNC_ROOT_DIR}")"
    cp -R "${SYNC_ROOT_BACKUP}" "${SYNC_ROOT_DIR}"
  fi
  if [[ "${HAD_WORDLIST}" -eq 1 ]]; then
    mkdir -p "$(dirname "${GENERATED_WORDLIST}")"
    rm -rf "${GENERATED_WORDLIST}"
    cp "${WORDLIST_BACKUP}" "${GENERATED_WORDLIST}"
  else
    rm -rf "${GENERATED_WORDLIST}"
  fi
  rm -rf "${TMP_DIR}"
}
trap restore_generated_tree EXIT

WORDLIST_FILE="${TMP_DIR}/english.txt"
python3 - "${WORDLIST_FILE}" <<'PY'
from pathlib import Path
import sys

letters = "abcdefghijklmnopqrstuvwxyz"
words = []
for index in range(2048):
    first = index // (26 * 26)
    second = (index // 26) % 26
    third = index % 26
    words.append(f"q{letters[first]}{letters[second]}{letters[third]}")
Path(sys.argv[1]).write_text("\n".join(words) + "\n", encoding="utf-8")
PY

AGENT_Q_BIP39_ENGLISH_WORDLIST_FILE="${WORDLIST_FILE}" "${SCRIPT_DIR}/prepare.sh" "${FIRMWARE_DIR}"

grep -Eq '^nvs,[[:space:]]+data,[[:space:]]+nvs,[[:space:]]+0x9000,[[:space:]]+0x10000,' "${FIRMWARE_DIR}/partitions.csv"
grep -Eq '^otadata,[[:space:]]+data,[[:space:]]+ota,[[:space:]]+0x19000,[[:space:]]+0x2000,' "${FIRMWARE_DIR}/partitions.csv"
grep -Eq '^phy_init,[[:space:]]+data,[[:space:]]+phy,[[:space:]]+0x1b000,[[:space:]]+0x1000,' "${FIRMWARE_DIR}/partitions.csv"

SYNC_ROOT_DIR="${FIRMWARE_DIR}/components/signing_crypto"
cp -R "${SYNC_ROOT_DIR}" "${SYNC_ROOT_BACKUP}"
EXTERNAL_SYNC_ROOT="${TMP_DIR}/external-signing-crypto"
mkdir -p "${EXTERNAL_SYNC_ROOT}"
printf 'external sync root must not be touched\n' >"${EXTERNAL_SYNC_ROOT}/sentinel.txt"
rm -rf "${SYNC_ROOT_DIR}"
ln -s "${EXTERNAL_SYNC_ROOT}" "${SYNC_ROOT_DIR}"
AGENT_Q_BIP39_ENGLISH_WORDLIST_FILE="${WORDLIST_FILE}" "${SCRIPT_DIR}/prepare.sh" "${FIRMWARE_DIR}"
if [[ -L "${SYNC_ROOT_DIR}" || ! -d "${SYNC_ROOT_DIR}" ]]; then
  echo "prepare.sh did not replace target root symlink: ${SYNC_ROOT_DIR}" >&2
  exit 1
fi
if [[ ! -f "${EXTERNAL_SYNC_ROOT}/sentinel.txt" ||
      "$(cat "${EXTERNAL_SYNC_ROOT}/sentinel.txt")" != "external sync root must not be touched" ]]; then
  echo "prepare.sh touched or cleaned the target root symlink referent" >&2
  exit 1
fi
if [[ -e "${EXTERNAL_SYNC_ROOT}/sign.h" || -e "${EXTERNAL_SYNC_ROOT}/CMakeLists.txt" ]]; then
  echo "prepare.sh wrote through the target root symlink referent" >&2
  exit 1
fi
cmp "${TARGET_ROOT}/components/signing_crypto/sign.h" "${SYNC_ROOT_DIR}/sign.h" >/dev/null

SOURCE_FILE="${TARGET_ROOT}/agent_q/agent_q_entropy.cpp"
TARGET_FILE="${FIRMWARE_DIR}/main/agent_q/agent_q_entropy.cpp"
cp "${TARGET_FILE}" "${TARGET_FILE_BACKUP}"
rm -f "${TARGET_FILE}"
ln -s "${SOURCE_FILE}" "${TARGET_FILE}"
AGENT_Q_BIP39_ENGLISH_WORDLIST_FILE="${WORDLIST_FILE}" "${SCRIPT_DIR}/prepare.sh" "${FIRMWARE_DIR}"
if [[ -L "${TARGET_FILE}" || ! -f "${TARGET_FILE}" ]]; then
  echo "prepare.sh did not replace target file symlink: ${TARGET_FILE}" >&2
  exit 1
fi
cmp "${SOURCE_FILE}" "${TARGET_FILE}" >/dev/null

rm -f "${TARGET_FILE}"
ln -s "${TMP_DIR}/missing-agent-q-entropy.cpp" "${TARGET_FILE}"
AGENT_Q_BIP39_ENGLISH_WORDLIST_FILE="${WORDLIST_FILE}" "${SCRIPT_DIR}/prepare.sh" "${FIRMWARE_DIR}"
if [[ -L "${TARGET_FILE}" || ! -f "${TARGET_FILE}" ]]; then
  echo "prepare.sh did not replace broken target file symlink: ${TARGET_FILE}" >&2
  exit 1
fi
cmp "${SOURCE_FILE}" "${TARGET_FILE}" >/dev/null

TARGET_DIR="${FIRMWARE_DIR}/main/agent_q_common/policy"
cp -R "${TARGET_DIR}" "${TARGET_DIR_BACKUP}"
rm -rf "${TARGET_DIR}"
ln -s "${TMP_DIR}/missing-policy-dir" "${TARGET_DIR}"
AGENT_Q_BIP39_ENGLISH_WORDLIST_FILE="${WORDLIST_FILE}" "${SCRIPT_DIR}/prepare.sh" "${FIRMWARE_DIR}"
if [[ -L "${TARGET_DIR}" || ! -d "${TARGET_DIR}" ]]; then
  echo "prepare.sh did not replace broken target directory symlink: ${TARGET_DIR}" >&2
  exit 1
fi
if [[ ! -f "${TARGET_DIR}/agent_q_policy_document.cpp" ]]; then
  echo "prepare.sh did not restore common policy sources under ${TARGET_DIR}" >&2
  exit 1
fi

EXTERNAL_WORDLIST_REFERENT="${TMP_DIR}/external-wordlist-output.cpp"
printf 'external referent must not be overwritten\n' >"${EXTERNAL_WORDLIST_REFERENT}"
rm -f "${GENERATED_WORDLIST}"
ln -s "${EXTERNAL_WORDLIST_REFERENT}" "${GENERATED_WORDLIST}"
AGENT_Q_BIP39_ENGLISH_WORDLIST_FILE="${WORDLIST_FILE}" "${SCRIPT_DIR}/prepare.sh" "${FIRMWARE_DIR}"
if [[ -L "${GENERATED_WORDLIST}" || ! -f "${GENERATED_WORDLIST}" ]]; then
  echo "prepare.sh did not replace generated wordlist symlink: ${GENERATED_WORDLIST}" >&2
  exit 1
fi
if [[ "$(cat "${EXTERNAL_WORDLIST_REFERENT}")" != "external referent must not be overwritten" ]]; then
  echo "wordlist generator wrote through a generated-tree symlink" >&2
  exit 1
fi
grep -q 'kBip39EnglishWords' "${GENERATED_WORDLIST}"

rm -f "${GENERATED_WORDLIST}"
ln -s "${TMP_DIR}/missing-wordlist-output.cpp" "${GENERATED_WORDLIST}"
AGENT_Q_BIP39_ENGLISH_WORDLIST_FILE="${WORDLIST_FILE}" "${SCRIPT_DIR}/prepare.sh" "${FIRMWARE_DIR}"
if [[ -L "${GENERATED_WORDLIST}" || ! -f "${GENERATED_WORDLIST}" ]]; then
  echo "prepare.sh did not replace broken generated wordlist symlink: ${GENERATED_WORDLIST}" >&2
  exit 1
fi
if [[ -e "${TMP_DIR}/missing-wordlist-output.cpp" ]]; then
  echo "wordlist generator created a broken symlink referent outside the generated tree" >&2
  exit 1
fi
grep -q 'kBip39EnglishWords' "${GENERATED_WORDLIST}"

echo "prepare sync tests passed"
