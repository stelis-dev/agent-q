#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_bip39_vectors.sh

ESP-IDF must already be active in the shell so IDF_PATH points to the ESP-IDF
checkout. The test compiles the Agent-Q BIP-39 encoder against ESP-IDF mbedtls
and a generated source file from the pinned BIP-39 English wordlist.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET_ROOT="${REPO_ROOT}/firmware/src/stackchan-cores3"
COMMON_SOURCE_ENV="${REPO_ROOT}/firmware/source.env"
DEFAULT_BIP39_WORDLIST_DIR="${REPO_ROOT}/.firmware-cache/bip39/bips"

# shellcheck source=/dev/null
source "${COMMON_SOURCE_ENV}"

BIP39_WORDLIST_FILE="${BIP39_ENGLISH_WORDLIST_FILE:-}"
if [[ -z "${BIP39_WORDLIST_FILE}" && -n "${BIP39_WORDLIST_ROOT:-}" && -n "${BIP39_ENGLISH_WORDLIST_PATH:-}" ]]; then
  BIP39_WORDLIST_FILE="${BIP39_WORDLIST_ROOT}/${BIP39_ENGLISH_WORDLIST_PATH}"
fi
if [[ -z "${BIP39_WORDLIST_FILE}" && -n "${BIP39_ENGLISH_WORDLIST_PATH:-}" ]]; then
  CACHED_WORDLIST_FILE="${DEFAULT_BIP39_WORDLIST_DIR}/${BIP39_ENGLISH_WORDLIST_PATH}"
  if [[ -f "${CACHED_WORDLIST_FILE}" ]]; then
    BIP39_WORDLIST_FILE="${CACHED_WORDLIST_FILE}"
  fi
fi
if [[ -z "${BIP39_WORDLIST_FILE}" || ! -f "${BIP39_WORDLIST_FILE}" ]]; then
  echo "Missing pinned BIP-39 English wordlist. Run firmware/tools/stackchan-cores3/build.sh or set BIP39_ENGLISH_WORDLIST_FILE." >&2
  exit 1
fi

if [[ -z "${IDF_PATH:-}" ]]; then
  echo "IDF_PATH is not set. Source ESP-IDF v5.5.4 export.sh before running this test." >&2
  exit 1
fi

MBEDTLS_ROOT="${IDF_PATH}/components/mbedtls/mbedtls"
MBEDTLS_INCLUDE_DIR="${MBEDTLS_ROOT}/include"
MBEDTLS_LIBRARY_DIR="${MBEDTLS_ROOT}/library"
if [[ ! -f "${MBEDTLS_INCLUDE_DIR}/mbedtls/sha256.h" || ! -f "${MBEDTLS_LIBRARY_DIR}/sha256.c" || ! -f "${MBEDTLS_LIBRARY_DIR}/platform_util.c" ]]; then
  echo "IDF_PATH does not expose the expected ESP-IDF mbedtls sources: ${IDF_PATH}" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bip39-vectors.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

python3 "${SCRIPT_DIR}/generate_bip39_wordlist.py" \
  "${BIP39_WORDLIST_FILE}" \
  "${TMP_DIR}/bip39_wordlist.cpp"

cat >"${TMP_DIR}/bip39_vector_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bip39.h"

namespace {

bool run_fill_vector(uint8_t fill, const char* expected)
{
    uint8_t entropy[signing::kBip39EntropyBytes] = {};
    memset(entropy, fill, sizeof(entropy));

    char output[signing::kBip39MnemonicMaxChars] = {};
    if (!signing::make_bip39_mnemonic_12_words(entropy, output, sizeof(output))) {
        fprintf(stderr, "make_bip39_mnemonic_12_words failed for fill 0x%02x\n", fill);
        signing::wipe_sensitive_buffer(entropy, sizeof(entropy));
        signing::wipe_sensitive_buffer(output, sizeof(output));
        return false;
    }

    if (strcmp(output, expected) != 0) {
        fprintf(stderr, "BIP-39 vector mismatch for fill 0x%02x\nexpected: %s\nactual:   %s\n", fill, expected, output);
        signing::wipe_sensitive_buffer(entropy, sizeof(entropy));
        signing::wipe_sensitive_buffer(output, sizeof(output));
        return false;
    }

    signing::wipe_sensitive_buffer(entropy, sizeof(entropy));
    signing::wipe_sensitive_buffer(output, sizeof(output));
    return true;
}

bool parse_expected_words(const char* mnemonic, uint16_t words[signing::kBip39MnemonicWordCount])
{
    char copy[signing::kBip39MnemonicMaxChars] = {};
    if (strlen(mnemonic) >= sizeof(copy)) {
        return false;
    }
    strcpy(copy, mnemonic);

    size_t word_count = 0;
    char* cursor = copy;
    while (*cursor != '\0') {
        while (*cursor == ' ') {
            ++cursor;
        }
        if (*cursor == '\0') {
            break;
        }
        char* start = cursor;
        while (*cursor != '\0' && *cursor != ' ') {
            ++cursor;
        }
        if (*cursor == ' ') {
            *cursor++ = '\0';
        }
        if (word_count >= signing::kBip39MnemonicWordCount ||
            !signing::bip39_english_word_index(start, &words[word_count])) {
            signing::wipe_sensitive_buffer(copy, sizeof(copy));
            return false;
        }
        ++word_count;
    }

    signing::wipe_sensitive_buffer(copy, sizeof(copy));
    return word_count == signing::kBip39MnemonicWordCount;
}

bool run_decode_vector(uint8_t fill, const char* mnemonic)
{
    uint16_t words[signing::kBip39MnemonicWordCount] = {};
    if (!parse_expected_words(mnemonic, words)) {
        fprintf(stderr, "Could not parse expected mnemonic words\n");
        return false;
    }

    uint8_t entropy[signing::kBip39EntropyBytes] = {};
    const signing::Bip39EntropyDecodeResult result =
        signing::decode_bip39_entropy_12_words(
            words, signing::kBip39MnemonicWordCount, entropy, sizeof(entropy));
    if (result != signing::Bip39EntropyDecodeResult::ok) {
        fprintf(stderr, "decode_bip39_entropy_12_words failed for fill 0x%02x\n", fill);
        signing::wipe_sensitive_buffer(entropy, sizeof(entropy));
        return false;
    }

    for (size_t index = 0; index < sizeof(entropy); ++index) {
        if (entropy[index] != fill) {
            fprintf(stderr, "Decoded entropy mismatch at byte %zu for fill 0x%02x\n", index, fill);
            signing::wipe_sensitive_buffer(entropy, sizeof(entropy));
            return false;
        }
    }

    words[signing::kBip39MnemonicWordCount - 1] ^= 0x01;
    const signing::Bip39EntropyDecodeResult checksum_result =
        signing::decode_bip39_entropy_12_words(
            words, signing::kBip39MnemonicWordCount, entropy, sizeof(entropy));
    signing::wipe_sensitive_buffer(entropy, sizeof(entropy));
    if (checksum_result != signing::Bip39EntropyDecodeResult::checksum_mismatch) {
        fprintf(stderr, "Checksum mismatch was not rejected for fill 0x%02x\n", fill);
        return false;
    }
    return true;
}

}  // namespace

int main()
{
    const char* zero_vector =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char* ff_vector =
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    if (!run_fill_vector(0x00, zero_vector)) {
        return 1;
    }
    if (!run_fill_vector(0xff, ff_vector)) {
        return 1;
    }
    if (!run_decode_vector(0x00, zero_vector)) {
        return 1;
    }
    if (!run_decode_vector(0xff, ff_vector)) {
        return 1;
    }

    return 0;
}
CPP

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 \
  -I"${TARGET_ROOT}/runtime" \
  -I"${COMMON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/bip39_vector_test.cpp" \
  "${TARGET_ROOT}/runtime/bip39.cpp" \
  "${TMP_DIR}/bip39_wordlist.cpp" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/bip39_vector_test"

"${TMP_DIR}/bip39_vector_test"
echo "BIP-39 vector tests passed"
