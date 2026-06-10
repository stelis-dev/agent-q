#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sui_signing_service.sh

Compiles the internal Agent-Q Sui signing substrate against the pinned MicroSui
signing source. It verifies deterministic transaction signatures for the Sui
standard account 0 derivation path, invalid-input output wiping, and the
stored-root signing boundary using host stubs. This is not a protocol signing
test and does not require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DEFAULT_SIGNING_DIR="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib"
SIGNING_ROOT="${AGENT_Q_SIGNING_CRYPTO_ROOT:-${DEFAULT_SIGNING_DIR}}"
SIGNING_CORE="${SIGNING_ROOT}/src/microsui_core"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
FIXTURE_DIR="${REPO_ROOT}/firmware/src/common/agent_q/sui/testdata/sui_transaction_facts"

for required in \
  "${SIGNING_CORE}/lib/monocypher/monocypher.c" \
  "${SIGNING_CORE}/byte_conversions.c" \
  "${SIGNING_CORE}/key_management.c" \
  "${SIGNING_CORE}/sign.c" \
  "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex" \
  "${AGENT_Q_DIR}/agent_q_sui_key_derivation.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_signing_service.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first, or set AGENT_Q_SIGNING_CRYPTO_ROOT." >&2
    exit 1
  fi
done

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sui-signing.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/sui_signing_service_test.cpp" <<'CPP'
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "agent_q_bip39.h"
#include "agent_q_root_material.h"
#include "agent_q_sui_signing_service.h"

extern "C" {
#include "byte_conversions.h"
#include "sign.h"
}

namespace {

constexpr const char* kMnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
constexpr const char* kExpectedSignatureBase64 =
    "ADqTxIgkfDWyvltJXwoGfXTzoxW1BLyq3C1tf9Gmsu1B+8yKrZNS4LBeU97uB7nRMJOwuHGYCmpfea3xI2H2HAWQC02B7s6j3y90sUIAxPTPP0mvrKemNP/Sz2/4K9rs8g==";
constexpr const uint8_t kPersonalMessage[] =
    "Agent-Q personal message test";
constexpr const uint8_t kExpectedPersonalMessageDigest[32] = {
    0xe5, 0x97, 0xf5, 0x26, 0xaa, 0xc7, 0x11, 0x68,
    0xe3, 0x13, 0x2b, 0x78, 0x5f, 0xa2, 0xb7, 0x9a,
    0xac, 0xa5, 0xd1, 0x96, 0xdb, 0x19, 0xf9, 0x62,
    0x40, 0xd3, 0x80, 0xc2, 0x34, 0x27, 0x37, 0x2b,
};

int failures = 0;
bool g_root_available = true;
bool g_mnemonic_available = true;

void expect(bool condition, const char* label)
{
    if (!condition) {
        std::fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

uint8_t hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(c - 'A' + 10);
    }
    std::fprintf(stderr, "Invalid fixture hex char: %c\n", c);
    std::exit(1);
}

std::vector<uint8_t> read_hex_fixture(const char* path)
{
    std::ifstream input(path);
    if (!input) {
        std::fprintf(stderr, "Could not open fixture: %s\n", path);
        std::exit(1);
    }
    std::string hex;
    input >> hex;
    if ((hex.size() % 2) != 0) {
        std::fprintf(stderr, "Fixture has odd hex length\n");
        std::exit(1);
    }
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<uint8_t>(
            (hex_value(hex[index * 2]) << 4) | hex_value(hex[index * 2 + 1]));
    }
    return bytes;
}

void expect_signature_cleared(const uint8_t* signature)
{
    for (size_t index = 0; index < agent_q::kSuiEd25519SignatureBytes; ++index) {
        if (signature[index] != 0) {
            std::fprintf(stderr, "FAILED: signature output not cleared at byte %zu\n", index);
            ++failures;
            return;
        }
    }
}

}  // namespace

namespace agent_q {

void wipe_sensitive_buffer(void* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool read_root_material(uint8_t* root_material_out, size_t root_material_size)
{
    if (!g_root_available || root_material_out == nullptr || root_material_size != kRootMaterialBytes) {
        wipe_sensitive_buffer(root_material_out, root_material_size);
        return false;
    }
    memset(root_material_out, 0x42, root_material_size);
    return true;
}

bool make_bip39_mnemonic_12_words(
    const uint8_t*, char* output, size_t output_size)
{
    if (!g_mnemonic_available || output == nullptr || output_size <= strlen(kMnemonic)) {
        wipe_sensitive_buffer(output, output_size);
        return false;
    }
    strcpy(output, kMnemonic);
    return true;
}

}  // namespace agent_q

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s /path/to/valid_sui_transfer_tx.bcs.hex\n", argv[0]);
        return 2;
    }
    const std::vector<uint8_t> tx_bytes = read_hex_fixture(argv[1]);

    uint8_t signature[agent_q::kSuiEd25519SignatureBytes] = {};
    g_root_available = true;
    g_mnemonic_available = true;
    const agent_q::SuiTransactionSigningResult result =
        agent_q::sign_sui_ed25519_transaction_from_stored_root(
            tx_bytes.data(), tx_bytes.size(), signature);
    expect(result == agent_q::SuiTransactionSigningResult::ok, "stored-root signing succeeds");
    expect(signature[0] == 0x00, "Sui signature uses Ed25519 scheme byte");
    expect(
        sui_signing_verify_signature_ed25519(
            signature, tx_bytes.data(), tx_bytes.size()) == 0,
        "signature verifies against tx bytes and Sui intent");

    uint8_t personal_digest[32] = {};
    expect(
        agent_q::build_sui_personal_message_intent_digest(
            kPersonalMessage,
            sizeof(kPersonalMessage) - 1,
            personal_digest),
        "personal-message intent digest builds");
    expect(
        memcmp(personal_digest, kExpectedPersonalMessageDigest, sizeof(personal_digest)) == 0,
        "personal-message digest matches Sui SDK vector");

    uint8_t personal_signature[agent_q::kSuiEd25519SignatureBytes] = {};
    expect(
        agent_q::sign_sui_ed25519_personal_message_from_stored_root(
            kPersonalMessage,
            sizeof(kPersonalMessage) - 1,
            personal_signature) == agent_q::SuiTransactionSigningResult::ok,
        "stored-root personal-message signing succeeds");
    expect(personal_signature[0] == 0x00, "Sui personal-message signature uses Ed25519 scheme byte");
    expect(
        sui_signing_verify_signature_ed25519_from_digest(personal_signature, personal_digest) == 0,
        "personal-message signature verifies against Sui SDK digest vector");

    char signature_base64[agent_q::kSuiEd25519SignatureBase64Chars + 1] = {};
    expect(
        bytes_to_base64(signature, sizeof(signature), signature_base64, sizeof(signature_base64)) == 0,
        "signature base64 encodes");
    if (strcmp(signature_base64, kExpectedSignatureBase64) != 0) {
        std::fprintf(stderr,
                     "FAILED: signature vector mismatch\n  expected: %s\n  actual:   %s\n",
                     kExpectedSignatureBase64,
                     signature_base64);
        ++failures;
    }

    uint8_t invalid_signature[agent_q::kSuiEd25519SignatureBytes];
    memset(invalid_signature, 0xA5, sizeof(invalid_signature));
    expect(
        agent_q::sign_sui_ed25519_transaction_from_stored_root(
            nullptr, tx_bytes.size(), invalid_signature) ==
            agent_q::SuiTransactionSigningResult::invalid_input,
        "null tx bytes are invalid");
    expect_signature_cleared(invalid_signature);

    memset(invalid_signature, 0xA5, sizeof(invalid_signature));
    expect(
        agent_q::sign_sui_ed25519_transaction_from_stored_root(
            tx_bytes.data(), 0, invalid_signature) ==
            agent_q::SuiTransactionSigningResult::invalid_input,
        "zero tx size is invalid");
    expect_signature_cleared(invalid_signature);

    uint8_t stored_root_signature[agent_q::kSuiEd25519SignatureBytes] = {};
    memset(stored_root_signature, 0xA5, sizeof(stored_root_signature));
    g_root_available = false;
    expect(
        agent_q::sign_sui_ed25519_transaction_from_stored_root(
            tx_bytes.data(), tx_bytes.size(), stored_root_signature) ==
            agent_q::SuiTransactionSigningResult::root_material_unavailable,
        "missing root material is reported");
    expect_signature_cleared(stored_root_signature);

    g_root_available = true;
    g_mnemonic_available = false;
    expect(
        agent_q::sign_sui_ed25519_transaction_from_stored_root(
            tx_bytes.data(), tx_bytes.size(), stored_root_signature) ==
            agent_q::SuiTransactionSigningResult::mnemonic_error,
        "mnemonic derivation failure is reported");

    if (failures != 0) {
        std::fprintf(stderr, "Sui signing service tests FAILED: %d\n", failures);
        return 1;
    }
    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${SIGNING_CORE}" \
  -Dmicrosui_sign=sui_signing_sign \
  -Dmicrosui_sign_ed25519=sui_signing_sign_ed25519 \
  -Dmicrosui_sign_ed25519_with_keys=sui_signing_sign_ed25519_with_keys \
  -Dmicrosui_sign_ed25519_from_digest=sui_signing_sign_ed25519_from_digest \
  -Dmicrosui_verify_signature=sui_signing_verify_signature \
  -Dmicrosui_verify_signature_with_public_key=sui_signing_verify_signature_with_public_key \
  -Dmicrosui_verify_signature_ed25519=sui_signing_verify_signature_ed25519 \
  -Dmicrosui_verify_signature_ed25519_from_digest=sui_signing_verify_signature_ed25519_from_digest \
  -Dmicrosui_verify_signature_ed25519_with_public_key=sui_signing_verify_signature_ed25519_with_public_key \
  -Dmicrosui_verify_signature_ed25519_with_public_key_from_digest=sui_signing_verify_signature_ed25519_with_public_key_from_digest \
  -Dmicrosui_sign_message=sui_signing_sign_message \
  -c "${SIGNING_CORE}/sign.c" -o "${TMP_DIR}/sign.o"
"${CC_BIN}" -std=c99 -I"${SIGNING_CORE}" \
  -c "${SIGNING_CORE}/lib/monocypher/monocypher.c" -o "${TMP_DIR}/monocypher.o"
"${CC_BIN}" -std=c99 -I"${SIGNING_CORE}" \
  -c "${SIGNING_CORE}/byte_conversions.c" -o "${TMP_DIR}/byte_conversions.o"
"${CC_BIN}" -std=c99 -I"${SIGNING_CORE}" \
  -c "${SIGNING_CORE}/key_management.c" -o "${TMP_DIR}/key_management.o"

"${CXX_BIN}" -std=c++17 \
  -I"${REPO_ROOT}/firmware/src/stackchan-cores3/components/signing_crypto" \
  -I"${SIGNING_CORE}" -I"${AGENT_Q_DIR}" \
  -c "${AGENT_Q_DIR}/agent_q_sui_key_derivation.cpp" -o "${TMP_DIR}/agent_q_sui_key_derivation.o"
"${CXX_BIN}" -std=c++17 \
  -I"${REPO_ROOT}/firmware/src/stackchan-cores3/components/signing_crypto" \
  -I"${SIGNING_CORE}" -I"${AGENT_Q_DIR}" \
  -c "${AGENT_Q_DIR}/agent_q_sui_signing_service.cpp" -o "${TMP_DIR}/agent_q_sui_signing_service.o"
"${CXX_BIN}" -std=c++17 \
  -I"${REPO_ROOT}/firmware/src/stackchan-cores3/components/signing_crypto" \
  -I"${SIGNING_CORE}" -I"${AGENT_Q_DIR}" \
  -c "${TMP_DIR}/sui_signing_service_test.cpp" -o "${TMP_DIR}/sui_signing_service_test.o"

"${CXX_BIN}" \
  "${TMP_DIR}/monocypher.o" \
  "${TMP_DIR}/byte_conversions.o" \
  "${TMP_DIR}/key_management.o" \
  "${TMP_DIR}/sign.o" \
  "${TMP_DIR}/agent_q_sui_key_derivation.o" \
  "${TMP_DIR}/agent_q_sui_signing_service.o" \
  "${TMP_DIR}/sui_signing_service_test.o" \
  -o "${TMP_DIR}/sui_signing_service_test"

"${TMP_DIR}/sui_signing_service_test" "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex"
echo "Sui signing service tests passed"
