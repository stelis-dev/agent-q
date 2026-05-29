#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_sui_account_vectors.sh

Compiles the Agent-Q Sui Ed25519 account derivation (BIP-39 mnemonic ->
PBKDF2-HMAC-SHA512 seed -> SLIP-0010 m/44'/784'/0'/0'/0' -> Ed25519 public key
-> Sui address) against the pinned MicroSui signing source (monocypher,
byte_conversions, key_management) and asserts known Sui SDK address vectors.

This test uses only a host C/C++ compiler and the pinned signing source; it does
NOT require ESP-IDF. Set AGENT_Q_SIGNING_CRYPTO_ROOT to override the source
location, otherwise the pinned .firmware-cache checkout from build.sh is used.
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
AGENT_Q_DIR="${REPO_ROOT}/products/firmware/src/stackchan-cores3/agent_q"

for required in \
  "${SIGNING_CORE}/lib/monocypher/monocypher.c" \
  "${SIGNING_CORE}/byte_conversions.c" \
  "${SIGNING_CORE}/key_management.c" \
  "${AGENT_Q_DIR}/agent_q_sui_account.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run tools/firmware/stackchan-cores3/build.sh first, or set AGENT_Q_SIGNING_CRYPTO_ROOT." >&2
    exit 1
  fi
done

CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sui-account.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/sui_account_vector_test.cpp" <<'CPP'
#include <cstdio>
#include <cstring>

#include "agent_q_sui_account.h"

extern "C" {
#include "byte_conversions.h"
}

namespace {

struct Vector {
    const char* mnemonic;
    const char* expected_address;
    const char* expected_public_key;  // raw 32-byte Ed25519 key, base64
};

// Authoritative vectors from the Sui TypeScript SDK
// (MystenLabs/sui, sdk/typescript/test/unit/cryptography/ed25519-keypair.test.ts),
// default derivation path m/44'/784'/0'/0'/0'.
//
// expected_address is the SDK address. expected_public_key is the raw 32-byte
// Ed25519 key (base64) whose blake2b256(0x00 || key) equals expected_address;
// each (address, public_key) pair was verified independently against the Sui
// address definition, so this is not the module's own output asserted against
// itself.
const Vector kVectors[] = {
    {"film crazy soon outside stand loop subway crumble thrive popular green nuclear struggle pistol arm wife phrase warfare march wheat nephew ask sunny firm",
     "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133",
     "ImR/7u82MGC9QgWhZxoV8QoSNnZZGLG19jjYLzPPxGk="},
    {"require decline left thought grid priority false tiny gasp angle royal system attack beef setup reward aunt skill wasp tray vital bounce inflict level",
     "0x1ada6e6f3f3e4055096f606c746690f1108fcc2ca479055cc434a3e1d3f758aa",
     "vG6hEnkYNIpdmWa/WaLivd1FWBkxG+HfhXkyWgs9uP4="},
    {"organ crash swim stick traffic remember army arctic mesh slice swear summer police vast chaos cradle squirrel hood useless evidence pet hub soap lake",
     "0xe69e896ca10f5a77732769803cc2b5707f0ab9d4407afb5e4b4464b89769af14",
     "arEzeF7Uu90jP4Sd+Or17c+A9kYviJpCEQAbEt0FHbU="},
};

}  // namespace

int main()
{
    int failures = 0;
    for (size_t index = 0; index < sizeof(kVectors) / sizeof(kVectors[0]); ++index) {
        uint8_t public_key[agent_q::kSuiEd25519PublicKeyBytes] = {};
        char address[agent_q::kSuiAddressBufferSize] = {};
        if (!agent_q::derive_sui_ed25519_account(
                kVectors[index].mnemonic, public_key, address, sizeof(address))) {
            fprintf(stderr, "Vector %zu: derivation failed\n", index);
            ++failures;
            continue;
        }
        if (strcmp(address, kVectors[index].expected_address) != 0) {
            fprintf(stderr, "Vector %zu address mismatch\n  expected: %s\n  actual:   %s\n",
                    index, kVectors[index].expected_address, address);
            ++failures;
        }

        // The address verifies the public-key bytes (a Sui address is
        // blake2b256(0x00 || publicKey)); this verifies the emitted base64
        // representation against the independently-derived public-key vector.
        char public_key_base64[48] = {};
        if (bytes_to_base64(public_key, sizeof(public_key), public_key_base64, sizeof(public_key_base64)) != 0) {
            fprintf(stderr, "Vector %zu public key base64 encoding failed\n", index);
            ++failures;
        } else if (strcmp(public_key_base64, kVectors[index].expected_public_key) != 0) {
            fprintf(stderr, "Vector %zu publicKey mismatch\n  expected: %s\n  actual:   %s\n",
                    index, kVectors[index].expected_public_key, public_key_base64);
            ++failures;
        }
    }

    uint8_t public_key[agent_q::kSuiEd25519PublicKeyBytes];
    char address[agent_q::kSuiAddressBufferSize];
    memset(public_key, 0xA5, sizeof(public_key));
    memset(address, 'x', sizeof(address));
    if (agent_q::derive_sui_ed25519_account("", public_key, address, sizeof(address))) {
        fprintf(stderr, "Invalid mnemonic unexpectedly derived an account\n");
        ++failures;
    }
    for (size_t index = 0; index < sizeof(public_key); ++index) {
        if (public_key[index] != 0) {
            fprintf(stderr, "Failure path left public_key_out uncleared at byte %zu\n", index);
            ++failures;
            break;
        }
    }
    for (size_t index = 0; index < sizeof(address); ++index) {
        if (address[index] != '\0') {
            fprintf(stderr, "Failure path left address_out uncleared at byte %zu\n", index);
            ++failures;
            break;
        }
    }

    if (failures != 0) {
        fprintf(stderr, "Sui account vector tests FAILED: %d\n", failures);
        return 1;
    }
    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${SIGNING_CORE}" \
  -c "${SIGNING_CORE}/lib/monocypher/monocypher.c" -o "${TMP_DIR}/monocypher.o"
"${CC_BIN}" -std=c99 -I"${SIGNING_CORE}" \
  -c "${SIGNING_CORE}/byte_conversions.c" -o "${TMP_DIR}/byte_conversions.o"
"${CC_BIN}" -std=c99 -I"${SIGNING_CORE}" \
  -c "${SIGNING_CORE}/key_management.c" -o "${TMP_DIR}/key_management.o"

"${CXX_BIN}" -std=c++17 -I"${SIGNING_CORE}" -I"${AGENT_Q_DIR}" \
  -c "${AGENT_Q_DIR}/agent_q_sui_account.cpp" -o "${TMP_DIR}/agent_q_sui_account.o"
"${CXX_BIN}" -std=c++17 -I"${SIGNING_CORE}" -I"${AGENT_Q_DIR}" \
  -c "${TMP_DIR}/sui_account_vector_test.cpp" -o "${TMP_DIR}/sui_account_vector_test.o"

"${CXX_BIN}" \
  "${TMP_DIR}/monocypher.o" \
  "${TMP_DIR}/byte_conversions.o" \
  "${TMP_DIR}/key_management.o" \
  "${TMP_DIR}/agent_q_sui_account.o" \
  "${TMP_DIR}/sui_account_vector_test.o" \
  -o "${TMP_DIR}/sui_account_vector_test"

"${TMP_DIR}/sui_account_vector_test"
echo "Sui account derivation vector tests passed"
