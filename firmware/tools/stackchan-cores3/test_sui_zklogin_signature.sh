#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sui_zklogin_signature.sh

Builds the Firmware-owned Sui zkLogin signature BCS serializer with a host
C++ compiler and compares its output to the local @mysten/sui SDK oracle. This
test does not require ESP-IDF or hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
CXX_BIN="${CXX:-c++}"

for required in \
  "${COMMON_SUI_DIR}/zklogin_signature.cpp" \
  "${COMMON_SUI_DIR}/zklogin_signature.h" \
  "${COMMON_SUI_DIR}/zklogin_proof_record.h" \
  "${COMMON_SUI_DIR}/signature_scheme.h" \
  "${COMMON_ROOT}/numeric/u64_decimal.h" \
  "${REPO_ROOT}/node_modules/@mysten/sui/src/zklogin/signature.ts"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-sui-zklogin-signature.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

node --input-type=module >"${TMP_DIR}/expected.hex" <<'JS'
import { getZkLoginSignature } from "@mysten/sui/zklogin";
import { fromBase64 } from "@mysten/sui/utils";

const userSignature = new Uint8Array(97);
userSignature[0] = 0;
for (let index = 1; index < userSignature.length; index += 1) {
  userSignature[index] = index;
}

const inputs = {
  proofPoints: {
    a: ["1", "2", "1"],
    b: [["3", "4"], ["5", "6"], ["1", "0"]],
    c: ["7", "8", "1"],
  },
  issBase64Details: {
    value: "aHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29t",
    indexMod4: 1,
  },
  headerBase64: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFnZW50LXEta2lkIn0",
  addressSeed: "1",
};

const signature = getZkLoginSignature({
  inputs,
  maxEpoch: "123",
  userSignature,
});
console.log(Buffer.from(fromBase64(signature)).toString("hex"));
JS

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "sui/zklogin_signature.h"

namespace {

int g_failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++g_failures;
    }
}

bool set_field(char* output, size_t output_size, const char* value)
{
    const size_t length = strlen(value);
    if (length + 1 > output_size) {
        return false;
    }
    memset(output, 0, output_size);
    memcpy(output, value, length + 1);
    return true;
}

signing::SuiZkLoginSignatureInputs make_inputs()
{
    signing::SuiZkLoginSignatureInputs inputs = {};
    const char* a_values[] = {"1", "2", "1"};
    const char* b_values[][signing::kSuiZkLoginProofPointBInnerCount] = {
        {"3", "4"},
        {"5", "6"},
        {"1", "0"},
    };
    const char* c_values[] = {"7", "8", "1"};
    for (size_t index = 0; index < signing::kSuiZkLoginProofPointACount; ++index) {
        expect(
            set_field(
                inputs.proof_points.a[index],
                sizeof(inputs.proof_points.a[index]),
                a_values[index]),
            "proof point a fits");
    }
    for (size_t row = 0; row < signing::kSuiZkLoginProofPointBOuterCount; ++row) {
        for (size_t column = 0; column < signing::kSuiZkLoginProofPointBInnerCount; ++column) {
            expect(
                set_field(
                    inputs.proof_points.b[row][column],
                    sizeof(inputs.proof_points.b[row][column]),
                    b_values[row][column]),
                "proof point b fits");
        }
    }
    for (size_t index = 0; index < signing::kSuiZkLoginProofPointCCount; ++index) {
        expect(
            set_field(
                inputs.proof_points.c[index],
                sizeof(inputs.proof_points.c[index]),
                c_values[index]),
            "proof point c fits");
    }
    expect(
        set_field(
            inputs.iss_base64_details.value,
            sizeof(inputs.iss_base64_details.value),
            "aHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29t"),
        "issuer claim fits");
    inputs.iss_base64_details.index_mod4 = 1;
    expect(
        set_field(
            inputs.header_base64,
            sizeof(inputs.header_base64),
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFnZW50LXEta2lkIn0"),
        "header fits");
    expect(
        set_field(
            inputs.address_seed,
            sizeof(inputs.address_seed),
            "1"),
        "address seed fits");
    return inputs;
}

void to_hex(const unsigned char* bytes, size_t bytes_size, char* output, size_t output_size)
{
    static const char* kHex = "0123456789abcdef";
    if (output == nullptr || output_size < (bytes_size * 2) + 1) {
        return;
    }
    for (size_t index = 0; index < bytes_size; ++index) {
        output[index * 2] = kHex[(bytes[index] >> 4) & 0x0f];
        output[(index * 2) + 1] = kHex[bytes[index] & 0x0f];
    }
    output[bytes_size * 2] = '\0';
}

bool read_expected_hex(const char* path, char* output, size_t output_size)
{
    FILE* file = fopen(path, "rb");
    if (file == nullptr) {
        return false;
    }
    const size_t read = fread(output, 1, output_size - 1, file);
    fclose(file);
    if (read == 0 || read >= output_size) {
        return false;
    }
    output[read] = '\0';
    const size_t length = strlen(output);
    if (length > 0 && output[length - 1] == '\n') {
        output[length - 1] = '\0';
    }
    return true;
}

}  // namespace

namespace signing {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

}  // namespace signing

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "expected fixture path\n");
        return 2;
    }

    signing::SuiZkLoginSignatureInputs inputs = make_inputs();
    unsigned char user_signature[signing::kSuiEd25519SignatureBytes] = {};
    for (size_t index = 1; index < sizeof(user_signature); ++index) {
        user_signature[index] = static_cast<unsigned char>(index);
    }

    unsigned char output[signing::kSuiSignatureEnvelopeMaxBytes] = {};
    size_t output_size = 0;
    const signing::SuiZkLoginSignatureBuildResult result =
        signing::build_sui_zklogin_signature_envelope(
            inputs,
            "123",
            user_signature,
            sizeof(user_signature),
            output,
            sizeof(output),
            &output_size);
    expect(result == signing::SuiZkLoginSignatureBuildResult::ok, "build succeeds");
    expect(output_size > signing::kSuiEd25519SignatureBytes, "zkLogin envelope is variable sized");
    expect(output[0] == signing::kSuiSignatureSchemeFlagZkLogin, "outer scheme flag is zkLogin");

    char expected_hex[signing::kSuiSignatureEnvelopeMaxBytes * 2 + 1] = {};
    char actual_hex[signing::kSuiSignatureEnvelopeMaxBytes * 2 + 1] = {};
    expect(read_expected_hex(argv[1], expected_hex, sizeof(expected_hex)), "read SDK oracle fixture");
    to_hex(output, output_size, actual_hex, sizeof(actual_hex));
    expect(strcmp(actual_hex, expected_hex) == 0, "Firmware BCS output matches Sui SDK");

    size_t invalid_size = 123;
    output[0] = 0xff;
    expect(
        signing::build_sui_zklogin_signature_envelope(
            inputs,
            "0123",
            user_signature,
            sizeof(user_signature),
            output,
            sizeof(output),
            &invalid_size) == signing::SuiZkLoginSignatureBuildResult::invalid_input,
        "non-canonical maxEpoch rejected");
    expect(invalid_size == 0 && output[0] == 0, "invalid maxEpoch wipes output");

    user_signature[0] = signing::kSuiSignatureSchemeFlagZkLogin;
    expect(
        signing::build_sui_zklogin_signature_envelope(
            inputs,
            "123",
            user_signature,
            sizeof(user_signature),
            output,
            sizeof(output),
            &invalid_size) == signing::SuiZkLoginSignatureBuildResult::invalid_input,
        "userSignature must be Ed25519 envelope");
    user_signature[0] = signing::kSuiSignatureSchemeFlagEd25519;

    unsigned char small_output[8] = {};
    expect(
        signing::build_sui_zklogin_signature_envelope(
            inputs,
            "123",
            user_signature,
            sizeof(user_signature),
            small_output,
            sizeof(small_output),
            &invalid_size) == signing::SuiZkLoginSignatureBuildResult::output_too_small,
        "undersized output rejected");

    return g_failures == 0 ? 0 : 1;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_SUI_DIR}/zklogin_signature.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test" "${TMP_DIR}/expected.hex"
