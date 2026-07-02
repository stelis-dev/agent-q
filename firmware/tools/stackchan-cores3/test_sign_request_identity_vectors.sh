#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sign_request_identity_vectors.sh

ESP-IDF must already be active in the shell so IDF_PATH points to the ESP-IDF
checkout. This host test checks Firmware-local signing request identity vectors.
It does not require hardware.
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
VECTOR_FILE="${RUNTIME_DIR}/testdata/sign_request_identity_vectors.tsv"

if [[ -z "${IDF_PATH:-}" ]]; then
  echo "IDF_PATH is not set. Source ESP-IDF v5.5.4 export.sh before running this test." >&2
  exit 1
fi

MBEDTLS_ROOT="${IDF_PATH}/components/mbedtls/mbedtls"
MBEDTLS_INCLUDE_DIR="${MBEDTLS_ROOT}/include"
MBEDTLS_LIBRARY_DIR="${MBEDTLS_ROOT}/library"
if [[ ! -f "${MBEDTLS_INCLUDE_DIR}/mbedtls/sha256.h" || ! -f "${MBEDTLS_LIBRARY_DIR}/sha256.c" || ! -f "${MBEDTLS_LIBRARY_DIR}/platform_util.c" ]]; then
  echo "IDF_PATH does not expose the expected ESP-IDF mbedTLS sources: ${IDF_PATH}" >&2
  exit 1
fi

for required in \
  "${VECTOR_FILE}" \
  "${RUNTIME_DIR}/sign_request_identity.cpp" \
  "${RUNTIME_DIR}/sign_request_identity.h" \
  "${COMMON_ROOT}/protocol/sign_route.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
CC_BIN="${CC:-cc}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-sign-request-identity-vectors.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "sign_request_identity.h"
#include "protocol/sign_route.h"

namespace {

struct Vector {
    std::string name;
    std::string operation;
    std::string chain;
    std::string method;
    std::string route;
    std::string network;
    std::string payload;
    std::string expected_hex;
};

std::vector<std::string> split_tabs(const std::string& line)
{
    std::vector<std::string> parts;
    std::string part;
    std::stringstream stream(line);
    while (std::getline(stream, part, '\t')) {
        parts.push_back(part);
    }
    return parts;
}

int hex_value(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return 10 + value - 'a';
    }
    if (value >= 'A' && value <= 'F') {
        return 10 + value - 'A';
    }
    return -1;
}

std::string to_hex(const uint8_t* bytes, size_t size)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (size_t index = 0; index < size; ++index) {
        out.push_back(kHex[(bytes[index] >> 4) & 0x0F]);
        out.push_back(kHex[bytes[index] & 0x0F]);
    }
    return out;
}

bool is_hex_string(const std::string& value)
{
    for (const char ch : value) {
        if (hex_value(ch) < 0) {
            return false;
        }
    }
    return !value.empty() && value.size() == signing::kSignRequestIdentitySize * 2;
}

signing::SignOperation parse_operation(const std::string& value)
{
    if (value == "sign_transaction") {
        return signing::SignOperation::sign_transaction;
    }
    if (value == "sign_personal_message") {
        return signing::SignOperation::sign_personal_message;
    }
    fprintf(stderr, "Unsupported operation in vector: %s\n", value.c_str());
    assert(false);
    return signing::SignOperation::sign_transaction;
}

const char* route_name(signing::SupportedSignRoute route)
{
    switch (route) {
        case signing::SupportedSignRoute::sui_sign_transaction:
            return "sui_sign_transaction";
        case signing::SupportedSignRoute::sui_sign_personal_message:
            return "sui_sign_personal_message";
        case signing::SupportedSignRoute::unsupported:
        default:
            return "unsupported";
    }
}

std::vector<Vector> read_vectors(const char* path)
{
    std::ifstream input(path);
    assert(input.good());
    std::vector<Vector> vectors;
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const std::vector<std::string> parts = split_tabs(line);
        if (parts.size() != 8) {
            fprintf(stderr, "Invalid vector row with %zu fields: %s\n", parts.size(), line.c_str());
            assert(false);
        }
        assert(is_hex_string(parts[7]));
        vectors.push_back(Vector{
            parts[0],
            parts[1],
            parts[2],
            parts[3],
            parts[4],
            parts[5],
            parts[6],
            parts[7],
        });
    }
    return vectors;
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: sign_request_identity_vector_test <vector-file>\n");
        return 2;
    }

    const std::vector<Vector> vectors = read_vectors(argv[1]);
    assert(vectors.size() >= 5);
    std::map<std::string, std::string> identities;

    for (const Vector& vector : vectors) {
        const signing::SignRouteClassification classification =
            signing::classify_sign_route(
                parse_operation(vector.operation),
                vector.chain.c_str(),
                vector.method.c_str());
        assert(classification.result == signing::SignRouteResult::ok);
        assert(vector.route == route_name(classification.route));

        uint8_t identity[signing::kSignRequestIdentitySize] = {};
        assert(signing::sign_request_identity(
            classification.route,
            vector.network.c_str(),
            vector.payload.c_str(),
            identity,
            sizeof(identity)));
        const std::string actual_hex = to_hex(identity, sizeof(identity));
        if (actual_hex != vector.expected_hex) {
            fprintf(stderr,
                    "%s identity mismatch\nexpected: %s\nactual:   %s\n",
                    vector.name.c_str(),
                    vector.expected_hex.c_str(),
                    actual_hex.c_str());
            return 1;
        }
        identities[vector.name] = actual_hex;
    }

    assert(identities["tx-mainnet"] != identities["tx-testnet"]);
    assert(identities["tx-mainnet"] != identities["tx-mainnet-payload-alt"]);
    assert(identities["tx-mainnet"] != identities["pm-mainnet-same-payload"]);

    printf("Signing request identity vector tests passed\n");
    return 0;
}
CPP

"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/sha256.c" \
  -o "${TMP_DIR}/sha256.o"
"${CC_BIN}" -std=c99 -I"${MBEDTLS_INCLUDE_DIR}" \
  -c "${MBEDTLS_LIBRARY_DIR}/platform_util.c" \
  -o "${TMP_DIR}/platform_util.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${MBEDTLS_INCLUDE_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/sign_request_identity.cpp" \
  "${TMP_DIR}/sha256.o" \
  "${TMP_DIR}/platform_util.o" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test" "${VECTOR_FILE}"
