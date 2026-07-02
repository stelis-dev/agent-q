#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
VECTOR_FILE="${REPO_ROOT}/specs/sign-route-vectors.tsv"
CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-sign-route.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/sign_route_test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "protocol/sign_route.h"

using signing::SignOperation;
using signing::SupportedSignRoute;
using signing::SignRouteResult;

SignOperation operation_from_name(const char* value)
{
    if (strcmp(value, "sign_transaction") == 0) {
        return SignOperation::sign_transaction;
    }
    assert(strcmp(value, "sign_personal_message") == 0);
    return SignOperation::sign_personal_message;
}

SignRouteResult result_from_name(const char* value)
{
    if (strcmp(value, "ok") == 0) {
        return SignRouteResult::ok;
    }
    if (strcmp(value, "invalid_params") == 0) {
        return SignRouteResult::invalid_params;
    }
    if (strcmp(value, "unsupported_chain") == 0) {
        return SignRouteResult::unsupported_chain;
    }
    assert(strcmp(value, "unsupported_method") == 0);
    return SignRouteResult::unsupported_method;
}

int main(int argc, char** argv)
{
    assert(argc == 2);
    FILE* vectors = fopen(argv[1], "r");
    assert(vectors != nullptr);
    char line[512] = {};
    size_t vector_count = 0;
    while (fgets(line, sizeof(line), vectors) != nullptr) {
        if (line[0] == '#') {
            continue;
        }
        char* operation = strtok(line, "\t");
        char* chain = strtok(nullptr, "\t");
        char* method = strtok(nullptr, "\t");
        char* expected = strtok(nullptr, "\t\r\n");
        assert(operation != nullptr && chain != nullptr && method != nullptr && expected != nullptr);
        const auto classification =
            signing::classify_sign_route(operation_from_name(operation), chain, method);
        assert(classification.result == result_from_name(expected));
        if (classification.result == SignRouteResult::ok) {
            assert(classification.route != SupportedSignRoute::unsupported);
        } else {
            assert(classification.route == SupportedSignRoute::unsupported);
        }
        ++vector_count;
    }
    fclose(vectors);
    assert(vector_count > 0);

    assert(signing::classify_sign_route(
        SignOperation::sign_transaction, nullptr, "sign_transaction").result ==
        SignRouteResult::invalid_params);
    assert(signing::classify_sign_route(
        SignOperation::sign_transaction, "sui", nullptr).result ==
        SignRouteResult::invalid_params);
    return 0;
}
CPP

"${CXX_BIN}" \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/sign_route_test.cpp" \
  -o "${TMP_DIR}/sign_route_test"

"${TMP_DIR}/sign_route_test" "${VECTOR_FILE}"
echo "sign route tests passed"
