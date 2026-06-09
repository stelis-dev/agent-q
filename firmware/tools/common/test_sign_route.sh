#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
VECTOR_FILE="${REPO_ROOT}/specs/sign-route-vectors.tsv"
CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sign-route.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/sign_route_test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_sign_route.h"

using agent_q::AgentQSignOperation;
using agent_q::AgentQSupportedSignRoute;
using agent_q::AgentQSignRouteResult;

AgentQSignOperation operation_from_name(const char* value)
{
    if (strcmp(value, "sign_transaction") == 0) {
        return AgentQSignOperation::sign_transaction;
    }
    assert(strcmp(value, "sign_personal_message") == 0);
    return AgentQSignOperation::sign_personal_message;
}

AgentQSignRouteResult result_from_name(const char* value)
{
    if (strcmp(value, "ok") == 0) {
        return AgentQSignRouteResult::ok;
    }
    if (strcmp(value, "invalid_params") == 0) {
        return AgentQSignRouteResult::invalid_params;
    }
    if (strcmp(value, "unsupported_chain") == 0) {
        return AgentQSignRouteResult::unsupported_chain;
    }
    assert(strcmp(value, "unsupported_method") == 0);
    return AgentQSignRouteResult::unsupported_method;
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
            agent_q::classify_sign_route(operation_from_name(operation), chain, method);
        assert(classification.result == result_from_name(expected));
        if (classification.result == AgentQSignRouteResult::ok) {
            assert(classification.route != AgentQSupportedSignRoute::unsupported);
        } else {
            assert(classification.route == AgentQSupportedSignRoute::unsupported);
        }
        ++vector_count;
    }
    fclose(vectors);
    assert(vector_count > 0);

    assert(agent_q::classify_sign_route(
        AgentQSignOperation::sign_transaction, nullptr, "sign_transaction").result ==
        AgentQSignRouteResult::invalid_params);
    assert(agent_q::classify_sign_route(
        AgentQSignOperation::sign_transaction, "sui", nullptr).result ==
        AgentQSignRouteResult::invalid_params);
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
