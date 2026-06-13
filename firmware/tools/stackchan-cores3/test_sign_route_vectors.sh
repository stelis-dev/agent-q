#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sign_route_vectors.sh

Compiles a tiny host test for the common signing route classifier and verifies
that Firmware route classification matches specs/sign-route-vectors.tsv.
It does not require hardware or ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
VECTOR_FILE="${REPO_ROOT}/specs/sign-route-vectors.tsv"

for required in \
  "${COMMON_ROOT}/agent_q_sign_route.h" \
  "${VECTOR_FILE}"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sign-route-vectors.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "agent_q_sign_route.h"

namespace {

struct Vector {
    std::string operation;
    std::string chain;
    std::string method;
    std::string expected;
};

agent_q::AgentQSignOperation parse_operation(const std::string& value)
{
    if (value == "sign_transaction") {
        return agent_q::AgentQSignOperation::sign_transaction;
    }
    if (value == "sign_personal_message") {
        return agent_q::AgentQSignOperation::sign_personal_message;
    }
    fprintf(stderr, "unsupported operation in route vector: %s\n", value.c_str());
    assert(false);
    return agent_q::AgentQSignOperation::sign_transaction;
}

const char* result_name(agent_q::AgentQSignRouteResult result)
{
    switch (result) {
        case agent_q::AgentQSignRouteResult::ok:
            return "ok";
        case agent_q::AgentQSignRouteResult::invalid_params:
            return "invalid_params";
        case agent_q::AgentQSignRouteResult::unsupported_chain:
            return "unsupported_chain";
        case agent_q::AgentQSignRouteResult::unsupported_method:
            return "unsupported_method";
    }
    return "unknown";
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
        std::vector<std::string> parts;
        std::stringstream stream(line);
        std::string part;
        while (std::getline(stream, part, '\t')) {
            parts.push_back(part);
        }
        assert(parts.size() == 4);
        vectors.push_back(Vector{parts[0], parts[1], parts[2], parts[3]});
    }
    return vectors;
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: sign_route_vector_test <vector-file>\n");
        return 2;
    }

    const std::vector<Vector> vectors = read_vectors(argv[1]);
    assert(vectors.size() >= 8);

    for (const Vector& vector : vectors) {
        const agent_q::AgentQSignRouteClassification classification =
            agent_q::classify_sign_route(
                parse_operation(vector.operation),
                vector.chain.c_str(),
                vector.method.c_str());
        const char* actual = result_name(classification.result);
        if (vector.expected != actual) {
            fprintf(stderr,
                    "route vector mismatch for %s/%s/%s: expected %s, got %s\n",
                    vector.operation.c_str(),
                    vector.chain.c_str(),
                    vector.method.c_str(),
                    vector.expected.c_str(),
                    actual);
            return 1;
        }
        if (classification.result == agent_q::AgentQSignRouteResult::ok) {
            assert(classification.route != agent_q::AgentQSupportedSignRoute::unsupported);
        } else {
            assert(classification.route == agent_q::AgentQSupportedSignRoute::unsupported);
        }
    }

    printf("Signing route vector tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  -o "${TMP_DIR}/test_sign_route_vectors"

"${TMP_DIR}/test_sign_route_vectors" "${VECTOR_FILE}"
