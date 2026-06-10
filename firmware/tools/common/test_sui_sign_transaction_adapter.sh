#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_SUI_DIR="${REPO_ROOT}/firmware/src/common/agent_q/sui"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"
CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sui-sign-transaction-adapter.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <vector>

#include "agent_q_sui_sign_transaction_adapter.h"

std::vector<uint8_t> read_hex(const std::string& path)
{
    FILE* file = fopen(path.c_str(), "rb");
    assert(file != nullptr);
    std::string hex;
    int ch = 0;
    while ((ch = fgetc(file)) != EOF) {
        if (!isspace(ch)) {
            hex.push_back(static_cast<char>(ch));
        }
    }
    fclose(file);
    assert((hex.size() % 2) == 0);
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t index = 0; index < bytes.size(); ++index) {
        const std::string pair = hex.substr(index * 2, 2);
        bytes[index] = static_cast<uint8_t>(strtoul(pair.c_str(), nullptr, 16));
    }
    return bytes;
}

int main(int argc, char** argv)
{
    assert(argc == 2);
    const std::string root = argv[1];
    agent_q::SuiTransactionPolicyFacts facts = {};

    const auto valid = read_hex(root + "/valid_sui_transfer_tx.bcs.hex");
    assert(agent_q::classify_sui_sign_transaction(valid.data(), valid.size(), &facts) ==
           agent_q::AgentQSuiSignTransactionAdapterResult::ok);

    const auto malformed = read_hex(root + "/malformed_short_tx.bcs.hex");
    assert(agent_q::classify_sui_sign_transaction(malformed.data(), malformed.size(), &facts) ==
           agent_q::AgentQSuiSignTransactionAdapterResult::malformed_transaction);

    const auto unsupported =
        read_hex(root + "/unsupported_result_reference_transfer_tx.bcs.hex");
    assert(agent_q::classify_sui_sign_transaction(
               unsupported.data(), unsupported.size(), &facts) ==
           agent_q::AgentQSuiSignTransactionAdapterResult::unsupported_transaction);

    const auto sponsored = read_hex(root + "/sponsored_gas_owner_tx.bcs.hex");
    assert(agent_q::classify_sui_sign_transaction(
               sponsored.data(), sponsored.size(), &facts) ==
           agent_q::AgentQSuiSignTransactionAdapterResult::ok);

    assert(agent_q::classify_sui_sign_transaction(nullptr, 0, &facts) ==
           agent_q::AgentQSuiSignTransactionAdapterResult::invalid_argument);
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_SUI_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_sign_transaction_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test" "${FIXTURE_DIR}"
echo "Sui sign_transaction adapter tests passed"
