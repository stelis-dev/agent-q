#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/common/test_sui_transaction_facts.sh

Compiles the common Agent-Q Sui transaction facts parser with a host C++
compiler and checks tracked positive/negative BCS fixtures. This test does not
require ESP-IDF and does not depend on .WORK paths.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"

for required in \
  "${COMMON_ROOT}/agent_q_u64_decimal.h" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/unsupported_result_reference_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/sponsored_gas_owner_tx.bcs.hex" \
  "${FIXTURE_DIR}/valid_sui_transfer_facts.json"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    echo "Run firmware/tools/common/generate_sui_transaction_fixtures.mjs first if fixtures are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sui-tx-facts.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/sui_transaction_facts_test.cpp" <<'CPP'
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "agent_q_sui_transaction_facts.h"

namespace {

std::string read_file(const char* path)
{
    FILE* file = fopen(path, "rb");
    if (file == nullptr) {
        fprintf(stderr, "Could not open %s\n", path);
        exit(1);
    }
    std::string data;
    char buffer[4096];
    while (true) {
        const size_t read = fread(buffer, 1, sizeof(buffer), file);
        if (read != 0) {
            data.append(buffer, read);
        }
        if (read < sizeof(buffer)) {
            if (ferror(file)) {
                fprintf(stderr, "Could not read %s\n", path);
                fclose(file);
                exit(1);
            }
            break;
        }
    }
    fclose(file);
    return data;
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

std::vector<uint8_t> read_hex_fixture(const char* path)
{
    const std::string raw = read_file(path);
    std::string hex;
    for (char ch : raw) {
        if (!isspace(static_cast<unsigned char>(ch))) {
            hex.push_back(ch);
        }
    }
    if (hex.size() % 2 != 0) {
        fprintf(stderr, "Odd-length hex fixture: %s\n", path);
        exit(1);
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t index = 0; index < hex.size(); index += 2) {
        const int high = hex_value(hex[index]);
        const int low = hex_value(hex[index + 1]);
        if (high < 0 || low < 0) {
            fprintf(stderr, "Invalid hex fixture: %s\n", path);
            exit(1);
        }
        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return bytes;
}

std::string json_string_field(const std::string& json, const char* field)
{
    const std::string key = std::string("\"") + field + "\"";
    const size_t key_pos = json.find(key);
    if (key_pos == std::string::npos) {
        fprintf(stderr, "Missing JSON field: %s\n", field);
        exit(1);
    }
    const size_t colon = json.find(':', key_pos + key.size());
    const size_t first_quote = json.find('"', colon);
    const size_t second_quote = json.find('"', first_quote + 1);
    if (colon == std::string::npos || first_quote == std::string::npos || second_quote == std::string::npos) {
        fprintf(stderr, "Malformed JSON string field: %s\n", field);
        exit(1);
    }
    return json.substr(first_quote + 1, second_quote - first_quote - 1);
}

uint16_t json_u16_field(const std::string& json, const char* field)
{
    const std::string key = std::string("\"") + field + "\"";
    const size_t key_pos = json.find(key);
    if (key_pos == std::string::npos) {
        fprintf(stderr, "Missing JSON field: %s\n", field);
        exit(1);
    }
    const size_t colon = json.find(':', key_pos + key.size());
    if (colon == std::string::npos) {
        fprintf(stderr, "Malformed JSON numeric field: %s\n", field);
        exit(1);
    }
    char* end = nullptr;
    const unsigned long value = strtoul(json.c_str() + colon + 1, &end, 10);
    if (value > 65535) {
        fprintf(stderr, "Out-of-range JSON numeric field: %s\n", field);
        exit(1);
    }
    return static_cast<uint16_t>(value);
}

void expect_equal(const char* label, const char* expected, const char* actual, int* failures)
{
    if (strcmp(expected, actual) != 0) {
        fprintf(stderr, "%s mismatch\n  expected: %s\n  actual:   %s\n", label, expected, actual);
        *failures += 1;
    }
}

void expect_reject(
    const char* fixture_path,
    agent_q::SuiTransactionFactsResult expected,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiTransferFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_transfer_facts(bytes.data(), bytes.size(), &facts);
    if (result != expected) {
        fprintf(stderr, "%s expected %s, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(expected),
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
    }
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s /path/to/fixture_dir\n", argv[0]);
        return 2;
    }

    const std::string fixture_dir = argv[1];
    int failures = 0;

    const std::vector<uint8_t> valid =
        read_hex_fixture((fixture_dir + "/valid_sui_transfer_tx.bcs.hex").c_str());
    const std::string expected_json =
        read_file((fixture_dir + "/valid_sui_transfer_facts.json").c_str());

    agent_q::SuiTransferFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_transfer_facts(valid.data(), valid.size(), &facts);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "valid fixture returned %s\n", agent_q::sui_transaction_facts_result_name(result));
        failures += 1;
    } else {
        expect_equal("sender", json_string_field(expected_json, "sender").c_str(), facts.sender, &failures);
        expect_equal("gasOwner", json_string_field(expected_json, "gasOwner").c_str(), facts.gas_owner, &failures);
        expect_equal("recipient", json_string_field(expected_json, "recipient").c_str(), facts.recipient, &failures);
        expect_equal("asset", json_string_field(expected_json, "asset").c_str(), facts.asset, &failures);
        expect_equal("amount", json_string_field(expected_json, "amount").c_str(), facts.amount, &failures);
        expect_equal("gasBudget", json_string_field(expected_json, "gasBudget").c_str(), facts.gas_budget, &failures);
        expect_equal("gasPrice", json_string_field(expected_json, "gasPrice").c_str(), facts.gas_price, &failures);
        const uint16_t expected_command_count = json_u16_field(expected_json, "commandCount");
        if (facts.command_count != expected_command_count) {
            fprintf(stderr, "commandCount mismatch\n  expected: %u\n  actual:   %u\n",
                    expected_command_count, facts.command_count);
            failures += 1;
        }
    }

    const std::vector<uint8_t> sponsored_gas_owner =
        read_hex_fixture((fixture_dir + "/sponsored_gas_owner_tx.bcs.hex").c_str());
    facts = {};
    const agent_q::SuiTransactionFactsResult sponsored_result =
        agent_q::parse_sui_transfer_facts(
            sponsored_gas_owner.data(),
            sponsored_gas_owner.size(),
            &facts);
    if (sponsored_result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "sponsored gas owner fixture returned %s\n",
                agent_q::sui_transaction_facts_result_name(sponsored_result));
        failures += 1;
    } else {
        expect_equal(
            "sponsored gas owner",
            "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            facts.gas_owner,
            &failures);
    }

    expect_reject(
        (fixture_dir + "/malformed_short_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::malformed,
        &failures);
    expect_reject(
        (fixture_dir + "/trailing_bytes_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::malformed,
        &failures);
    expect_reject(
        (fixture_dir + "/unsupported_merge_coins_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::unsupported,
        &failures);
    expect_reject(
        (fixture_dir + "/wrong_command_order_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::unsupported,
        &failures);
    expect_reject(
        (fixture_dir + "/unsupported_result_reference_transfer_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::unsupported,
        &failures);
    expect_reject(
        (fixture_dir + "/too_many_commands_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::too_large,
        &failures);

    std::vector<uint8_t> oversized(4097, 0);
    facts = {};
    const agent_q::SuiTransactionFactsResult oversized_result =
        agent_q::parse_sui_transfer_facts(oversized.data(), oversized.size(), &facts);
    if (oversized_result != agent_q::SuiTransactionFactsResult::too_large) {
        fprintf(stderr, "oversized tx expected too_large, got %s\n",
                agent_q::sui_transaction_facts_result_name(oversized_result));
        failures += 1;
    }

    if (failures != 0) {
        fprintf(stderr, "Sui transaction facts tests FAILED: %d\n", failures);
        return 1;
    }
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -I"${COMMON_ROOT}" -I"${COMMON_SUI_DIR}" \
  -c "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" -o "${TMP_DIR}/agent_q_sui_bcs_reader.o"
"${CXX_BIN}" -std=c++17 -I"${COMMON_ROOT}" -I"${COMMON_SUI_DIR}" \
  -c "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" -o "${TMP_DIR}/agent_q_sui_transaction_facts.o"
"${CXX_BIN}" -std=c++17 -I"${COMMON_ROOT}" -I"${COMMON_SUI_DIR}" \
  -c "${TMP_DIR}/sui_transaction_facts_test.cpp" -o "${TMP_DIR}/sui_transaction_facts_test.o"

"${CXX_BIN}" \
  "${TMP_DIR}/agent_q_sui_bcs_reader.o" \
  "${TMP_DIR}/agent_q_sui_transaction_facts.o" \
  "${TMP_DIR}/sui_transaction_facts_test.o" \
  -o "${TMP_DIR}/sui_transaction_facts_test"

"${TMP_DIR}/sui_transaction_facts_test" "${FIXTURE_DIR}"
echo "Sui transaction facts parser tests passed"
