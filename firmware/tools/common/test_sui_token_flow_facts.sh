#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/common/test_sui_token_flow_facts.sh

Compiles the common Agent-Q Sui token-flow analyzer with a host C++ compiler and
checks its output against the Stage 4 token-flow policy authorization matrix.
This test does not require ESP-IDF and does not depend on .WORK paths.
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
MATRIX="${COMMON_SUI_DIR}/testdata/sui_policy_token_flow_authorization.tsv"

for required in \
  "${COMMON_ROOT}/agent_q_u64_decimal.h" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_token_flow_facts.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_token_flow_facts.h" \
  "${MATRIX}"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sui-token-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/sui_token_flow_facts_test.cpp" <<'CPP'
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sstream>
#include <string>
#include <vector>

#include "agent_q_sui_token_flow_facts.h"
#include "agent_q_sui_transaction_facts.h"

namespace {

struct MatrixRow {
    std::string case_id;
    std::string fixture;
    std::string flow_case;
    std::string flow0_asset_state;
    std::string request_network;
    std::string amount_state;
    std::string sui_total_out_complete;
    std::string sui_total_out_raw;
    std::string transfer_total_out_raw;
    std::string move_call_total_in_raw;
    std::string merge_total_raw;
    std::string recipient0_address;
    std::string recipient0_amount_raw;
    std::string move_call0_package;
    std::string move_call0_module;
    std::string move_call0_function;
    std::string move_call0_sui_amount_raw;
    std::string expected_policy_decision;
};

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

std::vector<uint8_t> read_hex_fixture(const std::string& path)
{
    const std::string raw = read_file(path.c_str());
    std::string hex;
    for (char ch : raw) {
        if (!isspace(static_cast<unsigned char>(ch))) {
            hex.push_back(ch);
        }
    }
    if (hex.size() % 2 != 0) {
        fprintf(stderr, "Odd-length hex fixture: %s\n", path.c_str());
        exit(1);
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t index = 0; index < hex.size(); index += 2) {
        const int high = hex_value(hex[index]);
        const int low = hex_value(hex[index + 1]);
        if (high < 0 || low < 0) {
            fprintf(stderr, "Invalid hex fixture: %s\n", path.c_str());
            exit(1);
        }
        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return bytes;
}

std::vector<std::string> split_tab(const std::string& line)
{
    std::vector<std::string> fields;
    size_t start = 0;
    while (true) {
        const size_t end = line.find('\t', start);
        if (end == std::string::npos) {
            fields.push_back(line.substr(start));
            return fields;
        }
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
}

std::vector<MatrixRow> read_matrix(const char* matrix_path)
{
    const std::string raw = read_file(matrix_path);
    std::istringstream lines(raw);
    std::string line;
    std::vector<MatrixRow> rows;
    bool saw_header = false;
    while (std::getline(lines, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const std::vector<std::string> fields = split_tab(line);
        if (!saw_header) {
            saw_header = true;
            if (fields.size() != 21 || fields[0] != "case_id" ||
                fields[4] != "request_network") {
                fprintf(stderr, "Unexpected matrix header\n");
                exit(1);
            }
            continue;
        }
        if (fields.size() != 21) {
            fprintf(stderr, "Unexpected matrix column count for row: %s\n", line.c_str());
            exit(1);
        }
        MatrixRow row = {};
        row.case_id = fields[0];
        row.fixture = fields[1];
        row.flow_case = fields[2];
        row.flow0_asset_state = fields[3];
        row.request_network = fields[4];
        row.amount_state = fields[5];
        row.sui_total_out_complete = fields[6];
        row.sui_total_out_raw = fields[7];
        row.transfer_total_out_raw = fields[8];
        row.move_call_total_in_raw = fields[9];
        row.merge_total_raw = fields[10];
        row.recipient0_address = fields[11];
        row.recipient0_amount_raw = fields[12];
        row.move_call0_package = fields[13];
        row.move_call0_module = fields[14];
        row.move_call0_function = fields[15];
        row.move_call0_sui_amount_raw = fields[16];
        row.expected_policy_decision = fields[19];
        rows.push_back(row);
    }
    if (!saw_header || rows.empty()) {
        fprintf(stderr, "Empty matrix\n");
        exit(1);
    }
    return rows;
}

agent_q::SuiTokenAmountState state_from_matrix(const std::string& state)
{
    if (state == "known") {
        return agent_q::SuiTokenAmountState::known;
    }
    if (state == "unknown") {
        return agent_q::SuiTokenAmountState::unknown;
    }
    if (state == "incomplete") {
        return agent_q::SuiTokenAmountState::incomplete;
    }
    fprintf(stderr, "Invalid matrix amount_state: %s\n", state.c_str());
    exit(1);
}

agent_q::SuiTokenAssetState asset_state_from_matrix(const std::string& state)
{
    if (state == "proven_sui") {
        return agent_q::SuiTokenAssetState::proven_sui;
    }
    if (state == "unproven") {
        return agent_q::SuiTokenAssetState::unproven;
    }
    fprintf(stderr, "Invalid matrix flow0_asset_state: %s\n", state.c_str());
    exit(1);
}

void expect_string(
    const std::string& case_id,
    const char* label,
    const std::string& expected,
    const char* actual,
    int* failures)
{
    const std::string actual_value = actual == nullptr ? "" : actual;
    if (expected != actual_value) {
        fprintf(stderr,
                "%s %s mismatch\n  expected: %s\n  actual:   %s\n",
                case_id.c_str(),
                label,
                expected.c_str(),
                actual_value.c_str());
        *failures += 1;
    }
}

void expect_state(
    const std::string& case_id,
    const char* label,
    agent_q::SuiTokenAmountState expected,
    agent_q::SuiTokenAmountState actual,
    int* failures)
{
    if (expected != actual) {
        fprintf(stderr,
                "%s %s state mismatch\n  expected: %s\n  actual:   %s\n",
                case_id.c_str(),
                label,
                agent_q::sui_token_amount_state_name(expected),
                agent_q::sui_token_amount_state_name(actual));
        *failures += 1;
    }
}

void expect_raw_amount(
    const std::string& case_id,
    const char* label,
    const std::string& expected,
    agent_q::SuiTokenAmountState state,
    const char* actual,
    int* failures)
{
    if (expected == "unknown") {
        if (state == agent_q::SuiTokenAmountState::known || actual[0] != '\0') {
            fprintf(stderr,
                    "%s %s expected unknown amount, got state=%s raw=%s\n",
                    case_id.c_str(),
                    label,
                    agent_q::sui_token_amount_state_name(state),
                    actual);
            *failures += 1;
        }
        return;
    }
    expect_string(case_id, label, expected, actual, failures);
}

void expect_case(
    const MatrixRow& row,
    const char* fixture_dir,
    int* failures)
{
    if (row.expected_policy_decision == "invalid_params") {
        return;
    }
    if (row.flow_case == "publish") {
        return;
    }

    const std::string fixture_path =
        std::string(fixture_dir) + "/" + row.fixture + ".bcs.hex";
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiParsedTransactionFacts parsed = {};
    const agent_q::SuiTransactionFactsResult parse_result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &parsed);
    if (parse_result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr,
                "%s parser returned %s\n",
                row.case_id.c_str(),
                agent_q::sui_transaction_facts_result_name(parse_result));
        *failures += 1;
        return;
    }

    agent_q::SuiTokenFlowFacts facts = {};
    const agent_q::SuiTokenFlowFactsResult result =
        agent_q::build_sui_token_flow_facts(parsed, &facts);
    if (result != agent_q::SuiTokenFlowFactsResult::ok) {
        fprintf(stderr,
                "%s token-flow analyzer returned %s\n",
                row.case_id.c_str(),
                agent_q::sui_token_flow_facts_result_name(result));
        *failures += 1;
        return;
    }

    const agent_q::SuiTokenAmountState expected_state =
        state_from_matrix(row.amount_state);
    expect_state(
        row.case_id,
        "sui_total_out",
        expected_state,
        facts.sui_total_out_state,
        failures);
    if (row.sui_total_out_complete == "yes") {
        expect_state(
            row.case_id,
            "sui_total_out_complete",
            agent_q::SuiTokenAmountState::known,
            facts.sui_total_out_state,
            failures);
    } else if (facts.sui_total_out_state == agent_q::SuiTokenAmountState::known) {
        fprintf(stderr, "%s expected incomplete total coverage\n", row.case_id.c_str());
        *failures += 1;
    }

    expect_raw_amount(
        row.case_id,
        "sui_total_out_raw",
        row.sui_total_out_raw,
        facts.sui_total_out_state,
        facts.sui_total_out_raw,
        failures);
    expect_raw_amount(
        row.case_id,
        "transfer_total_out_raw",
        row.transfer_total_out_raw,
        facts.transfer_total_out_state,
        facts.transfer_total_out_raw,
        failures);
    expect_raw_amount(
        row.case_id,
        "move_call_total_in_raw",
        row.move_call_total_in_raw,
        facts.move_call_total_in_state,
        facts.move_call_total_in_raw,
        failures);
    expect_raw_amount(
        row.case_id,
        "merge_total_raw",
        row.merge_total_raw,
        facts.merge_total_state,
        facts.merge_total_raw,
        failures);
    expect_raw_amount(
        row.case_id,
        "recipient0_amount_raw",
        row.recipient0_amount_raw,
        facts.recipient0_amount_state,
        facts.recipient0_amount_raw,
        failures);
    expect_raw_amount(
        row.case_id,
        "move_call0_sui_amount_raw",
        row.move_call0_sui_amount_raw,
        facts.move_call0_sui_amount_state,
        facts.move_call0_sui_amount_raw,
        failures);
    if (row.flow0_asset_state == "none") {
        if (facts.flow_count != 0) {
            fprintf(stderr, "%s expected no token-flow rows\n", row.case_id.c_str());
            *failures += 1;
        }
    } else if (facts.flow_count == 0) {
        fprintf(stderr, "%s expected a first token-flow row\n", row.case_id.c_str());
        *failures += 1;
    } else {
        const agent_q::SuiTokenAssetState expected_asset_state =
            asset_state_from_matrix(row.flow0_asset_state);
        if (facts.flows[0].asset_state != expected_asset_state) {
            fprintf(stderr,
                    "%s flow0_asset_state expected %s got %s\n",
                    row.case_id.c_str(),
                    row.flow0_asset_state.c_str(),
                    agent_q::sui_token_asset_state_name(facts.flows[0].asset_state));
            *failures += 1;
        }
    }

    expect_string(
        row.case_id,
        "recipient0_address",
        row.recipient0_address,
        facts.recipient0_address,
        failures);
    const bool expected_recipient0_address_known = row.recipient0_address != "none";
    if (facts.recipient0_address_known != expected_recipient0_address_known) {
        fprintf(stderr,
                "%s recipient0_address_known expected %s got %s\n",
                row.case_id.c_str(),
                expected_recipient0_address_known ? "true" : "false",
                facts.recipient0_address_known ? "true" : "false");
        *failures += 1;
    }
    expect_string(
        row.case_id,
        "move_call0_package",
        row.move_call0_package,
        facts.move_call0_package,
        failures);
    expect_string(
        row.case_id,
        "move_call0_module",
        row.move_call0_module,
        facts.move_call0_module,
        failures);
    expect_string(
        row.case_id,
        "move_call0_function",
        row.move_call0_function,
        facts.move_call0_function,
        failures);
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <fixture-dir> <matrix>\n", argv[0]);
        return 2;
    }

    int failures = 0;
    const std::vector<MatrixRow> rows = read_matrix(argv[2]);
    for (const MatrixRow& row : rows) {
        expect_case(row, argv[1], &failures);
    }

    if (failures != 0) {
        fprintf(stderr, "Sui token-flow facts tests FAILED: %d\n", failures);
        return 1;
    }
    return 0;
}
CPP

"${CXX_BIN}" \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_SUI_DIR}" \
  "${TMP_DIR}/sui_token_flow_facts_test.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_token_flow_facts.cpp" \
  -o "${TMP_DIR}/sui_token_flow_facts_test"

"${TMP_DIR}/sui_token_flow_facts_test" "${FIXTURE_DIR}" "${MATRIX}"
echo "Sui token-flow facts tests passed"
