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
  "${FIXTURE_DIR}/move_call_tx.bcs.hex" \
  "${FIXTURE_DIR}/split_move_call_tx.bcs.hex" \
  "${FIXTURE_DIR}/direct_object_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/non_gas_split_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/merge_known_known_tx.bcs.hex" \
  "${FIXTURE_DIR}/merge_known_unknown_tx.bcs.hex" \
  "${FIXTURE_DIR}/move_call_vector_type_arg_tx.bcs.hex" \
  "${FIXTURE_DIR}/publish_tx.bcs.hex" \
  "${FIXTURE_DIR}/upgrade_tx.bcs.hex" \
  "${FIXTURE_DIR}/funds_withdrawal_tx.bcs.hex" \
  "${FIXTURE_DIR}/funds_withdrawal_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/valid_during_tx.bcs.hex" \
  "${FIXTURE_DIR}/epoch_expiration_tx.bcs.hex" \
  "${FIXTURE_DIR}/make_move_vec_tx.bcs.hex" \
  "${FIXTURE_DIR}/shared_object_move_call_tx.bcs.hex" \
  "${FIXTURE_DIR}/receiving_object_make_move_vec_tx.bcs.hex" \
  "${FIXTURE_DIR}/move_call_out_of_range_input_tx.bcs.hex" \
  "${FIXTURE_DIR}/transaction_kind_only_sui_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/result_reference_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/sponsored_gas_owner_tx.bcs.hex" \
  "${FIXTURE_DIR}/valid_sui_transfer_facts.json" \
  "${FIXTURE_DIR}/valid_sui_transfer_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/merge_coins_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/move_call_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/split_move_call_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/direct_object_transfer_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/non_gas_split_transfer_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/merge_known_known_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/merge_known_unknown_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/move_call_vector_type_arg_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/publish_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/upgrade_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/funds_withdrawal_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/funds_withdrawal_transfer_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/valid_during_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/epoch_expiration_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/make_move_vec_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/shared_object_move_call_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/receiving_object_make_move_vec_tx.sdk-v2-facts.json" \
  "${FIXTURE_DIR}/sponsored_gas_owner_tx.sdk-v2-facts.json"; do
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
    if (actual == nullptr || strcmp(expected, actual) != 0) {
        fprintf(stderr, "%s mismatch\n  expected: %s\n  actual:   %s\n",
                label,
                expected,
                actual == nullptr ? "(missing)" : actual);
        *failures += 1;
    }
}

const char* command_kind_name(agent_q::SuiCommandFactKind kind)
{
    switch (kind) {
        case agent_q::SuiCommandFactKind::unsupported:
            return "unsupported";
        case agent_q::SuiCommandFactKind::move_call:
            return "MoveCall";
        case agent_q::SuiCommandFactKind::transfer_objects:
            return "TransferObjects";
        case agent_q::SuiCommandFactKind::split_coins:
            return "SplitCoins";
        case agent_q::SuiCommandFactKind::merge_coins:
            return "MergeCoins";
        case agent_q::SuiCommandFactKind::publish:
            return "Publish";
        case agent_q::SuiCommandFactKind::make_move_vec:
            return "MakeMoveVec";
        case agent_q::SuiCommandFactKind::upgrade:
            return "Upgrade";
    }
    return "unknown";
}

const char* expiration_kind_name(agent_q::SuiTransactionExpirationFact kind)
{
    switch (kind) {
        case agent_q::SuiTransactionExpirationFact::none:
            return "None";
        case agent_q::SuiTransactionExpirationFact::epoch:
            return "Epoch";
        case agent_q::SuiTransactionExpirationFact::valid_during:
            return "ValidDuring";
    }
    return "unknown";
}

void expect_reject(
    const char* fixture_path,
    agent_q::SuiTransactionFactsResult expected,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiParsedTransactionFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &facts);
    if (result != expected) {
        fprintf(stderr, "%s expected %s, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(expected),
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
    }
}

agent_q::SuiTransactionFactsResult parse_policy_subject(
    const uint8_t* bytes,
    size_t size,
    agent_q::SuiPolicySubjectFacts* out)
{
    if (out != nullptr) {
        *out = {};
    }
    agent_q::SuiParsedTransactionFacts parsed = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes, size, &parsed);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        return result;
    }
    return agent_q::build_sui_policy_subject_facts(parsed, out)
               ? agent_q::SuiTransactionFactsResult::ok
               : agent_q::SuiTransactionFactsResult::unsupported_shape;
}

void expect_supported_policy_subject(
    const char* fixture_path,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiPolicySubjectFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        parse_policy_subject(bytes.data(), bytes.size(), &facts);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    if (facts.command_count == 0) {
        fprintf(stderr, "%s did not preserve generic command facts\n", fixture_path);
        *failures += 1;
    }
}

void expect_move_call_metadata(
    const char* fixture_path,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiParsedTransactionFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &facts);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    if (facts.command_count != 1 || facts.commands[0].kind != agent_q::SuiCommandFactKind::move_call) {
        fprintf(stderr, "%s did not expose one MoveCall command\n", fixture_path);
        *failures += 1;
        return;
    }
    expect_equal(
        "MoveCall package",
        "0x2222222222222222222222222222222222222222222222222222222222222222",
        facts.commands[0].move_call.package,
        failures);
    expect_equal("MoveCall module", "pay", facts.commands[0].move_call.module, failures);
    expect_equal("MoveCall function", "spend", facts.commands[0].move_call.function, failures);
    if (facts.commands[0].move_call.type_argument_count != 1 ||
        facts.commands[0].move_call.argument_count != 1) {
        fprintf(stderr, "%s MoveCall arg counts mismatch\n", fixture_path);
        *failures += 1;
    }
    if (facts.commands[0].move_call.type_arguments[0].kind != agent_q::SuiTypeTagFactKind::u64) {
        fprintf(stderr, "%s MoveCall type argument was not exposed as u64\n", fixture_path);
        *failures += 1;
    }
    expect_equal("MoveCall type argument canonical", "u64", facts.commands[0].move_call.type_arguments[0].canonical, failures);
    if (facts.commands[0].argument_count != 1 ||
        facts.commands[0].arguments[0].kind != agent_q::SuiArgumentFactKind::input ||
        facts.commands[0].arguments[0].index != 0) {
        fprintf(stderr, "%s MoveCall argument ref was not exposed as Input(0)\n", fixture_path);
        *failures += 1;
    }
}

void expect_move_call_vector_type_arg_metadata(
    const char* fixture_path,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiParsedTransactionFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &facts);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    if (facts.command_count != 1 || facts.commands[0].kind != agent_q::SuiCommandFactKind::move_call) {
        fprintf(stderr, "%s did not expose one MoveCall command\n", fixture_path);
        *failures += 1;
        return;
    }
    if (facts.commands[0].move_call.type_argument_count != 1 ||
        facts.commands[0].move_call.type_arguments[0].kind != agent_q::SuiTypeTagFactKind::vector) {
        fprintf(stderr, "%s MoveCall type argument was not exposed as vector\n", fixture_path);
        *failures += 1;
        return;
    }
    expect_equal(
        "MoveCall vector type argument canonical",
        "vector<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>",
        facts.commands[0].move_call.type_arguments[0].canonical,
        failures);
}

void expect_publish_metadata(
    const char* fixture_path,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiParsedTransactionFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &facts);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    if (facts.command_count != 1 || facts.commands[0].kind != agent_q::SuiCommandFactKind::publish) {
        fprintf(stderr, "%s did not expose one Publish command\n", fixture_path);
        *failures += 1;
        return;
    }
    if (facts.commands[0].publish.module_count != 1 ||
        facts.commands[0].publish.dependency_count != 1) {
        fprintf(stderr, "%s Publish package counts mismatch\n", fixture_path);
        *failures += 1;
    }
    expect_equal(
        "Publish dependency",
        "0x1111111111111111111111111111111111111111111111111111111111111111",
        facts.commands[0].publish.dependencies[0],
        failures);
}

void expect_upgrade_metadata(
    const char* fixture_path,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiParsedTransactionFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &facts);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    if (facts.command_count != 1 || facts.commands[0].kind != agent_q::SuiCommandFactKind::upgrade) {
        fprintf(stderr, "%s did not expose one Upgrade command\n", fixture_path);
        *failures += 1;
        return;
    }
    if (facts.commands[0].upgrade.module_count != 1 ||
        facts.commands[0].upgrade.dependency_count != 1) {
        fprintf(stderr, "%s Upgrade package counts mismatch\n", fixture_path);
        *failures += 1;
    }
    expect_equal(
        "Upgrade dependency",
        "0x3333333333333333333333333333333333333333333333333333333333333333",
        facts.commands[0].upgrade.dependencies[0],
        failures);
    expect_equal(
        "Upgrade package",
        "0x4444444444444444444444444444444444444444444444444444444444444444",
        facts.commands[0].upgrade.package,
        failures);
    if (facts.commands[0].upgrade.ticket.kind != agent_q::SuiArgumentFactKind::input ||
        facts.commands[0].upgrade.ticket.index != 0) {
        fprintf(stderr, "%s Upgrade ticket was not exposed as Input(0)\n", fixture_path);
        *failures += 1;
    }
}

void expect_funds_withdrawal_metadata(
    const char* fixture_path,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiParsedTransactionFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &facts);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    if (facts.input_count != 1 ||
        facts.inputs[0].kind != agent_q::SuiCallArgFactKind::funds_withdrawal) {
        fprintf(stderr, "%s did not expose one FundsWithdrawal input\n", fixture_path);
        *failures += 1;
        return;
    }
    expect_equal("FundsWithdrawal amount", "1000000", facts.inputs[0].funds_withdrawal.amount, failures);
    if (facts.inputs[0].funds_withdrawal.source != agent_q::SuiFundsWithdrawalSourceFact::sender) {
        fprintf(stderr, "%s FundsWithdrawal source was not Sender\n", fixture_path);
        *failures += 1;
    }
    if (facts.inputs[0].funds_withdrawal.type.kind != agent_q::SuiTypeTagFactKind::struct_) {
        fprintf(stderr, "%s FundsWithdrawal type was not a struct tag\n", fixture_path);
        *failures += 1;
    } else {
        expect_equal(
            "FundsWithdrawal type address",
            "0x0000000000000000000000000000000000000000000000000000000000000002",
            facts.inputs[0].funds_withdrawal.type.struct_tag.address,
            failures);
        expect_equal("FundsWithdrawal type module", "sui", facts.inputs[0].funds_withdrawal.type.struct_tag.module, failures);
        expect_equal("FundsWithdrawal type name", "SUI", facts.inputs[0].funds_withdrawal.type.struct_tag.name, failures);
        expect_equal(
            "FundsWithdrawal type canonical",
            "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI",
            facts.inputs[0].funds_withdrawal.type.canonical,
            failures);
    }
}

void expect_valid_during_metadata(
    const char* fixture_path,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiParsedTransactionFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &facts);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    if (facts.expiration_kind != agent_q::SuiTransactionExpirationFact::valid_during) {
        fprintf(stderr, "%s expiration was not ValidDuring\n", fixture_path);
        *failures += 1;
        return;
    }
    if (!facts.valid_during.has_min_epoch ||
        !facts.valid_during.has_max_epoch ||
        facts.valid_during.has_min_timestamp ||
        !facts.valid_during.has_max_timestamp) {
        fprintf(stderr, "%s ValidDuring option flags mismatch\n", fixture_path);
        *failures += 1;
    }
    expect_equal("ValidDuring minEpoch", "10", facts.valid_during.min_epoch, failures);
    expect_equal("ValidDuring maxEpoch", "20", facts.valid_during.max_epoch, failures);
    expect_equal("ValidDuring maxTimestamp", "123456789", facts.valid_during.max_timestamp, failures);
    expect_equal(
        "ValidDuring chain digest",
        "5555555555555555555555555555555555555555555555555555555555555555",
        facts.valid_during.chain_digest_hex,
        failures);
    expect_equal("ValidDuring nonce", "42", facts.valid_during.nonce, failures);
}

void expect_epoch_expiration_metadata(
    const char* fixture_path,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiParsedTransactionFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &facts);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    if (facts.expiration_kind != agent_q::SuiTransactionExpirationFact::epoch) {
        fprintf(stderr, "%s expiration was not Epoch\n", fixture_path);
        *failures += 1;
        return;
    }
    expect_equal("Expiration epoch", "123", facts.expiration_epoch, failures);
}

void expect_make_move_vec_metadata(
    const char* fixture_path,
    agent_q::SuiCallArgFactKind expected_input_kind,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiParsedTransactionFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &facts);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    if (facts.input_count != 1 || facts.inputs[0].kind != expected_input_kind) {
        fprintf(stderr, "%s input kind mismatch for MakeMoveVec fixture\n", fixture_path);
        *failures += 1;
    }
    if (facts.command_count != 1 || facts.commands[0].kind != agent_q::SuiCommandFactKind::make_move_vec) {
        fprintf(stderr, "%s did not expose one MakeMoveVec command\n", fixture_path);
        *failures += 1;
        return;
    }
    if (!facts.commands[0].has_make_move_vec_type ||
        facts.commands[0].make_move_vec_type.kind != agent_q::SuiTypeTagFactKind::struct_) {
        fprintf(stderr, "%s MakeMoveVec type was not exposed as a struct tag\n", fixture_path);
        *failures += 1;
    } else {
        expect_equal(
            "MakeMoveVec type canonical",
            "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI",
            facts.commands[0].make_move_vec_type.canonical,
            failures);
    }
    if (facts.commands[0].argument_count != 1 ||
        facts.commands[0].arguments[0].kind != agent_q::SuiArgumentFactKind::input ||
        facts.commands[0].arguments[0].index != 0) {
        fprintf(stderr, "%s MakeMoveVec argument ref was not exposed as Input(0)\n", fixture_path);
        *failures += 1;
    }
}

void expect_shared_object_metadata(
    const char* fixture_path,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiParsedTransactionFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &facts);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    if (facts.input_count != 1 ||
        facts.inputs[0].kind != agent_q::SuiCallArgFactKind::object_shared) {
        fprintf(stderr, "%s did not expose one shared object input\n", fixture_path);
        *failures += 1;
        return;
    }
    expect_equal(
        "Shared object id",
        "0x6666666666666666666666666666666666666666666666666666666666666666",
        facts.inputs[0].object_ref.object_id,
        failures);
    expect_equal("Shared initial version", "9", facts.inputs[0].shared_initial_version, failures);
    if (!facts.inputs[0].shared_mutable) {
        fprintf(stderr, "%s shared object mutable flag was not preserved\n", fixture_path);
        *failures += 1;
    }
}

void expect_parsed_transaction_facts(
    const char* label,
    const std::vector<uint8_t>& bytes,
    const std::string& expected_json,
    int* failures)
{
    agent_q::SuiParsedTransactionFacts parsed = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &parsed);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s parsed transaction facts returned %s\n",
                label,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    if (parsed.transaction_data_version != agent_q::SuiTransactionDataVersionFact::v1) {
        fprintf(stderr, "parsed transaction data version was not V1\n");
        *failures += 1;
    }
    if (parsed.transaction_kind != agent_q::SuiTransactionKindFact::programmable_transaction) {
        fprintf(stderr, "parsed transaction kind was not ProgrammableTransaction\n");
        *failures += 1;
    }
    expect_equal("parsed sender", json_string_field(expected_json, "sender").c_str(), parsed.sender, failures);
    expect_equal("parsed gasOwner", json_string_field(expected_json, "gasOwner").c_str(), parsed.gas_owner, failures);
    expect_equal("parsed gasBudget", json_string_field(expected_json, "gasBudget").c_str(), parsed.gas_budget, failures);
    expect_equal("parsed gasPrice", json_string_field(expected_json, "gasPrice").c_str(), parsed.gas_price, failures);
    const uint16_t expected_command_count = json_u16_field(expected_json, "commandCount");
    if (parsed.command_count != expected_command_count) {
        fprintf(stderr, "parsed commandCount mismatch\n  expected: %u\n  actual:   %u\n",
                expected_command_count, parsed.command_count);
        *failures += 1;
    }
}

void expect_minimum_transaction_facts(
    const char* label,
    const std::vector<uint8_t>& bytes,
    const std::string& expected_json,
    int* failures)
{
    agent_q::SuiMinimumTransactionFacts minimum = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_minimum_transaction_facts(bytes.data(), bytes.size(), &minimum);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s minimum transaction facts returned %s\n",
                label,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    if (minimum.transaction_data_version != agent_q::SuiTransactionDataVersionFact::v1) {
        fprintf(stderr, "%s minimum transaction data version was not V1\n", label);
        *failures += 1;
    }
    if (minimum.transaction_kind != agent_q::SuiTransactionKindFact::programmable_transaction) {
        fprintf(stderr, "%s minimum transaction kind was not ProgrammableTransaction\n", label);
        *failures += 1;
    }
    expect_equal("minimum sender", json_string_field(expected_json, "sender").c_str(), minimum.sender, failures);
    expect_equal("minimum gasOwner", json_string_field(expected_json, "gasOwner").c_str(), minimum.gas_owner, failures);
    expect_equal("minimum gasBudget", json_string_field(expected_json, "gasBudget").c_str(), minimum.gas_budget, failures);
    expect_equal("minimum gasPrice", json_string_field(expected_json, "gasPrice").c_str(), minimum.gas_price, failures);
}

void expect_minimum_reject(
    const char* fixture_path,
    agent_q::SuiTransactionFactsResult expected,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiMinimumTransactionFacts minimum = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_minimum_transaction_facts(bytes.data(), bytes.size(), &minimum);
    if (result != expected) {
        fprintf(stderr, "%s minimum parser expected %s, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(expected),
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
    }
}

void expect_sdk_v2_oracle_facts(
    const std::string& fixture_dir,
    const char* base_name,
    int* failures)
{
    const std::string tx_path = fixture_dir + "/" + base_name + ".bcs.hex";
    const std::string oracle_path = fixture_dir + "/" + base_name + ".sdk-v2-facts.json";
    const std::vector<uint8_t> bytes = read_hex_fixture(tx_path.c_str());
    const std::string oracle = read_file(oracle_path.c_str());

    agent_q::SuiParsedTransactionFacts parsed = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &parsed);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse for SDK v2 oracle comparison, got %s\n",
                base_name,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }

    expect_equal("SDK v2 sender", json_string_field(oracle, "sender").c_str(), parsed.sender, failures);
    expect_equal("SDK v2 gasOwner", json_string_field(oracle, "gasOwner").c_str(), parsed.gas_owner, failures);
    expect_equal("SDK v2 gasBudget", json_string_field(oracle, "gasBudget").c_str(), parsed.gas_budget, failures);
    expect_equal("SDK v2 gasPrice", json_string_field(oracle, "gasPrice").c_str(), parsed.gas_price, failures);

    const uint16_t expected_input_count = json_u16_field(oracle, "inputCount");
    if (parsed.input_count != expected_input_count) {
        fprintf(stderr, "%s inputCount mismatch\n  expected: %u\n  actual:   %u\n",
                base_name,
                expected_input_count,
                parsed.input_count);
        *failures += 1;
    }
    const uint16_t expected_command_count = json_u16_field(oracle, "commandCount");
    if (parsed.command_count != expected_command_count) {
        fprintf(stderr, "%s commandCount mismatch\n  expected: %u\n  actual:   %u\n",
                base_name,
                expected_command_count,
                parsed.command_count);
        *failures += 1;
    }
    if (parsed.command_count != 0) {
        expect_equal(
            "SDK v2 firstCommandKind",
            json_string_field(oracle, "firstCommandKind").c_str(),
            command_kind_name(parsed.commands[0].kind),
            failures);
    }
    expect_equal(
        "SDK v2 expirationKind",
        json_string_field(oracle, "expirationKind").c_str(),
        expiration_kind_name(parsed.expiration_kind),
        failures);
}

const char* review_row_value(
    const agent_q::SuiReviewSummary& summary,
    const char* label)
{
    for (uint16_t index = 0; index < summary.row_count; ++index) {
        if (strcmp(summary.rows[index].label, label) == 0) {
            return summary.rows[index].value;
        }
    }
    return nullptr;
}

void expect_review_row_equal(
    const agent_q::SuiReviewSummary& summary,
    const char* label,
    const char* expected,
    int* failures)
{
    expect_equal(label, expected, review_row_value(summary, label), failures);
}

void expect_review_row_present(
    const agent_q::SuiReviewSummary& summary,
    const char* label,
    int* failures)
{
    if (review_row_value(summary, label) == nullptr) {
        fprintf(stderr, "missing review row: %s\n", label);
        *failures += 1;
    }
}

void expect_review_summary(
    const char* fixture_path,
    const char* expected_type,
    const char* expected_risk,
    agent_q::SuiReviewSummaryStatus expected_status,
    int* failures)
{
    const std::vector<uint8_t> bytes = read_hex_fixture(fixture_path);
    agent_q::SuiParsedTransactionFacts parsed = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), &parsed);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse for review summary, got %s\n",
                fixture_path,
                agent_q::sui_transaction_facts_result_name(result));
        *failures += 1;
        return;
    }
    agent_q::SuiReviewSummary summary = {};
    if (!agent_q::build_sui_review_summary(parsed, &summary)) {
        fprintf(stderr, "%s failed to build review summary\n", fixture_path);
        *failures += 1;
        return;
    }
    if (summary.status != expected_status || summary.row_count == 0) {
        fprintf(stderr, "%s built invalid review summary\n", fixture_path);
        *failures += 1;
        return;
    }
    expect_review_row_equal(summary, "Type", expected_type, failures);
    expect_review_row_equal(summary, "Risk", expected_risk, failures);
    expect_review_row_equal(summary, "Sender", parsed.sender, failures);
    expect_review_row_equal(summary, "Gas owner", parsed.gas_owner, failures);
    expect_review_row_equal(summary, "Gas max", parsed.gas_budget, failures);
    expect_review_row_equal(summary, "Gas price", parsed.gas_price, failures);
    expect_review_row_present(summary, "Gas coins", failures);
    if (parsed.gas_payment_count > 0) {
        expect_review_row_equal(summary, "Gas0 object", parsed.gas_payments[0].object_id, failures);
        expect_review_row_equal(summary, "Gas0 version", parsed.gas_payments[0].version, failures);
        expect_review_row_equal(summary, "Gas0 digest", parsed.gas_payments[0].digest_hex, failures);
    }
    if (parsed.expiration_kind == agent_q::SuiTransactionExpirationFact::epoch) {
        expect_review_row_equal(summary, "Expiration", "epoch", failures);
        expect_review_row_equal(summary, "Exp epoch", parsed.expiration_epoch, failures);
    }
    if (parsed.expiration_kind == agent_q::SuiTransactionExpirationFact::valid_during) {
        expect_review_row_equal(summary, "Expiration", "valid_during", failures);
        expect_review_row_equal(summary, "Chain digest", parsed.valid_during.chain_digest_hex, failures);
        expect_review_row_equal(summary, "Nonce", parsed.valid_during.nonce, failures);
    }
    expect_review_row_present(summary, "Inputs", failures);
    expect_review_row_present(summary, "Commands", failures);
    if (parsed.input_count > 0) {
        expect_review_row_present(summary, "Input0 kind", failures);
    }
    if (parsed.command_count > 0) {
        expect_review_row_equal(summary, "Command 0", command_kind_name(parsed.commands[0].kind), failures);
        expect_review_row_present(summary, "Cmd0 args", failures);
    }
    if (parsed.command_count > 0) {
        if (parsed.commands[0].kind == agent_q::SuiCommandFactKind::move_call) {
            expect_review_row_equal(summary, "Cmd0 package", parsed.commands[0].move_call.package, failures);
            expect_review_row_equal(summary, "Cmd0 module", parsed.commands[0].move_call.module, failures);
            expect_review_row_equal(summary, "Cmd0 function", parsed.commands[0].move_call.function, failures);
            if (parsed.commands[0].move_call.type_argument_count > 0) {
                expect_review_row_equal(
                    summary,
                    "Cmd0 type0",
                    parsed.commands[0].move_call.type_arguments[0].canonical,
                    failures);
            }
        }
        if (parsed.commands[0].kind == agent_q::SuiCommandFactKind::publish) {
            expect_review_row_present(summary, "Cmd0 modules", failures);
            expect_review_row_present(summary, "Cmd0 deps", failures);
            if (parsed.commands[0].publish.dependency_count > 0) {
                expect_review_row_equal(
                    summary,
                    "Cmd0 dep0",
                    parsed.commands[0].publish.dependencies[0],
                    failures);
            }
        }
        if (parsed.commands[0].kind == agent_q::SuiCommandFactKind::upgrade) {
            expect_review_row_equal(summary, "Cmd0 package", parsed.commands[0].upgrade.package, failures);
            expect_review_row_present(summary, "Cmd0 modules", failures);
            expect_review_row_present(summary, "Cmd0 deps", failures);
            if (parsed.commands[0].upgrade.dependency_count > 0) {
                expect_review_row_equal(
                    summary,
                    "Cmd0 dep0",
                    parsed.commands[0].upgrade.dependencies[0],
                failures);
            }
        }
        if (parsed.commands[0].kind == agent_q::SuiCommandFactKind::split_coins &&
            parsed.commands[0].argument_count > 1) {
            expect_review_row_present(summary, "Cmd0 amount0", failures);
        }
    }
    if (parsed.command_count > 1 &&
        parsed.commands[1].kind == agent_q::SuiCommandFactKind::transfer_objects) {
        expect_review_row_present(summary, "Cmd1 recipient", failures);
    }
    if (parsed.input_count > 0) {
        if (parsed.inputs[0].kind == agent_q::SuiCallArgFactKind::object_shared) {
            expect_review_row_equal(summary, "Input0 object", parsed.inputs[0].object_ref.object_id, failures);
            expect_review_row_equal(summary, "Input0 version", parsed.inputs[0].shared_initial_version, failures);
            expect_review_row_present(summary, "Input0 mutable", failures);
        }
        if (parsed.inputs[0].kind == agent_q::SuiCallArgFactKind::funds_withdrawal) {
            expect_review_row_equal(summary, "Input0 amount", parsed.inputs[0].funds_withdrawal.amount, failures);
            expect_review_row_equal(summary, "Input0 type", parsed.inputs[0].funds_withdrawal.type.canonical, failures);
            expect_review_row_present(summary, "Input0 source", failures);
        }
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

    expect_parsed_transaction_facts("valid_sui_transfer_tx", valid, expected_json, &failures);
    expect_minimum_transaction_facts("valid_sui_transfer_tx", valid, expected_json, &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "valid_sui_transfer_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "merge_coins_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "move_call_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "split_move_call_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "direct_object_transfer_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "non_gas_split_transfer_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "merge_known_known_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "merge_known_unknown_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "move_call_vector_type_arg_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "publish_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "upgrade_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "funds_withdrawal_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "funds_withdrawal_transfer_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "valid_during_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "epoch_expiration_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "make_move_vec_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "shared_object_move_call_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "receiving_object_make_move_vec_tx", &failures);
    expect_sdk_v2_oracle_facts(fixture_dir, "sponsored_gas_owner_tx", &failures);
    expect_review_summary(
        (fixture_dir + "/valid_sui_transfer_tx.bcs.hex").c_str(),
        "Programmable transaction",
        "High",
        agent_q::SuiReviewSummaryStatus::ok,
        &failures);
    expect_review_summary(
        (fixture_dir + "/move_call_tx.bcs.hex").c_str(),
        "Move call",
        "High",
        agent_q::SuiReviewSummaryStatus::ok,
        &failures);
    expect_review_summary(
        (fixture_dir + "/publish_tx.bcs.hex").c_str(),
        "Publish package",
        "High",
        agent_q::SuiReviewSummaryStatus::insufficient_review,
        &failures);
    expect_review_summary(
        (fixture_dir + "/upgrade_tx.bcs.hex").c_str(),
        "Upgrade package",
        "High",
        agent_q::SuiReviewSummaryStatus::insufficient_review,
        &failures);
    expect_review_summary(
        (fixture_dir + "/merge_coins_tx.bcs.hex").c_str(),
        "Programmable transaction",
        "High",
        agent_q::SuiReviewSummaryStatus::ok,
        &failures);
    expect_review_summary(
        (fixture_dir + "/result_reference_transfer_tx.bcs.hex").c_str(),
        "Programmable transaction",
        "High",
        agent_q::SuiReviewSummaryStatus::ok,
        &failures);
    expect_review_summary(
        (fixture_dir + "/make_move_vec_tx.bcs.hex").c_str(),
        "Programmable transaction",
        "High",
        agent_q::SuiReviewSummaryStatus::ok,
        &failures);
    expect_review_summary(
        (fixture_dir + "/shared_object_move_call_tx.bcs.hex").c_str(),
        "Move call",
        "High",
        agent_q::SuiReviewSummaryStatus::ok,
        &failures);

    agent_q::SuiPolicySubjectFacts facts = {};
    const agent_q::SuiTransactionFactsResult result =
        parse_policy_subject(valid.data(), valid.size(), &facts);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "valid fixture returned %s\n", agent_q::sui_transaction_facts_result_name(result));
        failures += 1;
    } else {
        expect_equal("sender", json_string_field(expected_json, "sender").c_str(), facts.sender, &failures);
        expect_equal("gasOwner", json_string_field(expected_json, "gasOwner").c_str(), facts.gas_owner, &failures);
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
        parse_policy_subject(
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
    expect_minimum_reject(
        (fixture_dir + "/malformed_short_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::malformed,
        &failures);
    expect_reject(
        (fixture_dir + "/trailing_bytes_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::malformed,
        &failures);
    expect_reject(
        (fixture_dir + "/transaction_kind_only_sui_transfer_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::transaction_kind_only,
        &failures);
    expect_minimum_reject(
        (fixture_dir + "/transaction_kind_only_sui_transfer_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::transaction_kind_only,
        &failures);
    expect_supported_policy_subject(
        (fixture_dir + "/merge_coins_tx.bcs.hex").c_str(),
        &failures);
    expect_move_call_metadata(
        (fixture_dir + "/move_call_tx.bcs.hex").c_str(),
        &failures);
    expect_move_call_vector_type_arg_metadata(
        (fixture_dir + "/move_call_vector_type_arg_tx.bcs.hex").c_str(),
        &failures);
    expect_publish_metadata(
        (fixture_dir + "/publish_tx.bcs.hex").c_str(),
        &failures);
    expect_upgrade_metadata(
        (fixture_dir + "/upgrade_tx.bcs.hex").c_str(),
        &failures);
    expect_funds_withdrawal_metadata(
        (fixture_dir + "/funds_withdrawal_tx.bcs.hex").c_str(),
        &failures);
    expect_valid_during_metadata(
        (fixture_dir + "/valid_during_tx.bcs.hex").c_str(),
        &failures);
    expect_epoch_expiration_metadata(
        (fixture_dir + "/epoch_expiration_tx.bcs.hex").c_str(),
        &failures);
    expect_make_move_vec_metadata(
        (fixture_dir + "/make_move_vec_tx.bcs.hex").c_str(),
        agent_q::SuiCallArgFactKind::object_imm_or_owned,
        &failures);
    expect_shared_object_metadata(
        (fixture_dir + "/shared_object_move_call_tx.bcs.hex").c_str(),
        &failures);
    expect_make_move_vec_metadata(
        (fixture_dir + "/receiving_object_make_move_vec_tx.bcs.hex").c_str(),
        agent_q::SuiCallArgFactKind::object_receiving,
        &failures);
    expect_reject(
        (fixture_dir + "/move_call_out_of_range_input_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::malformed,
        &failures);
    expect_reject(
        (fixture_dir + "/wrong_command_order_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::malformed,
        &failures);
    expect_supported_policy_subject(
        (fixture_dir + "/result_reference_transfer_tx.bcs.hex").c_str(),
        &failures);
    expect_reject(
        (fixture_dir + "/too_many_commands_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::malformed,
        &failures);
    const std::vector<uint8_t> large_pure_input =
        read_hex_fixture((fixture_dir + "/large_pure_input_tx.bcs.hex").c_str());
    const std::string large_pure_input_expected_json =
        read_file((fixture_dir + "/large_pure_input_tx.sdk-v2-facts.json").c_str());
    expect_reject(
        (fixture_dir + "/large_pure_input_tx.bcs.hex").c_str(),
        agent_q::SuiTransactionFactsResult::too_large,
        &failures);
    expect_minimum_transaction_facts(
        "large_pure_input_tx",
        large_pure_input,
        large_pure_input_expected_json,
        &failures);

    const std::vector<uint8_t> future_transaction_data_version = {1};
    facts = {};
    const agent_q::SuiTransactionFactsResult future_version_result =
        parse_policy_subject(
            future_transaction_data_version.data(),
            future_transaction_data_version.size(),
            &facts);
    if (future_version_result != agent_q::SuiTransactionFactsResult::unsupported_version) {
        fprintf(stderr, "future transaction-data version expected unsupported_version, got %s\n",
                agent_q::sui_transaction_facts_result_name(future_version_result));
        failures += 1;
    }

    std::vector<uint8_t> oversized((128 * 1024) + 1, 0);
    facts = {};
    const agent_q::SuiTransactionFactsResult oversized_result =
        parse_policy_subject(oversized.data(), oversized.size(), &facts);
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
