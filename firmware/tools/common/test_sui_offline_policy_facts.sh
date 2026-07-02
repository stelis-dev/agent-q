#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/common/test_sui_offline_policy_facts.sh

Compiles the common Agent-Q Sui offline policy condition facts extractor with a
host C++ compiler and checks BCS fixtures. This test does not require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"

for required in \
  "${COMMON_ROOT}/numeric/u64_decimal.h" \
  "${COMMON_SUI_DIR}/bcs_reader.cpp" \
  "${COMMON_SUI_DIR}/transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/offline_policy_facts.cpp" \
  "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/funds_withdrawal_tx.bcs.hex" \
  "${FIXTURE_DIR}/non_sui_funds_withdrawal_tx.bcs.hex" \
  "${FIXTURE_DIR}/non_gas_split_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/direct_object_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/merge_known_known_tx.bcs.hex" \
  "${FIXTURE_DIR}/merge_known_unknown_tx.bcs.hex" \
  "${FIXTURE_DIR}/merge_known_known_then_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/merge_result_reference_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/token_amount_overflow_tx.bcs.hex" \
  "${FIXTURE_DIR}/move_call_tx.bcs.hex" \
  "${FIXTURE_DIR}/publish_tx.bcs.hex" \
  "${FIXTURE_DIR}/upgrade_tx.bcs.hex" \
  "${FIXTURE_DIR}/sponsored_gas_owner_tx.bcs.hex" \
  "${FIXTURE_DIR}/malformed_short_tx.bcs.hex"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-sui-offline-policy-facts.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/sui_offline_policy_facts_test.cpp" <<'CPP'
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "offline_policy_facts.h"

namespace {

constexpr const char* kSuiType =
    "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";
constexpr const char* kNonSuiType =
    "0x9999999999999999999999999999999999999999999999999999999999999999::token::TEST";
constexpr const char* kMoveCallPackage =
    "0x2222222222222222222222222222222222222222222222222222222222222222";
constexpr const char* kSender =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr const char* kRecipient =
    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
constexpr const char* kSponsoredGasOwner =
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

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

void expect_true(const char* label, bool value, int* failures)
{
    if (!value) {
        fprintf(stderr, "%s expected true\n", label);
        *failures += 1;
    }
}

void expect_false(const char* label, bool value, int* failures)
{
    if (value) {
        fprintf(stderr, "%s expected false\n", label);
        *failures += 1;
    }
}

void expect_u16_equal(const char* label, uint16_t expected, uint16_t actual, int* failures)
{
    if (expected != actual) {
        fprintf(stderr, "%s mismatch\n  expected: %u\n  actual:   %u\n",
                label,
                expected,
                actual);
        *failures += 1;
    }
}

void expect_equal(const char* label, const char* expected, const char* actual, int* failures)
{
    if (strcmp(expected, actual) != 0) {
        fprintf(stderr, "%s mismatch\n  expected: %s\n  actual:   %s\n", label, expected, actual);
        *failures += 1;
    }
}

signing::SuiOfflinePolicyConditionFacts parse_fixture(
    const std::string& fixture_dir,
    const char* name,
    int* failures)
{
    const std::string path = fixture_dir + "/" + name + ".bcs.hex";
    const std::vector<uint8_t> bytes = read_hex_fixture(path.c_str());
    signing::SuiOfflinePolicyConditionFacts facts = {};
    const signing::SuiTransactionFactsResult result =
        signing::parse_sui_offline_policy_condition_facts(bytes.data(), bytes.size(), &facts);
    if (result != signing::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "%s expected ok parse, got %s\n",
                name,
                signing::sui_transaction_facts_result_name(result));
        *failures += 1;
    }
    return facts;
}

bool set_contains(const signing::SuiOfflinePolicyStringSet& set, const char* value)
{
    for (uint16_t index = 0; index < set.count; ++index) {
        if (strcmp(set.values[index], value) == 0) {
            return true;
        }
    }
    return false;
}

void expect_gas_coin_split_source(const std::string& fixture_dir, int* failures)
{
    const signing::SuiOfflinePolicyConditionFacts facts =
        parse_fixture(fixture_dir, "valid_sui_transfer_tx", failures);
    expect_true("valid_sui_transfer valid", facts.valid_transaction_data, failures);
    expect_false("valid_sui_transfer sponsored", facts.sponsored, failures);
    expect_false("valid_sui_transfer unknown amount", facts.token_unknown_amount_present, failures);
    expect_equal("valid_sui_transfer sender", kSender, facts.sender, failures);
    expect_equal("valid_sui_transfer gas owner", kSender, facts.gas_owner, failures);
    expect_equal("valid_sui_transfer gas price", "1000", facts.gas_price_raw, failures);
    expect_equal("valid_sui_transfer gas budget", "50000000", facts.gas_budget_raw, failures);
    expect_equal("valid_sui_transfer command count", "2", facts.command_count, failures);
    expect_true("valid_sui_transfer split command", set_contains(facts.command_kinds, "split_coins"), failures);
    expect_true("valid_sui_transfer transfer command", set_contains(facts.command_kinds, "transfer_objects"), failures);
    expect_true(
        "valid_sui_transfer recipient address",
        set_contains(facts.recipient_addresses, kRecipient),
        failures);
    expect_true(
        "valid_sui_transfer pure address argument",
        set_contains(facts.pure_address_arguments, kRecipient),
        failures);
    if (facts.token_source_count != 1) {
        fprintf(stderr, "valid_sui_transfer expected one token source, got %u\n", facts.token_source_count);
        *failures += 1;
        return;
    }
    const signing::SuiOfflinePolicyTokenSourceFact& source = facts.token_sources[0];
    expect_equal("valid_sui_transfer token type", kSuiType, source.type_tag, failures);
    expect_equal("valid_sui_transfer amount", "1000000", source.amount_raw, failures);
    if (source.source != signing::SuiOfflinePolicyTokenSourceKind::gas_coin) {
        fprintf(stderr, "valid_sui_transfer source was not gas_coin\n");
        *failures += 1;
    }
    if (source.provenance != signing::SuiOfflinePolicyTokenProvenance::gas_coin_split) {
        fprintf(stderr, "valid_sui_transfer provenance was not gas_coin_split\n");
        *failures += 1;
    }
    expect_u16_equal("valid_sui_transfer total count", 1, facts.token_total_count, failures);
    if (facts.token_total_count > 0) {
        expect_equal("valid_sui_transfer total type", kSuiType, facts.token_totals_by_type[0].type_tag, failures);
        expect_equal("valid_sui_transfer total amount", "1000000", facts.token_totals_by_type[0].amount_raw, failures);
    }
}

void expect_funds_withdrawal_source(const std::string& fixture_dir, int* failures)
{
    const signing::SuiOfflinePolicyConditionFacts facts =
        parse_fixture(fixture_dir, "funds_withdrawal_tx", failures);
    if (facts.token_source_count != 1) {
        fprintf(stderr, "funds_withdrawal expected one token source, got %u\n", facts.token_source_count);
        *failures += 1;
        return;
    }
    const signing::SuiOfflinePolicyTokenSourceFact& source = facts.token_sources[0];
    expect_equal("funds_withdrawal token type", kSuiType, source.type_tag, failures);
    expect_equal("funds_withdrawal amount", "1000000", source.amount_raw, failures);
    if (source.source != signing::SuiOfflinePolicyTokenSourceKind::funds_withdrawal_sender) {
        fprintf(stderr, "funds_withdrawal source was not funds_withdrawal_sender\n");
        *failures += 1;
    }
    if (source.provenance != signing::SuiOfflinePolicyTokenProvenance::funds_withdrawal) {
        fprintf(stderr, "funds_withdrawal provenance was not funds_withdrawal\n");
        *failures += 1;
    }
    expect_u16_equal("funds_withdrawal total count", 1, facts.token_total_count, failures);
    if (facts.token_total_count > 0) {
        expect_equal("funds_withdrawal total type", kSuiType, facts.token_totals_by_type[0].type_tag, failures);
        expect_equal("funds_withdrawal total amount", "1000000", facts.token_totals_by_type[0].amount_raw, failures);
    }
}

void expect_mixed_sui_source_total(const std::string& fixture_dir, int* failures)
{
    const signing::SuiOfflinePolicyConditionFacts facts =
        parse_fixture(fixture_dir, "mixed_sui_source_total_tx", failures);
    expect_false("mixed_sui_source_total unknown amount", facts.token_unknown_amount_present, failures);
    expect_u16_equal("mixed_sui_source_total source count", 2, facts.token_source_count, failures);
    expect_u16_equal("mixed_sui_source_total total count", 1, facts.token_total_count, failures);
    if (facts.token_total_count > 0) {
        expect_equal("mixed_sui_source_total total type", kSuiType, facts.token_totals_by_type[0].type_tag, failures);
        expect_equal("mixed_sui_source_total total amount", "2000000", facts.token_totals_by_type[0].amount_raw, failures);
    }
}

void expect_non_sui_funds_withdrawal_source(const std::string& fixture_dir, int* failures)
{
    const signing::SuiOfflinePolicyConditionFacts facts =
        parse_fixture(fixture_dir, "non_sui_funds_withdrawal_tx", failures);
    if (facts.token_source_count != 1) {
        fprintf(stderr, "non_sui_funds_withdrawal expected one token source, got %u\n", facts.token_source_count);
        *failures += 1;
        return;
    }
    const signing::SuiOfflinePolicyTokenSourceFact& source = facts.token_sources[0];
    expect_equal("non_sui_funds_withdrawal token type", kNonSuiType, source.type_tag, failures);
    expect_equal("non_sui_funds_withdrawal amount", "1000000", source.amount_raw, failures);
    if (source.source != signing::SuiOfflinePolicyTokenSourceKind::funds_withdrawal_sender) {
        fprintf(stderr, "non_sui_funds_withdrawal source was not funds_withdrawal_sender\n");
        *failures += 1;
    }
}

void expect_merge_sources(const std::string& fixture_dir, int* failures)
{
    const signing::SuiOfflinePolicyConditionFacts known =
        parse_fixture(fixture_dir, "merge_known_known_tx", failures);
    expect_false("merge_known_known unknown amount", known.token_unknown_amount_present, failures);
    expect_u16_equal("merge_known_known source count", 2, known.token_source_count, failures);
    expect_u16_equal("merge_known_known total count", 1, known.token_total_count, failures);
    if (known.token_total_count > 0) {
        expect_equal("merge_known_known total type", kSuiType, known.token_totals_by_type[0].type_tag, failures);
        expect_equal("merge_known_known total amount", "3000000", known.token_totals_by_type[0].amount_raw, failures);
    }

    const signing::SuiOfflinePolicyConditionFacts mixed =
        parse_fixture(fixture_dir, "merge_known_unknown_tx", failures);
    expect_true("merge_known_unknown unknown amount", mixed.token_unknown_amount_present, failures);
    if (mixed.token_unknown_amount_reason !=
        signing::SuiOfflinePolicyFactsReason::mixed_known_unknown_token_merge) {
        fprintf(stderr, "merge_known_unknown reason was not mixed_known_unknown_token_merge\n");
        *failures += 1;
    }
    expect_u16_equal("merge_known_unknown source count", 1, mixed.token_source_count, failures);

    const signing::SuiOfflinePolicyConditionFacts reused =
        parse_fixture(fixture_dir, "merge_known_known_then_transfer_tx", failures);
    expect_false("merge_known_known_then_transfer unknown amount", reused.token_unknown_amount_present, failures);
    expect_u16_equal("merge_known_known_then_transfer source count", 2, reused.token_source_count, failures);
    expect_u16_equal("merge_known_known_then_transfer total count", 1, reused.token_total_count, failures);
    if (reused.token_total_count > 0) {
        expect_equal("merge_known_known_then_transfer total type", kSuiType, reused.token_totals_by_type[0].type_tag, failures);
        expect_equal("merge_known_known_then_transfer total amount", "3000000", reused.token_totals_by_type[0].amount_raw, failures);
    }

    const signing::SuiOfflinePolicyConditionFacts merge_result =
        parse_fixture(fixture_dir, "merge_result_reference_transfer_tx", failures);
    expect_true("merge_result_reference_transfer unknown amount", merge_result.token_unknown_amount_present, failures);
    if (merge_result.token_unknown_amount_reason !=
        signing::SuiOfflinePolicyFactsReason::unknown_token_provenance) {
        fprintf(stderr, "merge_result_reference_transfer reason was not unknown_token_provenance\n");
        *failures += 1;
    }
}

void expect_command_sets(const std::string& fixture_dir, int* failures)
{
    const signing::SuiOfflinePolicyConditionFacts move_call =
        parse_fixture(fixture_dir, "move_call_tx", failures);
    expect_true("move_call command kind", set_contains(move_call.command_kinds, "move_call"), failures);
    expect_true("move_call package", set_contains(move_call.move_call_packages, kMoveCallPackage), failures);
    expect_true("move_call module", set_contains(move_call.move_call_modules, "pay"), failures);
    expect_true("move_call function", set_contains(move_call.move_call_functions, "spend"), failures);

    const signing::SuiOfflinePolicyConditionFacts publish =
        parse_fixture(fixture_dir, "publish_tx", failures);
    expect_true("publish flag", publish.publish_present, failures);
    expect_true("publish command kind", set_contains(publish.command_kinds, "publish"), failures);

    const signing::SuiOfflinePolicyConditionFacts upgrade =
        parse_fixture(fixture_dir, "upgrade_tx", failures);
    expect_true("upgrade flag", upgrade.upgrade_present, failures);
    expect_true("upgrade command kind", set_contains(upgrade.command_kinds, "upgrade"), failures);

    const signing::SuiOfflinePolicyConditionFacts sponsored =
        parse_fixture(fixture_dir, "sponsored_gas_owner_tx", failures);
    expect_true("sponsored flag", sponsored.sponsored, failures);
    expect_equal("sponsored gas owner", kSponsoredGasOwner, sponsored.gas_owner, failures);
}

void expect_token_amount_overflow(const std::string& fixture_dir, int* failures)
{
    const signing::SuiOfflinePolicyConditionFacts facts =
        parse_fixture(fixture_dir, "token_amount_overflow_tx", failures);
    if (facts.completeness != signing::SuiOfflinePolicyFactsCompleteness::incomplete ||
        facts.reason != signing::SuiOfflinePolicyFactsReason::token_amount_overflow) {
        fprintf(stderr, "token_amount_overflow did not expose overflow reason\n");
        *failures += 1;
    }
}

void expect_unknown_direct_object_source(const std::string& fixture_dir, int* failures)
{
    const signing::SuiOfflinePolicyConditionFacts non_gas =
        parse_fixture(fixture_dir, "non_gas_split_transfer_tx", failures);
    expect_true("non_gas_split unknown amount", non_gas.token_unknown_amount_present, failures);
    if (non_gas.token_unknown_amount_reason !=
        signing::SuiOfflinePolicyFactsReason::unknown_token_provenance) {
        fprintf(stderr, "non_gas_split reason was not unknown_token_provenance\n");
        *failures += 1;
    }
    if (non_gas.token_source_count != 0) {
        fprintf(stderr, "non_gas_split should not expose known token sources\n");
        *failures += 1;
    }

    const signing::SuiOfflinePolicyConditionFacts direct =
        parse_fixture(fixture_dir, "direct_object_transfer_tx", failures);
    expect_true("direct_object_transfer unknown amount", direct.token_unknown_amount_present, failures);
    if (direct.token_unknown_amount_reason !=
        signing::SuiOfflinePolicyFactsReason::direct_object_token_amount_unknown) {
        fprintf(stderr, "direct_object_transfer reason was not direct_object_token_amount_unknown\n");
        *failures += 1;
    }
    if (direct.token_source_count != 0) {
        fprintf(stderr, "direct_object_transfer should not expose known token sources\n");
        *failures += 1;
    }
}

void expect_malformed_result(const std::string& fixture_dir, int* failures)
{
    const std::string path = fixture_dir + "/malformed_short_tx.bcs.hex";
    const std::vector<uint8_t> bytes = read_hex_fixture(path.c_str());
    signing::SuiOfflinePolicyConditionFacts facts = {};
    const signing::SuiTransactionFactsResult result =
        signing::parse_sui_offline_policy_condition_facts(bytes.data(), bytes.size(), &facts);
    if (result != signing::SuiTransactionFactsResult::malformed) {
        fprintf(stderr, "malformed_short expected malformed parse\n");
        *failures += 1;
    }
    if (facts.completeness != signing::SuiOfflinePolicyFactsCompleteness::malformed ||
        facts.reason != signing::SuiOfflinePolicyFactsReason::malformed_bcs) {
        fprintf(stderr, "malformed_short did not expose malformed reason\n");
        *failures += 1;
    }
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <fixture-dir>\n", argv[0]);
        return 2;
    }
    int failures = 0;
    const std::string fixture_dir = argv[1];
    expect_gas_coin_split_source(fixture_dir, &failures);
    expect_funds_withdrawal_source(fixture_dir, &failures);
    expect_mixed_sui_source_total(fixture_dir, &failures);
    expect_non_sui_funds_withdrawal_source(fixture_dir, &failures);
    expect_unknown_direct_object_source(fixture_dir, &failures);
    expect_merge_sources(fixture_dir, &failures);
    expect_token_amount_overflow(fixture_dir, &failures);
    expect_command_sets(fixture_dir, &failures);
    expect_malformed_result(fixture_dir, &failures);
    if (failures != 0) {
        fprintf(stderr, "sui offline policy facts test failed: %d\n", failures);
        return 1;
    }
    printf("sui offline policy facts test passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_SUI_DIR}" \
  "${TMP_DIR}/sui_offline_policy_facts_test.cpp" \
  "${COMMON_SUI_DIR}/bcs_reader.cpp" \
  "${COMMON_SUI_DIR}/transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/offline_policy_facts.cpp" \
  -o "${TMP_DIR}/sui_offline_policy_facts_test"

"${TMP_DIR}/sui_offline_policy_facts_test" "${FIXTURE_DIR}"
