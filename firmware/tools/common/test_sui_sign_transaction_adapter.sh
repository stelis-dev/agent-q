#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_SUI_DIR="${REPO_ROOT}/firmware/src/common/sui"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"
COVERAGE_MATRIX="${COMMON_SUI_DIR}/testdata/sui_transaction_authorization_coverage.tsv"
CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-sui-sign-transaction-adapter.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "sign_transaction_adapter.h"

void expect(bool condition, const std::string& message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message.c_str());
        abort();
    }
}

std::vector<std::string> split_tabs(const std::string& line)
{
    std::vector<std::string> parts;
    size_t offset = 0;
    while (true) {
        const size_t tab = line.find('\t', offset);
        if (tab == std::string::npos) {
            parts.push_back(line.substr(offset));
            return parts;
        }
        parts.push_back(line.substr(offset, tab - offset));
        offset = tab + 1;
    }
}

std::vector<std::string> split_commas(const std::string& value)
{
    std::vector<std::string> parts;
    if (value == "none") {
        return parts;
    }
    size_t offset = 0;
    while (true) {
        const size_t comma = value.find(',', offset);
        const std::string part =
            comma == std::string::npos
                ? value.substr(offset)
                : value.substr(offset, comma - offset);
        expect(!part.empty(), "comma-separated matrix field contains an empty item: " + value);
        parts.push_back(part);
        if (comma == std::string::npos) {
            return parts;
        }
        offset = comma + 1;
    }
}

struct MatrixRow {
    std::map<std::string, std::string> fields;
};

const std::string& field(const MatrixRow& row, const char* name)
{
    const auto found = row.fields.find(name);
    expect(found != row.fields.end(), std::string("matrix field missing: ") + name);
    return found->second;
}

bool yes_no(const MatrixRow& row, const char* name)
{
    const std::string& value = field(row, name);
    if (value == "yes") {
        return true;
    }
    if (value == "no") {
        return false;
    }
    expect(false, std::string("matrix field must be yes/no: ") + name + "=" + value);
    return false;
}

std::vector<MatrixRow> read_matrix(const std::string& path)
{
    std::ifstream input(path);
    expect(input.good(), "failed to open authorization coverage matrix: " + path);

    std::vector<std::string> headers;
    std::vector<MatrixRow> rows;
    std::string line;
    size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::vector<std::string> columns = split_tabs(line);
        if (headers.empty()) {
            headers = columns;
            expect(!headers.empty() && headers[0] == "fixture", "matrix header must start with fixture");
            continue;
        }
        expect(
            columns.size() == headers.size(),
            "matrix row column count mismatch on line " + std::to_string(line_number));
        MatrixRow row;
        for (size_t index = 0; index < headers.size(); ++index) {
            row.fields[headers[index]] = columns[index];
        }
        rows.push_back(row);
    }
    expect(!rows.empty(), "authorization coverage matrix has no rows");
    return rows;
}

signing::SuiSignTransactionAdapterResult expected_adapter_result(const MatrixRow& row)
{
    const std::string& user_gate = field(row, "expected_user_gate_after_adapter");
    if (user_gate == "ok_review_pending" || user_gate == "blind_signing_confirmation") {
        return signing::SuiSignTransactionAdapterResult::ok;
    }
    if (user_gate == "malformed_transaction") {
        return signing::SuiSignTransactionAdapterResult::malformed_transaction;
    }
    if (user_gate == "unsupported_transaction") {
        return signing::SuiSignTransactionAdapterResult::unsupported_transaction;
    }
    expect(false, "unsupported matrix expected_user_gate_after_adapter: " + user_gate);
    return signing::SuiSignTransactionAdapterResult::unsupported_transaction;
}

signing::SuiUserAuthorizationOutcome expected_user_outcome(const MatrixRow& row)
{
    const std::string& user_gate = field(row, "expected_user_gate_after_adapter");
    if (user_gate == "ok_review_pending") {
        return signing::SuiUserAuthorizationOutcome::offline_facts_review;
    }
    if (user_gate == "blind_signing_confirmation") {
        return signing::SuiUserAuthorizationOutcome::blind_signing;
    }
    return signing::SuiUserAuthorizationOutcome::unavailable;
}

signing::SuiTransactionFactsResult expected_parse_result(const MatrixRow& row)
{
    const std::string& parse_result = field(row, "full_facts_parse_result");
    if (parse_result == "ok") {
        return signing::SuiTransactionFactsResult::ok;
    }
    if (parse_result == "malformed") {
        return signing::SuiTransactionFactsResult::malformed;
    }
    if (parse_result == "transaction_kind_only") {
        return signing::SuiTransactionFactsResult::transaction_kind_only;
    }
    if (parse_result == "too_large") {
        return signing::SuiTransactionFactsResult::too_large;
    }
    expect(false, "unsupported matrix full_facts_parse_result: " + parse_result);
    return signing::SuiTransactionFactsResult::malformed;
}

const char* adapter_result_name(signing::SuiSignTransactionAdapterResult result)
{
    switch (result) {
        case signing::SuiSignTransactionAdapterResult::ok:
            return "ok";
        case signing::SuiSignTransactionAdapterResult::invalid_argument:
            return "invalid_argument";
        case signing::SuiSignTransactionAdapterResult::malformed_transaction:
            return "malformed_transaction";
        case signing::SuiSignTransactionAdapterResult::unsupported_transaction:
            return "unsupported_transaction";
    }
    return "unknown";
}

const char* review_status_name(signing::SuiReviewSummaryStatus status)
{
    switch (status) {
        case signing::SuiReviewSummaryStatus::ok:
            return "ok";
        case signing::SuiReviewSummaryStatus::unsupported_review:
            return "unsupported_review";
        case signing::SuiReviewSummaryStatus::insufficient_review:
            return "insufficient_review";
    }
    return "unknown";
}

std::vector<uint8_t> read_hex(const std::string& path)
{
    FILE* file = fopen(path.c_str(), "rb");
    expect(file != nullptr, "failed to open fixture: " + path);
    std::string hex;
    int ch = 0;
    while ((ch = fgetc(file)) != EOF) {
        if (!isspace(ch)) {
            hex.push_back(static_cast<char>(ch));
        }
    }
    fclose(file);
    expect((hex.size() % 2) == 0, "hex fixture length must be even: " + path);
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t index = 0; index < bytes.size(); ++index) {
        const std::string pair = hex.substr(index * 2, 2);
        bytes[index] = static_cast<uint8_t>(strtoul(pair.c_str(), nullptr, 16));
    }
    return bytes;
}

const char* review_row_value(const signing::SuiReviewSummary& review, const char* label)
{
    for (uint16_t index = 0; index < review.row_count; ++index) {
        if (strcmp(review.rows[index].label, label) == 0) {
            return review.rows[index].value;
        }
    }
    return nullptr;
}

void validate_required_review_fields(
    const MatrixRow& row,
    const signing::SuiReviewSummary& review)
{
    const std::vector<std::string> required = split_commas(field(row, "required_review_fields"));
    for (const std::string& label : required) {
        const char* value = review_row_value(review, label.c_str());
        expect(
            value != nullptr,
            field(row, "fixture") + ": required review row missing: " + label);
        expect(
            value != nullptr && value[0] != '\0',
            field(row, "fixture") + ": required review row has empty value: " + label);
    }
}

void validate_matrix_row_shape(const MatrixRow& row)
{
    const std::string& offline_review = field(row, "offline_review_coverage");
    const std::string& minimum_facts = field(row, "minimum_facts_coverage");
    const std::string& user_after_adapter = field(row, "expected_user_gate_after_adapter");
    const std::string& policy_after_adapter = field(row, "expected_policy_gate_after_adapter");

    expect(
        minimum_facts == "yes" || minimum_facts == "no",
        "invalid minimum_facts_coverage for " + field(row, "fixture"));
    expect(
        offline_review == "complete" || offline_review == "incomplete" ||
            offline_review == "unsupported",
        "invalid offline_review_coverage for " + field(row, "fixture"));
    expect(
        user_after_adapter == "ok_review_pending" ||
            user_after_adapter == "blind_signing_confirmation" ||
            user_after_adapter == "malformed_transaction" ||
            user_after_adapter == "unsupported_transaction",
        "invalid expected_user_gate_after_adapter for " + field(row, "fixture"));
    expect(
        policy_after_adapter == "policy_rejected" ||
            policy_after_adapter == "malformed_transaction" ||
            policy_after_adapter == "unsupported_transaction",
        "invalid expected_policy_gate_after_adapter for " + field(row, "fixture"));
    if (user_after_adapter == "ok_review_pending") {
        expect(offline_review == "complete", "clear user adapter gate requires complete review coverage for " + field(row, "fixture"));
    }
    if (user_after_adapter == "blind_signing_confirmation") {
        expect(offline_review == "incomplete", "blind user adapter gate requires incomplete review coverage for " + field(row, "fixture"));
        expect(minimum_facts == "yes", "blind user adapter gate requires minimum facts coverage for " + field(row, "fixture"));
    }
}

void validate_adapter_against_row(const std::string& root, const MatrixRow& row)
{
    validate_matrix_row_shape(row);

    const std::string fixture = field(row, "fixture");
    const auto bytes = read_hex(root + "/" + fixture + ".bcs.hex");

    signing::SuiParsedTransactionFacts* parsed =
        static_cast<signing::SuiParsedTransactionFacts*>(malloc(sizeof(signing::SuiParsedTransactionFacts)));
    expect(parsed != nullptr, fixture + ": failed to allocate parser scratch");
    const auto actual_parse_result =
        signing::parse_sui_parsed_transaction_facts(bytes.data(), bytes.size(), parsed);
    const auto expected_full_parse = expected_parse_result(row);
    expect(
        actual_parse_result == expected_full_parse,
        fixture + ": expected full parse result " +
            std::string(signing::sui_transaction_facts_result_name(expected_full_parse)) +
            ", got " + signing::sui_transaction_facts_result_name(actual_parse_result));
    free(parsed);

    signing::SuiMinimumTransactionFacts minimum = {};
    const auto minimum_result =
        signing::parse_sui_minimum_transaction_facts(bytes.data(), bytes.size(), &minimum);
    const bool minimum_ok = minimum_result == signing::SuiTransactionFactsResult::ok;
    expect(
        minimum_ok == yes_no(row, "minimum_facts_coverage"),
        fixture + ": minimum facts coverage mismatch");

    signing::SuiPolicySubjectFacts facts = {};
    signing::SuiReviewSummary review = {};
    signing::SuiSignTransactionAuthorizationCoverage coverage = {};

    const auto result =
        signing::classify_sui_sign_transaction(
            bytes.data(),
            bytes.size(),
            &facts,
            &review,
            &coverage);
    const auto expected = expected_adapter_result(row);
    expect(
        result == expected,
        fixture + ": expected adapter result " + adapter_result_name(expected) +
            ", got " + adapter_result_name(result));

    expect(
        coverage.user_mode_authorization_covered == yes_no(row, "adapter_user_gate_covered"),
        fixture + ": user adapter coverage mismatch");
    expect(
        coverage.policy_mode_authorization_covered == yes_no(row, "adapter_policy_gate_covered"),
        fixture + ": policy adapter coverage mismatch");
    expect(
        coverage.user_outcome == expected_user_outcome(row),
        fixture + ": user authorization outcome mismatch");
    expect(
        coverage.policy_outcome == signing::SuiPolicyAuthorizationOutcome::unavailable,
        fixture + ": policy authorization must stay unavailable before current evaluator is connected");

    if (result != signing::SuiSignTransactionAdapterResult::ok) {
        return;
    }

    const std::string& offline_review = field(row, "offline_review_coverage");
    if (offline_review == "complete") {
        expect(
            review.status == signing::SuiReviewSummaryStatus::ok,
            fixture + ": expected complete review status, got " + review_status_name(review.status));
    } else if (offline_review == "incomplete") {
        expect(
            review.status == signing::SuiReviewSummaryStatus::insufficient_review,
            fixture + ": expected insufficient review status, got " + review_status_name(review.status));
    } else {
        expect(
            review.status == signing::SuiReviewSummaryStatus::unsupported_review,
            fixture + ": expected unsupported review status, got " + review_status_name(review.status));
    }

    expect(review.row_count > 0, fixture + ": successful adapter rows must include review rows");
    expect(facts.sender[0] != '\0', fixture + ": successful adapter rows must include sender fact");
    expect(facts.gas_owner[0] != '\0', fixture + ": successful adapter rows must include gas owner fact");
    validate_required_review_fields(row, review);
}

int main(int argc, char** argv)
{
    expect(argc == 3, "usage: test <fixture-dir> <coverage-matrix>");
    const std::string root = argv[1];
    const std::string matrix = argv[2];

    const std::vector<MatrixRow> rows = read_matrix(matrix);
    for (const MatrixRow& row : rows) {
        validate_adapter_against_row(root, row);
    }

    signing::SuiPolicySubjectFacts facts = {};
    signing::SuiReviewSummary review = {};
    signing::SuiSignTransactionAuthorizationCoverage coverage = {};
    expect(
        signing::classify_sui_sign_transaction(nullptr, 0, &facts, &review, &coverage) ==
            signing::SuiSignTransactionAdapterResult::invalid_argument,
        "null transaction input must return invalid_argument");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_SUI_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${COMMON_SUI_DIR}/sign_transaction_adapter.cpp" \
  "${COMMON_SUI_DIR}/transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/bcs_reader.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test" "${FIXTURE_DIR}" "${COVERAGE_MATRIX}"
echo "Sui sign_transaction adapter tests passed"
