#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_method_signing_review_view_model.sh

Compiles the StackChan CoreS3 method-signing review view model against host
stubs and verifies that clear-signing review rows preserve the bounded request
summary and reject incomplete summaries. This test uses only a host C++ compiler
and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_POLICY_DIR="${REPO_ROOT}/firmware/src/common/agent_q/policy"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-method-signing-review-view-model.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/freertos" "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_POLICY_DIR}" "${TMP_DIR}/agent_q_common/policy"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
H

cat >"${TMP_DIR}/method_signing_review_view_model_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_method_signing_review_view_model.h"

namespace {

int failures = 0;

constexpr const char* kRecipient =
    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

agent_q::AgentQMethodSigningRequestSnapshot valid_snapshot()
{
    return agent_q::AgentQMethodSigningRequestSnapshot{
        true,
        agent_q::AgentQMethodSigningRequestStage::awaiting_review,
        agent_q::AgentQMethodSigningRequestPolicyDecision::ask,
        agent_q::AgentQMethodSigningRequestTerminalResult::none,
        "method-1",
        "session_abcdefghijklmnop",
        "sui",
        "sign_transaction",
        4,
        "devnet",
        kRecipient,
        "0x2::sui::SUI",
        "1000000",
        "50000000",
        "1000",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "ask_rule",
        100,
    };
}

bool build_model(
    const agent_q::AgentQMethodSigningRequestSnapshot& snapshot,
    agent_q::AgentQMethodSigningReviewViewModel* output)
{
    return agent_q::method_signing_review_view_model_from_snapshot(snapshot, output);
}

bool rows_contain(const agent_q::AgentQMethodSigningReviewViewModel& model, const char* text)
{
    for (size_t index = 0; index < model.row_count; ++index) {
        if (strstr(model.rows[index].text, text) != nullptr) {
            return true;
        }
    }
    return false;
}

bool rows_reconstruct_recipient(const agent_q::AgentQMethodSigningReviewViewModel& model)
{
    char reconstructed[agent_q::kAgentQMethodSigningRequestRecipientSize] = {};
    for (size_t index = 0; index < model.row_count; ++index) {
        const char* row = model.rows[index].text;
        if (strncmp(row, "To ", 3) == 0) {
            strncat(reconstructed, row + 3, sizeof(reconstructed) - strlen(reconstructed) - 1);
        } else if (reconstructed[0] != '\0' &&
                   strncmp(row, "Gas ", 4) != 0 &&
                   strncmp(row, "Amount ", 7) != 0 &&
                   strncmp(row, "Asset ", 6) != 0 &&
                   strstr(row, "/") == nullptr) {
            strncat(reconstructed, row, sizeof(reconstructed) - strlen(reconstructed) - 1);
        }
    }
    return strcmp(reconstructed, kRecipient) == 0;
}

void expect_missing_field_rejected(
    const char* field_name,
    agent_q::AgentQMethodSigningRequestSnapshot snapshot)
{
    agent_q::AgentQMethodSigningReviewViewModel model = {};
    expect(!build_model(snapshot, &model), field_name);
    expect(model.row_count == 0, "rejected incomplete summary leaves no rows");
}

}  // namespace

int main()
{
    agent_q::AgentQMethodSigningReviewViewModel model = {};
    expect(build_model(valid_snapshot(), &model), "valid snapshot builds review model");
    expect(model.row_count <= agent_q::kAgentQMethodSigningReviewMaxRows,
           "review row count stays within screen budget");
    expect(rows_contain(model, "sui/sign_transaction on devnet"), "chain method and network row");
    expect(rows_contain(model, "Amount 1000000"), "amount row");
    expect(rows_contain(model, "Asset 0x2::sui::SUI"), "asset row");
    expect(rows_contain(model, "Gas budget 50000000"), "gas budget row");
    expect(rows_contain(model, "Gas price 1000"), "gas price row");
    expect(rows_reconstruct_recipient(model), "full recipient is preserved across review rows");
    expect(!rows_contain(model, "sha256:111111"), "digest is not used as a summary fallback");

    agent_q::AgentQMethodSigningRequestSnapshot snapshot = valid_snapshot();
    snapshot.stage = agent_q::AgentQMethodSigningRequestStage::awaiting_user;
    expect_missing_field_rejected("non-review signing stage is rejected", snapshot);

    snapshot = valid_snapshot();
    snapshot.network = "";
    expect_missing_field_rejected("missing network is rejected", snapshot);

    snapshot = valid_snapshot();
    snapshot.amount = "";
    expect_missing_field_rejected("missing amount is rejected", snapshot);

    snapshot = valid_snapshot();
    snapshot.asset = "";
    expect_missing_field_rejected("missing asset is rejected", snapshot);

    snapshot = valid_snapshot();
    snapshot.recipient = "";
    expect_missing_field_rejected("missing recipient is rejected", snapshot);

    snapshot = valid_snapshot();
    snapshot.gas_budget = "";
    expect_missing_field_rejected("missing gas budget is rejected", snapshot);

    snapshot = valid_snapshot();
    snapshot.gas_price = "";
    expect_missing_field_rejected("missing gas price is rejected", snapshot);

    snapshot = valid_snapshot();
    snapshot.recipient = nullptr;
    expect_missing_field_rejected("null recipient is rejected", snapshot);

    snapshot = valid_snapshot();
    snapshot.payload_digest =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    snapshot.recipient = "";
    expect_missing_field_rejected("digest cannot replace missing recipient", snapshot);

    if (failures != 0) {
        fprintf(stderr, "%d method signing review view model test(s) failed\n", failures);
        return 1;
    }

    printf("Method signing review view model tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/method_signing_review_view_model_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_method_signing_review_view_model.cpp" \
  -o "${TMP_DIR}/method_signing_review_view_model_test"

"${TMP_DIR}/method_signing_review_view_model_test"
