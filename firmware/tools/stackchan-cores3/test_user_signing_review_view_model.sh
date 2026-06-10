#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_user_signing_review_view_model.sh

Compiles the StackChan CoreS3 device-confirmed user_signing review
view-model against host stubs and verifies that clear-signing rows are built
only from a reviewing signature-request snapshot. This test uses only a host
C++ compiler and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-signature-request-review.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/freertos"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
cat >"${TMP_DIR}/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(ms) (ms)
H

cat >"${TMP_DIR}/user_signing_review_view_model_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_user_signing_review_view_model.h"

namespace {

int failures = 0;

constexpr const char* kFullRecipient =
    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void copy_field(char* output, size_t output_size, const char* value)
{
    if (output_size == 0) {
        return;
    }
    snprintf(output, output_size, "%s", value);
}

agent_q::AgentQUserSigningFlowSnapshot valid_snapshot()
{
    agent_q::AgentQUserSigningFlowSnapshot snapshot = {};
    snapshot.active = true;
    snapshot.stage = agent_q::AgentQUserSigningStage::reviewing;
    snapshot.signing_route = agent_q::AgentQSigningRoute::sui_sign_transaction;
    copy_field(snapshot.chain, sizeof(snapshot.chain), "sui");
    copy_field(snapshot.method, sizeof(snapshot.method), "sign_transaction");
    copy_field(snapshot.network, sizeof(snapshot.network), "devnet");
    copy_field(snapshot.payload_digest, sizeof(snapshot.payload_digest),
               "sha256:1111111111111111111111111111111111111111111111111111111111111111");
    copy_field(snapshot.sui_facts.sender, sizeof(snapshot.sui_facts.sender),
               "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    copy_field(snapshot.sui_facts.gas_owner, sizeof(snapshot.sui_facts.gas_owner),
               "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    snapshot.sui_facts.has_restricted_transfer = true;
    copy_field(snapshot.sui_facts.restricted_transfer.recipient, sizeof(snapshot.sui_facts.restricted_transfer.recipient),
               kFullRecipient);
    copy_field(snapshot.sui_facts.restricted_transfer.asset, sizeof(snapshot.sui_facts.restricted_transfer.asset),
               "0x2::sui::SUI");
    copy_field(snapshot.sui_facts.restricted_transfer.amount, sizeof(snapshot.sui_facts.restricted_transfer.amount),
               "1000000000");
    copy_field(snapshot.sui_facts.gas_budget, sizeof(snapshot.sui_facts.gas_budget),
               "5000000");
    copy_field(snapshot.sui_facts.gas_price, sizeof(snapshot.sui_facts.gas_price),
               "1000");
    snapshot.sui_facts.restricted_transfer.command_count = 2;
    snapshot.signable_payload_available = true;
    snapshot.signable_payload_size = 128;
    return snapshot;
}

const char* row_value(
    const agent_q::AgentQUserSigningReviewViewModel& model,
    const char* label)
{
    for (size_t index = 0; index < model.row_count; ++index) {
        if (strcmp(model.rows[index].label, label) == 0) {
            return model.rows[index].value;
        }
    }
    return nullptr;
}

agent_q::AgentQUserSigningReviewRowKind row_kind(
    const agent_q::AgentQUserSigningReviewViewModel& model,
    const char* label)
{
    for (size_t index = 0; index < model.row_count; ++index) {
        if (strcmp(model.rows[index].label, label) == 0) {
            return model.rows[index].kind;
        }
    }
    return agent_q::AgentQUserSigningReviewRowKind::normal;
}

}  // namespace

int main()
{
    using Result = agent_q::AgentQUserSigningReviewBuildResult;

    agent_q::AgentQUserSigningReviewViewModel model = {};
    agent_q::AgentQUserSigningFlowSnapshot snapshot = valid_snapshot();
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::ok,
           "valid reviewing snapshot builds review model");
    expect(strcmp(model.title, "Review Sui transfer") == 0,
           "model title names review action");
    expect(model.row_count == 7,
           "model uses only txBytes-derived clear-signing rows");
    expect(strcmp(row_value(model, "Chain"), "sui") == 0,
           "chain row included");
    expect(strcmp(row_value(model, "Method"), "sign_transaction") == 0,
           "method row included");
    expect(row_value(model, "Network") == nullptr,
           "host-supplied network is not shown as a clear-signing fact");
    expect(strcmp(row_value(model, "Amount"), "1000000000") == 0,
           "amount row included");
    expect(strcmp(row_value(model, "Asset"), "0x2::sui::SUI") == 0,
           "asset row included");
    expect(strcmp(row_value(model, "Gas budget"), "5000000") == 0,
           "gas budget row included");
    expect(strcmp(row_value(model, "Gas price"), "1000") == 0,
           "gas price row included");
    expect(strcmp(row_value(model, "Recipient"), kFullRecipient) == 0,
           "full recipient row included without tail-only truncation");
    expect(row_kind(model, "Recipient") == agent_q::AgentQUserSigningReviewRowKind::wrapped_value,
           "recipient row carries wrapped-value layout kind");
    expect(row_kind(model, "Amount") == agent_q::AgentQUserSigningReviewRowKind::normal,
           "amount row carries normal layout kind");

    snapshot = valid_snapshot();
    copy_field(snapshot.method, sizeof(snapshot.method), "sign_personal_message");
    snapshot.signing_route = agent_q::AgentQSigningRoute::sui_sign_personal_message;
    copy_field(snapshot.account_address, sizeof(snapshot.account_address),
               "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    copy_field(snapshot.message_preview, sizeof(snapshot.message_preview), "Agent-Q personal message");
    snapshot.signable_payload_size = 24;
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::ok,
           "valid personal-message snapshot builds review model");
    expect(strcmp(model.title, "Review Sui message") == 0,
           "personal-message model title names review action");
    expect(model.row_count == 5,
           "personal-message model uses bounded message rows");
    expect(strcmp(row_value(model, "Chain"), "sui") == 0,
           "personal-message chain row included");
    expect(strcmp(row_value(model, "Method"), "sign_personal_message") == 0,
           "personal-message method row included");
    expect(strcmp(row_value(model, "Account"),
                  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0,
           "personal-message account row included");
    expect(strcmp(row_value(model, "Preview"), "Agent-Q personal message") == 0,
           "personal-message preview row included");
    expect(row_kind(model, "Preview") == agent_q::AgentQUserSigningReviewRowKind::wrapped_value,
           "personal-message preview row carries wrapped-value layout kind");
    expect(row_kind(model, "Account") == agent_q::AgentQUserSigningReviewRowKind::normal,
           "personal-message account row carries normal layout kind");
    expect(strcmp(row_value(model, "Payload digest"),
                  "sha256:1111111111111111111111111111111111111111111111111111111111111111") == 0,
           "personal-message payload digest row included");

    snapshot = valid_snapshot();
    snapshot.active = false;
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::inactive,
           "inactive snapshot is rejected");
    expect(model.row_count == 0, "inactive failure clears output");

    snapshot = valid_snapshot();
    snapshot.stage = agent_q::AgentQUserSigningStage::pin_entry;
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::wrong_stage,
           "non-reviewing snapshot is rejected");

    snapshot = valid_snapshot();
    snapshot.sui_facts.restricted_transfer.amount[0] = '\0';
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "missing amount is rejected");

    snapshot = valid_snapshot();
    snapshot.sui_facts.gas_budget[0] = '\0';
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "missing gas budget is rejected");

    snapshot = valid_snapshot();
    snapshot.signable_payload_available = false;
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "unavailable signable payload is rejected");

    snapshot = valid_snapshot();
    snapshot.payload_digest[0] = '\0';
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "missing payload digest is rejected");

    snapshot = valid_snapshot();
    memset(snapshot.chain, 's', sizeof(snapshot.chain));
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::ok,
           "review model uses verified route enum instead of raw snapshot chain");
    expect(strcmp(row_value(model, "Chain"), "sui") == 0,
           "chain row is derived from route enum");

    snapshot = valid_snapshot();
    memset(snapshot.method, 'm', sizeof(snapshot.method));
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::ok,
           "review model uses verified route enum instead of raw snapshot method");
    expect(strcmp(row_value(model, "Method"), "sign_transaction") == 0,
           "method row is derived from route enum");

    snapshot = valid_snapshot();
    copy_field(snapshot.method, sizeof(snapshot.method), "sign_unknown");
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::ok,
           "raw method metadata does not drive review branching");

    snapshot = valid_snapshot();
    snapshot.signing_route = agent_q::AgentQSigningRoute::unsupported;
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "unsupported route enum is rejected instead of falling through");

    snapshot = valid_snapshot();
    memset(snapshot.network, 'd', sizeof(snapshot.network));
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::ok,
           "host-supplied network is ignored by the clear-signing view model");

    snapshot = valid_snapshot();
    memset(snapshot.sui_facts.restricted_transfer.asset, 'S', sizeof(snapshot.sui_facts.restricted_transfer.asset));
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "unterminated asset is rejected instead of overread");

    snapshot = valid_snapshot();
    memset(snapshot.sui_facts.restricted_transfer.recipient, 'b', sizeof(snapshot.sui_facts.restricted_transfer.recipient));
    expect(agent_q::user_signing_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "unterminated overlong recipient is rejected instead of truncated");

    expect(strcmp(agent_q::user_signing_review_view_model_build_result_name(Result::ok), "ok") == 0,
           "result name exposes ok");
    expect(strcmp(agent_q::user_signing_review_view_model_build_result_name(Result::wrong_stage),
                  "wrong_stage") == 0,
           "result name exposes wrong_stage");

    if (failures != 0) {
        fprintf(stderr, "%d user_signing review view-model checks failed\n", failures);
        return 1;
    }
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${REPO_ROOT}/firmware/src/common" \
  -I"${REPO_ROOT}/firmware/src/common/agent_q" \
  "${TMP_DIR}/user_signing_review_view_model_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_user_signing_review_view_model.cpp" \
  -o "${TMP_DIR}/user_signing_review_view_model_test"

"${TMP_DIR}/user_signing_review_view_model_test"
