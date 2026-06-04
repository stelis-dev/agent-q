#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_signature_request_review_view_model.sh

Compiles the StackChan CoreS3 device-confirmed signature request review
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

cat >"${TMP_DIR}/signature_request_review_view_model_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_signature_request_review_view_model.h"

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

agent_q::AgentQSignatureRequestFlowSnapshot valid_snapshot()
{
    agent_q::AgentQSignatureRequestFlowSnapshot snapshot = {};
    snapshot.active = true;
    snapshot.stage = agent_q::AgentQSignatureRequestStage::reviewing;
    copy_field(snapshot.chain, sizeof(snapshot.chain), "sui");
    copy_field(snapshot.method, sizeof(snapshot.method), "sign_transaction");
    copy_field(snapshot.network, sizeof(snapshot.network), "devnet");
    copy_field(snapshot.payload_digest, sizeof(snapshot.payload_digest),
               "sha256:1111111111111111111111111111111111111111111111111111111111111111");
    copy_field(snapshot.sui_transfer.sender, sizeof(snapshot.sui_transfer.sender),
               "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    copy_field(snapshot.sui_transfer.gas_owner, sizeof(snapshot.sui_transfer.gas_owner),
               "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    copy_field(snapshot.sui_transfer.recipient, sizeof(snapshot.sui_transfer.recipient),
               kFullRecipient);
    copy_field(snapshot.sui_transfer.asset, sizeof(snapshot.sui_transfer.asset),
               "0x2::sui::SUI");
    copy_field(snapshot.sui_transfer.amount, sizeof(snapshot.sui_transfer.amount),
               "1000000000");
    copy_field(snapshot.sui_transfer.gas_budget, sizeof(snapshot.sui_transfer.gas_budget),
               "5000000");
    copy_field(snapshot.sui_transfer.gas_price, sizeof(snapshot.sui_transfer.gas_price),
               "1000");
    snapshot.sui_transfer.command_count = 2;
    snapshot.signable_payload_available = true;
    snapshot.signable_payload_size = 128;
    return snapshot;
}

const char* row_value(
    const agent_q::AgentQSignatureRequestReviewViewModel& model,
    const char* label)
{
    for (size_t index = 0; index < model.row_count; ++index) {
        if (strcmp(model.rows[index].label, label) == 0) {
            return model.rows[index].value;
        }
    }
    return nullptr;
}

}  // namespace

int main()
{
    using Result = agent_q::AgentQSignatureRequestReviewBuildResult;

    agent_q::AgentQSignatureRequestReviewViewModel model = {};
    agent_q::AgentQSignatureRequestFlowSnapshot snapshot = valid_snapshot();
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::ok,
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

    snapshot = valid_snapshot();
    snapshot.active = false;
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::inactive,
           "inactive snapshot is rejected");
    expect(model.row_count == 0, "inactive failure clears output");

    snapshot = valid_snapshot();
    snapshot.stage = agent_q::AgentQSignatureRequestStage::pin_entry;
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::wrong_stage,
           "non-reviewing snapshot is rejected");

    snapshot = valid_snapshot();
    snapshot.sui_transfer.amount[0] = '\0';
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "missing amount is rejected");

    snapshot = valid_snapshot();
    snapshot.sui_transfer.gas_budget[0] = '\0';
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "missing gas budget is rejected");

    snapshot = valid_snapshot();
    snapshot.signable_payload_available = false;
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "unavailable signable payload is rejected");

    snapshot = valid_snapshot();
    snapshot.payload_digest[0] = '\0';
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "missing payload digest is rejected");

    snapshot = valid_snapshot();
    copy_field(snapshot.method, sizeof(snapshot.method), "sign_personal_message");
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "unsupported method is rejected");

    snapshot = valid_snapshot();
    memset(snapshot.chain, 's', sizeof(snapshot.chain));
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "unterminated chain is rejected instead of overread");

    snapshot = valid_snapshot();
    memset(snapshot.method, 'm', sizeof(snapshot.method));
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "unterminated method is rejected instead of overread");

    snapshot = valid_snapshot();
    memset(snapshot.network, 'd', sizeof(snapshot.network));
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::ok,
           "host-supplied network is ignored by the clear-signing view model");

    snapshot = valid_snapshot();
    memset(snapshot.sui_transfer.asset, 'S', sizeof(snapshot.sui_transfer.asset));
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "unterminated asset is rejected instead of overread");

    snapshot = valid_snapshot();
    memset(snapshot.sui_transfer.recipient, 'b', sizeof(snapshot.sui_transfer.recipient));
    expect(agent_q::signature_request_review_view_model_build(snapshot, &model) == Result::invalid_summary,
           "unterminated overlong recipient is rejected instead of truncated");

    expect(strcmp(agent_q::signature_request_review_view_model_build_result_name(Result::ok), "ok") == 0,
           "result name exposes ok");
    expect(strcmp(agent_q::signature_request_review_view_model_build_result_name(Result::wrong_stage),
                  "wrong_stage") == 0,
           "result name exposes wrong_stage");

    if (failures != 0) {
        fprintf(stderr, "%d signature request review view-model checks failed\n", failures);
        return 1;
    }
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${REPO_ROOT}/firmware/src/common" \
  "${TMP_DIR}/signature_request_review_view_model_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_signature_request_review_view_model.cpp" \
  -o "${TMP_DIR}/signature_request_review_view_model_test"

"${TMP_DIR}/signature_request_review_view_model_test"
