#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_usb_operation_type.sh

Compiles the USB operation type classifier and verifies the current public
request type strings map to the expected operation enum. It does not require
hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"

if [[ ! -f "${AGENT_Q_DIR}/agent_q_usb_operation_type.h" ]]; then
  echo "Missing required source: ${AGENT_Q_DIR}/agent_q_usb_operation_type.h" >&2
  exit 1
fi

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-usb-operation-type.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>

#include "agent_q_usb_operation_type.h"

namespace {

void expect_type(const char* value, agent_q::AgentQUsbOperationType expected)
{
    assert(agent_q::classify_usb_operation_type(value) == expected);
}

}  // namespace

int main()
{
    using Type = agent_q::AgentQUsbOperationType;

    expect_type("get_status", Type::get_status);
    expect_type("identify_device", Type::identify_device);
    expect_type("connect", Type::connect);
    expect_type("sign_transaction", Type::sign_transaction);
    expect_type("sign_personal_message", Type::sign_personal_message);
    expect_type("get_result", Type::get_result);
    expect_type("ack_result", Type::ack_result);
    expect_type("disconnect", Type::disconnect);
    expect_type("get_capabilities", Type::get_capabilities);
    expect_type("get_accounts", Type::get_accounts);
    expect_type("policy_get", Type::policy_get);
    expect_type("get_approval_history", Type::get_approval_history);
    expect_type("policy_propose", Type::policy_propose);
    expect_type("", Type::unsupported);
    expect_type("sign_transaction_user", Type::unsupported);
    expect_type("sign_transaction_policy", Type::unsupported);
    expect_type("unknown", Type::unsupported);
    expect_type(nullptr, Type::unsupported);

    printf("USB operation type tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
