#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/common/test_sui_policy_token_flow_matrix.sh

Validates the Sui token-flow policy authorization matrix shape and fixture
coverage. This test fixes the implementation input contract before the
token-flow analyzer and policy signing stages consume it.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_SUI_DIR="${REPO_ROOT}/firmware/src/common/agent_q/sui"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"
MATRIX="${COMMON_SUI_DIR}/testdata/sui_policy_token_flow_authorization.tsv"

if [[ ! -f "${MATRIX}" ]]; then
  echo "Missing token-flow policy matrix: ${MATRIX}" >&2
  exit 1
fi

awk -F '\t' -v fixture_dir="${FIXTURE_DIR}" '
function fail(message) {
  print message > "/dev/stderr"
  exit 1
}

function valid_amount(value) {
  return value == "0" || value == "unknown" || value ~ /^[1-9][0-9]*$/
}

function valid_address(value) {
  return value == "none" || value ~ /^0x[0-9a-f]{64}$/
}

function valid_request_network(value) {
  return value == "mainnet" || value == "testnet" || value == "devnet" ||
         value == "localnet" || value == "missing" || value == "invalid"
}

function valid_asset_state(value) {
  return value == "proven_sui" || value == "unproven" || value == "none"
}

function mark_required(case_id) {
  if (case_id in required) {
    seen[case_id] = 1
  }
}

BEGIN {
  expected_header = "case_id\tfixture\tflow_case\tflow0_asset_state\trequest_network\tamount_state\tsui_total_out_complete\tsui_total_out_raw\ttransfer_total_out_raw\tmove_call_total_in_raw\tmerge_total_raw\trecipient0_address\trecipient0_amount_raw\tmove_call0_package\tmove_call0_module\tmove_call0_function\tmove_call0_sui_amount_raw\tpolicy_condition\texpected_sign_rule_valid\texpected_policy_decision\trequired_reason"
  split("split_transfer_total_pass split_transfer_total_reject split_move_call_amount_pass split_move_call_amount_reject direct_object_transfer_amount_limit_reject non_gas_split_transfer_reject funds_withdrawal_transfer_reject merge_known_known_sum merge_known_unknown_incomplete gas_budget_pass gas_budget_too_high_reject request_network_missing_invalid_params request_network_invalid_params wrong_move_call_package_reject missing_required_field_invalid policy_coverage_incomplete_reject user_blind_does_not_affect_policy", required_ids, " ")
  for (required_index in required_ids) {
    required[required_ids[required_index]] = 1
    seen[required_ids[required_index]] = 0
  }
}

/^#/ || NF == 0 {
  next
}

header == "" {
  header = $0
  if (header != expected_header) {
    fail("Unexpected token-flow policy matrix header")
  }
  next
}

{
  if (NF != 21) {
    fail("Column count mismatch for row: " $0)
  }

  case_id = $1
  fixture = $2
  flow_case = $3
  flow0_asset_state = $4
  request_network = $5
  amount_state = $6
  total_complete = $7
  total_raw = $8
  transfer_raw = $9
  move_call_raw = $10
  merge_raw = $11
  recipient0 = $12
  recipient0_raw = $13
  move_package = $14
  move_module = $15
  move_function = $16
  move_call0_raw = $17
  condition = $18
  sign_rule_valid = $19
  decision = $20
  reason = $21

  mark_required(case_id)

  if (system("test -f " fixture_dir "/" fixture ".bcs.hex") != 0) {
    fail("Missing BCS fixture for matrix row: " fixture)
  }

  if (!(flow_case == "split_to_transfer" ||
        flow_case == "split_to_move_call" ||
        flow_case == "direct_object_transfer" ||
        flow_case == "non_gas_split_transfer" ||
        flow_case == "funds_withdrawal_transfer" ||
        flow_case == "merge_known_known" ||
        flow_case == "merge_known_unknown" ||
        flow_case == "publish")) {
    fail("Invalid flow_case for " case_id ": " flow_case)
  }

  if (!valid_asset_state(flow0_asset_state)) {
    fail("Invalid flow0_asset_state for " case_id ": " flow0_asset_state)
  }

  if (!valid_request_network(request_network)) {
    fail("Invalid request_network for " case_id ": " request_network)
  }

  if (!(amount_state == "known" || amount_state == "unknown" || amount_state == "incomplete")) {
    fail("Invalid amount_state for " case_id ": " amount_state)
  }

  if (!(total_complete == "yes" || total_complete == "no")) {
    fail("Invalid sui_total_out_complete for " case_id ": " total_complete)
  }

  if (!valid_amount(total_raw) || !valid_amount(transfer_raw) ||
      !valid_amount(move_call_raw) || !valid_amount(merge_raw) ||
      !valid_amount(recipient0_raw) || !valid_amount(move_call0_raw)) {
    fail("Invalid amount field for " case_id)
  }

  if (!valid_address(recipient0) || !valid_address(move_package)) {
    fail("Invalid address field for " case_id)
  }

  if (!(sign_rule_valid == "yes" || sign_rule_valid == "no")) {
    fail("Invalid expected_sign_rule_valid for " case_id ": " sign_rule_valid)
  }

  if (!(decision == "sign" ||
        decision == "policy_rejected" ||
        decision == "invalid_policy" ||
        decision == "invalid_params")) {
    fail("Invalid expected_policy_decision for " case_id ": " decision)
  }

  if (reason == "") {
    fail("Missing required_reason for " case_id)
  }

  if (decision == "sign" && sign_rule_valid != "yes") {
    fail("Signing expectation requires a valid sign rule for " case_id)
  }

  if ((amount_state == "unknown" || amount_state == "incomplete") && decision == "sign") {
    fail("Unknown or incomplete amount must not authorize signing for " case_id)
  }

  if (flow0_asset_state != "proven_sui" && decision == "sign") {
    fail("Unproven token-flow asset must not authorize signing for " case_id)
  }

  if (condition == "missing_required_amount_field" &&
      !(sign_rule_valid == "no" && decision == "invalid_policy")) {
    fail("Missing required amount field must be invalid policy for " case_id)
  }

  if ((request_network == "missing" || request_network == "invalid") &&
      decision != "invalid_params") {
    fail("Missing or invalid request network must fail before policy for " case_id)
  }

  if (decision == "invalid_params" &&
      !(request_network == "missing" || request_network == "invalid")) {
    fail("invalid_params expectation must be tied to invalid request context for " case_id)
  }

  rows += 1
}

END {
  if (header == "") {
    fail("Token-flow policy matrix is empty")
  }
  if (rows == 0) {
    fail("Token-flow policy matrix has no rows")
  }
  for (case_id in required) {
    if (!seen[case_id]) {
      fail("Missing required token-flow policy case: " case_id)
    }
  }
}
' "${MATRIX}"

echo "Sui token-flow policy matrix test passed"
