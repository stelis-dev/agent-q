#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sign_transaction_policy_runtime.sh

Compiles the StackChan CoreS3 sign_transaction policy runtime boundary with a
host C++ compiler. Policy mode evaluates the active current-schema policy
document against Firmware-derived offline facts and must not fall back to user
confirmation or blind signing.
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

for required in \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_policy_runtime.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_policy_runtime.h" \
  "${AGENT_Q_DIR}/agent_q_policy_store.h" \
  "${COMMON_ROOT}/agent_q_sign_route.h" \
  "${COMMON_ROOT}/policy/agent_q_policy_document.h" \
  "${COMMON_ROOT}/policy/agent_q_policy_evaluator.h" \
  "${COMMON_ROOT}/sui/agent_q_sui_offline_policy_facts.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

if grep -Eq 'string_eq\(condition\.field, "sui\.' \
  "${COMMON_ROOT}/policy/agent_q_policy_evaluator.cpp"; then
  echo "Policy evaluator must dispatch through current policy field descriptors" >&2
  exit 1
fi

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sign-transaction-policy-runtime.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/stubs"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once

#define ESP_LOGI(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGE(tag, format, ...) do { (void)(tag); } while (0)
H

cat >"${TMP_DIR}/sign_transaction_policy_runtime_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_policy_store.h"
#include "agent_q_sign_transaction_policy_runtime.h"
#include "agent_q_common/policy/agent_q_policy_evaluator.h"
#include "agent_q_common/sui/agent_q_sui_offline_policy_facts.h"

namespace {

constexpr const char* kPolicyHash =
    "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3";
constexpr const char* kPayloadDigest =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
constexpr const char* kSuiTypeTag =
    "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";
constexpr const char* kNonSuiTypeTag =
    "0x0000000000000000000000000000000000000000000000000000000000000123::coin::TOKEN";
constexpr const char* kSenderAddress =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr const char* kSponsorAddress =
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
constexpr const char* kOtherSponsorAddress =
    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

bool g_policy_summary_available = true;
bool g_policy_document_available = true;
int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void set_token_total(
    agent_q::SuiOfflinePolicyConditionFacts* facts,
    uint16_t index,
    const char* type_tag,
    const char* amount_raw)
{
    snprintf(facts->token_totals_by_type[index].type_tag,
             sizeof(facts->token_totals_by_type[index].type_tag),
             "%s", type_tag);
    snprintf(facts->token_totals_by_type[index].amount_raw,
             sizeof(facts->token_totals_by_type[index].amount_raw),
             "%s", amount_raw);
    if (facts->token_total_count <= index) {
        facts->token_total_count = index + 1;
    }
}

agent_q::SuiOfflinePolicyConditionFacts matching_facts()
{
    agent_q::SuiOfflinePolicyConditionFacts facts = {};
    facts.valid_transaction_data = true;
    snprintf(facts.gas_budget_raw, sizeof(facts.gas_budget_raw), "%s", "50000000");
    snprintf(facts.gas_price_raw, sizeof(facts.gas_price_raw), "%s", "1000");
    snprintf(facts.gas_owner, sizeof(facts.gas_owner), "%s", kSenderAddress);
    snprintf(facts.sender, sizeof(facts.sender), "%s", kSenderAddress);
    facts.sponsored = false;
    snprintf(facts.command_count, sizeof(facts.command_count), "%s", "2");
    facts.command_kinds.count = 2;
    snprintf(facts.command_kinds.values[0], sizeof(facts.command_kinds.values[0]), "%s", "split_coins");
    snprintf(facts.command_kinds.values[1], sizeof(facts.command_kinds.values[1]), "%s", "transfer_objects");
    set_token_total(&facts, 0, kSuiTypeTag, "1000000000");
    facts.token_source_count = 1;
    snprintf(facts.token_sources[0].type_tag, sizeof(facts.token_sources[0].type_tag),
             "%s", facts.token_totals_by_type[0].type_tag);
    facts.token_sources[0].source = agent_q::SuiOfflinePolicyTokenSourceKind::gas_coin;
    facts.token_sources[0].amount_known = true;
    facts.token_sources[0].provenance = agent_q::SuiOfflinePolicyTokenProvenance::gas_coin_split;
    snprintf(facts.token_sources[0].amount_raw, sizeof(facts.token_sources[0].amount_raw),
             "%s", "1000000000");
    facts.token_unknown_amount_present = false;
    facts.completeness = agent_q::SuiOfflinePolicyFactsCompleteness::complete;
    facts.reason = agent_q::SuiOfflinePolicyFactsReason::none;
    return facts;
}

agent_q::SuiOfflinePolicyConditionFacts sponsored_facts()
{
    agent_q::SuiOfflinePolicyConditionFacts facts = matching_facts();
    snprintf(facts.gas_owner, sizeof(facts.gas_owner), "%s", kSponsorAddress);
    facts.sponsored = true;
    return facts;
}

const agent_q::AgentQCurrentPolicyDocument& sponsored_gas_policy_document()
{
    static const char* sponsored_values[] = {"true"};
    static const char* owner_values[] = {kSponsorAddress};
    static const char* budget_values[] = {"50000000"};
    static const char* price_values[] = {"1000"};
    static const agent_q::AgentQCurrentPolicyCondition conditions[] = {
        {
            "sui.sponsored",
            agent_q::AgentQCurrentPolicyOperator::eq,
            sponsored_values,
            sizeof(sponsored_values) / sizeof(sponsored_values[0]),
            nullptr,
        },
        {
            "sui.gas_owner",
            agent_q::AgentQCurrentPolicyOperator::eq,
            owner_values,
            sizeof(owner_values) / sizeof(owner_values[0]),
            nullptr,
        },
        {
            "sui.gas_budget_raw",
            agent_q::AgentQCurrentPolicyOperator::lte,
            budget_values,
            sizeof(budget_values) / sizeof(budget_values[0]),
            nullptr,
        },
        {
            "sui.gas_price_raw",
            agent_q::AgentQCurrentPolicyOperator::eq,
            price_values,
            sizeof(price_values) / sizeof(price_values[0]),
            nullptr,
        },
    };
    static const agent_q::AgentQCurrentPolicy policies[] = {
        {
            "sponsored-gas-facts",
            agent_q::AgentQCurrentPolicyAction::sign,
            conditions,
            sizeof(conditions) / sizeof(conditions[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyNetworkScope networks[] = {
        {
            "devnet",
            policies,
            sizeof(policies) / sizeof(policies[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyBlockchainScope blockchains[] = {
        {
            "sui",
            networks,
            sizeof(networks) / sizeof(networks[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyDocument document = {
        agent_q::kAgentQCurrentPolicySchema,
        agent_q::AgentQCurrentPolicyAction::reject,
        blockchains,
        sizeof(blockchains) / sizeof(blockchains[0]),
    };
    return document;
}

const agent_q::AgentQCurrentPolicyDocument& non_sponsored_only_policy_document()
{
    static const char* sponsored_values[] = {"false"};
    static const agent_q::AgentQCurrentPolicyCondition conditions[] = {
        {
            "sui.sponsored",
            agent_q::AgentQCurrentPolicyOperator::eq,
            sponsored_values,
            sizeof(sponsored_values) / sizeof(sponsored_values[0]),
            nullptr,
        },
    };
    static const agent_q::AgentQCurrentPolicy policies[] = {
        {
            "non-sponsored-only",
            agent_q::AgentQCurrentPolicyAction::sign,
            conditions,
            sizeof(conditions) / sizeof(conditions[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyNetworkScope networks[] = {
        {
            "devnet",
            policies,
            sizeof(policies) / sizeof(policies[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyBlockchainScope blockchains[] = {
        {
            "sui",
            networks,
            sizeof(networks) / sizeof(networks[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyDocument document = {
        agent_q::kAgentQCurrentPolicySchema,
        agent_q::AgentQCurrentPolicyAction::reject,
        blockchains,
        sizeof(blockchains) / sizeof(blockchains[0]),
    };
    return document;
}

const agent_q::AgentQCurrentPolicyDocument& sui_only_amount_policy_document()
{
    static const char* amount_values[] = {"1000000000"};
    static const agent_q::AgentQCurrentPolicyCondition conditions[] = {
        {
            "sui.token_totals_by_type.amount_raw",
            agent_q::AgentQCurrentPolicyOperator::lte,
            amount_values,
            sizeof(amount_values) / sizeof(amount_values[0]),
            kSuiTypeTag,
        },
    };
    static const agent_q::AgentQCurrentPolicy policies[] = {
        {
            "sui-only-amount",
            agent_q::AgentQCurrentPolicyAction::sign,
            conditions,
            sizeof(conditions) / sizeof(conditions[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyNetworkScope networks[] = {
        {
            "devnet",
            policies,
            sizeof(policies) / sizeof(policies[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyBlockchainScope blockchains[] = {
        {
            "sui",
            networks,
            sizeof(networks) / sizeof(networks[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyDocument document = {
        agent_q::kAgentQCurrentPolicySchema,
        agent_q::AgentQCurrentPolicyAction::reject,
        blockchains,
        sizeof(blockchains) / sizeof(blockchains[0]),
    };
    return document;
}

const agent_q::AgentQCurrentPolicyDocument& two_token_amount_policy_document()
{
    static const char* sui_amount_values[] = {"1000000000"};
    static const char* non_sui_amount_values[] = {"500"};
    static const agent_q::AgentQCurrentPolicyCondition conditions[] = {
        {
            "sui.token_totals_by_type.amount_raw",
            agent_q::AgentQCurrentPolicyOperator::lte,
            sui_amount_values,
            sizeof(sui_amount_values) / sizeof(sui_amount_values[0]),
            kSuiTypeTag,
        },
        {
            "sui.token_totals_by_type.amount_raw",
            agent_q::AgentQCurrentPolicyOperator::lte,
            non_sui_amount_values,
            sizeof(non_sui_amount_values) / sizeof(non_sui_amount_values[0]),
            kNonSuiTypeTag,
        },
    };
    static const agent_q::AgentQCurrentPolicy policies[] = {
        {
            "two-token-limits",
            agent_q::AgentQCurrentPolicyAction::sign,
            conditions,
            sizeof(conditions) / sizeof(conditions[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyNetworkScope networks[] = {
        {
            "devnet",
            policies,
            sizeof(policies) / sizeof(policies[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyBlockchainScope blockchains[] = {
        {
            "sui",
            networks,
            sizeof(networks) / sizeof(networks[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyDocument document = {
        agent_q::kAgentQCurrentPolicySchema,
        agent_q::AgentQCurrentPolicyAction::reject,
        blockchains,
        sizeof(blockchains) / sizeof(blockchains[0]),
    };
    return document;
}

const agent_q::AgentQCurrentPolicyDocument& non_sui_only_amount_policy_document()
{
    static const char* amount_values[] = {"500"};
    static const agent_q::AgentQCurrentPolicyCondition conditions[] = {
        {
            "sui.token_totals_by_type.amount_raw",
            agent_q::AgentQCurrentPolicyOperator::lte,
            amount_values,
            sizeof(amount_values) / sizeof(amount_values[0]),
            kNonSuiTypeTag,
        },
    };
    static const agent_q::AgentQCurrentPolicy policies[] = {
        {
            "non-sui-only-amount",
            agent_q::AgentQCurrentPolicyAction::sign,
            conditions,
            sizeof(conditions) / sizeof(conditions[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyNetworkScope networks[] = {
        {
            "devnet",
            policies,
            sizeof(policies) / sizeof(policies[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyBlockchainScope blockchains[] = {
        {
            "sui",
            networks,
            sizeof(networks) / sizeof(networks[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyDocument document = {
        agent_q::kAgentQCurrentPolicySchema,
        agent_q::AgentQCurrentPolicyAction::reject,
        blockchains,
        sizeof(blockchains) / sizeof(blockchains[0]),
    };
    return document;
}

agent_q::AgentQSuiPreparedSignTransaction prepared_request(
    bool policy_covered,
    agent_q::SuiOfflinePolicyConditionFacts* facts,
    const char* network = "devnet",
    agent_q::AgentQSuiPolicyAuthorizationOutcome outcome =
        agent_q::AgentQSuiPolicyAuthorizationOutcome::policy_evaluation)
{
    static uint8_t tx_bytes[] = {0x01, 0x02, 0x03};
    agent_q::AgentQSuiPreparedSignTransaction prepared = {};
    prepared.route = agent_q::AgentQSupportedSignRoute::sui_sign_transaction;
    snprintf(prepared.network, sizeof(prepared.network), "%s", network);
    prepared.tx_bytes = tx_bytes;
    prepared.tx_bytes_size = sizeof(tx_bytes);
    memcpy(prepared.payload_digest, kPayloadDigest, strlen(kPayloadDigest) + 1);
    prepared.policy_mode_authorization_covered = policy_covered;
    prepared.policy_authorization_outcome = outcome;
    prepared.sui_offline_policy_facts = facts;
    return prepared;
}

}  // namespace

namespace agent_q {

bool read_active_policy_summary(AgentQStoredPolicySummary* out)
{
    if (!g_policy_summary_available || out == nullptr) {
        return false;
    }
    *out = {};
    out->schema = kAgentQCurrentPolicySchema;
    memcpy(out->policy_id, kPolicyHash, strlen(kPolicyHash) + 1);
    out->default_action = "reject";
    return true;
}

const AgentQCurrentPolicyDocument* active_policy_document()
{
    static constexpr const char* kSuiTypeTag =
        "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";
    static const char* amount_values[] = {"1000000000"};
    static const char* unknown_values[] = {"false"};
    static const AgentQCurrentPolicyCondition sign_conditions[] = {
        {
            "sui.token_totals_by_type.amount_raw",
            AgentQCurrentPolicyOperator::lte,
            amount_values,
            sizeof(amount_values) / sizeof(amount_values[0]),
            kSuiTypeTag,
        },
        {
            "sui.token_unknown_amount_present",
            AgentQCurrentPolicyOperator::eq,
            unknown_values,
            sizeof(unknown_values) / sizeof(unknown_values[0]),
            nullptr,
        },
    };
    static const AgentQCurrentPolicy policies[] = {
        {
            "sui-devnet-max-one-sui",
            AgentQCurrentPolicyAction::sign,
            sign_conditions,
            sizeof(sign_conditions) / sizeof(sign_conditions[0]),
        },
    };
    static const AgentQCurrentPolicyNetworkScope networks[] = {
        {
            "devnet",
            policies,
            sizeof(policies) / sizeof(policies[0]),
        },
    };
    static const AgentQCurrentPolicyBlockchainScope blockchains[] = {
        {
            "sui",
            networks,
            sizeof(networks) / sizeof(networks[0]),
        },
    };
    static const AgentQCurrentPolicyDocument document = {
        kAgentQCurrentPolicySchema,
        AgentQCurrentPolicyAction::reject,
        blockchains,
        sizeof(blockchains) / sizeof(blockchains[0]),
    };
    return &document;
}

bool read_active_policy_document(AgentQStoredPolicyDocument* out)
{
    if (!g_policy_document_available || out == nullptr) {
        return false;
    }
    *out = {};
    out->schema = kAgentQCurrentPolicySchema;
    memcpy(out->policy_id, kPolicyHash, strlen(kPolicyHash) + 1);
    out->default_action = "reject";
    out->blockchain_count = 1;
    out->network_count = 1;
    out->policy_count = 1;
    out->condition_count = 2;
    out->document = active_policy_document();
    return true;
}

const char* sui_offline_policy_facts_reason_name(SuiOfflinePolicyFactsReason reason)
{
    switch (reason) {
        case SuiOfflinePolicyFactsReason::none:
            return "none";
        case SuiOfflinePolicyFactsReason::direct_object_token_amount_unknown:
            return "direct_object_token_amount_unknown";
        default:
            return "policy_facts_incomplete";
    }
}

}  // namespace agent_q

int main()
{
    agent_q::SuiOfflinePolicyConditionFacts facts = matching_facts();
    agent_q::AgentQSignTransactionPolicyRuntimeResult result =
        agent_q::evaluate_sign_transaction_policy(prepared_request(false, nullptr));
    expect(result.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_rejected,
           "coverage incomplete rejects");
    expect(strcmp(result.code, "policy_rejected") == 0, "coverage incomplete code");
    expect(strcmp(result.reason_code, "policy_coverage_incomplete") == 0,
           "coverage incomplete reason");
    expect(strcmp(result.chain, "sui") == 0, "coverage incomplete chain");
    expect(strcmp(result.method, "sign_transaction") == 0, "coverage incomplete method");
    expect(strcmp(result.payload_digest, kPayloadDigest) == 0, "coverage incomplete digest");
    expect(strcmp(result.policy_hash, kPolicyHash) == 0, "coverage incomplete policy hash");

    result = agent_q::evaluate_sign_transaction_policy(prepared_request(true, &facts));
    expect(result.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_authorized,
           "matching policy authorizes");
    expect(strcmp(result.code, "policy_authorized") == 0, "authorized code");
    expect(strcmp(result.reason_code, "policy_authorized") == 0, "authorized reason");
    expect(strcmp(result.rule_ref, "sui-devnet-max-one-sui") == 0, "authorized rule ref");
    expect(result.tx_bytes != nullptr && result.tx_bytes_size == 3,
           "authorization exposes exact signable bytes");

    agent_q::SuiOfflinePolicyConditionFacts sponsored = sponsored_facts();
    result = agent_q::evaluate_sign_transaction_policy(prepared_request(true, &sponsored));
    expect(result.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_authorized,
           "sponsored facts reach policy runtime after account binding allows them");
    expect(strcmp(result.reason_code, "policy_authorized") == 0,
           "sponsored facts active policy reason");

    agent_q::AgentQCurrentPolicyEvaluationResult sponsored_evaluation =
        agent_q::evaluate_agent_q_current_policy_for_sui_sign_transaction(
            sponsored_gas_policy_document(),
            "devnet",
            sponsored);
    expect(sponsored_evaluation.status ==
               agent_q::AgentQCurrentPolicyEvaluationStatus::authorized,
           "sponsored gas owner and gas facts authorize");
    expect(strcmp(sponsored_evaluation.rule_ref, "sponsored-gas-facts") == 0,
           "sponsored gas facts rule ref");

    sponsored_evaluation =
        agent_q::evaluate_agent_q_current_policy_for_sui_sign_transaction(
            non_sponsored_only_policy_document(),
            "devnet",
            sponsored);
    expect(sponsored_evaluation.status ==
               agent_q::AgentQCurrentPolicyEvaluationStatus::no_matching_policy,
           "non-sponsored-only policy rejects sponsored facts");

    agent_q::SuiOfflinePolicyConditionFacts wrong_sponsor = sponsored;
    snprintf(wrong_sponsor.gas_owner, sizeof(wrong_sponsor.gas_owner), "%s", kOtherSponsorAddress);
    sponsored_evaluation =
        agent_q::evaluate_agent_q_current_policy_for_sui_sign_transaction(
            sponsored_gas_policy_document(),
            "devnet",
            wrong_sponsor);
    expect(sponsored_evaluation.status ==
               agent_q::AgentQCurrentPolicyEvaluationStatus::no_matching_policy,
           "sponsored gas owner condition must match the sponsor gas owner");

    agent_q::SuiOfflinePolicyConditionFacts too_large = facts;
    snprintf(too_large.token_totals_by_type[0].amount_raw, sizeof(too_large.token_totals_by_type[0].amount_raw),
             "%s", "1000000001");
    snprintf(too_large.token_sources[0].amount_raw, sizeof(too_large.token_sources[0].amount_raw),
             "%s", "1000000001");
    result = agent_q::evaluate_sign_transaction_policy(prepared_request(true, &too_large));
    expect(result.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_rejected,
           "non-matching policy rejects");
    expect(strcmp(result.reason_code, "policy_no_matching_rule") == 0,
           "non-matching policy reason");
    expect(result.tx_bytes == nullptr && result.tx_bytes_size == 0,
           "rejection does not expose signable bytes");

    agent_q::SuiOfflinePolicyConditionFacts mixed_token_facts = facts;
    set_token_total(&mixed_token_facts, 1, kNonSuiTypeTag, "999999999999");
    result = agent_q::evaluate_sign_transaction_policy(prepared_request(true, &mixed_token_facts));
    expect(result.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_authorized,
           "sui selector ignores unrelated non-sui total");

    agent_q::SuiOfflinePolicyConditionFacts two_token_facts = facts;
    set_token_total(&two_token_facts, 1, kNonSuiTypeTag, "500");
    agent_q::AgentQCurrentPolicyEvaluationResult direct_evaluation =
        agent_q::evaluate_agent_q_current_policy_for_sui_sign_transaction(
            two_token_amount_policy_document(),
            "devnet",
            two_token_facts);
    expect(direct_evaluation.status == agent_q::AgentQCurrentPolicyEvaluationStatus::authorized,
           "two token amount limits authorize independently");

    set_token_total(&two_token_facts, 1, kNonSuiTypeTag, "501");
    direct_evaluation =
        agent_q::evaluate_agent_q_current_policy_for_sui_sign_transaction(
            two_token_amount_policy_document(),
            "devnet",
            two_token_facts);
    expect(direct_evaluation.status == agent_q::AgentQCurrentPolicyEvaluationStatus::no_matching_policy,
           "non-sui selector rejects only its own excess total");

    direct_evaluation =
        agent_q::evaluate_agent_q_current_policy_for_sui_sign_transaction(
            non_sui_only_amount_policy_document(),
            "devnet",
            facts);
    expect(direct_evaluation.status == agent_q::AgentQCurrentPolicyEvaluationStatus::no_matching_policy,
           "missing selector token type is false");

    agent_q::SuiOfflinePolicyConditionFacts duplicate_sui_facts = facts;
    set_token_total(&duplicate_sui_facts, 1, kSuiTypeTag, "1");
    direct_evaluation =
        agent_q::evaluate_agent_q_current_policy_for_sui_sign_transaction(
            sui_only_amount_policy_document(),
            "devnet",
            duplicate_sui_facts);
    expect(direct_evaluation.status == agent_q::AgentQCurrentPolicyEvaluationStatus::no_matching_policy,
           "duplicate selector token type fails closed");

    agent_q::SuiOfflinePolicyConditionFacts unknown_amount_facts = facts;
    unknown_amount_facts.token_unknown_amount_present = true;
    direct_evaluation =
        agent_q::evaluate_agent_q_current_policy_for_sui_sign_transaction(
            sui_only_amount_policy_document(),
            "devnet",
            unknown_amount_facts);
    expect(direct_evaluation.status == agent_q::AgentQCurrentPolicyEvaluationStatus::no_matching_policy,
           "unknown amount fails token amount policy");

    result = agent_q::evaluate_sign_transaction_policy(prepared_request(true, &facts, "mainnet"));
    expect(result.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_rejected,
           "scope mismatch rejects");
    expect(strcmp(result.reason_code, "policy_scope_unmatched") == 0,
           "scope mismatch reason");

    agent_q::SuiOfflinePolicyConditionFacts incomplete = facts;
    incomplete.completeness = agent_q::SuiOfflinePolicyFactsCompleteness::incomplete;
    incomplete.reason = agent_q::SuiOfflinePolicyFactsReason::direct_object_token_amount_unknown;
    const agent_q::AgentQCurrentPolicyEvaluationResult incomplete_evaluation =
        agent_q::evaluate_agent_q_current_policy_for_sui_sign_transaction(
            *agent_q::active_policy_document(),
            "devnet",
            incomplete);
    expect(incomplete_evaluation.status == agent_q::AgentQCurrentPolicyEvaluationStatus::facts_incomplete,
           "direct incomplete evaluator result");
    expect(strcmp(incomplete_evaluation.reason_code, "policy_facts_incomplete") == 0,
           "direct incomplete evaluator reason");
    result = agent_q::evaluate_sign_transaction_policy(prepared_request(true, &incomplete));
    if (result.status != agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_rejected ||
        strcmp(result.reason_code, "policy_facts_incomplete") != 0) {
        fprintf(stderr,
                "incomplete runtime result: status=%d code=%s reason=%s\n",
                static_cast<int>(result.status),
                result.code != nullptr ? result.code : "",
                result.reason_code);
    }
    expect(result.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_rejected,
           "incomplete facts reject");
    expect(strcmp(result.reason_code, "policy_facts_incomplete") == 0,
           "incomplete facts reason");

    agent_q::AgentQSuiPreparedSignTransaction invalid = prepared_request(true, &facts);
    invalid.tx_bytes = nullptr;
    invalid.tx_bytes_size = 0;
    result = agent_q::evaluate_sign_transaction_policy(invalid);
    expect(result.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::invalid_params,
           "invalid prepared request rejected");

    agent_q::AgentQSuiPreparedSignTransaction unsupported = prepared_request(true, &facts);
    unsupported.route = agent_q::AgentQSupportedSignRoute::sui_sign_personal_message;
    result = agent_q::evaluate_sign_transaction_policy(unsupported);
    expect(result.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::unsupported_method,
           "unsupported route rejected");

    g_policy_summary_available = false;
    result = agent_q::evaluate_sign_transaction_policy(prepared_request(false, nullptr));
    expect(result.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_error,
           "missing active policy summary is policy error");
    g_policy_summary_available = true;

    g_policy_document_available = false;
    result = agent_q::evaluate_sign_transaction_policy(prepared_request(true, &facts));
    expect(result.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_error,
           "missing active policy document is policy error");

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("sign transaction policy runtime tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_ROOT}/policy" \
  -I"${COMMON_ROOT}/sui" \
  "${TMP_DIR}/sign_transaction_policy_runtime_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_policy_runtime.cpp" \
  "${COMMON_ROOT}/policy/agent_q_policy_document.cpp" \
  "${COMMON_ROOT}/policy/agent_q_policy_evaluator.cpp" \
  -o "${TMP_DIR}/sign_transaction_policy_runtime_test"

"${TMP_DIR}/sign_transaction_policy_runtime_test"
