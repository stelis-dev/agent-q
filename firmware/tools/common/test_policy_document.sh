#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/common/test_policy_document.sh

Compiles the current Agent-Q policy document packet with a host C++ compiler.
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
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"

for required in \
  "${COMMON_POLICY_DIR}/agent_q_policy_document.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_document.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-policy-document.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/policy_document_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "agent_q_policy_document.h"

namespace {

int failures = 0;
constexpr const char* kSuiTypeTag =
    "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

}  // namespace

int main()
{
    expect(strcmp(agent_q::kAgentQCurrentPolicySchema, "agentq.policy") == 0, "current schema name");
    expect(agent_q::kAgentQCurrentPolicyFieldDescriptorCount == 18, "current field descriptor count");
    bool saw_token_total_amount = false;
    for (size_t index = 0; index < agent_q::kAgentQCurrentPolicyFieldDescriptorCount; ++index) {
        const agent_q::AgentQCurrentPolicyFieldDescriptor& descriptor =
            agent_q::kAgentQCurrentPolicyFieldDescriptors[index];
        if (strcmp(descriptor.field, "sui.token_totals_by_type.amount_raw") == 0) {
            saw_token_total_amount = true;
            expect(descriptor.where_type_requirement ==
                       agent_q::AgentQCurrentPolicyWhereTypeRequirement::required,
                   "token total amount descriptor requires where.type");
            expect(descriptor.evaluation_kind ==
                       agent_q::AgentQCurrentPolicyEvaluationKind::sui_token_totals_by_type_amount_raw,
                   "token total amount descriptor owns evaluator semantic");
        } else {
            expect(descriptor.where_type_requirement ==
                       agent_q::AgentQCurrentPolicyWhereTypeRequirement::forbidden,
                   "non-selector descriptor forbids where.type");
        }
    }
    expect(saw_token_total_amount, "token total amount descriptor exists");

    static const agent_q::AgentQCurrentPolicyNetworkScope networks[] = {
        {
            "testnet",
            nullptr,
            0,
        },
    };
    static const agent_q::AgentQCurrentPolicyBlockchainScope blockchains[] = {
        {
            "sui",
            networks,
            sizeof(networks) / sizeof(networks[0]),
        },
    };
    const agent_q::AgentQCurrentPolicyDocument document = {
        agent_q::kAgentQCurrentPolicySchema,
        agent_q::AgentQCurrentPolicyAction::reject,
        blockchains,
        sizeof(blockchains) / sizeof(blockchains[0]),
    };

    expect(document.default_action == agent_q::AgentQCurrentPolicyAction::reject, "default reject");
    expect(document.blockchain_count == 1, "one blockchain scope");
    expect(strcmp(document.blockchains[0].blockchain, "sui") == 0, "sui blockchain scope");
    expect(document.blockchains[0].network_count == 1, "one network scope");
    expect(strcmp(document.blockchains[0].networks[0].network, "testnet") == 0, "testnet network scope");
    expect(document.blockchains[0].networks[0].policy_count == 0, "no policy entries");
    expect(
        agent_q::validate_agent_q_current_policy_document(document) ==
            agent_q::AgentQCurrentPolicyDocumentStatus::ok,
        "scoped empty document validates");

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
            "sui-testnet-max-one-sui",
            agent_q::AgentQCurrentPolicyAction::sign,
            conditions,
            sizeof(conditions) / sizeof(conditions[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyNetworkScope non_empty_networks[] = {
        {
            "testnet",
            policies,
            sizeof(policies) / sizeof(policies[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyBlockchainScope non_empty_blockchains[] = {
        {
            "sui",
            non_empty_networks,
            sizeof(non_empty_networks) / sizeof(non_empty_networks[0]),
        },
    };
    const agent_q::AgentQCurrentPolicyDocument non_empty_document = {
        agent_q::kAgentQCurrentPolicySchema,
        agent_q::AgentQCurrentPolicyAction::reject,
        non_empty_blockchains,
        sizeof(non_empty_blockchains) / sizeof(non_empty_blockchains[0]),
    };
    expect(
        agent_q::validate_agent_q_current_policy_document(non_empty_document) ==
            agent_q::AgentQCurrentPolicyDocumentStatus::ok,
        "non-empty current policy document validates");

    agent_q::AgentQCurrentPolicyCanonicalDocument* canonical =
        static_cast<agent_q::AgentQCurrentPolicyCanonicalDocument*>(
            calloc(1, sizeof(agent_q::AgentQCurrentPolicyCanonicalDocument)));
    agent_q::AgentQCurrentPolicyCanonicalDocument* decoded =
        static_cast<agent_q::AgentQCurrentPolicyCanonicalDocument*>(
            calloc(1, sizeof(agent_q::AgentQCurrentPolicyCanonicalDocument)));
    agent_q::AgentQCurrentPolicyRuntimeView* runtime =
        static_cast<agent_q::AgentQCurrentPolicyRuntimeView*>(
            calloc(1, sizeof(agent_q::AgentQCurrentPolicyRuntimeView)));
    expect(canonical != nullptr && decoded != nullptr && runtime != nullptr, "large policy workspaces allocate");
    if (canonical == nullptr || decoded == nullptr || runtime == nullptr) {
        free(canonical);
        free(decoded);
        free(runtime);
        return 1;
    }
    expect(
        agent_q::canonicalize_agent_q_current_policy_document(document, canonical) ==
            agent_q::AgentQCurrentPolicyDocumentStatus::ok,
        "document canonicalizes");
    expect(canonical->blockchain_count == 1, "canonical blockchain count");
    expect(canonical->total_network_count == 1, "canonical network count");
    expect(canonical->total_policy_count == 0, "canonical policy count");
    expect(canonical->total_condition_count == 0, "canonical condition count");

    uint8_t record[agent_q::kAgentQCurrentPolicyMaxCanonicalRecordBytes] = {};
    size_t record_size = 0;
    expect(
            agent_q::encode_agent_q_current_policy_canonical_record(
            *canonical,
            record,
            sizeof(record),
            &record_size) == agent_q::AgentQCurrentPolicyDocumentStatus::ok,
        "canonical record encodes");
    expect(record_size > agent_q::kAgentQCurrentPolicyDefaultCanonicalRecordBytes, "scoped record has body");

    expect(
        agent_q::decode_agent_q_current_policy_canonical_record(record, record_size, decoded) ==
            agent_q::AgentQCurrentPolicyDocumentStatus::ok,
        "canonical record decodes");
    expect(decoded->blockchain_count == 1, "decoded blockchain count");
    expect(decoded->total_network_count == 1, "decoded network count");
    expect(decoded->total_policy_count == 0, "decoded policy count");
    expect(decoded->total_condition_count == 0, "decoded condition count");

    const bool runtime_ok =
        agent_q::agent_q_current_policy_canonical_to_runtime_view(*decoded, runtime);
    expect(runtime_ok, "decoded canonical converts to runtime view");
    if (runtime_ok) {
        expect(runtime->document.blockchain_count == 1, "runtime document blockchain count");
        expect(strcmp(runtime->document.blockchains[0].blockchain, "sui") == 0, "runtime blockchain");
        expect(strcmp(runtime->document.blockchains[0].networks[0].network, "testnet") == 0, "runtime network");
        expect(runtime->document.blockchains[0].networks[0].policy_count == 0, "runtime has no policy entries");
    }

    expect(
        agent_q::canonicalize_agent_q_current_policy_document(non_empty_document, canonical) ==
            agent_q::AgentQCurrentPolicyDocumentStatus::ok,
        "non-empty document canonicalizes");
    expect(canonical->total_policy_count == 1, "non-empty canonical policy count");
    expect(canonical->total_condition_count == 1, "non-empty canonical condition count");
    memset(record, 0, sizeof(record));
    record_size = 0;
    expect(
        agent_q::encode_agent_q_current_policy_canonical_record(
            *canonical,
            record,
            sizeof(record),
            &record_size) == agent_q::AgentQCurrentPolicyDocumentStatus::ok,
        "non-empty canonical record encodes");
    expect(
        agent_q::decode_agent_q_current_policy_canonical_record(record, record_size, decoded) ==
            agent_q::AgentQCurrentPolicyDocumentStatus::ok,
        "non-empty canonical record decodes");
    expect(decoded->total_policy_count == 1, "decoded non-empty policy count");
    expect(decoded->total_condition_count == 1, "decoded non-empty condition count");
    expect(
        agent_q::agent_q_current_policy_canonical_to_runtime_view(*decoded, runtime),
        "decoded non-empty canonical converts to runtime view");
    expect(runtime->document.blockchains[0].networks[0].policy_count == 1,
           "runtime has one policy entry");
    expect(strcmp(runtime->document.blockchains[0].networks[0].policies[0].id,
                  "sui-testnet-max-one-sui") == 0,
           "runtime policy id preserved");
    expect(runtime->document.blockchains[0].networks[0].policies[0].action ==
               agent_q::AgentQCurrentPolicyAction::sign,
           "runtime policy action preserved");
    expect(runtime->document.blockchains[0].networks[0].policies[0].condition_count == 1,
           "runtime policy condition count preserved");
    expect(strcmp(runtime->document.blockchains[0].networks[0].policies[0].conditions[0].field,
                  "sui.token_totals_by_type.amount_raw") == 0,
           "runtime condition field preserved");
    expect(runtime->document.blockchains[0].networks[0].policies[0].conditions[0].op ==
               agent_q::AgentQCurrentPolicyOperator::lte,
           "runtime condition op preserved");
    expect(strcmp(runtime->document.blockchains[0].networks[0].policies[0].conditions[0].values[0],
                  "1000000000") == 0,
           "runtime condition value preserved");
    expect(strcmp(runtime->document.blockchains[0].networks[0].policies[0].conditions[0].where_type,
                  kSuiTypeTag) == 0,
           "runtime condition selector preserved");
    canonical->blockchains[0].networks[0].policies[0].conditions[0].has_where_type = false;
    expect(
        agent_q::validate_agent_q_current_policy_canonical_document(*canonical) ==
            agent_q::AgentQCurrentPolicyDocumentStatus::invalid_policy,
        "canonical token total amount condition requires selector");

    static const agent_q::AgentQCurrentPolicyCondition missing_selector_conditions[] = {
        {
            "sui.token_totals_by_type.amount_raw",
            agent_q::AgentQCurrentPolicyOperator::lte,
            amount_values,
            sizeof(amount_values) / sizeof(amount_values[0]),
            nullptr,
        },
    };
    static const agent_q::AgentQCurrentPolicy missing_selector_policies[] = {
        {
            "missing-selector",
            agent_q::AgentQCurrentPolicyAction::sign,
            missing_selector_conditions,
            sizeof(missing_selector_conditions) / sizeof(missing_selector_conditions[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyNetworkScope missing_selector_networks[] = {
        {
            "testnet",
            missing_selector_policies,
            sizeof(missing_selector_policies) / sizeof(missing_selector_policies[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyBlockchainScope missing_selector_blockchains[] = {
        {
            "sui",
            missing_selector_networks,
            sizeof(missing_selector_networks) / sizeof(missing_selector_networks[0]),
        },
    };
    const agent_q::AgentQCurrentPolicyDocument missing_selector_document = {
        agent_q::kAgentQCurrentPolicySchema,
        agent_q::AgentQCurrentPolicyAction::reject,
        missing_selector_blockchains,
        sizeof(missing_selector_blockchains) / sizeof(missing_selector_blockchains[0]),
    };
    expect(
        agent_q::validate_agent_q_current_policy_document(missing_selector_document) ==
            agent_q::AgentQCurrentPolicyDocumentStatus::invalid_policy,
        "token total amount condition requires selector");

    static const agent_q::AgentQCurrentPolicyCondition forbidden_selector_conditions[] = {
        {
            "sui.gas_budget_raw",
            agent_q::AgentQCurrentPolicyOperator::lte,
            amount_values,
            sizeof(amount_values) / sizeof(amount_values[0]),
            kSuiTypeTag,
        },
    };
    static const agent_q::AgentQCurrentPolicy forbidden_selector_policies[] = {
        {
            "forbidden-selector",
            agent_q::AgentQCurrentPolicyAction::reject,
            forbidden_selector_conditions,
            sizeof(forbidden_selector_conditions) / sizeof(forbidden_selector_conditions[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyNetworkScope forbidden_selector_networks[] = {
        {
            "testnet",
            forbidden_selector_policies,
            sizeof(forbidden_selector_policies) / sizeof(forbidden_selector_policies[0]),
        },
    };
    static const agent_q::AgentQCurrentPolicyBlockchainScope forbidden_selector_blockchains[] = {
        {
            "sui",
            forbidden_selector_networks,
            sizeof(forbidden_selector_networks) / sizeof(forbidden_selector_networks[0]),
        },
    };
    const agent_q::AgentQCurrentPolicyDocument forbidden_selector_document = {
        agent_q::kAgentQCurrentPolicySchema,
        agent_q::AgentQCurrentPolicyAction::reject,
        forbidden_selector_blockchains,
        sizeof(forbidden_selector_blockchains) / sizeof(forbidden_selector_blockchains[0]),
    };
    expect(
        agent_q::validate_agent_q_current_policy_document(forbidden_selector_document) ==
            agent_q::AgentQCurrentPolicyDocumentStatus::invalid_policy,
        "scalar condition rejects selector");

    free(canonical);
    free(decoded);
    free(runtime);

    if (failures != 0) {
        return 1;
    }
    printf("policy document packet test passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_POLICY_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/policy_document_test.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_document.cpp" \
  -o "${TMP_DIR}/policy_document_test"

"${TMP_DIR}/policy_document_test"
