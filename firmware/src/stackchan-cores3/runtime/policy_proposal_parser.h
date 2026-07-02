#pragma once

#include <ArduinoJson.h>

#include "policy/document.h"

namespace signing {

constexpr size_t kPolicyProposalMaxSerializedObjectBytes =
    kCurrentPolicyMaxCanonicalRecordBytes;

enum class PolicyProposalParseStatus {
    ok,
    invalid_argument,
    too_large,
    invalid_policy,
    unsupported_field,
};

struct ParsedPolicyProposal {
    CurrentPolicyCondition conditions[kCurrentPolicyMaxTotalConditions];
    const char* values[kCurrentPolicyMaxTotalConditions][kCurrentPolicyMaxConditionValues];
    CurrentPolicy policies[kCurrentPolicyMaxTotalPolicies];
    CurrentPolicyNetworkScope networks[kCurrentPolicyMaxTotalNetworks];
    CurrentPolicyBlockchainScope blockchains[kCurrentPolicyMaxBlockchains];
    CurrentPolicyDocument document;
    char string_pool[kCurrentPolicyCanonicalStringPoolBytes];
    size_t string_pool_size;
    size_t condition_count;
    size_t policy_count;
    size_t network_count;
};

PolicyProposalParseStatus parse_signing_policy_proposal(
    JsonVariantConst policy,
    ParsedPolicyProposal* out);

const char* policy_proposal_parse_status_name(
    PolicyProposalParseStatus status);

}  // namespace signing
