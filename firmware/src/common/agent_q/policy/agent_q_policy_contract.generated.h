#pragma once

// Generated from specs/sui-sign-transaction-policy-contract.tsv.
// Do not edit by hand. Run npm run generate:sui-policy-contract.

static_assert(
    kAgentQPolicyCommonFieldDescriptorCount == 3,
    "Common policy field descriptor count must match the shared policy contract");

const AgentQPolicyFieldDescriptor
    kAgentQPolicyCommonFieldDescriptors[kAgentQPolicyCommonFieldDescriptorCount] = {
    {"common.chain", AgentQPolicyValueType::string, true, true, false},
    {"common.method", AgentQPolicyValueType::string, true, true, false},
    {"common.intent", AgentQPolicyValueType::string, true, true, false},
    };
