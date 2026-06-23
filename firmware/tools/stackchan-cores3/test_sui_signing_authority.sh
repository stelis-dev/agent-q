#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sui_signing_authority.sh

Compiles the production Sui signing account-binding comparator with host stubs
for active identity resolution. It verifies sponsored transaction receive-path
binding without relying on the signing-preparation test's comparator stub.
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

for required in \
  "${AGENT_Q_DIR}/agent_q_sui_signing_authority.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_signing_authority.h" \
  "${AGENT_Q_DIR}/agent_q_sui_account_settings.h" \
  "${COMMON_ROOT}/sui/agent_q_sui_transaction_facts.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sui-signing-authority.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_sui_signing_authority.h"

namespace {

constexpr const char* kDeviceAddress =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr const char* kSponsorAddress =
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
constexpr const char* kOtherAddress =
    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

int failures = 0;
agent_q::AgentQSuiActiveIdentity g_active_identity = {};

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

agent_q::AgentQSuiActiveIdentity native_identity(const char* address)
{
    agent_q::AgentQSuiActiveIdentity identity = {};
    identity.kind = agent_q::AgentQSuiActiveIdentityKind::native;
    identity.error = agent_q::AgentQSuiActiveIdentityError::none;
    snprintf(identity.address, sizeof(identity.address), "%s", address);
    return identity;
}

agent_q::AgentQSuiActiveIdentity zklogin_identity(const char* address, const char* network)
{
    agent_q::AgentQSuiActiveIdentity identity = native_identity(address);
    identity.kind = agent_q::AgentQSuiActiveIdentityKind::zklogin;
    snprintf(identity.zklogin.network, sizeof(identity.zklogin.network), "%s", network);
    return identity;
}

agent_q::AgentQSuiActiveIdentity error_identity(agent_q::AgentQSuiActiveIdentityError error)
{
    agent_q::AgentQSuiActiveIdentity identity = {};
    identity.kind = agent_q::AgentQSuiActiveIdentityKind::error;
    identity.error = error;
    return identity;
}

agent_q::SuiPolicySubjectFacts facts(const char* sender, const char* gas_owner)
{
    agent_q::SuiPolicySubjectFacts out = {};
    snprintf(out.sender, sizeof(out.sender), "%s", sender);
    snprintf(out.gas_owner, sizeof(out.gas_owner), "%s", gas_owner);
    return out;
}

}  // namespace

namespace agent_q {

AgentQSuiActiveIdentity resolve_active_sui_identity()
{
    return ::g_active_identity;
}

}  // namespace agent_q

int main()
{
    using Binding = agent_q::AgentQSuiSigningAccountBindingResult;
    using Network = agent_q::AgentQSuiSigningActiveIdentityNetworkResult;

    const agent_q::AgentQSuiAccountSettings reject_sponsored = {false};
    const agent_q::AgentQSuiAccountSettings accept_sponsored = {true};
    const agent_q::AgentQSuiActiveIdentity native = native_identity(kDeviceAddress);
    const agent_q::SuiPolicySubjectFacts normal = facts(kDeviceAddress, kDeviceAddress);
    const agent_q::SuiPolicySubjectFacts sponsored = facts(kDeviceAddress, kSponsorAddress);
    const agent_q::SuiPolicySubjectFacts sponsor_role = facts(kOtherAddress, kDeviceAddress);
    const agent_q::SuiPolicySubjectFacts mismatch = facts(kOtherAddress, kSponsorAddress);

    expect(agent_q::verify_sui_signing_active_account_binding(
               normal,
               native,
               reject_sponsored) == Binding::ok,
           "normal transaction is bound");
    expect(agent_q::verify_sui_signing_active_account_binding(
               sponsored,
               native,
               reject_sponsored) == Binding::account_mismatch,
           "sponsored receive path is rejected when account setting rejects it");
    expect(agent_q::verify_sui_signing_active_account_binding(
               sponsored,
               native,
               accept_sponsored) == Binding::ok,
           "sponsored receive path is accepted when account setting accepts it");
    expect(agent_q::verify_sui_signing_active_account_binding(
               sponsor_role,
               native,
               accept_sponsored) == Binding::account_mismatch,
           "sponsor gas-owner signing role remains rejected");
    expect(agent_q::verify_sui_signing_active_account_binding(
               mismatch,
               native,
               accept_sponsored) == Binding::account_mismatch,
           "sender mismatch remains rejected");
    expect(agent_q::verify_sui_signing_active_account_binding(
               normal,
               error_identity(agent_q::AgentQSuiActiveIdentityError::native_account_unavailable),
               accept_sponsored) == Binding::account_unavailable,
           "native account unavailable maps to account_unavailable");
    expect(agent_q::verify_sui_signing_active_account_binding(
               normal,
               error_identity(agent_q::AgentQSuiActiveIdentityError::proof_storage_error),
               accept_sponsored) == Binding::active_identity_unavailable,
           "proof storage error maps to active_identity_unavailable");

    const agent_q::AgentQSuiActiveIdentity zklogin = zklogin_identity(kDeviceAddress, "devnet");
    expect(agent_q::verify_sui_signing_active_account_binding(
               sponsored,
               zklogin,
               accept_sponsored) == Binding::ok,
           "zkLogin active identity consumes the same account setting");

    g_active_identity = native;
    expect(agent_q::verify_sui_signing_active_identity_network("devnet") == Network::ok,
           "native identity accepts request network");
    g_active_identity = zklogin;
    expect(agent_q::verify_sui_signing_active_identity_network("devnet") == Network::ok,
           "zkLogin matching network is accepted");
    expect(agent_q::verify_sui_signing_active_identity_network("testnet") == Network::network_mismatch,
           "zkLogin mismatched network is rejected");
    expect(agent_q::verify_sui_signing_active_identity_network(nullptr) == Network::network_mismatch,
           "zkLogin missing network is rejected");
    g_active_identity = error_identity(agent_q::AgentQSuiActiveIdentityError::native_account_unavailable);
    expect(agent_q::verify_sui_signing_active_identity_network("devnet") == Network::account_unavailable,
           "network helper maps native account unavailable");

    if (failures != 0) {
        fprintf(stderr, "%d Sui signing authority test(s) failed\n", failures);
        return 1;
    }
    printf("Sui signing authority tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_ROOT}/sui" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_signing_authority.cpp" \
  -o "${TMP_DIR}/sui_signing_authority_test"

"${TMP_DIR}/sui_signing_authority_test"
