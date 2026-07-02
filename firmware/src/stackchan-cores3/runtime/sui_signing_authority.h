#pragma once

#include "sui/transaction_facts.h"
#include "sui_account_settings.h"
#include "sui_zklogin_proof_store.h"

namespace signing {

enum class SuiSigningAccountBindingResult {
    ok,
    account_unavailable,
    active_identity_unavailable,
    account_mismatch,
};

enum class SuiSigningActiveIdentityNetworkResult {
    ok,
    account_unavailable,
    active_identity_unavailable,
    network_mismatch,
};

SuiSigningAccountBindingResult verify_sui_signing_active_account_binding(
    const SuiPolicySubjectFacts& facts,
    const SuiActiveIdentity& active_identity,
    const SuiAccountSettings& account_settings);
SuiSigningActiveIdentityNetworkResult verify_sui_signing_active_identity_network(
    const SuiActiveIdentity& active_identity,
    const char* request_network);
SuiSigningActiveIdentityNetworkResult verify_sui_signing_active_identity_network(
    const char* request_network);

}  // namespace signing
