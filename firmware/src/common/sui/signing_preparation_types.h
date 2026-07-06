#pragma once

#include <stddef.h>
#include <stdint.h>

#include "protocol/approval_history.h"
#include "protocol/sign_route.h"
#include "sui/offline_policy_facts.h"
#include "sui/sign_transaction_adapter.h"
#include "sui/signing_limits.h"
#include "sui/transaction_facts.h"
#include "signing/user_signing_limits.h"

namespace signing {

enum class SuiSigningPreparationResult {
    ok,
    invalid_argument,
    invalid_params,
    invalid_network,
    payload_too_large,
    payload_unavailable,
    malformed_transaction,
    unsupported_transaction,
    account_unavailable,
    active_identity_unavailable,
    invalid_account,
    digest_error,
};

struct SuiPreparedSignTransaction {
    SupportedSignRoute route;
    char network[kUserSigningNetworkSize];
    uint8_t* tx_bytes;
    size_t tx_bytes_size;
    char payload_digest[kApprovalHistoryDigestSize];
    SuiPolicySubjectFacts sui_policy_subject;
    SuiOfflinePolicyConditionFacts* sui_offline_policy_facts;
    SuiReviewSummary sui_review;
    bool user_mode_authorization_covered;
    bool policy_mode_authorization_covered;
    SuiUserAuthorizationOutcome user_authorization_outcome;
    SuiPolicyAuthorizationOutcome policy_authorization_outcome;
};

struct SuiPreparedPersonalMessage {
    SupportedSignRoute route;
    char network[kUserSigningNetworkSize];
    uint8_t message[kSuiSignPersonalMessageMaxBytes];
    size_t message_size;
    char payload_digest[kApprovalHistoryDigestSize];
    char account_address[kSuiAddressStringBufferSize];
};

}  // namespace signing
