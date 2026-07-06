#pragma once

#include <stddef.h>
#include <stdint.h>

#include "protocol/approval_history.h"
#include "sui/signing_limits.h"
#include "protocol/sign_route.h"
#include "user_signing_limits.h"
#include "sui_account.h"
#include "sui/offline_policy_facts.h"
#include "sui/sign_transaction_adapter.h"
#include "sui/transaction_facts.h"

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
    char account_address[kSuiAddressBufferSize];
};

SuiSigningPreparationResult prepare_sui_sign_transaction(
    SupportedSignRoute route,
    const char* network,
    const char* tx_bytes_base64,
    size_t decoded_tx_size,
    SuiPreparedSignTransaction* out);

SuiSigningPreparationResult prepare_sui_sign_personal_message(
    SupportedSignRoute route,
    const char* network,
    const char* message_base64,
    size_t decoded_message_size,
    SuiPreparedPersonalMessage* out);

void clear_prepared_sui_sign_transaction(SuiPreparedSignTransaction* prepared);
void clear_prepared_sui_sign_personal_message(SuiPreparedPersonalMessage* prepared);

}  // namespace signing
