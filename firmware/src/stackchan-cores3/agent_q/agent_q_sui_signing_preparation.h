#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_approval_history.h"
#include "agent_q_sign_personal_message_limits.h"
#include "agent_q_sign_route.h"
#include "agent_q_sign_transaction_limits.h"
#include "agent_q_user_signing_limits.h"
#include "agent_q_sui_account.h"
#include "agent_q_common/sui/agent_q_sui_sign_transaction_adapter.h"
#include "agent_q_common/sui/agent_q_sui_token_flow_facts.h"
#include "agent_q_common/sui/agent_q_sui_transaction_facts.h"

namespace agent_q {

enum class AgentQSuiSigningPreparationResult {
    ok,
    invalid_argument,
    invalid_params,
    unsupported_payload_size,
    malformed_transaction,
    unsupported_transaction,
    account_unavailable,
    invalid_account,
    digest_error,
};

struct AgentQSuiPreparedSignTransaction {
    AgentQSupportedSignRoute route;
    char network[kAgentQUserSigningNetworkSize];
    uint8_t* tx_bytes;
    size_t tx_bytes_size;
    char payload_digest[kAgentQApprovalHistoryDigestSize];
    SuiPolicySubjectFacts sui_policy_subject;
    SuiTokenFlowFacts sui_token_flow;
    SuiReviewSummary sui_review;
    bool user_mode_authorization_covered;
    bool policy_mode_authorization_covered;
    AgentQSuiUserAuthorizationOutcome user_authorization_outcome;
    AgentQSuiPolicyAuthorizationOutcome policy_authorization_outcome;
};

struct AgentQSuiPreparedPersonalMessage {
    AgentQSupportedSignRoute route;
    char network[kAgentQUserSigningNetworkSize];
    uint8_t message[kAgentQSuiSignPersonalMessageMaxBytes];
    size_t message_size;
    char payload_digest[kAgentQApprovalHistoryDigestSize];
    char account_address[kSuiAddressBufferSize];
};

AgentQSuiSigningPreparationResult prepare_sui_sign_transaction(
    AgentQSupportedSignRoute route,
    const char* network,
    const char* tx_bytes_base64,
    size_t decoded_tx_size,
    AgentQSuiPreparedSignTransaction* out);

AgentQSuiSigningPreparationResult prepare_sui_sign_transaction_from_owned_bytes(
    AgentQSupportedSignRoute route,
    const char* network,
    uint8_t* tx_bytes,
    size_t tx_bytes_size,
    const char* payload_digest,
    AgentQSuiPreparedSignTransaction* out);

AgentQSuiSigningPreparationResult prepare_sui_sign_personal_message(
    AgentQSupportedSignRoute route,
    const char* network,
    const char* message_base64,
    size_t decoded_message_size,
    AgentQSuiPreparedPersonalMessage* out);

void clear_prepared_sui_sign_transaction(AgentQSuiPreparedSignTransaction* prepared);
void clear_prepared_sui_sign_personal_message(AgentQSuiPreparedPersonalMessage* prepared);

}  // namespace agent_q
