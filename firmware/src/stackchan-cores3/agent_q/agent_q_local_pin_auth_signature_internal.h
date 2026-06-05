#pragma once

#include <stdint.h>

#include "agent_q_local_auth_worker.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQLocalPinAuthSignatureVerifyResult {
    not_ready,
    verified,
    wrong_pin,
    locked,
    auth_unavailable,
};

struct AgentQLocalPinAuthSignatureBinding {
    uint32_t token;
};

bool local_pin_auth_begin_sign_transaction_user(
    const AgentQLocalPinAuthSignatureBinding& binding,
    TickType_t deadline);
bool local_pin_auth_sign_transaction_user_matches(
    const AgentQLocalPinAuthSignatureBinding& binding);
AgentQLocalPinAuthSignatureVerifyResult local_pin_auth_complete_sign_transaction_user_verify_job(
    const AgentQLocalAuthWorkerResult& result,
    TickType_t retry_deadline,
    TickType_t lockout_until);

}  // namespace agent_q
