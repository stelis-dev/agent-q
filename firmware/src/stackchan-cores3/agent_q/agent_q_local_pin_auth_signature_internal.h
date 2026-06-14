#pragma once

#include <stdint.h>

#include "agent_q_local_auth_worker.h"
#include "agent_q_timeout_window.h"
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

bool local_pin_auth_begin_user_signing(
    const AgentQLocalPinAuthSignatureBinding& binding,
    TickType_t now,
    AgentQTimeoutWindow input_window);
bool local_pin_auth_user_signing_matches(
    const AgentQLocalPinAuthSignatureBinding& binding);
AgentQLocalPinAuthSignatureVerifyResult local_pin_auth_complete_user_signing_verify_job(
    const AgentQLocalAuthWorkerResult& result,
    TickType_t lockout_until);

}  // namespace agent_q
