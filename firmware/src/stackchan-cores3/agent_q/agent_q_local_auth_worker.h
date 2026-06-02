#pragma once

#include <stdint.h>

#include "agent_q_local_auth.h"

namespace agent_q {

constexpr uint32_t kAgentQLocalAuthWorkerMaxMs = 10000;

enum class AgentQLocalAuthWorkerOwner {
    provisioning_setup,
    local_reset,
    local_pin_auth,
};

enum class AgentQLocalAuthWorkerOperation {
    verify_pin,
    prepare_verifier_record,
};

enum class AgentQLocalAuthWorkerStatus {
    ok,
    auth_unavailable,
    worker_unavailable,
};

struct AgentQLocalAuthWorkerResult {
    uint32_t job_id;
    AgentQLocalAuthWorkerOwner owner;
    AgentQLocalAuthWorkerOperation operation;
    AgentQLocalAuthWorkerStatus status;
    bool verified;
    AgentQLocalAuthPreparedRecord prepared_record;
};

bool local_auth_worker_init();
bool local_auth_worker_submit_verify(
    AgentQLocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id);
bool local_auth_worker_submit_prepare_verifier(
    AgentQLocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id);
bool local_auth_worker_cancel_job(uint32_t job_id);
bool local_auth_worker_poll_result(AgentQLocalAuthWorkerResult* result);
void local_auth_worker_wipe_result(AgentQLocalAuthWorkerResult* result);

}  // namespace agent_q
