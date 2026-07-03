#pragma once

#include <stdint.h>

#include "local_auth.h"

namespace signing {

constexpr uint32_t kLocalAuthWorkerMaxMs = 10000;

enum class LocalAuthWorkerOwner {
    provisioning_setup,
    storage_maintenance,
    local_pin_auth,
};

enum class LocalAuthWorkerOperation {
    verify_pin,
    prepare_verifier_record,
};

enum class LocalAuthWorkerStatus {
    ok,
    auth_unavailable,
    worker_unavailable,
};

struct LocalAuthWorkerResult {
    uint32_t job_id;
    LocalAuthWorkerOwner owner;
    LocalAuthWorkerOperation operation;
    LocalAuthWorkerStatus status;
    bool verified;
    LocalAuthPreparedRecord prepared_record;
};

bool local_auth_worker_init();
bool local_auth_worker_submit_verify(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id);
bool local_auth_worker_submit_prepare_verifier(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id);
bool local_auth_worker_cancel_job(uint32_t job_id);
bool local_auth_worker_poll_result(LocalAuthWorkerResult* result);
void local_auth_worker_wipe_result(LocalAuthWorkerResult* result);

}  // namespace signing
