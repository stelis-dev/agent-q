#pragma once

#include <stdint.h>

#include "keystore/encrypted_keystore.h"

namespace stopwatch_target {

constexpr uint32_t kLocalAuthWorkerMaxMs = 10000;

enum class LocalAuthWorkerOperation {
    create_keystore,
    unlock_keystore,
    authenticate_pin,
};

enum class LocalAuthWorkerStatus {
    completed,
    cancelled,
    unavailable,
};

struct LocalAuthWorkerResult {
    uint32_t job_id;
    LocalAuthWorkerOperation operation;
    LocalAuthWorkerStatus status;
    signing::KeystoreOperationStatus operation_status;
};

bool local_auth_worker_init();
bool local_auth_worker_submit(
    LocalAuthWorkerOperation operation,
    const char* pin,
    uint32_t* job_id);
bool local_auth_worker_cancel(uint32_t job_id);
bool local_auth_worker_poll_result(LocalAuthWorkerResult* result);
void local_auth_worker_wipe_result(LocalAuthWorkerResult* result);

}  // namespace stopwatch_target
