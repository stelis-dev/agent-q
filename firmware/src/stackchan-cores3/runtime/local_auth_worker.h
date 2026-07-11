#pragma once

#include <stdint.h>

#include "keystore/encrypted_keystore.h"

namespace signing {

constexpr uint32_t kLocalAuthWorkerMaxMs = 10000;

enum class LocalAuthWorkerOwner {
    provisioning_setup,
    storage_maintenance,
    local_pin_auth,
};

enum class LocalAuthWorkerOperation {
    create_keystore,
    unlock_keystore,
    authenticate_pin,
    rewrap_keystore,
};

enum class LocalAuthWorkerStatus {
    completed,
    worker_unavailable,
};

struct LocalAuthWorkerResult {
    uint32_t job_id;
    LocalAuthWorkerOwner owner;
    LocalAuthWorkerOperation operation;
    LocalAuthWorkerStatus status;
    KeystoreOperationStatus operation_status;
};

bool local_auth_worker_init();
bool local_auth_worker_submit_create(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id);
bool local_auth_worker_submit_unlock(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id);
bool local_auth_worker_submit_authenticate(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id);
bool local_auth_worker_submit_rewrap(
    LocalAuthWorkerOwner owner,
    const char* current_pin,
    const char* new_pin,
    uint32_t* job_id);
bool local_auth_worker_cancel_authentication(uint32_t job_id);
bool local_auth_worker_poll_result(LocalAuthWorkerResult* result);
void local_auth_worker_wipe_result(LocalAuthWorkerResult* result);

}  // namespace signing
