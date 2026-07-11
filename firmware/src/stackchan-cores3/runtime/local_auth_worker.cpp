#include "local_auth_worker.h"

#include <string.h>

#include "bip39.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "stackchan_keystore.h"

namespace signing {
namespace {

constexpr const char* kTag = "LocalAuthWorker";
constexpr UBaseType_t kLocalAuthWorkerPriority = 2;
constexpr uint32_t kLocalAuthWorkerStackBytes = 16 * 1024;

struct LocalAuthWorkerRequest {
    uint32_t job_id;
    LocalAuthWorkerOwner owner;
    LocalAuthWorkerOperation operation;
};

QueueHandle_t g_request_queue = nullptr;
QueueHandle_t g_result_queue = nullptr;
TaskHandle_t g_worker_task = nullptr;
bool g_job_in_flight = false;
uint32_t g_job_in_flight_id = 0;
LocalAuthWorkerOperation g_job_in_flight_operation =
    LocalAuthWorkerOperation::authenticate_pin;
uint32_t g_next_job_id = 1;
char g_pending_pin[kKeystorePinBufferBytes] = {};
char g_pending_new_pin[kKeystorePinBufferBytes] = {};
uint8_t* g_kdf_work_area = nullptr;
uint32_t g_cancelled_job_id = 0;
bool g_terminal_result_pending = false;
LocalAuthWorkerResult g_terminal_result = {};
portMUX_TYPE g_worker_state_lock = portMUX_INITIALIZER_UNLOCKED;

class WorkerStateGuard {
public:
    WorkerStateGuard()
    {
        portENTER_CRITICAL(&g_worker_state_lock);
    }

    ~WorkerStateGuard()
    {
        portEXIT_CRITICAL(&g_worker_state_lock);
    }
};

uint32_t next_job_id()
{
    const uint32_t job_id = g_next_job_id++;
    if (g_next_job_id == 0) {
        g_next_job_id = 1;
    }
    return job_id;
}

void wipe_pending_pin()
{
    wipe_sensitive_buffer(g_pending_pin, sizeof(g_pending_pin));
    wipe_sensitive_buffer(g_pending_new_pin, sizeof(g_pending_new_pin));
}

void clear_request(LocalAuthWorkerRequest* request)
{
    if (request == nullptr) {
        return;
    }
    request->job_id = 0;
    request->owner = LocalAuthWorkerOwner::provisioning_setup;
    request->operation = LocalAuthWorkerOperation::authenticate_pin;
}

void store_terminal_result(const LocalAuthWorkerResult& result)
{
    WorkerStateGuard guard;
    local_auth_worker_wipe_result(&g_terminal_result);
    g_terminal_result = result;
    g_terminal_result_pending = true;
}

bool job_cancelled_locked(uint32_t job_id)
{
    return job_id != 0 && g_cancelled_job_id == job_id;
}

void clear_cancelled_job_locked(uint32_t job_id)
{
    if (job_cancelled_locked(job_id)) {
        g_cancelled_job_id = 0;
    }
}

void clear_in_flight_job_locked(uint32_t job_id)
{
    if (job_id == 0 || g_job_in_flight_id == job_id) {
        g_job_in_flight = false;
        g_job_in_flight_id = 0;
        g_job_in_flight_operation = LocalAuthWorkerOperation::authenticate_pin;
    }
    clear_cancelled_job_locked(job_id);
}

void clear_in_flight_job(uint32_t job_id)
{
    WorkerStateGuard guard;
    clear_in_flight_job_locked(job_id);
}

bool copy_pending_request(
    const LocalAuthWorkerRequest& request,
    char pin[kKeystorePinBufferBytes],
    char new_pin[kKeystorePinBufferBytes])
{
    WorkerStateGuard guard;
    if (!g_job_in_flight || g_job_in_flight_id != request.job_id ||
        g_job_in_flight_operation != request.operation) {
        wipe_pending_pin();
        return false;
    }
    strlcpy(pin, g_pending_pin, kKeystorePinBufferBytes);
    strlcpy(new_pin, g_pending_new_pin, kKeystorePinBufferBytes);
    wipe_pending_pin();
    if (job_cancelled_locked(request.job_id)) {
        clear_in_flight_job_locked(request.job_id);
        return false;
    }
    return true;
}

bool discard_cancelled_authentication(uint32_t job_id)
{
    WorkerStateGuard guard;
    if (!job_cancelled_locked(job_id)) {
        return false;
    }
    clear_in_flight_job_locked(job_id);
    return true;
}

bool submit_request(
    LocalAuthWorkerOwner owner,
    LocalAuthWorkerOperation operation,
    const char* pin,
    const char* new_pin,
    uint32_t* job_id)
{
    if (job_id != nullptr) {
        *job_id = 0;
    }
    if (g_request_queue == nullptr || g_result_queue == nullptr || g_worker_task == nullptr ||
        !keystore_pin_valid(
            pin, kLocalAuthMinDigits, kLocalAuthMaxDigits) ||
        (operation == LocalAuthWorkerOperation::rewrap_keystore &&
         !keystore_pin_valid(
             new_pin, kLocalAuthMinDigits, kLocalAuthMaxDigits))) {
        return false;
    }

    LocalAuthWorkerRequest request = {};
    {
        WorkerStateGuard guard;
        if (g_job_in_flight) {
            return false;
        }
        wipe_pending_pin();
        strlcpy(g_pending_pin, pin, sizeof(g_pending_pin));
        if (new_pin != nullptr) {
            strlcpy(g_pending_new_pin, new_pin, sizeof(g_pending_new_pin));
        }
        request.job_id = next_job_id();
        request.owner = owner;
        request.operation = operation;
        g_job_in_flight = true;
        g_job_in_flight_id = request.job_id;
        g_job_in_flight_operation = operation;
    }
    if (xQueueSend(g_request_queue, &request, 0) != pdTRUE) {
        clear_in_flight_job(request.job_id);
        {
            WorkerStateGuard guard;
            wipe_pending_pin();
        }
        clear_request(&request);
        return false;
    }

    if (job_id != nullptr) {
        *job_id = request.job_id;
    }
    clear_request(&request);
    return true;
}

void local_auth_worker_task(void*)
{
    while (true) {
        LocalAuthWorkerRequest request = {};
        if (xQueueReceive(g_request_queue, &request, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        char pin[kKeystorePinBufferBytes] = {};
        char new_pin[kKeystorePinBufferBytes] = {};
        if (!copy_pending_request(request, pin, new_pin)) {
            wipe_sensitive_buffer(pin, sizeof(pin));
            wipe_sensitive_buffer(new_pin, sizeof(new_pin));
            clear_request(&request);
            continue;
        }

        LocalAuthWorkerResult result = {};
        result.job_id = request.job_id;
        result.owner = request.owner;
        result.operation = request.operation;
        result.status = LocalAuthWorkerStatus::worker_unavailable;
        result.operation_status = KeystoreOperationStatus::invalid_input;

        result.status = LocalAuthWorkerStatus::completed;
        if (request.operation == LocalAuthWorkerOperation::create_keystore) {
            result.operation_status = stackchan_keystore_create(
                pin, g_kdf_work_area, kStackChanKeystoreKdfWorkAreaBytes);
        } else if (request.operation == LocalAuthWorkerOperation::unlock_keystore) {
            result.operation_status = stackchan_keystore_unlock(
                pin, g_kdf_work_area, kStackChanKeystoreKdfWorkAreaBytes);
        } else if (request.operation == LocalAuthWorkerOperation::authenticate_pin) {
            result.operation_status = stackchan_keystore_authenticate_pin(
                pin, g_kdf_work_area, kStackChanKeystoreKdfWorkAreaBytes);
        } else if (request.operation == LocalAuthWorkerOperation::rewrap_keystore) {
            result.operation_status = stackchan_keystore_rewrap(
                pin,
                new_pin,
                g_kdf_work_area,
                kStackChanKeystoreKdfWorkAreaBytes);
        }

        wipe_sensitive_buffer(pin, sizeof(pin));
        wipe_sensitive_buffer(new_pin, sizeof(new_pin));
        if (discard_cancelled_authentication(request.job_id)) {
            local_auth_worker_wipe_result(&result);
            clear_request(&request);
            continue;
        }

        if (xQueueSend(g_result_queue, &result, 0) != pdTRUE) {
            ESP_LOGE(kTag, "Could not enqueue local auth worker result");
            store_terminal_result(result);
        }
        local_auth_worker_wipe_result(&result);
        clear_request(&request);
    }
}

}  // namespace

bool local_auth_worker_init()
{
    if (g_kdf_work_area == nullptr) {
        g_kdf_work_area = static_cast<uint8_t*>(heap_caps_aligned_alloc(
            kKeystoreKdfWorkAreaAlignment,
            kStackChanKeystoreKdfWorkAreaBytes,
            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
        if (g_kdf_work_area == nullptr) {
            ESP_LOGE(kTag, "Could not allocate KDF work area");
            return false;
        }
        wipe_sensitive_buffer(
            g_kdf_work_area, kStackChanKeystoreKdfWorkAreaBytes);
    }
    if (g_request_queue == nullptr) {
        g_request_queue = xQueueCreate(1, sizeof(LocalAuthWorkerRequest));
        if (g_request_queue == nullptr) {
            ESP_LOGE(kTag, "Could not create local auth worker request queue");
            return false;
        }
    }
    if (g_result_queue == nullptr) {
        g_result_queue = xQueueCreate(1, sizeof(LocalAuthWorkerResult));
        if (g_result_queue == nullptr) {
            ESP_LOGE(kTag, "Could not create local auth worker result queue");
            return false;
        }
    }
    if (g_worker_task == nullptr) {
        BaseType_t task_created = xTaskCreatePinnedToCore(
            local_auth_worker_task,
            "local_auth",
            kLocalAuthWorkerStackBytes,
            nullptr,
            kLocalAuthWorkerPriority,
            &g_worker_task,
            1);
        if (task_created != pdPASS) {
            g_worker_task = nullptr;
            ESP_LOGE(kTag, "Could not create local auth worker task");
            return false;
        }
    }
    return true;
}

bool local_auth_worker_submit_create(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id)
{
    return submit_request(
        owner, LocalAuthWorkerOperation::create_keystore, pin, nullptr, job_id);
}

bool local_auth_worker_submit_unlock(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id)
{
    return submit_request(
        owner, LocalAuthWorkerOperation::unlock_keystore, pin, nullptr, job_id);
}

bool local_auth_worker_submit_authenticate(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id)
{
    return submit_request(
        owner, LocalAuthWorkerOperation::authenticate_pin, pin, nullptr, job_id);
}

bool local_auth_worker_submit_rewrap(
    LocalAuthWorkerOwner owner,
    const char* current_pin,
    const char* new_pin,
    uint32_t* job_id)
{
    return submit_request(
        owner,
        LocalAuthWorkerOperation::rewrap_keystore,
        current_pin,
        new_pin,
        job_id);
}

bool local_auth_worker_cancel_authentication(uint32_t job_id)
{
    WorkerStateGuard guard;
    if (job_id == 0 || !g_job_in_flight || g_job_in_flight_id != job_id ||
        g_job_in_flight_operation != LocalAuthWorkerOperation::authenticate_pin) {
        return false;
    }
    wipe_pending_pin();
    g_cancelled_job_id = job_id;
    return true;
}

bool local_auth_worker_poll_result(LocalAuthWorkerResult* result)
{
    if (result == nullptr || g_result_queue == nullptr) {
        return false;
    }
    {
        WorkerStateGuard guard;
        if (g_terminal_result_pending) {
            if (job_cancelled_locked(g_terminal_result.job_id)) {
                const uint32_t cancelled_job_id = g_terminal_result.job_id;
                local_auth_worker_wipe_result(&g_terminal_result);
                g_terminal_result = {};
                g_terminal_result_pending = false;
                clear_in_flight_job_locked(cancelled_job_id);
                return false;
            }
            *result = g_terminal_result;
            const uint32_t completed_job_id = result->job_id;
            local_auth_worker_wipe_result(&g_terminal_result);
            g_terminal_result = {};
            g_terminal_result_pending = false;
            clear_in_flight_job_locked(completed_job_id);
            return true;
        }
    }
    if (xQueueReceive(g_result_queue, result, 0) != pdTRUE) {
        return false;
    }
    {
        WorkerStateGuard guard;
        if (job_cancelled_locked(result->job_id)) {
            const uint32_t cancelled_job_id = result->job_id;
            local_auth_worker_wipe_result(result);
            clear_in_flight_job_locked(cancelled_job_id);
            return false;
        }
        clear_in_flight_job_locked(result->job_id);
    }
    return true;
}

void local_auth_worker_wipe_result(LocalAuthWorkerResult* result)
{
    if (result == nullptr) {
        return;
    }
    result->job_id = 0;
    result->owner = LocalAuthWorkerOwner::provisioning_setup;
    result->operation = LocalAuthWorkerOperation::authenticate_pin;
    result->status = LocalAuthWorkerStatus::worker_unavailable;
    result->operation_status = KeystoreOperationStatus::invalid_input;
}

}  // namespace signing
