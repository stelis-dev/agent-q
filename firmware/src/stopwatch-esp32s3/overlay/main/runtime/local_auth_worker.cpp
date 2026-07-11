#include "local_auth_worker.h"

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "sensitive_memory.h"
#include "stopwatch_keystore.h"

namespace stopwatch_target {
namespace {

constexpr const char* kTag = "StopWatchAuthWorker";
constexpr UBaseType_t kWorkerPriority = 2;
constexpr uint32_t kWorkerStackBytes = 16 * 1024;

struct LocalAuthWorkerRequest {
    uint32_t job_id;
    LocalAuthWorkerOperation operation;
};

QueueHandle_t g_request_queue = nullptr;
QueueHandle_t g_result_queue = nullptr;
TaskHandle_t g_worker_task = nullptr;
uint8_t* g_kdf_work_area = nullptr;
bool g_job_in_flight = false;
uint32_t g_job_in_flight_id = 0;
LocalAuthWorkerOperation g_job_in_flight_operation =
    LocalAuthWorkerOperation::authenticate_pin;
uint32_t g_next_job_id = 1;
uint32_t g_cancelled_job_id = 0;
char g_pending_pin[signing::kKeystorePinBufferBytes] = {};
bool g_terminal_result_pending = false;
LocalAuthWorkerResult g_terminal_result = {};
portMUX_TYPE g_state_lock = portMUX_INITIALIZER_UNLOCKED;

class WorkerStateGuard {
public:
    WorkerStateGuard() { portENTER_CRITICAL(&g_state_lock); }
    ~WorkerStateGuard() { portEXIT_CRITICAL(&g_state_lock); }
};

uint32_t next_job_id()
{
    const uint32_t job_id = g_next_job_id++;
    if (g_next_job_id == 0) {
        g_next_job_id = 1;
    }
    return job_id;
}

void clear_in_flight_locked(uint32_t job_id)
{
    if (job_id == 0 || g_job_in_flight_id == job_id) {
        g_job_in_flight = false;
        g_job_in_flight_id = 0;
        g_job_in_flight_operation = LocalAuthWorkerOperation::authenticate_pin;
    }
    if (g_cancelled_job_id == job_id) {
        g_cancelled_job_id = 0;
    }
}

bool copy_pending_pin(
    const LocalAuthWorkerRequest& request,
    char pin[signing::kKeystorePinBufferBytes],
    bool* cancelled)
{
    WorkerStateGuard guard;
    if (cancelled != nullptr) {
        *cancelled = false;
    }
    if (!g_job_in_flight || g_job_in_flight_id != request.job_id ||
        g_job_in_flight_operation != request.operation) {
        wipe_sensitive_buffer(g_pending_pin, sizeof(g_pending_pin));
        return false;
    }
    strlcpy(pin, g_pending_pin, signing::kKeystorePinBufferBytes);
    wipe_sensitive_buffer(g_pending_pin, sizeof(g_pending_pin));
    if (cancelled != nullptr) {
        *cancelled = g_cancelled_job_id == request.job_id;
    }
    return true;
}

bool job_cancelled(uint32_t job_id)
{
    WorkerStateGuard guard;
    return job_id != 0 && g_cancelled_job_id == job_id;
}

void store_terminal_result(const LocalAuthWorkerResult& result)
{
    WorkerStateGuard guard;
    local_auth_worker_wipe_result(&g_terminal_result);
    g_terminal_result = result;
    g_terminal_result_pending = true;
}

void cleanup_cancelled_operation(LocalAuthWorkerOperation operation)
{
    if (operation == LocalAuthWorkerOperation::create_keystore) {
        stopwatch_keystore_erase();
        return;
    }
    stopwatch_keystore_lock();
}

void worker_task(void*)
{
    while (true) {
        LocalAuthWorkerRequest request = {};
        if (xQueueReceive(g_request_queue, &request, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        char pin[signing::kKeystorePinBufferBytes] = {};
        bool cancelled_before_start = false;
        if (!copy_pending_pin(request, pin, &cancelled_before_start)) {
            wipe_sensitive_buffer(pin, sizeof(pin));
            continue;
        }

        LocalAuthWorkerResult result{
            request.job_id,
            request.operation,
            LocalAuthWorkerStatus::completed,
            signing::KeystoreOperationStatus::invalid_input,
        };
        if (!cancelled_before_start) {
            switch (request.operation) {
                case LocalAuthWorkerOperation::create_keystore:
                    result.operation_status = stopwatch_keystore_create(
                        pin,
                        g_kdf_work_area,
                        kStopWatchKeystoreKdfWorkAreaBytes);
                    break;
                case LocalAuthWorkerOperation::unlock_keystore:
                    result.operation_status = stopwatch_keystore_unlock(
                        pin,
                        g_kdf_work_area,
                        kStopWatchKeystoreKdfWorkAreaBytes);
                    break;
                case LocalAuthWorkerOperation::authenticate_pin:
                    result.operation_status = stopwatch_keystore_authenticate_pin(
                        pin,
                        g_kdf_work_area,
                        kStopWatchKeystoreKdfWorkAreaBytes);
                    break;
            }
        }
        wipe_sensitive_buffer(pin, sizeof(pin));

        if (cancelled_before_start || job_cancelled(request.job_id)) {
            cleanup_cancelled_operation(request.operation);
            result.status = LocalAuthWorkerStatus::cancelled;
            result.operation_status = signing::KeystoreOperationStatus::locked;
        }

        {
            WorkerStateGuard guard;
            clear_in_flight_locked(request.job_id);
        }
        if (xQueueSend(g_result_queue, &result, 0) != pdTRUE) {
            ESP_LOGE(kTag, "Could not enqueue authentication result");
            store_terminal_result(result);
        }
        local_auth_worker_wipe_result(&result);
    }
}

}  // namespace

bool local_auth_worker_init()
{
    if (g_kdf_work_area == nullptr) {
        g_kdf_work_area = static_cast<uint8_t*>(heap_caps_aligned_alloc(
            signing::kKeystoreKdfWorkAreaAlignment,
            kStopWatchKeystoreKdfWorkAreaBytes,
            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
        if (g_kdf_work_area == nullptr) {
            ESP_LOGE(kTag, "Could not allocate KDF work area");
            return false;
        }
        wipe_sensitive_buffer(
            g_kdf_work_area,
            kStopWatchKeystoreKdfWorkAreaBytes);
    }
    if (g_request_queue == nullptr) {
        g_request_queue = xQueueCreate(1, sizeof(LocalAuthWorkerRequest));
        if (g_request_queue == nullptr) {
            ESP_LOGE(kTag, "Could not create request queue");
            return false;
        }
    }
    if (g_result_queue == nullptr) {
        g_result_queue = xQueueCreate(1, sizeof(LocalAuthWorkerResult));
        if (g_result_queue == nullptr) {
            ESP_LOGE(kTag, "Could not create result queue");
            return false;
        }
    }
    if (g_worker_task == nullptr) {
        if (xTaskCreatePinnedToCore(
                worker_task,
                "stopwatch_auth",
                kWorkerStackBytes,
                nullptr,
                kWorkerPriority,
                &g_worker_task,
                1) != pdPASS) {
            g_worker_task = nullptr;
            ESP_LOGE(kTag, "Could not create authentication worker");
            return false;
        }
    }
    return true;
}

bool local_auth_worker_submit(
    LocalAuthWorkerOperation operation,
    const char* pin,
    uint32_t* job_id)
{
    if (job_id != nullptr) {
        *job_id = 0;
    }
    if (g_request_queue == nullptr || g_result_queue == nullptr ||
        g_worker_task == nullptr ||
        !signing::keystore_pin_valid(
            pin, kLocalAuthMinDigits, kLocalAuthMaxDigits)) {
        return false;
    }

    LocalAuthWorkerRequest request = {};
    {
        WorkerStateGuard guard;
        if (g_job_in_flight) {
            return false;
        }
        wipe_sensitive_buffer(g_pending_pin, sizeof(g_pending_pin));
        strlcpy(g_pending_pin, pin, sizeof(g_pending_pin));
        request.job_id = next_job_id();
        request.operation = operation;
        g_job_in_flight = true;
        g_job_in_flight_id = request.job_id;
        g_job_in_flight_operation = operation;
        g_cancelled_job_id = 0;
    }
    if (xQueueSend(g_request_queue, &request, 0) != pdTRUE) {
        WorkerStateGuard guard;
        clear_in_flight_locked(request.job_id);
        wipe_sensitive_buffer(g_pending_pin, sizeof(g_pending_pin));
        return false;
    }
    if (job_id != nullptr) {
        *job_id = request.job_id;
    }
    return true;
}

bool local_auth_worker_cancel(uint32_t job_id)
{
    WorkerStateGuard guard;
    if (!g_job_in_flight || job_id == 0 || g_job_in_flight_id != job_id) {
        return false;
    }
    wipe_sensitive_buffer(g_pending_pin, sizeof(g_pending_pin));
    g_cancelled_job_id = job_id;
    return true;
}

bool local_auth_worker_poll_result(LocalAuthWorkerResult* result)
{
    if (result == nullptr) {
        return false;
    }
    local_auth_worker_wipe_result(result);
    {
        WorkerStateGuard guard;
        if (g_terminal_result_pending) {
            *result = g_terminal_result;
            local_auth_worker_wipe_result(&g_terminal_result);
            g_terminal_result_pending = false;
            return true;
        }
    }
    return g_result_queue != nullptr &&
        xQueueReceive(g_result_queue, result, 0) == pdTRUE;
}

void local_auth_worker_wipe_result(LocalAuthWorkerResult* result)
{
    if (result == nullptr) {
        return;
    }
    memset(result, 0, sizeof(*result));
    result->operation = LocalAuthWorkerOperation::authenticate_pin;
    result->status = LocalAuthWorkerStatus::unavailable;
    result->operation_status = signing::KeystoreOperationStatus::invalid_input;
}

}  // namespace stopwatch_target
