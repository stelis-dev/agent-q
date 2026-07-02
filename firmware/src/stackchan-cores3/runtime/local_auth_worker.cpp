#include "local_auth_worker.h"

#include <string.h>

#include "bip39.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

namespace signing {
namespace {

constexpr const char* kTag = "LocalAuthWorker";
constexpr UBaseType_t kLocalAuthWorkerPriority = 2;
constexpr uint32_t kLocalAuthWorkerStackWords = 4096;

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
uint32_t g_next_job_id = 1;
char g_pending_pin[kLocalPinBufferSize] = {};
uint32_t g_cancelled_job_id = 0;
bool g_terminal_failure_pending = false;
LocalAuthWorkerResult g_terminal_failure_result = {};

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
}

void clear_request(LocalAuthWorkerRequest* request)
{
    if (request == nullptr) {
        return;
    }
    request->job_id = 0;
    request->owner = LocalAuthWorkerOwner::provisioning_setup;
    request->operation = LocalAuthWorkerOperation::verify_pin;
}

void store_terminal_failure_result(const LocalAuthWorkerRequest& request)
{
    local_auth_worker_wipe_result(&g_terminal_failure_result);
    g_terminal_failure_result = {};
    g_terminal_failure_result.job_id = request.job_id;
    g_terminal_failure_result.owner = request.owner;
    g_terminal_failure_result.operation = request.operation;
    g_terminal_failure_result.status = LocalAuthWorkerStatus::worker_unavailable;
    g_terminal_failure_pending = true;
}

bool job_cancelled(uint32_t job_id)
{
    return job_id != 0 && g_cancelled_job_id == job_id;
}

void clear_cancelled_job(uint32_t job_id)
{
    if (job_cancelled(job_id)) {
        g_cancelled_job_id = 0;
    }
}

void clear_in_flight_job(uint32_t job_id)
{
    if (job_id == 0 || g_job_in_flight_id == job_id) {
        g_job_in_flight = false;
        g_job_in_flight_id = 0;
    }
    clear_cancelled_job(job_id);
}

bool submit_request(
    LocalAuthWorkerOwner owner,
    LocalAuthWorkerOperation operation,
    const char* pin,
    uint32_t* job_id)
{
    if (job_id != nullptr) {
        *job_id = 0;
    }
    if (g_request_queue == nullptr || g_result_queue == nullptr || g_worker_task == nullptr ||
        g_job_in_flight || !is_valid_local_pin(pin)) {
        return false;
    }

    wipe_pending_pin();
    strlcpy(g_pending_pin, pin, sizeof(g_pending_pin));

    LocalAuthWorkerRequest request = {};
    request.job_id = next_job_id();
    request.owner = owner;
    request.operation = operation;

    g_job_in_flight = true;
    g_job_in_flight_id = request.job_id;
    if (xQueueSend(g_request_queue, &request, 0) != pdTRUE) {
        clear_in_flight_job(request.job_id);
        wipe_pending_pin();
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

        char pin[kLocalPinBufferSize] = {};
        strlcpy(pin, g_pending_pin, sizeof(pin));
        wipe_pending_pin();

        if (job_cancelled(request.job_id)) {
            wipe_sensitive_buffer(pin, sizeof(pin));
            clear_in_flight_job(request.job_id);
            clear_request(&request);
            continue;
        }

        LocalAuthWorkerResult result = {};
        result.job_id = request.job_id;
        result.owner = request.owner;
        result.operation = request.operation;
        result.status = LocalAuthWorkerStatus::worker_unavailable;

        if (request.operation == LocalAuthWorkerOperation::verify_pin) {
            bool verified = false;
            if (verify_local_pin(pin, &verified)) {
                result.status = LocalAuthWorkerStatus::ok;
                result.verified = verified;
            } else {
                result.status = LocalAuthWorkerStatus::auth_unavailable;
            }
        } else if (request.operation == LocalAuthWorkerOperation::prepare_verifier_record) {
            if (prepare_local_pin_verifier_record(pin, &result.prepared_record)) {
                result.status = LocalAuthWorkerStatus::ok;
            } else {
                result.status = LocalAuthWorkerStatus::auth_unavailable;
            }
        }

        wipe_sensitive_buffer(pin, sizeof(pin));
        if (job_cancelled(request.job_id)) {
            local_auth_worker_wipe_result(&result);
            clear_in_flight_job(request.job_id);
            clear_request(&request);
            continue;
        }

        if (xQueueSend(g_result_queue, &result, 0) != pdTRUE) {
            ESP_LOGE(kTag, "Could not enqueue local auth worker result");
            store_terminal_failure_result(request);
        }
        local_auth_worker_wipe_result(&result);
        clear_request(&request);
    }
}

}  // namespace

bool local_auth_worker_init()
{
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
            kLocalAuthWorkerStackWords,
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

bool local_auth_worker_submit_verify(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id)
{
    return submit_request(owner, LocalAuthWorkerOperation::verify_pin, pin, job_id);
}

bool local_auth_worker_submit_prepare_verifier(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id)
{
    return submit_request(owner, LocalAuthWorkerOperation::prepare_verifier_record, pin, job_id);
}

bool local_auth_worker_cancel_job(uint32_t job_id)
{
    if (job_id == 0 || !g_job_in_flight || g_job_in_flight_id != job_id) {
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
    if (g_terminal_failure_pending) {
        if (job_cancelled(g_terminal_failure_result.job_id)) {
            const uint32_t cancelled_job_id = g_terminal_failure_result.job_id;
            local_auth_worker_wipe_result(&g_terminal_failure_result);
            g_terminal_failure_result = {};
            g_terminal_failure_pending = false;
            clear_in_flight_job(cancelled_job_id);
            return false;
        }
        *result = g_terminal_failure_result;
        const uint32_t completed_job_id = result->job_id;
        local_auth_worker_wipe_result(&g_terminal_failure_result);
        g_terminal_failure_result = {};
        g_terminal_failure_pending = false;
        clear_in_flight_job(completed_job_id);
        return true;
    }
    if (xQueueReceive(g_result_queue, result, 0) != pdTRUE) {
        return false;
    }
    if (job_cancelled(result->job_id)) {
        const uint32_t cancelled_job_id = result->job_id;
        local_auth_worker_wipe_result(result);
        clear_in_flight_job(cancelled_job_id);
        return false;
    }
    clear_in_flight_job(result->job_id);
    return true;
}

void local_auth_worker_wipe_result(LocalAuthWorkerResult* result)
{
    if (result == nullptr) {
        return;
    }
    wipe_local_pin_verifier_record(&result->prepared_record);
    result->job_id = 0;
    result->verified = false;
}

}  // namespace signing
