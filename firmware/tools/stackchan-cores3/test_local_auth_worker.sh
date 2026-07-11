#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_local_auth_worker.sh

Compiles the StackChan CoreS3 local-auth worker against host FreeRTOS stubs and
verifies the worker request queue carries only job metadata, not raw PIN bytes.
This test uses only a host C++ compiler and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CXX_BIN="${CXX:-c++}"

for required in \
  "${RUNTIME_DIR}/local_auth_worker.cpp" \
  "${RUNTIME_DIR}/local_auth_worker.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-local-auth-worker.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/stubs/freertos"

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once

#define ESP_LOGI(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGE(tag, format, ...) do { (void)(tag); } while (0)
H

cat >"${TMP_DIR}/stubs/esp_heap_caps.h" <<'H'
#pragma once

#include <stddef.h>
#include <stdint.h>

#define MALLOC_CAP_SPIRAM 0x1u
#define MALLOC_CAP_8BIT 0x2u

extern "C" void* heap_caps_aligned_alloc(
    size_t alignment,
    size_t size,
    uint32_t caps);
H

cat >"${TMP_DIR}/stubs/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef int BaseType_t;
typedef unsigned int UBaseType_t;
typedef unsigned int TickType_t;

#define pdTRUE 1
#define pdFALSE 0
#define pdPASS 1
#define portMAX_DELAY 0xffffffffu

typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0

inline void portENTER_CRITICAL(portMUX_TYPE*) {}
inline void portEXIT_CRITICAL(portMUX_TYPE*) {}
H

if rg -q 'atomic_flag|test_and_set' "${RUNTIME_DIR}/local_auth_worker.cpp"; then
  echo "FAILED: local-auth worker must not wait on a preemptible atomic spin lock" >&2
  exit 1
fi
for required_lock_call in portENTER_CRITICAL portEXIT_CRITICAL; do
  if ! rg -q "${required_lock_call}" "${RUNTIME_DIR}/local_auth_worker.cpp"; then
    echo "FAILED: local-auth worker missing ${required_lock_call}" >&2
    exit 1
  fi
done

cat >"${TMP_DIR}/stubs/freertos/queue.h" <<'H'
#pragma once

#include "freertos/FreeRTOS.h"

typedef void* QueueHandle_t;

extern "C" {
QueueHandle_t xQueueCreate(UBaseType_t queue_length, UBaseType_t item_size);
BaseType_t xQueueSend(QueueHandle_t queue, const void* item, TickType_t ticks_to_wait);
BaseType_t xQueueReceive(QueueHandle_t queue, void* item, TickType_t ticks_to_wait);
}
H

cat >"${TMP_DIR}/stubs/freertos/task.h" <<'H'
#pragma once

#include "freertos/FreeRTOS.h"

typedef void* TaskHandle_t;
typedef void (*TaskFunction_t)(void*);

extern "C" {
BaseType_t xTaskCreatePinnedToCore(
    TaskFunction_t task_code,
    const char* name,
    uint32_t stack_depth,
    void* parameters,
    UBaseType_t priority,
    TaskHandle_t* created_task,
    BaseType_t core_id);
}
H

cat >"${TMP_DIR}/local_auth_worker_test.cpp" <<'CPP'
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "local_auth_worker.h"
#include "stackchan_keystore.h"
#include "esp_heap_caps.h"
#include "freertos/queue.h"
#include "freertos/task.h"

namespace {

struct QueueStub {
    size_t item_size = 0;
    bool has_item = false;
    unsigned char item[256] = {};
};

QueueStub g_request_queue;
QueueStub g_result_queue;
int g_create_count = 0;
bool g_fail_next_request_send = false;
bool g_fail_next_result_send = false;
bool g_stop_worker_when_idle = false;
TaskFunction_t g_worker_task_code = nullptr;
alignas(16) uint8_t g_kdf_work_area[signing::kStackChanKeystoreKdfWorkAreaBytes] = {};
size_t g_heap_request_alignment = 0;
size_t g_heap_request_size = 0;
uint32_t g_heap_request_caps = 0;
int g_heap_request_count = 0;
int g_create_keystore_calls = 0;
int g_unlock_keystore_calls = 0;
int g_authenticate_pin_calls = 0;
int g_rewrap_keystore_calls = 0;
signing::KeystoreOperationStatus g_operation_status =
    signing::KeystoreOperationStatus::success;
int failures = 0;

struct WorkerStop {};

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

bool bytes_contain(const unsigned char* bytes, size_t size, const char* needle)
{
    const size_t needle_size = strlen(needle);
    if (needle_size == 0 || size < needle_size) {
        return false;
    }
    for (size_t index = 0; index + needle_size <= size; ++index) {
        if (memcmp(bytes + index, needle, needle_size) == 0) {
            return true;
        }
    }
    return false;
}

void finish_worker_job(uint32_t job_id)
{
    g_request_queue.has_item = false;

    signing::LocalAuthWorkerResult result = {};
    result.job_id = job_id;
    result.owner = signing::LocalAuthWorkerOwner::local_pin_auth;
    result.operation = signing::LocalAuthWorkerOperation::authenticate_pin;
    result.status = signing::LocalAuthWorkerStatus::completed;
    result.operation_status = signing::KeystoreOperationStatus::success;
    memcpy(g_result_queue.item, &result, sizeof(result));
    g_result_queue.has_item = true;

    signing::LocalAuthWorkerResult polled = {};
    expect(signing::local_auth_worker_poll_result(&polled), "worker result can be polled");
    signing::local_auth_worker_wipe_result(&polled);
}

void run_worker_until_idle()
{
    expect(g_worker_task_code != nullptr, "worker task function was captured");
    g_stop_worker_when_idle = true;
    try {
        g_worker_task_code(nullptr);
    } catch (const WorkerStop&) {
    }
    g_stop_worker_when_idle = false;
}

signing::LocalAuthWorkerResult run_worker_and_poll(const char* label)
{
    run_worker_until_idle();
    signing::LocalAuthWorkerResult result = {};
    expect(signing::local_auth_worker_poll_result(&result), label);
    return result;
}

}  // namespace

namespace signing {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool valid_worker_inputs(
    const char* pin,
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    return keystore_pin_valid(
               pin, kLocalAuthMinDigits, kLocalAuthMaxDigits) &&
           kdf_work_area == g_kdf_work_area &&
           kdf_work_area_size == kStackChanKeystoreKdfWorkAreaBytes;
}

KeystoreOperationStatus stackchan_keystore_create(
    char pin[kLocalAuthMaxDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    ++g_create_keystore_calls;
    return valid_worker_inputs(pin, kdf_work_area, kdf_work_area_size)
               ? g_operation_status
               : KeystoreOperationStatus::invalid_input;
}

KeystoreOperationStatus stackchan_keystore_unlock(
    char pin[kLocalAuthMaxDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    ++g_unlock_keystore_calls;
    return valid_worker_inputs(pin, kdf_work_area, kdf_work_area_size)
               ? g_operation_status
               : KeystoreOperationStatus::invalid_input;
}

KeystoreOperationStatus stackchan_keystore_authenticate_pin(
    char pin[kLocalAuthMaxDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    ++g_authenticate_pin_calls;
    return valid_worker_inputs(pin, kdf_work_area, kdf_work_area_size)
               ? g_operation_status
               : KeystoreOperationStatus::invalid_input;
}

KeystoreOperationStatus stackchan_keystore_rewrap(
    char current_pin[kLocalAuthMaxDigits + 1],
    char new_pin[kLocalAuthMaxDigits + 1],
    void* kdf_work_area,
    size_t kdf_work_area_size)
{
    ++g_rewrap_keystore_calls;
    return valid_worker_inputs(current_pin, kdf_work_area, kdf_work_area_size) &&
                   keystore_pin_valid(
                       new_pin, kLocalAuthMinDigits, kLocalAuthMaxDigits)
               ? g_operation_status
               : KeystoreOperationStatus::invalid_input;
}

}  // namespace signing

extern "C" {

void* heap_caps_aligned_alloc(size_t alignment, size_t size, uint32_t caps)
{
    ++g_heap_request_count;
    g_heap_request_alignment = alignment;
    g_heap_request_size = size;
    g_heap_request_caps = caps;
    return size == sizeof(g_kdf_work_area) ? g_kdf_work_area : nullptr;
}

QueueHandle_t xQueueCreate(UBaseType_t queue_length, UBaseType_t item_size)
{
    (void)queue_length;
    QueueStub* queue = (g_create_count++ == 0) ? &g_request_queue : &g_result_queue;
    queue->item_size = item_size;
    queue->has_item = false;
    memset(queue->item, 0, sizeof(queue->item));
    return queue;
}

BaseType_t xQueueSend(QueueHandle_t queue_handle, const void* item, TickType_t ticks_to_wait)
{
    (void)ticks_to_wait;
    QueueStub* queue = static_cast<QueueStub*>(queue_handle);
    if (queue == &g_request_queue && g_fail_next_request_send) {
        g_fail_next_request_send = false;
        return pdFALSE;
    }
    if (queue == &g_result_queue && g_fail_next_result_send) {
        g_fail_next_result_send = false;
        return pdFALSE;
    }
    if (queue == nullptr || item == nullptr || queue->item_size > sizeof(queue->item)) {
        return pdFALSE;
    }
    memcpy(queue->item, item, queue->item_size);
    queue->has_item = true;
    return pdTRUE;
}

BaseType_t xQueueReceive(QueueHandle_t queue_handle, void* item, TickType_t ticks_to_wait)
{
    (void)ticks_to_wait;
    QueueStub* queue = static_cast<QueueStub*>(queue_handle);
    if (queue == nullptr || item == nullptr || !queue->has_item) {
        if (queue == &g_request_queue && g_stop_worker_when_idle) {
            throw WorkerStop{};
        }
        return pdFALSE;
    }
    memcpy(item, queue->item, queue->item_size);
    queue->has_item = false;
    return pdTRUE;
}

BaseType_t xTaskCreatePinnedToCore(
    TaskFunction_t task_code,
    const char* name,
    uint32_t stack_depth,
    void* parameters,
    UBaseType_t priority,
    TaskHandle_t* created_task,
    BaseType_t core_id)
{
    (void)name;
    (void)stack_depth;
    (void)parameters;
    (void)priority;
    (void)core_id;
    if (created_task == nullptr) {
        return pdFALSE;
    }
    g_worker_task_code = task_code;
    *created_task = reinterpret_cast<TaskHandle_t>(0x1);
    return pdPASS;
}

}  // extern "C"

int main()
{
    expect(signing::local_auth_worker_init(), "worker initializes");
    expect(g_heap_request_count == 1, "worker allocates one KDF work area");
    expect(g_heap_request_alignment == signing::kKeystoreKdfWorkAreaAlignment,
           "worker requests the common Argon2 work-area alignment");
    expect(g_heap_request_size == signing::kStackChanKeystoreKdfWorkAreaBytes,
           "worker allocates the StackChan measured KDF work-area size");
    expect(g_heap_request_caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT),
           "worker allocates the KDF work area from byte-addressable PSRAM");
    expect(signing::local_auth_worker_init(), "worker initialization is idempotent");
    expect(g_heap_request_count == 1, "idempotent initialization reuses the KDF work area");

    uint32_t job_id = 0;
    expect(signing::local_auth_worker_submit_create(
               signing::LocalAuthWorkerOwner::provisioning_setup,
               "654321",
               &job_id),
           "create submit succeeds");
    expect(job_id != 0, "create submit returns job id");
    expect(g_request_queue.has_item, "create submit enqueues request metadata");
    expect(!bytes_contain(g_request_queue.item, g_request_queue.item_size, "654321"),
           "create request queue item does not contain raw PIN");
    expect(!signing::local_auth_worker_cancel_authentication(job_id),
           "create job cannot be discarded after submission");
    signing::LocalAuthWorkerResult operation_result =
        run_worker_and_poll("create result can be polled");
    expect(operation_result.operation == signing::LocalAuthWorkerOperation::create_keystore,
           "create result preserves operation");
    expect(operation_result.status == signing::LocalAuthWorkerStatus::completed &&
               operation_result.operation_status == signing::KeystoreOperationStatus::success,
           "create result preserves keystore success");
    expect(g_create_keystore_calls == 1, "create routes to the StackChan keystore adapter");
    signing::local_auth_worker_wipe_result(&operation_result);
    expect(operation_result.job_id == 0 &&
               operation_result.operation_status == signing::KeystoreOperationStatus::invalid_input,
           "result wipe clears job metadata and status");

    expect(signing::local_auth_worker_submit_unlock(
               signing::LocalAuthWorkerOwner::local_pin_auth,
               "123456",
               &job_id),
           "unlock submit succeeds");
    expect(!signing::local_auth_worker_cancel_authentication(job_id),
           "unlock job cannot be discarded after submission");
    operation_result = run_worker_and_poll("unlock result can be polled");
    expect(operation_result.operation == signing::LocalAuthWorkerOperation::unlock_keystore &&
               operation_result.operation_status == signing::KeystoreOperationStatus::success,
           "unlock routes to the StackChan keystore adapter");
    expect(g_unlock_keystore_calls == 1, "unlock adapter called once");
    signing::local_auth_worker_wipe_result(&operation_result);

    g_operation_status = signing::KeystoreOperationStatus::wrong_pin;
    expect(signing::local_auth_worker_submit_authenticate(
               signing::LocalAuthWorkerOwner::storage_maintenance,
               "111111",
               &job_id),
           "PIN authentication submit succeeds");
    operation_result = run_worker_and_poll("PIN authentication result can be polled");
    expect(operation_result.operation == signing::LocalAuthWorkerOperation::authenticate_pin &&
               operation_result.operation_status == signing::KeystoreOperationStatus::wrong_pin,
           "PIN authentication preserves wrong-PIN status");
    expect(g_authenticate_pin_calls == 1, "PIN authentication adapter called once");
    signing::local_auth_worker_wipe_result(&operation_result);
    g_operation_status = signing::KeystoreOperationStatus::success;

    expect(signing::local_auth_worker_submit_rewrap(
               signing::LocalAuthWorkerOwner::local_pin_auth,
               "123456",
               "654321",
               &job_id),
           "PIN rewrap submit succeeds");
    expect(!bytes_contain(g_request_queue.item, g_request_queue.item_size, "123456") &&
               !bytes_contain(g_request_queue.item, g_request_queue.item_size, "654321"),
           "rewrap request queue contains neither current nor new PIN");
    expect(!signing::local_auth_worker_cancel_authentication(job_id),
           "PIN rewrap job cannot be discarded after submission");
    operation_result = run_worker_and_poll("PIN rewrap result can be polled");
    expect(operation_result.operation == signing::LocalAuthWorkerOperation::rewrap_keystore &&
               operation_result.operation_status == signing::KeystoreOperationStatus::success,
           "PIN rewrap routes to the StackChan keystore adapter");
    expect(g_rewrap_keystore_calls == 1, "PIN rewrap adapter called once");
    signing::local_auth_worker_wipe_result(&operation_result);

    expect(signing::local_auth_worker_submit_rewrap(
               signing::LocalAuthWorkerOwner::local_pin_auth,
               "123456",
               "654321",
               &job_id),
           "PIN rewrap submit succeeds before result queue failure");
    g_fail_next_result_send = true;
    run_worker_until_idle();
    signing::LocalAuthWorkerResult rewrap_fallback = {};
    expect(signing::local_auth_worker_poll_result(&rewrap_fallback),
           "effectful PIN rewrap result survives queue-send failure");
    expect(rewrap_fallback.operation ==
                   signing::LocalAuthWorkerOperation::rewrap_keystore &&
               rewrap_fallback.status == signing::LocalAuthWorkerStatus::completed &&
               rewrap_fallback.operation_status ==
                   signing::KeystoreOperationStatus::success,
           "effectful terminal fallback preserves exact PIN rewrap outcome");
    signing::local_auth_worker_wipe_result(&rewrap_fallback);

    expect(signing::local_auth_worker_submit_authenticate(
               signing::LocalAuthWorkerOwner::local_pin_auth,
               "123456",
               &job_id),
           "verify submit succeeds before result queue failure");
    g_fail_next_result_send = true;
    run_worker_until_idle();
    expect(!g_result_queue.has_item, "failed result send does not leave a queue item");
    signing::LocalAuthWorkerResult failed_result = {};
    expect(signing::local_auth_worker_poll_result(&failed_result),
           "result send failure produces terminal result");
    expect(failed_result.job_id == job_id, "terminal result keeps job id");
    expect(failed_result.owner == signing::LocalAuthWorkerOwner::local_pin_auth,
           "terminal result keeps owner");
    expect(failed_result.operation == signing::LocalAuthWorkerOperation::authenticate_pin,
           "terminal result keeps operation");
    expect(failed_result.status == signing::LocalAuthWorkerStatus::completed &&
               failed_result.operation_status == signing::KeystoreOperationStatus::success,
           "terminal fallback preserves the exact completed operation result");
    signing::local_auth_worker_wipe_result(&failed_result);
    expect(signing::local_auth_worker_submit_authenticate(
               signing::LocalAuthWorkerOwner::local_pin_auth,
               "333333",
               &job_id),
           "submit can retry after terminal worker failure is polled");
    finish_worker_job(job_id);

    expect(signing::local_auth_worker_submit_authenticate(
               signing::LocalAuthWorkerOwner::storage_maintenance,
               "444444",
               &job_id),
           "submit succeeds before queued job cancellation");
    expect(signing::local_auth_worker_cancel_authentication(job_id),
           "queued authentication job can be cancelled");
    const int verify_count_before_cancelled_job = g_authenticate_pin_calls;
    run_worker_until_idle();
    expect(g_authenticate_pin_calls == verify_count_before_cancelled_job,
           "cancelled queued job does not verify wiped PIN");
    signing::LocalAuthWorkerResult cancelled_result = {};
    expect(!signing::local_auth_worker_poll_result(&cancelled_result),
           "cancelled queued job does not produce caller result");
    expect(signing::local_auth_worker_submit_authenticate(
               signing::LocalAuthWorkerOwner::local_pin_auth,
               "555555",
               &job_id),
           "submit can retry after queued job cancellation");
    finish_worker_job(job_id);

    expect(signing::local_auth_worker_submit_authenticate(
               signing::LocalAuthWorkerOwner::local_pin_auth,
               "666666",
               &job_id),
           "submit succeeds before queued result cancellation");
    g_request_queue.has_item = false;
    signing::LocalAuthWorkerResult queued_result = {};
    queued_result.job_id = job_id;
    queued_result.owner = signing::LocalAuthWorkerOwner::local_pin_auth;
    queued_result.operation = signing::LocalAuthWorkerOperation::authenticate_pin;
    queued_result.status = signing::LocalAuthWorkerStatus::completed;
    queued_result.operation_status = signing::KeystoreOperationStatus::success;
    memcpy(g_result_queue.item, &queued_result, sizeof(queued_result));
    g_result_queue.has_item = true;
    expect(signing::local_auth_worker_cancel_authentication(job_id),
           "queued authentication result can be cancelled");
    expect(!signing::local_auth_worker_poll_result(&cancelled_result),
           "cancelled queued result is discarded");
    expect(signing::local_auth_worker_submit_authenticate(
               signing::LocalAuthWorkerOwner::local_pin_auth,
               "777777",
               &job_id),
           "submit can retry after queued result cancellation");
    finish_worker_job(job_id);

    g_fail_next_request_send = true;
    expect(!signing::local_auth_worker_submit_authenticate(
               signing::LocalAuthWorkerOwner::storage_maintenance,
               "111111",
               &job_id),
           "request queue send failure is reported");
    expect(signing::local_auth_worker_submit_authenticate(
               signing::LocalAuthWorkerOwner::storage_maintenance,
               "222222",
               &job_id),
           "submit can retry after request queue send failure");
    expect(!bytes_contain(g_request_queue.item, g_request_queue.item_size, "222222"),
           "retry request queue item does not contain raw PIN");

    if (failures != 0) {
        fprintf(stderr, "%d local auth worker test(s) failed\n", failures);
        return 1;
    }
    printf("Local auth worker tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${COMMON_ROOT}" \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/local_auth_worker_test.cpp" \
  "${RUNTIME_DIR}/local_auth_worker.cpp" \
  -o "${TMP_DIR}/local_auth_worker_test"

"${TMP_DIR}/local_auth_worker_test"
