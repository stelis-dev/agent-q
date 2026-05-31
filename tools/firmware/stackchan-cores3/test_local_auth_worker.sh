#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_local_auth_worker.sh

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
AGENT_Q_DIR="${REPO_ROOT}/products/firmware/src/stackchan-cores3/agent_q"
CXX_BIN="${CXX:-c++}"

for required in \
  "${AGENT_Q_DIR}/agent_q_local_auth_worker.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_auth_worker.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-local-auth-worker.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/stubs/freertos"

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once

#define ESP_LOGI(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGE(tag, format, ...) do { (void)(tag); } while (0)
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
H

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

#include "agent_q_local_auth_worker.h"
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
int g_verify_call_count = 0;
int g_prepare_call_count = 0;
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

    agent_q::AgentQLocalAuthWorkerResult result = {};
    result.job_id = job_id;
    result.owner = agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth;
    result.operation = agent_q::AgentQLocalAuthWorkerOperation::verify_pin;
    result.status = agent_q::AgentQLocalAuthWorkerStatus::ok;
    result.verified = true;
    memcpy(g_result_queue.item, &result, sizeof(result));
    g_result_queue.has_item = true;

    agent_q::AgentQLocalAuthWorkerResult polled = {};
    expect(agent_q::local_auth_worker_poll_result(&polled), "worker result can be polled");
    agent_q::local_auth_worker_wipe_result(&polled);
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

}  // namespace

namespace agent_q {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool is_valid_local_pin(const char* pin)
{
    if (pin == nullptr || strlen(pin) != kLocalPinDigits) {
        return false;
    }
    for (size_t index = 0; index < kLocalPinDigits; ++index) {
        if (!isdigit(static_cast<unsigned char>(pin[index]))) {
            return false;
        }
    }
    return true;
}

bool prepare_local_pin_verifier_record(const char* pin, AgentQLocalAuthPreparedRecord* out)
{
    ++g_prepare_call_count;
    if (!is_valid_local_pin(pin) || out == nullptr) {
        return false;
    }
    memset(out->bytes, 0xa5, sizeof(out->bytes));
    return true;
}

void wipe_local_pin_verifier_record(AgentQLocalAuthPreparedRecord* prepared)
{
    if (prepared != nullptr) {
        memset(prepared->bytes, 0, sizeof(prepared->bytes));
    }
}

bool verify_local_pin(const char* pin, bool* verified)
{
    ++g_verify_call_count;
    if (!is_valid_local_pin(pin) || verified == nullptr) {
        return false;
    }
    *verified = strcmp(pin, "123456") == 0;
    return true;
}

}  // namespace agent_q

extern "C" {

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
    expect(agent_q::local_auth_worker_init(), "worker initializes");

    uint32_t job_id = 0;
    expect(agent_q::local_auth_worker_submit_verify(
               agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth,
               "123456",
               &job_id),
           "verify submit succeeds");
    expect(job_id != 0, "verify submit returns job id");
    expect(g_request_queue.has_item, "verify submit enqueues request metadata");
    expect(!bytes_contain(g_request_queue.item, g_request_queue.item_size, "123456"),
           "verify request queue item does not contain raw PIN");

    finish_worker_job(job_id);

    expect(agent_q::local_auth_worker_submit_prepare_verifier(
               agent_q::AgentQLocalAuthWorkerOwner::provisioning_setup,
               "654321",
               &job_id),
           "prepare submit succeeds");
    expect(g_request_queue.has_item, "prepare submit enqueues request metadata");
    expect(!bytes_contain(g_request_queue.item, g_request_queue.item_size, "654321"),
           "prepare request queue item does not contain raw PIN");

    finish_worker_job(job_id);

    expect(agent_q::local_auth_worker_submit_verify(
               agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth,
               "123456",
               &job_id),
           "verify submit succeeds before result queue failure");
    g_fail_next_result_send = true;
    run_worker_until_idle();
    expect(!g_result_queue.has_item, "failed result send does not leave a queue item");
    agent_q::AgentQLocalAuthWorkerResult failed_result = {};
    expect(agent_q::local_auth_worker_poll_result(&failed_result),
           "result send failure produces terminal result");
    expect(failed_result.job_id == job_id, "terminal result keeps job id");
    expect(failed_result.owner == agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth,
           "terminal result keeps owner");
    expect(failed_result.operation == agent_q::AgentQLocalAuthWorkerOperation::verify_pin,
           "terminal result keeps operation");
    expect(failed_result.status == agent_q::AgentQLocalAuthWorkerStatus::worker_unavailable,
           "terminal result reports worker unavailable");
    agent_q::local_auth_worker_wipe_result(&failed_result);
    expect(agent_q::local_auth_worker_submit_verify(
               agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth,
               "333333",
               &job_id),
           "submit can retry after terminal worker failure is polled");
    finish_worker_job(job_id);

    expect(agent_q::local_auth_worker_submit_verify(
               agent_q::AgentQLocalAuthWorkerOwner::local_reset,
               "444444",
               &job_id),
           "submit succeeds before queued job cancellation");
    expect(agent_q::local_auth_worker_cancel_job(job_id), "queued worker job can be cancelled");
    const int verify_count_before_cancelled_job = g_verify_call_count;
    run_worker_until_idle();
    expect(g_verify_call_count == verify_count_before_cancelled_job,
           "cancelled queued job does not verify wiped PIN");
    agent_q::AgentQLocalAuthWorkerResult cancelled_result = {};
    expect(!agent_q::local_auth_worker_poll_result(&cancelled_result),
           "cancelled queued job does not produce caller result");
    expect(agent_q::local_auth_worker_submit_verify(
               agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth,
               "555555",
               &job_id),
           "submit can retry after queued job cancellation");
    finish_worker_job(job_id);

    expect(agent_q::local_auth_worker_submit_verify(
               agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth,
               "666666",
               &job_id),
           "submit succeeds before queued result cancellation");
    g_request_queue.has_item = false;
    agent_q::AgentQLocalAuthWorkerResult queued_result = {};
    queued_result.job_id = job_id;
    queued_result.owner = agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth;
    queued_result.operation = agent_q::AgentQLocalAuthWorkerOperation::verify_pin;
    queued_result.status = agent_q::AgentQLocalAuthWorkerStatus::ok;
    queued_result.verified = true;
    memcpy(g_result_queue.item, &queued_result, sizeof(queued_result));
    g_result_queue.has_item = true;
    expect(agent_q::local_auth_worker_cancel_job(job_id), "queued result job can be cancelled");
    expect(!agent_q::local_auth_worker_poll_result(&cancelled_result),
           "cancelled queued result is discarded");
    expect(agent_q::local_auth_worker_submit_verify(
               agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth,
               "777777",
               &job_id),
           "submit can retry after queued result cancellation");
    finish_worker_job(job_id);

    g_fail_next_request_send = true;
    expect(!agent_q::local_auth_worker_submit_verify(
               agent_q::AgentQLocalAuthWorkerOwner::local_reset,
               "111111",
               &job_id),
           "request queue send failure is reported");
    expect(agent_q::local_auth_worker_submit_verify(
               agent_q::AgentQLocalAuthWorkerOwner::local_reset,
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
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/local_auth_worker_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_auth_worker.cpp" \
  -o "${TMP_DIR}/local_auth_worker_test"

"${TMP_DIR}/local_auth_worker_test"
