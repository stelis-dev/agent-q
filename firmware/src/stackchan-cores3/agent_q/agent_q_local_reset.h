#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_persistent_material.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_pin_attempt.h"
#include "agent_q_timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

constexpr uint32_t kAgentQLocalResetEntryMs = 60000;
constexpr uint32_t kAgentQLocalResetPinLockoutMs = kAgentQPinLockoutMs;
constexpr uint8_t kAgentQLocalResetMaxWrongPinAttempts = kAgentQMaxWrongPinAttempts;

enum class AgentQLocalResetStage {
    none,
    settings_menu,
    pin_entry,
    pin_verifying,
    error_recovery_confirm,
    wiping,
};

enum class AgentQLocalResetCommitResult {
    ok,
    missing_state,
    root_wipe_error,
    policy_wipe_error,
    local_auth_wipe_error,
    connect_setting_wipe_error,
    signing_mode_wipe_error,
    approval_history_wipe_error,
    policy_update_marker_wipe_error,
    material_remaining_error,
    reset_marker_storage_error,
    state_storage_error,
};

enum class AgentQLocalResetPinSubmitResult {
    started_verification,
    invalid_pin,
    unavailable_stage,
    locked,
    worker_unavailable,
};

enum class AgentQLocalResetPinVerifyResult {
    not_ready,
    verified,
    wrong_pin,
    locked,
    auth_unavailable,
};

enum class AgentQLocalResetLockoutReleaseResult {
    not_released,
    released,
    failed,
};

struct AgentQLocalResetSnapshot {
    AgentQLocalResetStage stage;
    size_t pin_entry_length;
    AgentQTimeoutWindow input_window;
    bool lockout_active;
    bool flow_active;
};

struct AgentQLocalResetPersistenceOps {
    void (*clear_active_session)();
    bool (*persist_unprovisioned_state)();
    void (*record_material_failure)(AgentQPersistentMaterialRuntimeFailure failure);
};

AgentQLocalResetSnapshot local_reset_snapshot(TickType_t now);
bool local_reset_persistent_material_exists();
bool local_reset_deadline_expired(TickType_t now);
bool local_reset_processing_deadline_expired(TickType_t now);
bool local_reset_fail_processing_if_expired(TickType_t now);
AgentQLocalResetLockoutReleaseResult local_reset_release_lockout_if_elapsed(TickType_t now);
bool local_reset_wipe_ready(TickType_t now);

void local_reset_wipe();
void local_reset_begin_settings(AgentQTimeoutWindow input_window);
void local_reset_begin_error_recovery_confirm(AgentQTimeoutWindow input_window);
bool local_reset_begin_pin_entry(AgentQTimeoutWindow input_window);
bool local_reset_begin_error_recovery_wipe(TickType_t wipe_ready_at);
bool local_reset_add_pin_digit(char digit);
bool local_reset_clear_pin();
bool local_reset_backspace_pin();
AgentQLocalResetPinSubmitResult local_reset_submit_pin_for_verification(
    TickType_t verify_ready_at,
    TickType_t worker_deadline);
AgentQLocalResetPinVerifyResult local_reset_complete_pin_verify_job(
    const AgentQLocalAuthWorkerResult& result,
    TickType_t lockout_until,
    TickType_t wipe_ready_at);

bool local_reset_pending_marker_present();
AgentQLocalResetCommitResult local_reset_commit_material(
    const AgentQLocalResetPersistenceOps& ops);
AgentQLocalResetCommitResult local_reset_resume_pending_if_needed(
    const AgentQLocalResetPersistenceOps& ops,
    bool* marker_present);

}  // namespace agent_q
