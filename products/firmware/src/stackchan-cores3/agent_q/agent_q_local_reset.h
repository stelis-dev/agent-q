#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_persistent_material.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_pin_attempt.h"
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

struct AgentQLocalResetSnapshot {
    AgentQLocalResetStage stage;
    size_t pin_entry_length;
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
bool local_reset_fail_pin_verification_if_expired(TickType_t now);
bool local_reset_release_lockout_if_elapsed(TickType_t now);
bool local_reset_wipe_ready(TickType_t now);

void local_reset_wipe();
void local_reset_begin_settings(TickType_t deadline);
void local_reset_begin_error_recovery_confirm(TickType_t deadline);
bool local_reset_begin_pin_entry(TickType_t deadline);
bool local_reset_begin_error_recovery_wipe(TickType_t wipe_ready_at);
bool local_reset_add_pin_digit(char digit, TickType_t deadline);
bool local_reset_clear_pin(TickType_t deadline);
bool local_reset_backspace_pin(TickType_t deadline);
AgentQLocalResetPinSubmitResult local_reset_submit_pin_for_verification(
    TickType_t verify_ready_at,
    TickType_t invalid_deadline,
    TickType_t worker_deadline);
AgentQLocalResetPinVerifyResult local_reset_complete_pin_verify_job(
    const AgentQLocalAuthWorkerResult& result,
    TickType_t retry_deadline,
    TickType_t lockout_until,
    TickType_t wipe_ready_at);

bool local_reset_pending_marker_present();
AgentQLocalResetCommitResult local_reset_commit_material(
    const AgentQLocalResetPersistenceOps& ops);
AgentQLocalResetCommitResult local_reset_resume_pending_if_needed(
    const AgentQLocalResetPersistenceOps& ops,
    bool* marker_present);

}  // namespace agent_q
