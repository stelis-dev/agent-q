#include "agent_q_local_pin_auth.h"

#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_connect_settings.h"
#include "agent_q_local_auth.h"
#include "agent_q_pin_attempt.h"
#include "freertos/task.h"

namespace agent_q {
namespace {

struct AgentQLocalPinAuthState {
    char pin_entry[kLocalPinBufferSize] = {};
    char new_pin[kLocalPinBufferSize] = {};
    size_t pin_entry_length = 0;
    AgentQLocalPinAuthPurpose purpose = AgentQLocalPinAuthPurpose::none;
    AgentQLocalPinAuthStage stage = AgentQLocalPinAuthStage::none;
    bool target_require_pin_on_connect = true;
    uint32_t auth_job_id = 0;
    TickType_t deadline = 0;
    TickType_t verify_ready_at = 0;
    TickType_t commit_ready_at = 0;
    TickType_t worker_deadline = 0;

    bool flow_active() const
    {
        return purpose != AgentQLocalPinAuthPurpose::none &&
               stage != AgentQLocalPinAuthStage::none;
    }

    void clear_pin_only()
    {
        wipe_sensitive_buffer(pin_entry, sizeof(pin_entry));
        pin_entry_length = 0;
        verify_ready_at = 0;
        commit_ready_at = 0;
        worker_deadline = 0;
    }

    void clear_new_pin()
    {
        wipe_sensitive_buffer(new_pin, sizeof(new_pin));
    }

    void clear_flow()
    {
        if (auth_job_id != 0) {
            local_auth_worker_cancel_job(auth_job_id);
        }
        wipe_sensitive_buffer(pin_entry, sizeof(pin_entry));
        wipe_sensitive_buffer(new_pin, sizeof(new_pin));
        pin_entry_length = 0;
        purpose = AgentQLocalPinAuthPurpose::none;
        stage = AgentQLocalPinAuthStage::none;
        target_require_pin_on_connect = true;
        auth_job_id = 0;
        deadline = 0;
        verify_ready_at = 0;
        commit_ready_at = 0;
        worker_deadline = 0;
    }
};

AgentQLocalPinAuthState g_state;

bool tick_reached(TickType_t deadline, TickType_t now)
{
    return deadline != 0 && static_cast<int32_t>(now - deadline) >= 0;
}

bool processing_stage(AgentQLocalPinAuthStage stage)
{
    return stage == AgentQLocalPinAuthStage::pin_verifying ||
           stage == AgentQLocalPinAuthStage::committing_setting ||
           stage == AgentQLocalPinAuthStage::committing_pin_change;
}

bool release_lockout_if_elapsed(TickType_t now, TickType_t retry_deadline)
{
    if (!pin_attempt_release_if_elapsed(now)) {
        return false;
    }
    g_state.deadline = retry_deadline;
    return true;
}

}  // namespace

AgentQLocalPinAuthSnapshot local_pin_auth_snapshot(TickType_t now)
{
    const bool accepts =
        g_state.flow_active() &&
        (g_state.stage == AgentQLocalPinAuthStage::pin_entry ||
         g_state.stage == AgentQLocalPinAuthStage::new_pin_entry ||
         g_state.stage == AgentQLocalPinAuthStage::repeat_pin_entry);
    return AgentQLocalPinAuthSnapshot{
        g_state.purpose,
        g_state.stage,
        g_state.pin_entry_length,
        g_state.target_require_pin_on_connect,
        g_state.flow_active(),
        accepts,
        processing_stage(g_state.stage),
        pin_attempt_locked_at(now),
    };
}

bool local_pin_auth_flow_active()
{
    return g_state.flow_active();
}

bool local_pin_auth_accepts_keypad_input()
{
    return g_state.flow_active() &&
           (g_state.stage == AgentQLocalPinAuthStage::pin_entry ||
            g_state.stage == AgentQLocalPinAuthStage::new_pin_entry ||
            g_state.stage == AgentQLocalPinAuthStage::repeat_pin_entry);
}

bool local_pin_auth_deadline_expired(TickType_t now)
{
    return tick_reached(g_state.deadline, now);
}

bool local_pin_auth_fail_processing_if_expired(TickType_t now)
{
    if (!g_state.flow_active() ||
        !processing_stage(g_state.stage) ||
        !tick_reached(g_state.worker_deadline, now)) {
        return false;
    }
    g_state.clear_flow();
    return true;
}

bool local_pin_auth_release_lockout_if_elapsed(TickType_t now, TickType_t retry_deadline)
{
    return release_lockout_if_elapsed(now, retry_deadline);
}

void local_pin_auth_clear_flow()
{
    g_state.clear_flow();
}

void local_pin_auth_begin_connect(TickType_t deadline)
{
    g_state.clear_flow();
    g_state.purpose = AgentQLocalPinAuthPurpose::connect;
    g_state.stage = AgentQLocalPinAuthStage::pin_entry;
    g_state.deadline = deadline;
}

void local_pin_auth_begin_connect_setting(bool target_require_pin_on_connect, TickType_t deadline)
{
    g_state.clear_flow();
    g_state.purpose = AgentQLocalPinAuthPurpose::settings_connect_pin;
    g_state.stage = AgentQLocalPinAuthStage::pin_entry;
    g_state.target_require_pin_on_connect = target_require_pin_on_connect;
    g_state.deadline = deadline;
}

void local_pin_auth_begin_change_pin(TickType_t deadline)
{
    g_state.clear_flow();
    g_state.purpose = AgentQLocalPinAuthPurpose::settings_change_pin;
    g_state.stage = AgentQLocalPinAuthStage::pin_entry;
    g_state.deadline = deadline;
}

void local_pin_auth_begin_policy_update(TickType_t deadline)
{
    g_state.clear_flow();
    g_state.purpose = AgentQLocalPinAuthPurpose::policy_update;
    g_state.stage = AgentQLocalPinAuthStage::pin_entry;
    g_state.deadline = deadline;
}

AgentQLocalPinAuthInputResult local_pin_auth_add_digit(char digit, TickType_t deadline)
{
    const TickType_t now = xTaskGetTickCount();
    release_lockout_if_elapsed(now, deadline);
    if (!local_pin_auth_accepts_keypad_input()) {
        return AgentQLocalPinAuthInputResult::inactive;
    }
    if (pin_attempt_locked_at(now)) {
        return AgentQLocalPinAuthInputResult::locked;
    }
    if (digit < '0' || digit > '9') {
        return AgentQLocalPinAuthInputResult::invalid_digit;
    }
    if (g_state.pin_entry_length >= kLocalPinDigits) {
        g_state.deadline = deadline;
        return AgentQLocalPinAuthInputResult::full;
    }

    g_state.pin_entry[g_state.pin_entry_length++] = digit;
    g_state.pin_entry[g_state.pin_entry_length] = '\0';
    g_state.deadline = deadline;
    return AgentQLocalPinAuthInputResult::accepted;
}

bool local_pin_auth_clear_pin(TickType_t deadline)
{
    const TickType_t now = xTaskGetTickCount();
    release_lockout_if_elapsed(now, deadline);
    if (!local_pin_auth_accepts_keypad_input() ||
        pin_attempt_locked_at(now)) {
        return false;
    }
    g_state.clear_pin_only();
    g_state.deadline = deadline;
    return true;
}

bool local_pin_auth_backspace_pin(TickType_t deadline)
{
    const TickType_t now = xTaskGetTickCount();
    release_lockout_if_elapsed(now, deadline);
    if (!local_pin_auth_accepts_keypad_input() ||
        pin_attempt_locked_at(now)) {
        return false;
    }
    if (g_state.pin_entry_length > 0) {
        g_state.pin_entry[--g_state.pin_entry_length] = '\0';
    }
    g_state.deadline = deadline;
    return true;
}

AgentQLocalPinAuthSubmitResult local_pin_auth_submit(
    TickType_t verify_ready_at,
    TickType_t commit_ready_at,
    TickType_t retry_deadline,
    TickType_t worker_deadline)
{
    const TickType_t now = xTaskGetTickCount();
    release_lockout_if_elapsed(now, retry_deadline);
    if (!local_pin_auth_accepts_keypad_input()) {
        return AgentQLocalPinAuthSubmitResult::unavailable_stage;
    }
    if (pin_attempt_locked_at(now)) {
        return AgentQLocalPinAuthSubmitResult::locked;
    }
    if (g_state.pin_entry_length != kLocalPinDigits ||
        !is_valid_local_pin(g_state.pin_entry)) {
        g_state.deadline = retry_deadline;
        return AgentQLocalPinAuthSubmitResult::invalid_pin;
    }

    if (g_state.purpose == AgentQLocalPinAuthPurpose::settings_change_pin &&
        g_state.stage == AgentQLocalPinAuthStage::new_pin_entry) {
        memcpy(g_state.new_pin, g_state.pin_entry, sizeof(g_state.new_pin));
        g_state.new_pin[sizeof(g_state.new_pin) - 1] = '\0';
        g_state.clear_pin_only();
        g_state.stage = AgentQLocalPinAuthStage::repeat_pin_entry;
        g_state.deadline = retry_deadline;
        return AgentQLocalPinAuthSubmitResult::advanced_to_repeat_pin;
    }

    if (g_state.purpose == AgentQLocalPinAuthPurpose::settings_change_pin &&
        g_state.stage == AgentQLocalPinAuthStage::repeat_pin_entry) {
        if (strcmp(g_state.new_pin, g_state.pin_entry) != 0) {
            g_state.clear_new_pin();
            g_state.clear_pin_only();
            g_state.stage = AgentQLocalPinAuthStage::new_pin_entry;
            g_state.deadline = retry_deadline;
            return AgentQLocalPinAuthSubmitResult::mismatch_restart;
        }

        uint32_t job_id = 0;
        if (!local_auth_worker_submit_prepare_verifier(
                AgentQLocalAuthWorkerOwner::local_pin_auth,
                g_state.new_pin,
                &job_id)) {
            g_state.clear_new_pin();
            g_state.clear_pin_only();
            g_state.stage = AgentQLocalPinAuthStage::new_pin_entry;
            g_state.deadline = retry_deadline;
            return AgentQLocalPinAuthSubmitResult::worker_unavailable;
        }
        g_state.clear_new_pin();
        g_state.clear_pin_only();
        g_state.stage = AgentQLocalPinAuthStage::committing_pin_change;
        g_state.auth_job_id = job_id;
        g_state.commit_ready_at = commit_ready_at;
        g_state.worker_deadline = worker_deadline;
        g_state.deadline = 0;
        return AgentQLocalPinAuthSubmitResult::started_pin_change_commit;
    }

    uint32_t job_id = 0;
    if (!local_auth_worker_submit_verify(
            AgentQLocalAuthWorkerOwner::local_pin_auth,
            g_state.pin_entry,
            &job_id)) {
        g_state.deadline = retry_deadline;
        return AgentQLocalPinAuthSubmitResult::worker_unavailable;
    }
    g_state.clear_pin_only();
    g_state.stage = AgentQLocalPinAuthStage::pin_verifying;
    g_state.auth_job_id = job_id;
    g_state.verify_ready_at = verify_ready_at;
    g_state.worker_deadline = worker_deadline;
    g_state.deadline = 0;
    return AgentQLocalPinAuthSubmitResult::started_verification;
}

AgentQLocalPinAuthVerifyResult local_pin_auth_complete_verify_job(
    const AgentQLocalAuthWorkerResult& result,
    TickType_t retry_deadline,
    TickType_t lockout_until,
    TickType_t setting_commit_ready_at)
{
    if (!g_state.flow_active() ||
        g_state.stage != AgentQLocalPinAuthStage::pin_verifying ||
        g_state.auth_job_id == 0 ||
        result.job_id != g_state.auth_job_id ||
        result.owner != AgentQLocalAuthWorkerOwner::local_pin_auth ||
        result.operation != AgentQLocalAuthWorkerOperation::verify_pin) {
        return AgentQLocalPinAuthVerifyResult::not_ready;
    }

    g_state.auth_job_id = 0;
    g_state.verify_ready_at = 0;
    g_state.worker_deadline = 0;
    if (result.status != AgentQLocalAuthWorkerStatus::ok) {
        g_state.clear_pin_only();
        return AgentQLocalPinAuthVerifyResult::auth_unavailable;
    }

    if (!result.verified) {
        g_state.clear_pin_only();
        g_state.stage = AgentQLocalPinAuthStage::pin_entry;
        g_state.deadline = retry_deadline;
        const bool locked = pin_attempt_record_failure(lockout_until);
        return locked ? AgentQLocalPinAuthVerifyResult::locked
                      : AgentQLocalPinAuthVerifyResult::wrong_pin;
    }

    g_state.clear_pin_only();
    pin_attempt_clear();

    if (g_state.purpose == AgentQLocalPinAuthPurpose::settings_change_pin) {
        g_state.stage = AgentQLocalPinAuthStage::new_pin_entry;
        g_state.deadline = retry_deadline;
        return AgentQLocalPinAuthVerifyResult::advanced_to_change_pin;
    }

    if (g_state.purpose == AgentQLocalPinAuthPurpose::settings_connect_pin) {
        g_state.stage = AgentQLocalPinAuthStage::committing_setting;
        g_state.commit_ready_at = setting_commit_ready_at;
        g_state.deadline = 0;
        return AgentQLocalPinAuthVerifyResult::started_setting_commit;
    }

    if (g_state.purpose == AgentQLocalPinAuthPurpose::policy_update) {
        return AgentQLocalPinAuthVerifyResult::verified_policy_update;
    }

    return AgentQLocalPinAuthVerifyResult::verified_connect;
}

AgentQLocalPinAuthCommitResult local_pin_auth_complete_pin_change_job(
    const AgentQLocalAuthWorkerResult& result)
{
    if (!g_state.flow_active() ||
        g_state.stage != AgentQLocalPinAuthStage::committing_pin_change ||
        g_state.auth_job_id == 0 ||
        result.job_id != g_state.auth_job_id ||
        result.owner != AgentQLocalAuthWorkerOwner::local_pin_auth ||
        result.operation != AgentQLocalAuthWorkerOperation::prepare_verifier_record) {
        return AgentQLocalPinAuthCommitResult::not_ready;
    }

    g_state.auth_job_id = 0;
    g_state.commit_ready_at = 0;
    g_state.worker_deadline = 0;
    if (result.status != AgentQLocalAuthWorkerStatus::ok) {
        g_state.clear_flow();
        return AgentQLocalPinAuthCommitResult::pin_change_auth_unavailable;
    }

    const bool stored = store_prepared_local_pin_verifier(&result.prepared_record);
    g_state.clear_flow();
    if (!stored) {
        if (local_auth_status() != AgentQLocalAuthStatus::active) {
            return AgentQLocalPinAuthCommitResult::pin_change_auth_unavailable;
        }
        return AgentQLocalPinAuthCommitResult::pin_change_storage_error;
    }
    return AgentQLocalPinAuthCommitResult::pin_changed;
}

AgentQLocalPinAuthCommitResult local_pin_auth_commit_if_ready(TickType_t now)
{
    if (!g_state.flow_active() ||
        g_state.stage != AgentQLocalPinAuthStage::committing_setting ||
        g_state.commit_ready_at == 0 ||
        !tick_reached(g_state.commit_ready_at, now)) {
        return AgentQLocalPinAuthCommitResult::not_ready;
    }

    const bool next_value = g_state.target_require_pin_on_connect;
    const bool stored = store_require_pin_on_connect(next_value);
    g_state.clear_flow();

    if (!stored) {
        return AgentQLocalPinAuthCommitResult::storage_error;
    }

    return AgentQLocalPinAuthCommitResult::setting_stored;
}

}  // namespace agent_q
