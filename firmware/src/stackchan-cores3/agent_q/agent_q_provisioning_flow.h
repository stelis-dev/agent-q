#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_bip39.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

constexpr size_t kProvisioningFlowPhrasePrefixCellCount = kBip39MnemonicWordCount;
constexpr size_t kProvisioningFlowPhrasePrefixCellSize = 8;
constexpr size_t kProvisioningFlowImportWordsPerPage = 3;
constexpr size_t kProvisioningFlowImportPageCount =
    kBip39MnemonicWordCount / kProvisioningFlowImportWordsPerPage;
constexpr size_t kProvisioningFlowImportPrefixMaxChars = 4;
constexpr size_t kProvisioningFlowImportPrefixBufferSize =
    kProvisioningFlowImportPrefixMaxChars + 1;

enum class AgentQProvisioningFlowStage {
    none,
    setup_choice,
    backup_phrase_displayed,
    import_word_entry,
    pin_first_entry,
    pin_repeat_entry,
    pin_committing,
};

enum class AgentQProvisioningFlowPanel {
    setup_choice,
    backup_phrase_display,
    import_word_entry,
    pin_entry,
};

enum class AgentQProvisioningFlowGenerateResult {
    stale,
    ok,
    rng_error,
    generation_error,
};

enum class AgentQProvisioningFlowImportStartResult {
    stale,
    failed,
    started,
};

enum class AgentQProvisioningFlowPinSubmitResult {
    inactive,
    invalid_pin,
    worker_unavailable,
    advanced_to_repeat,
    mismatch_restart,
    commit_started,
};

enum class AgentQProvisioningFlowCleanupResult {
    inactive,
    wiped,
};

enum class AgentQProvisioningFlowPanelLifetimeResult {
    unchanged,
    clear_panel_timeout,
    clear_panel_preserve_timeout,
    wiped_panel_lost,
    wiped_panel_lost_timeout,
};

enum class AgentQProvisioningFlowCancelResult {
    stale,
    canceled,
};

enum class AgentQProvisioningFlowReturnToChoiceResult {
    stale,
    failed,
    started,
};

enum class AgentQProvisioningFlowConfirmBackupResult {
    stale,
    failed,
    started,
};

enum class AgentQProvisioningFlowImportNextResult {
    ignored,
    page_advanced,
    incomplete,
    checksum_failed,
    pin_setup_failed,
    pin_setup_started,
};

enum class AgentQProvisioningFlowCommitResult {
    ok,
    missing_input,
    storage_error,
};

enum class AgentQProvisioningFlowCommitFinishStatus {
    stale,
    failed,
    committed,
};

struct AgentQProvisioningFlowCommitFinishResult {
    AgentQProvisioningFlowCommitFinishStatus status;
    AgentQProvisioningFlowCommitResult commit_result;
};

using AgentQProvisioningFlowCommitSetupWithPreparedAuth =
    AgentQProvisioningFlowCommitResult (*)(
        const uint8_t* root_material,
        size_t root_material_size,
        const AgentQLocalAuthPreparedRecord* prepared_auth);

struct AgentQProvisioningFlowSnapshot {
    AgentQProvisioningFlowStage stage;
    uint8_t import_page;
    uint8_t import_active_slot;
    size_t pin_entry_length;
    bool flow_active;
    bool accepts_setup_pin_input;
    bool backup_phrase_confirmation_ready;
    bool import_current_page_complete;
    bool import_all_words_complete;
    AgentQTimeoutWindow input_window;
};

AgentQProvisioningFlowSnapshot provisioning_flow_snapshot();
bool provisioning_flow_active();
bool provisioning_flow_stage_is(AgentQProvisioningFlowStage stage);
bool provisioning_flow_stage_expired(TickType_t now);
bool provisioning_flow_commit_job_active(uint32_t job_id);

void provisioning_flow_wipe();
AgentQProvisioningFlowCleanupResult provisioning_flow_wipe_active();
void provisioning_flow_wipe_displayed_phrase_text();
bool provisioning_flow_handle_panel_deleted(AgentQProvisioningFlowPanel panel);
AgentQProvisioningFlowPanelLifetimeResult provisioning_flow_handle_panel_lifetime(
    AgentQProvisioningFlowPanel panel,
    bool panel_active,
    TickType_t now);
AgentQProvisioningFlowPanelLifetimeResult provisioning_flow_handle_pin_setup_lifetime(
    bool panel_active,
    TickType_t now);

bool provisioning_flow_begin_setup_choice(AgentQTimeoutWindow input_window);
bool provisioning_flow_setup_choice_action_allowed(TickType_t now);
AgentQProvisioningFlowGenerateResult provisioning_flow_begin_generate(
    TickType_t action_now,
    AgentQTimeoutWindow input_window);
AgentQProvisioningFlowImportStartResult provisioning_flow_begin_import_phrase(
    TickType_t action_now,
    AgentQTimeoutWindow input_window);

const char* provisioning_flow_backup_phrase();
const char* provisioning_flow_backup_phrase_prefix_cell(size_t index);

size_t provisioning_flow_import_global_word_slot();
size_t provisioning_flow_import_global_word_slot_for(uint8_t page, uint8_t slot);
const char* provisioning_flow_import_prefix(size_t global_slot);
bool provisioning_flow_import_word_selected(size_t global_slot);
bool provisioning_flow_import_current_page_complete();
bool provisioning_flow_import_all_words_complete();
bool provisioning_flow_word_starts_with_prefix(const char* word, const char* prefix);

bool provisioning_flow_import_select_slot(uint8_t slot, AgentQTimeoutWindow input_window);
bool provisioning_flow_import_add_letter(char letter, AgentQTimeoutWindow input_window);
bool provisioning_flow_import_clear_active(AgentQTimeoutWindow input_window);
bool provisioning_flow_import_select_candidate(uint16_t word_index, AgentQTimeoutWindow input_window);
bool provisioning_flow_import_previous_page(AgentQTimeoutWindow input_window);
bool provisioning_flow_import_next_page(AgentQTimeoutWindow input_window);
bool provisioning_flow_import_refresh_deadline(AgentQTimeoutWindow input_window);

AgentQProvisioningFlowCancelResult provisioning_flow_cancel_local_setup();
AgentQProvisioningFlowReturnToChoiceResult provisioning_flow_return_to_setup_choice(
    AgentQTimeoutWindow input_window);
AgentQProvisioningFlowConfirmBackupResult provisioning_flow_confirm_backup_phrase(
    AgentQTimeoutWindow input_window);
AgentQProvisioningFlowImportNextResult provisioning_flow_handle_import_next(
    AgentQTimeoutWindow import_input_window,
    AgentQTimeoutWindow pin_input_window);
bool provisioning_flow_add_pin_digit(char digit, AgentQTimeoutWindow input_window);
bool provisioning_flow_clear_pin_entry(AgentQTimeoutWindow input_window);
bool provisioning_flow_backspace_pin(AgentQTimeoutWindow input_window);
AgentQProvisioningFlowPinSubmitResult provisioning_flow_submit_pin(
    AgentQTimeoutWindow retry_window,
    TickType_t commit_ready_at,
    TickType_t worker_deadline);

AgentQProvisioningFlowCommitFinishResult provisioning_flow_finish_commit_worker_result(
    const AgentQLocalAuthWorkerResult& result,
    AgentQProvisioningFlowCommitSetupWithPreparedAuth commit_setup);

}  // namespace agent_q
