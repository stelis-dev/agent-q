#pragma once

#include <stddef.h>
#include <stdint.h>

#include "bip39.h"
#include "local_auth_worker.h"
#include "transport/timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace signing {

constexpr size_t kProvisioningFlowPhrasePrefixCellCount = kBip39MnemonicWordCount;
constexpr size_t kProvisioningFlowPhrasePrefixCellSize = 8;
constexpr size_t kProvisioningFlowImportWordsPerPage = 3;
constexpr size_t kProvisioningFlowImportPageCount =
    kBip39MnemonicWordCount / kProvisioningFlowImportWordsPerPage;
constexpr size_t kProvisioningFlowImportPrefixMaxChars = 4;
constexpr size_t kProvisioningFlowImportPrefixBufferSize =
    kProvisioningFlowImportPrefixMaxChars + 1;

enum class ProvisioningFlowStage {
    none,
    setup_choice,
    backup_phrase_displayed,
    import_word_entry,
    pin_first_entry,
    pin_repeat_entry,
    pin_committing,
};

enum class ProvisioningFlowPanel {
    setup_choice,
    backup_phrase_display,
    import_word_entry,
    pin_entry,
};

enum class ProvisioningFlowGenerateResult {
    stale,
    ok,
    rng_error,
    generation_error,
};

enum class ProvisioningFlowImportStartResult {
    stale,
    failed,
    started,
};

enum class ProvisioningFlowPinSubmitResult {
    inactive,
    invalid_pin,
    worker_unavailable,
    advanced_to_repeat,
    mismatch_restart,
    commit_started,
};

enum class ProvisioningFlowCleanupResult {
    inactive,
    wiped,
    commit_in_progress,
};

enum class ProvisioningFlowPanelLifetimeResult {
    unchanged,
    clear_panel_timeout,
    clear_panel_preserve_timeout,
    wiped_panel_lost,
    wiped_panel_lost_timeout,
};

enum class ProvisioningFlowCancelResult {
    stale,
    canceled,
};

enum class ProvisioningFlowReturnToChoiceResult {
    stale,
    failed,
    started,
};

enum class ProvisioningFlowConfirmBackupResult {
    stale,
    failed,
    started,
};

enum class ProvisioningFlowImportNextResult {
    ignored,
    page_advanced,
    incomplete,
    checksum_failed,
    pin_setup_failed,
    pin_setup_started,
};

enum class ProvisioningFlowCommitResult {
    ok,
    missing_input,
    storage_error,
};

enum class ProvisioningFlowCommitFinishStatus {
    stale,
    failed,
    committed,
};

struct ProvisioningFlowCommitFinishResult {
    ProvisioningFlowCommitFinishStatus status;
    ProvisioningFlowCommitResult commit_result;
};

using ProvisioningFlowCommitSetup =
    ProvisioningFlowCommitResult (*)(
        const uint8_t* root_material,
        size_t root_material_size);
using ProvisioningFlowRollbackSetup = bool (*)();

struct ProvisioningFlowSnapshot {
    ProvisioningFlowStage stage;
    uint8_t import_page;
    uint8_t import_active_slot;
    size_t pin_entry_length;
    bool flow_active;
    bool accepts_setup_pin_input;
    bool backup_phrase_confirmation_ready;
    bool import_current_page_complete;
    bool import_all_words_complete;
    TimeoutWindow input_window;
};

ProvisioningFlowSnapshot provisioning_flow_snapshot();
bool provisioning_flow_active();
bool provisioning_flow_stage_is(ProvisioningFlowStage stage);
bool provisioning_flow_stage_expired(TickType_t now);
bool provisioning_flow_commit_job_active(uint32_t job_id);

bool provisioning_flow_wipe();
ProvisioningFlowCleanupResult provisioning_flow_wipe_active();
void provisioning_flow_wipe_displayed_phrase_text();
bool provisioning_flow_handle_panel_deleted(ProvisioningFlowPanel panel);
ProvisioningFlowPanelLifetimeResult provisioning_flow_handle_panel_lifetime(
    ProvisioningFlowPanel panel,
    bool panel_active,
    TickType_t now);
ProvisioningFlowPanelLifetimeResult provisioning_flow_handle_pin_setup_lifetime(
    bool panel_active,
    TickType_t now);

bool provisioning_flow_begin_setup_choice(TimeoutWindow input_window);
bool provisioning_flow_setup_choice_action_allowed(TickType_t now);
ProvisioningFlowGenerateResult provisioning_flow_begin_generate(
    TickType_t action_now,
    TimeoutWindow input_window);
ProvisioningFlowImportStartResult provisioning_flow_begin_import_phrase(
    TickType_t action_now,
    TimeoutWindow input_window);

const char* provisioning_flow_backup_phrase();
const char* provisioning_flow_backup_phrase_prefix_cell(size_t index);

size_t provisioning_flow_import_global_word_slot();
size_t provisioning_flow_import_global_word_slot_for(uint8_t page, uint8_t slot);
const char* provisioning_flow_import_prefix(size_t global_slot);
bool provisioning_flow_import_word_selected(size_t global_slot);
bool provisioning_flow_import_current_page_complete();
bool provisioning_flow_import_all_words_complete();
bool provisioning_flow_word_starts_with_prefix(const char* word, const char* prefix);

bool provisioning_flow_import_select_slot(uint8_t slot, TimeoutWindow input_window);
bool provisioning_flow_import_add_letter(char letter, TimeoutWindow input_window);
bool provisioning_flow_import_clear_active(TimeoutWindow input_window);
bool provisioning_flow_import_select_candidate(uint16_t word_index, TimeoutWindow input_window);
bool provisioning_flow_import_previous_page(TimeoutWindow input_window);
bool provisioning_flow_import_next_page(TimeoutWindow input_window);
bool provisioning_flow_import_refresh_deadline(TimeoutWindow input_window);

ProvisioningFlowCancelResult provisioning_flow_cancel_local_setup();
ProvisioningFlowReturnToChoiceResult provisioning_flow_return_to_setup_choice(
    TimeoutWindow input_window);
ProvisioningFlowConfirmBackupResult provisioning_flow_confirm_backup_phrase(
    TimeoutWindow input_window);
ProvisioningFlowImportNextResult provisioning_flow_handle_import_next(
    TimeoutWindow import_input_window,
    TimeoutWindow pin_input_window);
bool provisioning_flow_add_pin_digit(char digit, TimeoutWindow input_window);
bool provisioning_flow_clear_pin_entry(TimeoutWindow input_window);
bool provisioning_flow_backspace_pin(TimeoutWindow input_window);
ProvisioningFlowPinSubmitResult provisioning_flow_submit_pin(
    TimeoutWindow retry_window,
    TickType_t commit_ready_at);

ProvisioningFlowCommitFinishResult provisioning_flow_finish_commit_worker_result(
    const LocalAuthWorkerResult& result,
    ProvisioningFlowCommitSetup commit_setup,
    ProvisioningFlowRollbackSetup rollback_setup);

}  // namespace signing
