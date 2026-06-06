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
constexpr size_t kProvisioningFlowRecoverWordsPerPage = 3;
constexpr size_t kProvisioningFlowRecoverPageCount =
    kBip39MnemonicWordCount / kProvisioningFlowRecoverWordsPerPage;
constexpr size_t kProvisioningFlowRecoverPrefixMaxChars = 4;
constexpr size_t kProvisioningFlowRecoverPrefixBufferSize =
    kProvisioningFlowRecoverPrefixMaxChars + 1;

enum class AgentQProvisioningFlowStage {
    none,
    setup_choice,
    recovery_phrase_displayed,
    recover_word_entry,
    pin_first_entry,
    pin_repeat_entry,
    pin_committing,
};

enum class AgentQProvisioningFlowPanel {
    setup_choice,
    recovery_phrase_display,
    recovery_word_entry,
    pin_entry,
};

enum class AgentQProvisioningFlowGenerateResult {
    ok,
    rng_error,
    generation_error,
};

enum class AgentQProvisioningFlowPinSubmitResult {
    inactive,
    invalid_pin,
    worker_unavailable,
    advanced_to_repeat,
    mismatch_restart,
    commit_started,
};

struct AgentQProvisioningFlowSnapshot {
    AgentQProvisioningFlowStage stage;
    uint8_t recover_page;
    uint8_t recover_active_slot;
    size_t pin_entry_length;
    bool flow_active;
    bool accepts_setup_pin_input;
    bool recovery_phrase_confirmation_ready;
    bool recover_current_page_complete;
    bool recover_all_words_complete;
    AgentQTimeoutWindow input_window;
};

AgentQProvisioningFlowSnapshot provisioning_flow_snapshot();
AgentQProvisioningFlowStage provisioning_flow_stage();
bool provisioning_flow_active();
bool provisioning_flow_stage_is(AgentQProvisioningFlowStage stage);
bool provisioning_flow_stage_expired(TickType_t now);
bool provisioning_flow_fail_pin_commit_if_expired(TickType_t now);
bool provisioning_flow_commit_job_active(uint32_t job_id);

void provisioning_flow_wipe();
void provisioning_flow_wipe_displayed_phrase_text();
bool provisioning_flow_handle_panel_deleted(AgentQProvisioningFlowPanel panel);

void provisioning_flow_begin_setup_choice(AgentQTimeoutWindow input_window);
bool provisioning_flow_setup_choice_action_allowed(TickType_t now);
AgentQProvisioningFlowGenerateResult provisioning_flow_begin_generate(AgentQTimeoutWindow input_window);
void provisioning_flow_begin_recover(AgentQTimeoutWindow input_window);

const char* provisioning_flow_recovery_phrase();
const char* provisioning_flow_recovery_phrase_prefix_cell(size_t index);

size_t provisioning_flow_recover_global_word_slot();
size_t provisioning_flow_recover_global_word_slot_for(uint8_t page, uint8_t slot);
const char* provisioning_flow_recover_prefix(size_t global_slot);
bool provisioning_flow_recover_word_selected(size_t global_slot);
bool provisioning_flow_recover_current_page_complete();
bool provisioning_flow_recover_all_words_complete();
bool provisioning_flow_word_starts_with_prefix(const char* word, const char* prefix);

bool provisioning_flow_recover_select_slot(uint8_t slot, AgentQTimeoutWindow input_window);
bool provisioning_flow_recover_add_letter(char letter, AgentQTimeoutWindow input_window);
bool provisioning_flow_recover_clear_active(AgentQTimeoutWindow input_window);
bool provisioning_flow_recover_select_candidate(uint16_t word_index, AgentQTimeoutWindow input_window);
bool provisioning_flow_recover_previous_page(AgentQTimeoutWindow input_window);
bool provisioning_flow_recover_next_page(AgentQTimeoutWindow input_window);
bool provisioning_flow_recover_refresh_deadline(AgentQTimeoutWindow input_window);
Bip39EntropyRecoveryResult provisioning_flow_recover_entropy_from_words();

bool provisioning_flow_begin_pin_setup_from_displayed_phrase(AgentQTimeoutWindow input_window);
void provisioning_flow_begin_pin_setup_after_recovery(AgentQTimeoutWindow input_window);
bool provisioning_flow_add_pin_digit(char digit, AgentQTimeoutWindow input_window);
bool provisioning_flow_clear_pin_entry(AgentQTimeoutWindow input_window);
bool provisioning_flow_backspace_pin(AgentQTimeoutWindow input_window);
AgentQProvisioningFlowPinSubmitResult provisioning_flow_submit_pin(
    AgentQTimeoutWindow retry_window,
    TickType_t commit_ready_at,
    TickType_t worker_deadline);

bool provisioning_flow_commit_inputs(
    const uint8_t** root_material,
    size_t* root_material_size);
bool provisioning_flow_commit_worker_result(
    const AgentQLocalAuthWorkerResult& result,
    const uint8_t** root_material,
    size_t* root_material_size,
    const AgentQLocalAuthPreparedRecord** prepared_auth);

}  // namespace agent_q
