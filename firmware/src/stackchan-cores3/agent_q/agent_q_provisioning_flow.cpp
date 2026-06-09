#include "agent_q_provisioning_flow.h"

#include <stdio.h>
#include <string.h>

#include "agent_q_bip39_wordlist.h"
#include "agent_q_entropy.h"
#include "agent_q_local_auth.h"
#include "agent_q_root_material.h"

namespace agent_q {
namespace {

struct ProvisioningFlowState {
    uint8_t root_material[kRootMaterialBytes] = {};
    char backup_phrase[kBip39MnemonicMaxChars] = {};
    char backup_phrase_prefix_cells[kProvisioningFlowPhrasePrefixCellCount]
                                     [kProvisioningFlowPhrasePrefixCellSize] = {};
    uint16_t import_word_indices[kBip39MnemonicWordCount] = {};
    bool import_word_selected[kBip39MnemonicWordCount] = {};
    char import_prefixes[kBip39MnemonicWordCount][kProvisioningFlowImportPrefixBufferSize] = {};
    char pin_first[kLocalPinBufferSize] = {};
    char pin_entry[kLocalPinBufferSize] = {};
    size_t pin_entry_length = 0;
    uint32_t pin_commit_job_id = 0;
    uint8_t import_page = 0;
    uint8_t import_active_slot = 0;
    AgentQProvisioningFlowStage stage = AgentQProvisioningFlowStage::none;
    AgentQTimeoutWindow setup_choice_window = kAgentQTimeoutWindowNone;
    AgentQTimeoutWindow backup_phrase_window = kAgentQTimeoutWindowNone;
    AgentQTimeoutWindow import_word_window = kAgentQTimeoutWindowNone;
    AgentQTimeoutWindow pin_window = kAgentQTimeoutWindowNone;
    TickType_t pin_commit_ready_at = 0;
    TickType_t pin_commit_deadline = 0;

    void wipe_pin_only()
    {
        if (pin_commit_job_id != 0) {
            local_auth_worker_cancel_job(pin_commit_job_id);
        }
        wipe_sensitive_buffer(pin_first, sizeof(pin_first));
        wipe_sensitive_buffer(pin_entry, sizeof(pin_entry));
        pin_entry_length = 0;
        pin_commit_job_id = 0;
        pin_window = kAgentQTimeoutWindowNone;
        pin_commit_ready_at = 0;
        pin_commit_deadline = 0;
    }

    void wipe_displayed_phrase_text()
    {
        wipe_sensitive_buffer(backup_phrase, sizeof(backup_phrase));
        wipe_sensitive_buffer(
            backup_phrase_prefix_cells,
            kProvisioningFlowPhrasePrefixCellCount * kProvisioningFlowPhrasePrefixCellSize);
    }

    void wipe_import_word_entry()
    {
        wipe_sensitive_buffer(import_word_indices, sizeof(import_word_indices));
        wipe_sensitive_buffer(import_word_selected, sizeof(import_word_selected));
        wipe_sensitive_buffer(import_prefixes, sizeof(import_prefixes));
        import_page = 0;
        import_active_slot = 0;
        import_word_window = kAgentQTimeoutWindowNone;
    }

    void wipe()
    {
        wipe_sensitive_buffer(root_material, sizeof(root_material));
        wipe_displayed_phrase_text();
        wipe_import_word_entry();
        wipe_pin_only();
        stage = AgentQProvisioningFlowStage::none;
        setup_choice_window = kAgentQTimeoutWindowNone;
        backup_phrase_window = kAgentQTimeoutWindowNone;
    }
};

ProvisioningFlowState g_state;

bool deadline_reached(TickType_t now, TickType_t deadline)
{
    return deadline != 0 && static_cast<int32_t>(now - deadline) >= 0;
}

AgentQTimeoutWindow current_input_window()
{
    switch (g_state.stage) {
        case AgentQProvisioningFlowStage::setup_choice:
            return g_state.setup_choice_window;
        case AgentQProvisioningFlowStage::backup_phrase_displayed:
            return g_state.backup_phrase_window;
        case AgentQProvisioningFlowStage::import_word_entry:
            return g_state.import_word_window;
        case AgentQProvisioningFlowStage::pin_first_entry:
        case AgentQProvisioningFlowStage::pin_repeat_entry:
            return g_state.pin_window;
        case AgentQProvisioningFlowStage::none:
        case AgentQProvisioningFlowStage::pin_committing:
            return kAgentQTimeoutWindowNone;
    }
    return kAgentQTimeoutWindowNone;
}

void wipe_backup_phrase_prefix_cells(
    char cells[kProvisioningFlowPhrasePrefixCellCount][kProvisioningFlowPhrasePrefixCellSize])
{
    wipe_sensitive_buffer(
        cells, kProvisioningFlowPhrasePrefixCellCount * kProvisioningFlowPhrasePrefixCellSize);
}

bool format_backup_phrase_prefix_cells(
    const char* phrase,
    char cells[kProvisioningFlowPhrasePrefixCellCount][kProvisioningFlowPhrasePrefixCellSize])
{
    if (phrase == nullptr || cells == nullptr) {
        return false;
    }

    wipe_backup_phrase_prefix_cells(cells);
    size_t word_count = 0;
    const char* cursor = phrase;
    while (*cursor != '\0') {
        while (*cursor == ' ') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }

        char prefix[5] = {};
        size_t prefix_length = 0;
        while (*cursor != '\0' && *cursor != ' ') {
            if (prefix_length < 4) {
                prefix[prefix_length++] = *cursor;
            }
            cursor++;
        }
        word_count++;
        if (word_count > kBip39MnemonicWordCount) {
            wipe_backup_phrase_prefix_cells(cells);
            return false;
        }

        const int written = snprintf(
            cells[word_count - 1],
            kProvisioningFlowPhrasePrefixCellSize,
            "%s",
            prefix);
        if (written <= 0 ||
            static_cast<size_t>(written) >= kProvisioningFlowPhrasePrefixCellSize) {
            wipe_backup_phrase_prefix_cells(cells);
            return false;
        }
    }

    if (word_count != kBip39MnemonicWordCount) {
        wipe_backup_phrase_prefix_cells(cells);
        return false;
    }
    return true;
}

bool pin_setup_stage()
{
    return g_state.stage == AgentQProvisioningFlowStage::pin_first_entry ||
           g_state.stage == AgentQProvisioningFlowStage::pin_repeat_entry;
}

void reset_pin_entry(AgentQTimeoutWindow input_window)
{
    wipe_sensitive_buffer(g_state.pin_entry, sizeof(g_state.pin_entry));
    g_state.pin_entry_length = 0;
    g_state.pin_window = input_window;
}

void write_selected_word_prefix(size_t global_slot, uint16_t word_index)
{
    if (global_slot >= kBip39MnemonicWordCount) {
        return;
    }
    char* prefix = g_state.import_prefixes[global_slot];
    wipe_sensitive_buffer(prefix, kProvisioningFlowImportPrefixBufferSize);
    const char* word = bip39_english_word(word_index);
    if (word == nullptr) {
        return;
    }
    size_t index = 0;
    while (index < kProvisioningFlowImportPrefixMaxChars && word[index] != '\0') {
        prefix[index] = word[index];
        ++index;
    }
    prefix[index] = '\0';
}

}  // namespace

AgentQProvisioningFlowSnapshot provisioning_flow_snapshot()
{
    return {
        g_state.stage,
        g_state.import_page,
        g_state.import_active_slot,
        g_state.pin_entry_length,
        g_state.stage != AgentQProvisioningFlowStage::none,
        pin_setup_stage(),
        g_state.stage == AgentQProvisioningFlowStage::backup_phrase_displayed,
        provisioning_flow_import_current_page_complete(),
        provisioning_flow_import_all_words_complete(),
        current_input_window(),
    };
}

bool provisioning_flow_active()
{
    return g_state.stage != AgentQProvisioningFlowStage::none;
}

bool provisioning_flow_stage_is(AgentQProvisioningFlowStage stage)
{
    return g_state.stage == stage;
}

bool provisioning_flow_stage_expired(TickType_t now)
{
    switch (g_state.stage) {
        case AgentQProvisioningFlowStage::setup_choice:
            return timeout_window_reached(g_state.setup_choice_window, now);
        case AgentQProvisioningFlowStage::backup_phrase_displayed:
            return timeout_window_reached(g_state.backup_phrase_window, now);
        case AgentQProvisioningFlowStage::import_word_entry:
            return timeout_window_reached(g_state.import_word_window, now);
        case AgentQProvisioningFlowStage::pin_first_entry:
        case AgentQProvisioningFlowStage::pin_repeat_entry:
            return timeout_window_reached(g_state.pin_window, now);
        case AgentQProvisioningFlowStage::none:
        case AgentQProvisioningFlowStage::pin_committing:
            return false;
    }
    return false;
}

bool provisioning_flow_fail_pin_commit_if_expired(TickType_t now)
{
    if (g_state.stage != AgentQProvisioningFlowStage::pin_committing ||
        !deadline_reached(now, g_state.pin_commit_deadline)) {
        return false;
    }
    g_state.wipe();
    return true;
}

bool provisioning_flow_commit_job_active(uint32_t job_id)
{
    return job_id != 0 &&
           g_state.stage == AgentQProvisioningFlowStage::pin_committing &&
           g_state.pin_commit_job_id == job_id;
}

void provisioning_flow_wipe()
{
    g_state.wipe();
}

void provisioning_flow_wipe_displayed_phrase_text()
{
    g_state.wipe_displayed_phrase_text();
}

bool provisioning_flow_handle_panel_deleted(AgentQProvisioningFlowPanel panel)
{
    const bool matches =
        (panel == AgentQProvisioningFlowPanel::setup_choice &&
         g_state.stage == AgentQProvisioningFlowStage::setup_choice) ||
        (panel == AgentQProvisioningFlowPanel::backup_phrase_display &&
         g_state.stage == AgentQProvisioningFlowStage::backup_phrase_displayed) ||
        (panel == AgentQProvisioningFlowPanel::import_word_entry &&
         g_state.stage == AgentQProvisioningFlowStage::import_word_entry) ||
        (panel == AgentQProvisioningFlowPanel::pin_entry &&
         (pin_setup_stage() || g_state.stage == AgentQProvisioningFlowStage::pin_committing));
    if (!matches) {
        return false;
    }
    g_state.wipe();
    return true;
}

void provisioning_flow_begin_setup_choice(AgentQTimeoutWindow input_window)
{
    g_state.wipe();
    if (!timeout_window_valid(input_window)) {
        return;
    }
    g_state.stage = AgentQProvisioningFlowStage::setup_choice;
    g_state.setup_choice_window = input_window;
}

bool provisioning_flow_setup_choice_action_allowed(TickType_t now)
{
    return g_state.stage == AgentQProvisioningFlowStage::setup_choice &&
           timeout_window_open_at(g_state.setup_choice_window, now);
}

AgentQProvisioningFlowGenerateResult provisioning_flow_begin_generate(AgentQTimeoutWindow input_window)
{
    g_state.wipe();

    if (!timeout_window_valid(input_window)) {
        return AgentQProvisioningFlowGenerateResult::generation_error;
    }

    if (!fill_secure_random(g_state.root_material, sizeof(g_state.root_material))) {
        g_state.wipe();
        return AgentQProvisioningFlowGenerateResult::rng_error;
    }
    if (!make_bip39_mnemonic_12_words(
            g_state.root_material,
            g_state.backup_phrase,
            sizeof(g_state.backup_phrase)) ||
        !format_backup_phrase_prefix_cells(
            g_state.backup_phrase,
            g_state.backup_phrase_prefix_cells)) {
        g_state.wipe();
        return AgentQProvisioningFlowGenerateResult::generation_error;
    }

    g_state.stage = AgentQProvisioningFlowStage::backup_phrase_displayed;
    g_state.backup_phrase_window = input_window;
    return AgentQProvisioningFlowGenerateResult::ok;
}

void provisioning_flow_begin_import_phrase(AgentQTimeoutWindow input_window)
{
    g_state.wipe();
    if (!timeout_window_valid(input_window)) {
        return;
    }
    g_state.stage = AgentQProvisioningFlowStage::import_word_entry;
    g_state.import_page = 0;
    g_state.import_active_slot = 0;
    g_state.import_word_window = input_window;
}

const char* provisioning_flow_backup_phrase()
{
    return g_state.backup_phrase;
}

const char* provisioning_flow_backup_phrase_prefix_cell(size_t index)
{
    if (index >= kProvisioningFlowPhrasePrefixCellCount) {
        return "";
    }
    return g_state.backup_phrase_prefix_cells[index];
}

size_t provisioning_flow_import_global_word_slot()
{
    return provisioning_flow_import_global_word_slot_for(
        g_state.import_page,
        g_state.import_active_slot);
}

size_t provisioning_flow_import_global_word_slot_for(uint8_t page, uint8_t slot)
{
    return static_cast<size_t>(page) * kProvisioningFlowImportWordsPerPage + slot;
}

const char* provisioning_flow_import_prefix(size_t global_slot)
{
    if (global_slot >= kBip39MnemonicWordCount) {
        return "";
    }
    return g_state.import_prefixes[global_slot];
}

bool provisioning_flow_import_word_selected(size_t global_slot)
{
    return global_slot < kBip39MnemonicWordCount && g_state.import_word_selected[global_slot];
}

bool provisioning_flow_import_current_page_complete()
{
    if (g_state.import_page >= kProvisioningFlowImportPageCount) {
        return false;
    }
    for (size_t slot = 0; slot < kProvisioningFlowImportWordsPerPage; ++slot) {
        const size_t global_slot =
            provisioning_flow_import_global_word_slot_for(g_state.import_page, slot);
        if (global_slot >= kBip39MnemonicWordCount || !g_state.import_word_selected[global_slot]) {
            return false;
        }
    }
    return true;
}

bool provisioning_flow_import_all_words_complete()
{
    for (size_t index = 0; index < kBip39MnemonicWordCount; ++index) {
        if (!g_state.import_word_selected[index]) {
            return false;
        }
    }
    return true;
}

bool provisioning_flow_word_starts_with_prefix(const char* word, const char* prefix)
{
    if (word == nullptr || prefix == nullptr || prefix[0] == '\0') {
        return false;
    }
    for (size_t index = 0; prefix[index] != '\0'; ++index) {
        if (word[index] != prefix[index]) {
            return false;
        }
    }
    return true;
}

bool provisioning_flow_import_select_slot(uint8_t slot, AgentQTimeoutWindow input_window)
{
    if (g_state.stage != AgentQProvisioningFlowStage::import_word_entry ||
        slot >= kProvisioningFlowImportWordsPerPage ||
        !timeout_window_valid(input_window)) {
        return false;
    }
    g_state.import_active_slot = slot;
    g_state.import_word_window = input_window;
    return true;
}

bool provisioning_flow_import_add_letter(char letter, AgentQTimeoutWindow input_window)
{
    if (g_state.stage != AgentQProvisioningFlowStage::import_word_entry ||
        letter < 'a' || letter > 'z' ||
        !timeout_window_valid(input_window)) {
        return false;
    }
    const size_t global_slot = provisioning_flow_import_global_word_slot();
    if (global_slot >= kBip39MnemonicWordCount) {
        return false;
    }
    char* prefix = g_state.import_prefixes[global_slot];
    size_t length = strlen(prefix);
    if (length >= kProvisioningFlowImportPrefixMaxChars) {
        g_state.import_word_window = input_window;
        return true;
    }
    prefix[length++] = letter;
    prefix[length] = '\0';
    g_state.import_word_selected[global_slot] = false;
    g_state.import_word_indices[global_slot] = 0;
    g_state.import_word_window = input_window;
    return true;
}

bool provisioning_flow_import_clear_active(AgentQTimeoutWindow input_window)
{
    if (g_state.stage != AgentQProvisioningFlowStage::import_word_entry ||
        !timeout_window_valid(input_window)) {
        return false;
    }
    const size_t global_slot = provisioning_flow_import_global_word_slot();
    if (global_slot >= kBip39MnemonicWordCount) {
        return false;
    }
    wipe_sensitive_buffer(g_state.import_prefixes[global_slot], kProvisioningFlowImportPrefixBufferSize);
    g_state.import_word_selected[global_slot] = false;
    g_state.import_word_indices[global_slot] = 0;
    g_state.import_word_window = input_window;
    return true;
}

bool provisioning_flow_import_select_candidate(uint16_t word_index, AgentQTimeoutWindow input_window)
{
    if (g_state.stage != AgentQProvisioningFlowStage::import_word_entry ||
        word_index >= kBip39WordCount ||
        bip39_english_word(word_index) == nullptr ||
        !timeout_window_valid(input_window)) {
        return false;
    }
    const size_t global_slot = provisioning_flow_import_global_word_slot();
    if (global_slot >= kBip39MnemonicWordCount) {
        return false;
    }
    g_state.import_word_indices[global_slot] = word_index;
    g_state.import_word_selected[global_slot] = true;
    write_selected_word_prefix(global_slot, word_index);
    if (g_state.import_active_slot + 1 < kProvisioningFlowImportWordsPerPage) {
        ++g_state.import_active_slot;
    }
    g_state.import_word_window = input_window;
    return true;
}

bool provisioning_flow_import_previous_page(AgentQTimeoutWindow input_window)
{
    if (g_state.stage != AgentQProvisioningFlowStage::import_word_entry ||
        g_state.import_page == 0 ||
        !timeout_window_valid(input_window)) {
        return false;
    }
    --g_state.import_page;
    g_state.import_active_slot = 0;
    g_state.import_word_window = input_window;
    return true;
}

bool provisioning_flow_import_next_page(AgentQTimeoutWindow input_window)
{
    if (g_state.stage != AgentQProvisioningFlowStage::import_word_entry ||
        !provisioning_flow_import_current_page_complete() ||
        !timeout_window_valid(input_window)) {
        return false;
    }
    if (g_state.import_page + 1 >= kProvisioningFlowImportPageCount) {
        return false;
    }
    ++g_state.import_page;
    g_state.import_active_slot = 0;
    g_state.import_word_window = input_window;
    return true;
}

bool provisioning_flow_import_refresh_deadline(AgentQTimeoutWindow input_window)
{
    if (g_state.stage != AgentQProvisioningFlowStage::import_word_entry ||
        !timeout_window_valid(input_window)) {
        return false;
    }
    g_state.import_word_window = input_window;
    return true;
}

Bip39EntropyDecodeResult provisioning_flow_decode_entropy_from_words()
{
    if (g_state.stage != AgentQProvisioningFlowStage::import_word_entry ||
        !provisioning_flow_import_all_words_complete()) {
        return Bip39EntropyDecodeResult::invalid_word_count;
    }
    const Bip39EntropyDecodeResult result = decode_bip39_entropy_12_words(
        g_state.import_word_indices,
        kBip39MnemonicWordCount,
        g_state.root_material,
        sizeof(g_state.root_material));
    if (result != Bip39EntropyDecodeResult::ok) {
        wipe_sensitive_buffer(g_state.root_material, sizeof(g_state.root_material));
    }
    return result;
}

bool provisioning_flow_begin_pin_setup_from_displayed_phrase(AgentQTimeoutWindow input_window)
{
    if (g_state.stage != AgentQProvisioningFlowStage::backup_phrase_displayed ||
        !timeout_window_valid(input_window)) {
        return false;
    }
    g_state.stage = AgentQProvisioningFlowStage::pin_first_entry;
    g_state.wipe_pin_only();
    g_state.pin_window = input_window;
    g_state.wipe_displayed_phrase_text();
    return true;
}

void provisioning_flow_begin_pin_setup_after_import(AgentQTimeoutWindow input_window)
{
    if (!timeout_window_valid(input_window)) {
        g_state.wipe();
        return;
    }
    g_state.stage = AgentQProvisioningFlowStage::pin_first_entry;
    g_state.wipe_import_word_entry();
    g_state.wipe_pin_only();
    g_state.pin_window = input_window;
}

bool provisioning_flow_add_pin_digit(char digit, AgentQTimeoutWindow input_window)
{
    if (!pin_setup_stage() || digit < '0' || digit > '9' ||
        !timeout_window_valid(input_window)) {
        return false;
    }
    if (g_state.pin_entry_length >= kLocalPinDigits) {
        g_state.pin_window = input_window;
        return true;
    }
    g_state.pin_entry[g_state.pin_entry_length++] = digit;
    g_state.pin_entry[g_state.pin_entry_length] = '\0';
    g_state.pin_window = input_window;
    return true;
}

bool provisioning_flow_clear_pin_entry(AgentQTimeoutWindow input_window)
{
    if (!pin_setup_stage() || !timeout_window_valid(input_window)) {
        return false;
    }
    reset_pin_entry(input_window);
    return true;
}

bool provisioning_flow_backspace_pin(AgentQTimeoutWindow input_window)
{
    if (!pin_setup_stage() || !timeout_window_valid(input_window)) {
        return false;
    }
    if (g_state.pin_entry_length > 0) {
        g_state.pin_entry[--g_state.pin_entry_length] = '\0';
    }
    g_state.pin_window = input_window;
    return true;
}

AgentQProvisioningFlowPinSubmitResult provisioning_flow_submit_pin(
    AgentQTimeoutWindow retry_window,
    TickType_t commit_ready_at,
    TickType_t worker_deadline)
{
    if (!pin_setup_stage()) {
        return AgentQProvisioningFlowPinSubmitResult::inactive;
    }
    if (!timeout_window_valid(retry_window)) {
        return AgentQProvisioningFlowPinSubmitResult::inactive;
    }
    if (g_state.pin_entry_length != kLocalPinDigits || !is_valid_local_pin(g_state.pin_entry)) {
        g_state.pin_window = retry_window;
        return AgentQProvisioningFlowPinSubmitResult::invalid_pin;
    }

    if (g_state.stage == AgentQProvisioningFlowStage::pin_first_entry) {
        snprintf(g_state.pin_first, sizeof(g_state.pin_first), "%s", g_state.pin_entry);
        wipe_sensitive_buffer(g_state.pin_entry, sizeof(g_state.pin_entry));
        g_state.pin_entry_length = 0;
        g_state.stage = AgentQProvisioningFlowStage::pin_repeat_entry;
        g_state.pin_window = retry_window;
        return AgentQProvisioningFlowPinSubmitResult::advanced_to_repeat;
    }

    if (strcmp(g_state.pin_first, g_state.pin_entry) != 0) {
        wipe_sensitive_buffer(g_state.pin_first, sizeof(g_state.pin_first));
        wipe_sensitive_buffer(g_state.pin_entry, sizeof(g_state.pin_entry));
        g_state.pin_entry_length = 0;
        g_state.stage = AgentQProvisioningFlowStage::pin_first_entry;
        g_state.pin_window = retry_window;
        return AgentQProvisioningFlowPinSubmitResult::mismatch_restart;
    }

    uint32_t job_id = 0;
    if (!local_auth_worker_submit_prepare_verifier(
            AgentQLocalAuthWorkerOwner::provisioning_setup,
                g_state.pin_entry,
            &job_id)) {
        g_state.pin_window = retry_window;
        return AgentQProvisioningFlowPinSubmitResult::worker_unavailable;
    }

    g_state.stage = AgentQProvisioningFlowStage::pin_committing;
    g_state.pin_commit_job_id = job_id;
    g_state.pin_commit_ready_at = commit_ready_at;
    g_state.pin_commit_deadline = worker_deadline;
    g_state.pin_window = kAgentQTimeoutWindowNone;
    wipe_sensitive_buffer(g_state.pin_first, sizeof(g_state.pin_first));
    wipe_sensitive_buffer(g_state.pin_entry, sizeof(g_state.pin_entry));
    g_state.pin_entry_length = 0;
    return AgentQProvisioningFlowPinSubmitResult::commit_started;
}

bool provisioning_flow_commit_worker_result(
    const AgentQLocalAuthWorkerResult& result,
    const uint8_t** root_material,
    size_t* root_material_size,
    const AgentQLocalAuthPreparedRecord** prepared_auth)
{
    if (root_material == nullptr || root_material_size == nullptr || prepared_auth == nullptr ||
        result.owner != AgentQLocalAuthWorkerOwner::provisioning_setup ||
        result.operation != AgentQLocalAuthWorkerOperation::prepare_verifier_record ||
        !provisioning_flow_commit_job_active(result.job_id)) {
        return false;
    }
    g_state.pin_commit_job_id = 0;
    g_state.pin_commit_deadline = 0;
    if (result.status != AgentQLocalAuthWorkerStatus::ok) {
        return false;
    }
    *root_material = g_state.root_material;
    *root_material_size = sizeof(g_state.root_material);
    *prepared_auth = &result.prepared_record;
    return true;
}

}  // namespace agent_q
