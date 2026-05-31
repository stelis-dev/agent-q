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
    char recovery_phrase[kBip39MnemonicMaxChars] = {};
    char recovery_phrase_prefix_cells[kProvisioningFlowPhrasePrefixCellCount]
                                     [kProvisioningFlowPhrasePrefixCellSize] = {};
    uint16_t recover_word_indices[kBip39MnemonicWordCount] = {};
    bool recover_word_selected[kBip39MnemonicWordCount] = {};
    char recover_prefixes[kBip39MnemonicWordCount][kProvisioningFlowRecoverPrefixBufferSize] = {};
    char pin_first[kLocalPinBufferSize] = {};
    char pin_entry[kLocalPinBufferSize] = {};
    size_t pin_entry_length = 0;
    uint8_t recover_page = 0;
    uint8_t recover_active_slot = 0;
    AgentQProvisioningFlowStage stage = AgentQProvisioningFlowStage::none;
    TickType_t setup_choice_deadline = 0;
    TickType_t recovery_phrase_deadline = 0;
    TickType_t recover_word_deadline = 0;
    TickType_t pin_deadline = 0;
    TickType_t pin_commit_ready_at = 0;

    void wipe_pin_only()
    {
        wipe_sensitive_buffer(pin_first, sizeof(pin_first));
        wipe_sensitive_buffer(pin_entry, sizeof(pin_entry));
        pin_entry_length = 0;
        pin_deadline = 0;
        pin_commit_ready_at = 0;
    }

    void wipe_displayed_phrase_text()
    {
        wipe_sensitive_buffer(recovery_phrase, sizeof(recovery_phrase));
        wipe_sensitive_buffer(
            recovery_phrase_prefix_cells,
            kProvisioningFlowPhrasePrefixCellCount * kProvisioningFlowPhrasePrefixCellSize);
    }

    void wipe_recover_word_entry()
    {
        wipe_sensitive_buffer(recover_word_indices, sizeof(recover_word_indices));
        wipe_sensitive_buffer(recover_word_selected, sizeof(recover_word_selected));
        wipe_sensitive_buffer(recover_prefixes, sizeof(recover_prefixes));
        recover_page = 0;
        recover_active_slot = 0;
        recover_word_deadline = 0;
    }

    void wipe()
    {
        wipe_sensitive_buffer(root_material, sizeof(root_material));
        wipe_displayed_phrase_text();
        wipe_recover_word_entry();
        wipe_pin_only();
        stage = AgentQProvisioningFlowStage::none;
        setup_choice_deadline = 0;
        recovery_phrase_deadline = 0;
    }
};

ProvisioningFlowState g_state;

bool deadline_reached(TickType_t now, TickType_t deadline)
{
    return deadline != 0 && static_cast<int32_t>(now - deadline) >= 0;
}

void wipe_recovery_phrase_prefix_cells(
    char cells[kProvisioningFlowPhrasePrefixCellCount][kProvisioningFlowPhrasePrefixCellSize])
{
    wipe_sensitive_buffer(
        cells, kProvisioningFlowPhrasePrefixCellCount * kProvisioningFlowPhrasePrefixCellSize);
}

bool format_recovery_phrase_prefix_cells(
    const char* phrase,
    char cells[kProvisioningFlowPhrasePrefixCellCount][kProvisioningFlowPhrasePrefixCellSize])
{
    if (phrase == nullptr || cells == nullptr) {
        return false;
    }

    wipe_recovery_phrase_prefix_cells(cells);
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
            wipe_recovery_phrase_prefix_cells(cells);
            return false;
        }

        const int written = snprintf(
            cells[word_count - 1],
            kProvisioningFlowPhrasePrefixCellSize,
            "%s",
            prefix);
        if (written <= 0 ||
            static_cast<size_t>(written) >= kProvisioningFlowPhrasePrefixCellSize) {
            wipe_recovery_phrase_prefix_cells(cells);
            return false;
        }
    }

    if (word_count != kBip39MnemonicWordCount) {
        wipe_recovery_phrase_prefix_cells(cells);
        return false;
    }
    return true;
}

bool pin_setup_stage()
{
    return g_state.stage == AgentQProvisioningFlowStage::pin_first_entry ||
           g_state.stage == AgentQProvisioningFlowStage::pin_repeat_entry;
}

void reset_pin_entry(TickType_t deadline)
{
    wipe_sensitive_buffer(g_state.pin_entry, sizeof(g_state.pin_entry));
    g_state.pin_entry_length = 0;
    g_state.pin_deadline = deadline;
}

void write_selected_word_prefix(size_t global_slot, uint16_t word_index)
{
    if (global_slot >= kBip39MnemonicWordCount) {
        return;
    }
    char* prefix = g_state.recover_prefixes[global_slot];
    wipe_sensitive_buffer(prefix, kProvisioningFlowRecoverPrefixBufferSize);
    const char* word = bip39_english_word(word_index);
    if (word == nullptr) {
        return;
    }
    size_t index = 0;
    while (index < kProvisioningFlowRecoverPrefixMaxChars && word[index] != '\0') {
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
        g_state.recover_page,
        g_state.recover_active_slot,
        g_state.pin_entry_length,
        g_state.stage != AgentQProvisioningFlowStage::none,
        pin_setup_stage(),
        g_state.stage == AgentQProvisioningFlowStage::recovery_phrase_displayed,
        provisioning_flow_recover_current_page_complete(),
        provisioning_flow_recover_all_words_complete(),
    };
}

AgentQProvisioningFlowStage provisioning_flow_stage()
{
    return g_state.stage;
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
            return deadline_reached(now, g_state.setup_choice_deadline);
        case AgentQProvisioningFlowStage::recovery_phrase_displayed:
            return deadline_reached(now, g_state.recovery_phrase_deadline);
        case AgentQProvisioningFlowStage::recover_word_entry:
            return deadline_reached(now, g_state.recover_word_deadline);
        case AgentQProvisioningFlowStage::pin_first_entry:
        case AgentQProvisioningFlowStage::pin_repeat_entry:
            return deadline_reached(now, g_state.pin_deadline);
        case AgentQProvisioningFlowStage::none:
        case AgentQProvisioningFlowStage::pin_committing:
            return false;
    }
    return false;
}

bool provisioning_flow_commit_ready(TickType_t now)
{
    return g_state.stage == AgentQProvisioningFlowStage::pin_committing &&
           deadline_reached(now, g_state.pin_commit_ready_at);
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
        (panel == AgentQProvisioningFlowPanel::recovery_phrase_display &&
         g_state.stage == AgentQProvisioningFlowStage::recovery_phrase_displayed) ||
        (panel == AgentQProvisioningFlowPanel::recovery_word_entry &&
         g_state.stage == AgentQProvisioningFlowStage::recover_word_entry) ||
        (panel == AgentQProvisioningFlowPanel::pin_entry && pin_setup_stage());
    if (!matches) {
        return false;
    }
    g_state.wipe();
    return true;
}

void provisioning_flow_begin_setup_choice(TickType_t deadline)
{
    g_state.wipe();
    g_state.stage = AgentQProvisioningFlowStage::setup_choice;
    g_state.setup_choice_deadline = deadline;
}

bool provisioning_flow_setup_choice_action_allowed(TickType_t now)
{
    return g_state.stage == AgentQProvisioningFlowStage::setup_choice &&
           g_state.setup_choice_deadline != 0 &&
           !deadline_reached(now, g_state.setup_choice_deadline);
}

AgentQProvisioningFlowGenerateResult provisioning_flow_begin_generate(TickType_t deadline)
{
    g_state.wipe();

    if (!fill_secure_random(g_state.root_material, sizeof(g_state.root_material))) {
        g_state.wipe();
        return AgentQProvisioningFlowGenerateResult::rng_error;
    }
    if (!make_bip39_mnemonic_12_words(
            g_state.root_material,
            g_state.recovery_phrase,
            sizeof(g_state.recovery_phrase)) ||
        !format_recovery_phrase_prefix_cells(
            g_state.recovery_phrase,
            g_state.recovery_phrase_prefix_cells)) {
        g_state.wipe();
        return AgentQProvisioningFlowGenerateResult::generation_error;
    }

    g_state.stage = AgentQProvisioningFlowStage::recovery_phrase_displayed;
    g_state.recovery_phrase_deadline = deadline;
    return AgentQProvisioningFlowGenerateResult::ok;
}

void provisioning_flow_begin_recover(TickType_t deadline)
{
    g_state.wipe();
    g_state.stage = AgentQProvisioningFlowStage::recover_word_entry;
    g_state.recover_page = 0;
    g_state.recover_active_slot = 0;
    g_state.recover_word_deadline = deadline;
}

const char* provisioning_flow_recovery_phrase()
{
    return g_state.recovery_phrase;
}

const char* provisioning_flow_recovery_phrase_prefix_cell(size_t index)
{
    if (index >= kProvisioningFlowPhrasePrefixCellCount) {
        return "";
    }
    return g_state.recovery_phrase_prefix_cells[index];
}

size_t provisioning_flow_recover_global_word_slot()
{
    return provisioning_flow_recover_global_word_slot_for(
        g_state.recover_page,
        g_state.recover_active_slot);
}

size_t provisioning_flow_recover_global_word_slot_for(uint8_t page, uint8_t slot)
{
    return static_cast<size_t>(page) * kProvisioningFlowRecoverWordsPerPage + slot;
}

const char* provisioning_flow_recover_prefix(size_t global_slot)
{
    if (global_slot >= kBip39MnemonicWordCount) {
        return "";
    }
    return g_state.recover_prefixes[global_slot];
}

bool provisioning_flow_recover_word_selected(size_t global_slot)
{
    return global_slot < kBip39MnemonicWordCount && g_state.recover_word_selected[global_slot];
}

bool provisioning_flow_recover_current_page_complete()
{
    if (g_state.recover_page >= kProvisioningFlowRecoverPageCount) {
        return false;
    }
    for (size_t slot = 0; slot < kProvisioningFlowRecoverWordsPerPage; ++slot) {
        const size_t global_slot =
            provisioning_flow_recover_global_word_slot_for(g_state.recover_page, slot);
        if (global_slot >= kBip39MnemonicWordCount || !g_state.recover_word_selected[global_slot]) {
            return false;
        }
    }
    return true;
}

bool provisioning_flow_recover_all_words_complete()
{
    for (size_t index = 0; index < kBip39MnemonicWordCount; ++index) {
        if (!g_state.recover_word_selected[index]) {
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

bool provisioning_flow_recover_select_slot(uint8_t slot, TickType_t deadline)
{
    if (g_state.stage != AgentQProvisioningFlowStage::recover_word_entry ||
        slot >= kProvisioningFlowRecoverWordsPerPage) {
        return false;
    }
    g_state.recover_active_slot = slot;
    g_state.recover_word_deadline = deadline;
    return true;
}

bool provisioning_flow_recover_add_letter(char letter, TickType_t deadline)
{
    if (g_state.stage != AgentQProvisioningFlowStage::recover_word_entry ||
        letter < 'a' || letter > 'z') {
        return false;
    }
    const size_t global_slot = provisioning_flow_recover_global_word_slot();
    if (global_slot >= kBip39MnemonicWordCount) {
        return false;
    }
    char* prefix = g_state.recover_prefixes[global_slot];
    size_t length = strlen(prefix);
    if (length >= kProvisioningFlowRecoverPrefixMaxChars) {
        g_state.recover_word_deadline = deadline;
        return true;
    }
    prefix[length++] = letter;
    prefix[length] = '\0';
    g_state.recover_word_selected[global_slot] = false;
    g_state.recover_word_indices[global_slot] = 0;
    g_state.recover_word_deadline = deadline;
    return true;
}

bool provisioning_flow_recover_clear_active(TickType_t deadline)
{
    if (g_state.stage != AgentQProvisioningFlowStage::recover_word_entry) {
        return false;
    }
    const size_t global_slot = provisioning_flow_recover_global_word_slot();
    if (global_slot >= kBip39MnemonicWordCount) {
        return false;
    }
    wipe_sensitive_buffer(g_state.recover_prefixes[global_slot], kProvisioningFlowRecoverPrefixBufferSize);
    g_state.recover_word_selected[global_slot] = false;
    g_state.recover_word_indices[global_slot] = 0;
    g_state.recover_word_deadline = deadline;
    return true;
}

bool provisioning_flow_recover_select_candidate(uint16_t word_index, TickType_t deadline)
{
    if (g_state.stage != AgentQProvisioningFlowStage::recover_word_entry ||
        word_index >= kBip39WordCount ||
        bip39_english_word(word_index) == nullptr) {
        return false;
    }
    const size_t global_slot = provisioning_flow_recover_global_word_slot();
    if (global_slot >= kBip39MnemonicWordCount) {
        return false;
    }
    g_state.recover_word_indices[global_slot] = word_index;
    g_state.recover_word_selected[global_slot] = true;
    write_selected_word_prefix(global_slot, word_index);
    if (g_state.recover_active_slot + 1 < kProvisioningFlowRecoverWordsPerPage) {
        ++g_state.recover_active_slot;
    }
    g_state.recover_word_deadline = deadline;
    return true;
}

bool provisioning_flow_recover_previous_page(TickType_t deadline)
{
    if (g_state.stage != AgentQProvisioningFlowStage::recover_word_entry ||
        g_state.recover_page == 0) {
        return false;
    }
    --g_state.recover_page;
    g_state.recover_active_slot = 0;
    g_state.recover_word_deadline = deadline;
    return true;
}

bool provisioning_flow_recover_next_page(TickType_t deadline)
{
    if (g_state.stage != AgentQProvisioningFlowStage::recover_word_entry ||
        !provisioning_flow_recover_current_page_complete()) {
        return false;
    }
    if (g_state.recover_page + 1 >= kProvisioningFlowRecoverPageCount) {
        return false;
    }
    ++g_state.recover_page;
    g_state.recover_active_slot = 0;
    g_state.recover_word_deadline = deadline;
    return true;
}

bool provisioning_flow_recover_refresh_deadline(TickType_t deadline)
{
    if (g_state.stage != AgentQProvisioningFlowStage::recover_word_entry) {
        return false;
    }
    g_state.recover_word_deadline = deadline;
    return true;
}

Bip39EntropyRecoveryResult provisioning_flow_recover_entropy_from_words()
{
    if (g_state.stage != AgentQProvisioningFlowStage::recover_word_entry ||
        !provisioning_flow_recover_all_words_complete()) {
        return Bip39EntropyRecoveryResult::invalid_word_count;
    }
    const Bip39EntropyRecoveryResult result = recover_bip39_entropy_12_words(
        g_state.recover_word_indices,
        kBip39MnemonicWordCount,
        g_state.root_material,
        sizeof(g_state.root_material));
    if (result != Bip39EntropyRecoveryResult::ok) {
        wipe_sensitive_buffer(g_state.root_material, sizeof(g_state.root_material));
    }
    return result;
}

bool provisioning_flow_begin_pin_setup_from_displayed_phrase(TickType_t deadline)
{
    if (g_state.stage != AgentQProvisioningFlowStage::recovery_phrase_displayed) {
        return false;
    }
    g_state.stage = AgentQProvisioningFlowStage::pin_first_entry;
    g_state.wipe_pin_only();
    g_state.pin_deadline = deadline;
    g_state.wipe_displayed_phrase_text();
    return true;
}

void provisioning_flow_begin_pin_setup_after_recovery(TickType_t deadline)
{
    g_state.stage = AgentQProvisioningFlowStage::pin_first_entry;
    g_state.wipe_recover_word_entry();
    g_state.wipe_pin_only();
    g_state.pin_deadline = deadline;
}

bool provisioning_flow_add_pin_digit(char digit, TickType_t deadline)
{
    if (!pin_setup_stage() || digit < '0' || digit > '9') {
        return false;
    }
    if (g_state.pin_entry_length >= kLocalPinDigits) {
        g_state.pin_deadline = deadline;
        return true;
    }
    g_state.pin_entry[g_state.pin_entry_length++] = digit;
    g_state.pin_entry[g_state.pin_entry_length] = '\0';
    g_state.pin_deadline = deadline;
    return true;
}

bool provisioning_flow_clear_pin_entry(TickType_t deadline)
{
    if (!pin_setup_stage()) {
        return false;
    }
    reset_pin_entry(deadline);
    return true;
}

bool provisioning_flow_backspace_pin(TickType_t deadline)
{
    if (!pin_setup_stage()) {
        return false;
    }
    if (g_state.pin_entry_length > 0) {
        g_state.pin_entry[--g_state.pin_entry_length] = '\0';
    }
    g_state.pin_deadline = deadline;
    return true;
}

AgentQProvisioningFlowPinSubmitResult provisioning_flow_submit_pin(
    TickType_t retry_deadline,
    TickType_t commit_ready_at)
{
    if (!pin_setup_stage()) {
        return AgentQProvisioningFlowPinSubmitResult::inactive;
    }
    if (g_state.pin_entry_length != kLocalPinDigits || !is_valid_local_pin(g_state.pin_entry)) {
        g_state.pin_deadline = retry_deadline;
        return AgentQProvisioningFlowPinSubmitResult::invalid_pin;
    }

    if (g_state.stage == AgentQProvisioningFlowStage::pin_first_entry) {
        snprintf(g_state.pin_first, sizeof(g_state.pin_first), "%s", g_state.pin_entry);
        wipe_sensitive_buffer(g_state.pin_entry, sizeof(g_state.pin_entry));
        g_state.pin_entry_length = 0;
        g_state.stage = AgentQProvisioningFlowStage::pin_repeat_entry;
        g_state.pin_deadline = retry_deadline;
        return AgentQProvisioningFlowPinSubmitResult::advanced_to_repeat;
    }

    if (strcmp(g_state.pin_first, g_state.pin_entry) != 0) {
        wipe_sensitive_buffer(g_state.pin_first, sizeof(g_state.pin_first));
        wipe_sensitive_buffer(g_state.pin_entry, sizeof(g_state.pin_entry));
        g_state.pin_entry_length = 0;
        g_state.stage = AgentQProvisioningFlowStage::pin_first_entry;
        g_state.pin_deadline = retry_deadline;
        return AgentQProvisioningFlowPinSubmitResult::mismatch_restart;
    }

    g_state.stage = AgentQProvisioningFlowStage::pin_committing;
    g_state.pin_commit_ready_at = commit_ready_at;
    wipe_sensitive_buffer(g_state.pin_first, sizeof(g_state.pin_first));
    return AgentQProvisioningFlowPinSubmitResult::commit_started;
}

bool provisioning_flow_commit_inputs(
    const uint8_t** root_material,
    size_t* root_material_size,
    const char** pin)
{
    if (root_material == nullptr || root_material_size == nullptr || pin == nullptr ||
        g_state.stage != AgentQProvisioningFlowStage::pin_committing ||
        !is_valid_local_pin(g_state.pin_entry)) {
        return false;
    }
    *root_material = g_state.root_material;
    *root_material_size = sizeof(g_state.root_material);
    *pin = g_state.pin_entry;
    return true;
}

}  // namespace agent_q
