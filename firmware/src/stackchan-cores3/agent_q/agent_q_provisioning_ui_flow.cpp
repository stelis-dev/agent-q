#include "agent_q_provisioning_ui_flow.h"

#include "agent_q_bip39.h"
#include "agent_q_provisioning_flow.h"

namespace agent_q {
namespace {

using Stage = AgentQProvisioningFlowStage;
using Panel = AgentQProvisioningFlowPanel;
using GenerateResult = AgentQProvisioningFlowGenerateResult;
using PinSubmitResult = AgentQProvisioningFlowPinSubmitResult;
using CommitResult = AgentQPersistentMaterialCommitResult;

AgentQTimeoutWindow window_from_now_ms(
    const AgentQProvisioningUiFlowOps& ops,
    uint32_t duration_ms)
{
    const TickType_t now = ops.now();
    return timeout_window_from_deadline(now, now + pdMS_TO_TICKS(duration_ms));
}

void log_info(const AgentQProvisioningUiFlowOps& ops, const char* message)
{
    if (ops.log_info != nullptr) {
        ops.log_info(message);
    }
}

void log_warn(const AgentQProvisioningUiFlowOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

void show_result(
    const AgentQProvisioningUiFlowOps& ops,
    const char* message,
    AgentQMessageKind kind)
{
    ops.show_message(message, kind);
}

void wipe_setup_scratch(const AgentQProvisioningUiFlowOps& ops, const char* reason)
{
    const bool had_setup_scratch = provisioning_flow_active();
    provisioning_flow_wipe();
    if (had_setup_scratch) {
        log_warn(ops, reason != nullptr ? reason : "setup scratch wiped");
    }
}

bool redraw_pin_setup_panel_or_wipe(
    const AgentQProvisioningUiFlowOps& ops,
    const char* message,
    const char* wipe_reason)
{
    if (ops.draw_pin_setup_panel(message)) {
        return true;
    }
    wipe_setup_scratch(ops, wipe_reason);
    show_result(ops, "Display error", AgentQMessageKind::error);
    return false;
}

void clear_provisioning_panel_if_needed(
    const AgentQProvisioningUiFlowOps& ops,
    Stage stage,
    AgentQUiPanelKind panel_kind,
    const char* lost_reason,
    const char* expired_message)
{
    if (!provisioning_flow_stage_is(stage)) {
        return;
    }

    const bool panel_active = ops.panel_active(panel_kind);
    const bool expired = provisioning_flow_stage_expired(ops.now());
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        ops.clear_panel_if_kind(panel_kind, SensitiveUiClearPolicy::wipe);
    } else {
        wipe_setup_scratch(ops, lost_reason);
    }

    if (expired) {
        show_result(ops, expired_message, AgentQMessageKind::timeout);
    }
}

void start_pin_setup_after_imported_entropy(const AgentQProvisioningUiFlowOps& ops)
{
    provisioning_flow_begin_pin_setup_after_import(
        window_from_now_ms(ops, ops.local_pin_setup_ms));

    redraw_pin_setup_panel_or_wipe(
        ops,
        nullptr,
        "local PIN setup display allocation failed after import");
}

}  // namespace

void provisioning_ui_clear_setup_choice_if_needed(const AgentQProvisioningUiFlowOps& ops)
{
    clear_provisioning_panel_if_needed(
        ops,
        Stage::setup_choice,
        AgentQUiPanelKind::setup_choice,
        "setup choice panel lost",
        "Setup expired");
}

void provisioning_ui_clear_import_word_entry_if_needed(const AgentQProvisioningUiFlowOps& ops)
{
    clear_provisioning_panel_if_needed(
        ops,
        Stage::import_word_entry,
        AgentQUiPanelKind::import_word_entry,
        "import word entry panel lost",
        "Import expired");
}

void provisioning_ui_clear_backup_phrase_if_needed(const AgentQProvisioningUiFlowOps& ops)
{
    clear_provisioning_panel_if_needed(
        ops,
        Stage::backup_phrase_displayed,
        AgentQUiPanelKind::backup_phrase_display,
        "backup phrase display lost",
        "Phrase expired");
}

void provisioning_ui_clear_pin_setup_if_needed(const AgentQProvisioningUiFlowOps& ops)
{
    const TickType_t now = ops.now();
    if (provisioning_flow_stage_is(Stage::pin_committing)) {
        if (!provisioning_flow_fail_pin_commit_if_expired(now)) {
            return;
        }
        ops.clear_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
        show_result(ops, "Setup timed out", AgentQMessageKind::timeout);
        return;
    }

    if (!provisioning_flow_snapshot().accepts_setup_pin_input) {
        return;
    }

    const bool panel_active = ops.panel_active(AgentQUiPanelKind::pin_entry);
    const bool expired = provisioning_flow_stage_expired(now);
    if (panel_active && !expired) {
        return;
    }

    if (panel_active) {
        ops.clear_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::wipe);
    } else {
        wipe_setup_scratch(ops, "local PIN setup panel lost");
    }

    if (expired) {
        show_result(ops, "Setup expired", AgentQMessageKind::timeout);
    }
}

void provisioning_ui_show_setup_choice_from_touch(const AgentQProvisioningUiFlowOps& ops)
{
    if (!ops.local_setup_start_allowed()) {
        log_warn(ops, "Local setup touch ignored because setup is unavailable");
        ops.clear_overlay();
        show_result(ops, "Setup unavailable", AgentQMessageKind::error);
        return;
    }

    provisioning_flow_begin_setup_choice(
        window_from_now_ms(ops, ops.provisioning_approval_ms));
    if (!ops.draw_setup_choice_panel()) {
        wipe_setup_scratch(ops, "setup choice display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void provisioning_ui_start_generate_from_setup_choice(const AgentQProvisioningUiFlowOps& ops)
{
    if (!ops.setup_choice_action_allowed()) {
        log_warn(ops, "Stale local setup generate action ignored");
        return;
    }

    const GenerateResult generation_result =
        provisioning_flow_begin_generate(window_from_now_ms(ops, ops.backup_phrase_display_ms));
    if (generation_result == GenerateResult::ok) {
        if (ops.draw_backup_phrase_display(provisioning_flow_backup_phrase())) {
            log_info(ops, "Local setup backup phrase displayed");
        } else {
            wipe_setup_scratch(ops, "local setup backup phrase display allocation failed");
            log_warn(ops, "Local setup display failed");
            show_result(ops, "Display error", AgentQMessageKind::error);
        }
        return;
    }

    if (generation_result == GenerateResult::rng_error) {
        log_warn(ops, "Local setup RNG failed");
        show_result(ops, "RNG error", AgentQMessageKind::error);
        return;
    }

    log_warn(ops, "Local setup phrase generation failed");
    show_result(ops, "Generation error", AgentQMessageKind::error);
}

void provisioning_ui_start_import_from_setup_choice(const AgentQProvisioningUiFlowOps& ops)
{
    if (!ops.setup_choice_action_allowed()) {
        log_warn(ops, "Stale local import action ignored");
        return;
    }

    provisioning_flow_begin_import_phrase(window_from_now_ms(ops, ops.provisioning_approval_ms));
    if (!ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void provisioning_ui_cancel_from_local_ui(const AgentQProvisioningUiFlowOps& ops)
{
    if (provisioning_flow_stage_is(Stage::none) ||
        provisioning_flow_stage_is(Stage::pin_committing)) {
        log_warn(ops, "Stale local setup cancel ignored");
        return;
    }

    ops.clear_panel_if_kind(AgentQUiPanelKind::setup_choice, SensitiveUiClearPolicy::preserve);
    ops.clear_panel_if_kind(AgentQUiPanelKind::backup_phrase_display, SensitiveUiClearPolicy::preserve);
    ops.clear_panel_if_kind(AgentQUiPanelKind::import_word_entry, SensitiveUiClearPolicy::preserve);
    ops.clear_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
    wipe_setup_scratch(ops, "provisioning scratch wipe");
    log_info(ops, "Local setup canceled from backup phrase UI");
    show_result(ops, "Setup canceled", AgentQMessageKind::rejected);
}

void provisioning_ui_return_to_setup_choice(const AgentQProvisioningUiFlowOps& ops)
{
    if (!provisioning_flow_stage_is(Stage::backup_phrase_displayed) &&
        !provisioning_flow_stage_is(Stage::import_word_entry)) {
        log_warn(ops, "Stale local back-to-choice ignored");
        return;
    }

    ops.clear_panel_if_kind(AgentQUiPanelKind::backup_phrase_display, SensitiveUiClearPolicy::preserve);
    ops.clear_panel_if_kind(AgentQUiPanelKind::import_word_entry, SensitiveUiClearPolicy::preserve);
    wipe_setup_scratch(ops, "provisioning back-to-choice wipe");
    log_info(ops, "Returned to setup choice from generate/import UI");

    provisioning_flow_begin_setup_choice(
        window_from_now_ms(ops, ops.provisioning_approval_ms));
    if (!ops.draw_setup_choice_panel()) {
        wipe_setup_scratch(ops, "setup choice display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void provisioning_ui_confirm_backup_phrase(const AgentQProvisioningUiFlowOps& ops)
{
    if (!provisioning_flow_stage_is(Stage::backup_phrase_displayed)) {
        log_warn(ops, "Stale local backup confirmation ignored");
        return;
    }

    if (!provisioning_flow_begin_pin_setup_from_displayed_phrase(
            window_from_now_ms(ops, ops.local_pin_setup_ms))) {
        log_warn(ops, "Local backup confirmation could not enter setup PIN state");
        return;
    }

    if (!ops.draw_pin_setup_panel(nullptr)) {
        wipe_setup_scratch(ops, "local PIN setup display allocation failed");
        log_warn(ops, "Local backup confirmation could not start setup PIN entry");
        show_result(ops, "Display error", AgentQMessageKind::error);
        return;
    }

    log_info(ops, "Local backup confirmed; setup PIN entry started");
}

void provisioning_ui_handle_import_slot(uint8_t slot, const AgentQProvisioningUiFlowOps& ops)
{
    if (!provisioning_flow_import_select_slot(
            slot,
            window_from_now_ms(ops, ops.provisioning_approval_ms))) {
        return;
    }
    if (!ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void provisioning_ui_handle_import_letter(char letter, const AgentQProvisioningUiFlowOps& ops)
{
    if (!provisioning_flow_import_add_letter(
            letter,
            window_from_now_ms(ops, ops.provisioning_approval_ms))) {
        return;
    }
    if (!ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void provisioning_ui_handle_import_clear(const AgentQProvisioningUiFlowOps& ops)
{
    if (provisioning_flow_import_clear_active(
            window_from_now_ms(ops, ops.provisioning_approval_ms)) &&
        !ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void provisioning_ui_handle_import_candidate(
    uint16_t word_index,
    const AgentQProvisioningUiFlowOps& ops)
{
    if (provisioning_flow_import_select_candidate(
            word_index,
            window_from_now_ms(ops, ops.provisioning_approval_ms)) &&
        !ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void provisioning_ui_handle_import_previous(const AgentQProvisioningUiFlowOps& ops)
{
    if (provisioning_flow_import_previous_page(
            window_from_now_ms(ops, ops.provisioning_approval_ms)) &&
        !ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void provisioning_ui_handle_import_next(const AgentQProvisioningUiFlowOps& ops)
{
    if (!provisioning_flow_stage_is(Stage::import_word_entry) ||
        !provisioning_flow_import_current_page_complete()) {
        return;
    }

    if (provisioning_flow_import_next_page(
            window_from_now_ms(ops, ops.provisioning_approval_ms))) {
        if (!ops.draw_import_word_entry_panel(nullptr)) {
            wipe_setup_scratch(ops, "import word entry display allocation failed");
            show_result(ops, "Display error", AgentQMessageKind::error);
        }
        return;
    }

    if (!provisioning_flow_import_all_words_complete()) {
        return;
    }

    const Bip39EntropyDecodeResult result = provisioning_flow_decode_entropy_from_words();
    if (result != Bip39EntropyDecodeResult::ok) {
        provisioning_flow_import_refresh_deadline(
            window_from_now_ms(ops, ops.provisioning_approval_ms));
        if (!ops.draw_import_word_entry_panel("Checksum failed. Recheck words.")) {
            wipe_setup_scratch(ops, "import checksum failure display allocation failed");
            show_result(ops, "Import error", AgentQMessageKind::error);
        }
        return;
    }

    start_pin_setup_after_imported_entropy(ops);
}

void provisioning_ui_handle_pin_digit(char digit, const AgentQProvisioningUiFlowOps& ops)
{
    if (!provisioning_flow_add_pin_digit(
            digit,
            window_from_now_ms(ops, ops.local_pin_setup_ms))) {
        return;
    }
    redraw_pin_setup_panel_or_wipe(
        ops,
        nullptr,
        "local PIN setup display allocation failed");
}

void provisioning_ui_handle_pin_clear(const AgentQProvisioningUiFlowOps& ops)
{
    if (!provisioning_flow_clear_pin_entry(
            window_from_now_ms(ops, ops.local_pin_setup_ms))) {
        return;
    }
    redraw_pin_setup_panel_or_wipe(
        ops,
        nullptr,
        "local PIN setup display allocation failed");
}

void provisioning_ui_handle_pin_backspace(const AgentQProvisioningUiFlowOps& ops)
{
    if (!provisioning_flow_backspace_pin(
            window_from_now_ms(ops, ops.local_pin_setup_ms))) {
        return;
    }
    redraw_pin_setup_panel_or_wipe(
        ops,
        nullptr,
        "local PIN setup display allocation failed");
}

void provisioning_ui_handle_pin_submit(const AgentQProvisioningUiFlowOps& ops)
{
    if (!provisioning_flow_snapshot().accepts_setup_pin_input) {
        log_warn(ops, "Stale local PIN submit ignored");
        return;
    }
    const TickType_t now = ops.now();
    const PinSubmitResult result =
        provisioning_flow_submit_pin(
            window_from_now_ms(ops, ops.local_pin_setup_ms),
            now + pdMS_TO_TICKS(ops.local_processing_display_ms),
            now + pdMS_TO_TICKS(ops.local_auth_worker_max_ms));
    if (result == PinSubmitResult::invalid_pin) {
        redraw_pin_setup_panel_or_wipe(
            ops,
            "Enter exactly 6 digits.",
            "local PIN setup display allocation failed");
        return;
    }
    if (result == PinSubmitResult::worker_unavailable) {
        redraw_pin_setup_panel_or_wipe(
            ops,
            "Auth worker busy. Try again.",
            "local PIN setup worker unavailable display allocation failed");
        return;
    }
    if (result == PinSubmitResult::advanced_to_repeat) {
        redraw_pin_setup_panel_or_wipe(
            ops,
            nullptr,
            "local PIN setup display allocation failed");
        return;
    }
    if (result == PinSubmitResult::mismatch_restart) {
        redraw_pin_setup_panel_or_wipe(
            ops,
            "PINs did not match.",
            "local PIN setup display allocation failed");
        return;
    }
    if (result != PinSubmitResult::commit_started) {
        log_warn(ops, "Stale local PIN submit ignored");
        return;
    }

    if (!ops.draw_pin_setup_processing_or_panel()) {
        log_warn(ops, "Local setup committing panel could not be shown");
        wipe_setup_scratch(ops, "local PIN setup committing display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void provisioning_ui_handle_setup_auth_worker_result(
    AgentQLocalAuthWorkerResult& worker_result,
    const AgentQProvisioningUiFlowOps& ops)
{
    if (!provisioning_flow_commit_job_active(worker_result.job_id)) {
        return;
    }

    const uint8_t* root_material = nullptr;
    size_t root_material_size = 0;
    const AgentQLocalAuthPreparedRecord* prepared_auth = nullptr;
    if (!provisioning_flow_commit_worker_result(
            worker_result,
            &root_material,
            &root_material_size,
            &prepared_auth)) {
        wipe_setup_scratch(ops, "local setup PIN verifier preparation failed");
        ops.clear_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
        show_result(ops, "Storage error", AgentQMessageKind::error);
        return;
    }

    const CommitResult result =
        ops.commit_setup_with_prepared_auth(root_material, root_material_size, prepared_auth);
    wipe_setup_scratch(ops, "local backup phrase and PIN committed");
    ops.clear_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
    switch (result) {
        case CommitResult::ok:
            log_info(ops, "Local setup PIN confirmed and provisioned");
            show_result(ops, "Provisioned", AgentQMessageKind::success);
            break;
        case CommitResult::missing_input:
            log_warn(ops, "Local PIN confirmation missing scratch");
            show_result(ops, "Setup unavailable", AgentQMessageKind::error);
            break;
        case CommitResult::root_storage_error:
        case CommitResult::policy_storage_error:
        case CommitResult::local_auth_storage_error:
        case CommitResult::signing_mode_storage_error:
        case CommitResult::human_approval_setting_storage_error:
        case CommitResult::sui_account_settings_storage_error:
        case CommitResult::state_storage_error:
            log_warn(ops, "Local PIN confirmation storage error");
            show_result(ops, "Storage error", AgentQMessageKind::error);
            break;
    }
}

}  // namespace agent_q
