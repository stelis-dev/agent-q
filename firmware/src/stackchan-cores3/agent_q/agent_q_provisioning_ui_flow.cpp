#include "agent_q_provisioning_ui_flow.h"

#include "agent_q_provisioning_flow.h"

namespace agent_q {
namespace {

using Panel = AgentQProvisioningFlowPanel;
using GenerateResult = AgentQProvisioningFlowGenerateResult;
using ImportStartResult = AgentQProvisioningFlowImportStartResult;
using PinSubmitResult = AgentQProvisioningFlowPinSubmitResult;
using CleanupResult = AgentQProvisioningFlowCleanupResult;
using PanelLifetimeResult = AgentQProvisioningFlowPanelLifetimeResult;
using CancelResult = AgentQProvisioningFlowCancelResult;
using ReturnToChoiceResult = AgentQProvisioningFlowReturnToChoiceResult;
using ConfirmBackupResult = AgentQProvisioningFlowConfirmBackupResult;
using ImportNextResult = AgentQProvisioningFlowImportNextResult;
using CommitFinishStatus = AgentQProvisioningFlowCommitFinishStatus;
using CommitResult = AgentQProvisioningFlowCommitResult;

AgentQTimeoutWindow window_from_now_ms(
    const AgentQProvisioningUiFlowOps& ops,
    uint32_t duration_ms)
{
    const TickType_t now = ops.now();
    return timeout_window_from_deadline(now, now + pdMS_TO_TICKS(duration_ms));
}

AgentQTimeoutWindow window_from_tick_ms(TickType_t now, uint32_t duration_ms)
{
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
    if (provisioning_flow_wipe_active() == CleanupResult::wiped) {
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
    Panel panel,
    AgentQUiPanelKind panel_kind,
    const char* lost_reason,
    const char* expired_message)
{
    const PanelLifetimeResult result =
        provisioning_flow_handle_panel_lifetime(panel, ops.panel_active(panel_kind), ops.now());
    switch (result) {
        case PanelLifetimeResult::unchanged:
            return;
        case PanelLifetimeResult::clear_panel_timeout:
            ops.clear_panel_if_kind(panel_kind, SensitiveUiClearPolicy::wipe);
            show_result(ops, expired_message, AgentQMessageKind::timeout);
            return;
        case PanelLifetimeResult::wiped_panel_lost:
            log_warn(ops, lost_reason);
            return;
        case PanelLifetimeResult::wiped_panel_lost_timeout:
            log_warn(ops, lost_reason);
            show_result(ops, expired_message, AgentQMessageKind::timeout);
            return;
        case PanelLifetimeResult::clear_panel_preserve_timeout:
            ops.clear_panel_if_kind(panel_kind, SensitiveUiClearPolicy::preserve);
            show_result(ops, expired_message, AgentQMessageKind::timeout);
            return;
    }
}

void show_pin_setup_after_imported_entropy(const AgentQProvisioningUiFlowOps& ops)
{
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
        Panel::setup_choice,
        AgentQUiPanelKind::setup_choice,
        "setup choice panel lost",
        "Setup expired");
}

void provisioning_ui_clear_import_word_entry_if_needed(const AgentQProvisioningUiFlowOps& ops)
{
    clear_provisioning_panel_if_needed(
        ops,
        Panel::import_word_entry,
        AgentQUiPanelKind::import_word_entry,
        "import word entry panel lost",
        "Import expired");
}

void provisioning_ui_clear_backup_phrase_if_needed(const AgentQProvisioningUiFlowOps& ops)
{
    clear_provisioning_panel_if_needed(
        ops,
        Panel::backup_phrase_display,
        AgentQUiPanelKind::backup_phrase_display,
        "backup phrase display lost",
        "Phrase expired");
}

void provisioning_ui_clear_pin_setup_if_needed(const AgentQProvisioningUiFlowOps& ops)
{
    const TickType_t now = ops.now();
    const PanelLifetimeResult result =
        provisioning_flow_handle_pin_setup_lifetime(
            ops.panel_active(AgentQUiPanelKind::pin_entry),
            now);
    switch (result) {
        case PanelLifetimeResult::unchanged:
            return;
        case PanelLifetimeResult::clear_panel_timeout:
            ops.clear_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::wipe);
            show_result(ops, "Setup expired", AgentQMessageKind::timeout);
            return;
        case PanelLifetimeResult::clear_panel_preserve_timeout:
            ops.clear_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
            show_result(ops, "Setup timed out", AgentQMessageKind::timeout);
            return;
        case PanelLifetimeResult::wiped_panel_lost:
            log_warn(ops, "local PIN setup panel lost");
            return;
        case PanelLifetimeResult::wiped_panel_lost_timeout:
            log_warn(ops, "local PIN setup panel lost");
            show_result(ops, "Setup expired", AgentQMessageKind::timeout);
            return;
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

    if (!provisioning_flow_begin_setup_choice(
            window_from_now_ms(ops, ops.provisioning_approval_ms))) {
        log_warn(ops, "Local setup touch ignored because setup is unavailable");
        ops.clear_overlay();
        show_result(ops, "Setup unavailable", AgentQMessageKind::error);
        return;
    }
    if (!ops.draw_setup_choice_panel()) {
        wipe_setup_scratch(ops, "setup choice display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void provisioning_ui_start_generate_from_setup_choice(const AgentQProvisioningUiFlowOps& ops)
{
    if (!ops.setup_app_action_allowed()) {
        log_warn(ops, "Stale local setup generate action ignored");
        return;
    }

    const TickType_t now = ops.now();
    const GenerateResult generation_result =
        provisioning_flow_begin_generate(
            now,
            window_from_tick_ms(now, ops.backup_phrase_display_ms));
    if (generation_result == GenerateResult::stale) {
        log_warn(ops, "Stale local setup generate action ignored");
        return;
    }
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
    if (!ops.setup_app_action_allowed()) {
        log_warn(ops, "Stale local import action ignored");
        return;
    }

    const TickType_t now = ops.now();
    const ImportStartResult import_result =
        provisioning_flow_begin_import_phrase(
            now,
            window_from_tick_ms(now, ops.provisioning_approval_ms));
    if (import_result == ImportStartResult::stale) {
        log_warn(ops, "Stale local import action ignored");
        return;
    }
    if (import_result == ImportStartResult::failed) {
        log_warn(ops, "Local import setup could not start");
        show_result(ops, "Setup unavailable", AgentQMessageKind::error);
        return;
    }

    if (!ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void provisioning_ui_cancel_from_local_ui(const AgentQProvisioningUiFlowOps& ops)
{
    if (provisioning_flow_cancel_local_setup() != CancelResult::canceled) {
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
    const ReturnToChoiceResult result =
        provisioning_flow_return_to_setup_choice(
            window_from_now_ms(ops, ops.provisioning_approval_ms));
    if (result == ReturnToChoiceResult::stale) {
        log_warn(ops, "Stale local back-to-choice ignored");
        return;
    }

    ops.clear_panel_if_kind(AgentQUiPanelKind::backup_phrase_display, SensitiveUiClearPolicy::preserve);
    ops.clear_panel_if_kind(AgentQUiPanelKind::import_word_entry, SensitiveUiClearPolicy::preserve);

    if (result == ReturnToChoiceResult::failed) {
        log_warn(ops, "Local back-to-choice could not restart setup choice");
        show_result(ops, "Setup unavailable", AgentQMessageKind::error);
        return;
    }

    log_info(ops, "Returned to setup choice from generate/import UI");

    if (!ops.draw_setup_choice_panel()) {
        wipe_setup_scratch(ops, "setup choice display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void provisioning_ui_confirm_backup_phrase(const AgentQProvisioningUiFlowOps& ops)
{
    const ConfirmBackupResult result =
        provisioning_flow_confirm_backup_phrase(
            window_from_now_ms(ops, ops.local_pin_setup_ms));
    switch (result) {
        case ConfirmBackupResult::stale:
            log_warn(ops, "Stale local backup confirmation ignored");
            return;
        case ConfirmBackupResult::failed:
            log_warn(ops, "Local backup confirmation could not enter setup PIN state");
            return;
        case ConfirmBackupResult::started:
            break;
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
    const AgentQTimeoutWindow import_window =
        window_from_now_ms(ops, ops.provisioning_approval_ms);
    const AgentQTimeoutWindow pin_window =
        window_from_now_ms(ops, ops.local_pin_setup_ms);
    const ImportNextResult result =
        provisioning_flow_handle_import_next(import_window, pin_window);
    if (result == ImportNextResult::ignored || result == ImportNextResult::incomplete) {
        return;
    }

    if (result == ImportNextResult::page_advanced) {
        if (!ops.draw_import_word_entry_panel(nullptr)) {
            wipe_setup_scratch(ops, "import word entry display allocation failed");
            show_result(ops, "Display error", AgentQMessageKind::error);
        }
        return;
    }

    if (result == ImportNextResult::checksum_failed) {
        if (!ops.draw_import_word_entry_panel("Checksum failed. Recheck words.")) {
            wipe_setup_scratch(ops, "import checksum failure display allocation failed");
            show_result(ops, "Import error", AgentQMessageKind::error);
        }
        return;
    }

    if (result == ImportNextResult::pin_setup_failed) {
        log_warn(ops, "Imported phrase could not enter setup PIN state");
        show_result(ops, "Setup unavailable", AgentQMessageKind::error);
        return;
    }

    show_pin_setup_after_imported_entropy(ops);
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
    const AgentQProvisioningFlowCommitFinishResult finish_result =
        provisioning_flow_finish_commit_worker_result(
            worker_result,
            ops.commit_setup_with_prepared_auth);
    if (finish_result.status == CommitFinishStatus::stale) {
        return;
    }

    if (finish_result.status == CommitFinishStatus::failed) {
        log_warn(ops, "local setup PIN verifier preparation failed");
        ops.clear_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
        show_result(ops, "Storage error", AgentQMessageKind::error);
        return;
    }

    ops.clear_panel_if_kind(AgentQUiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
    switch (finish_result.commit_result) {
        case CommitResult::ok:
            log_info(ops, "Local setup PIN confirmed and provisioned");
            show_result(ops, "Provisioned", AgentQMessageKind::success);
            break;
        case CommitResult::missing_input:
            log_warn(ops, "Local PIN confirmation missing scratch");
            show_result(ops, "Setup unavailable", AgentQMessageKind::error);
            break;
        case CommitResult::storage_error:
            log_warn(ops, "Local PIN confirmation storage error");
            show_result(ops, "Storage error", AgentQMessageKind::error);
            break;
    }
}

}  // namespace agent_q
