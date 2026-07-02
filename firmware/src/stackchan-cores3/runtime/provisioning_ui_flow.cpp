#include "provisioning_ui_flow.h"

#include "provisioning_flow.h"

namespace signing {
namespace {

using Panel = ProvisioningFlowPanel;
using GenerateResult = ProvisioningFlowGenerateResult;
using ImportStartResult = ProvisioningFlowImportStartResult;
using PinSubmitResult = ProvisioningFlowPinSubmitResult;
using CleanupResult = ProvisioningFlowCleanupResult;
using PanelLifetimeResult = ProvisioningFlowPanelLifetimeResult;
using CancelResult = ProvisioningFlowCancelResult;
using ReturnToChoiceResult = ProvisioningFlowReturnToChoiceResult;
using ConfirmBackupResult = ProvisioningFlowConfirmBackupResult;
using ImportNextResult = ProvisioningFlowImportNextResult;
using CommitFinishStatus = ProvisioningFlowCommitFinishStatus;
using CommitResult = ProvisioningFlowCommitResult;

TimeoutWindow window_from_now_ms(
    const ProvisioningUiFlowOps& ops,
    uint32_t duration_ms)
{
    const TickType_t now = ops.now();
    return timeout_window_from_deadline(now, now + pdMS_TO_TICKS(duration_ms));
}

TimeoutWindow window_from_tick_ms(TickType_t now, uint32_t duration_ms)
{
    return timeout_window_from_deadline(now, now + pdMS_TO_TICKS(duration_ms));
}

void log_info(const ProvisioningUiFlowOps& ops, const char* message)
{
    if (ops.log_info != nullptr) {
        ops.log_info(message);
    }
}

void log_warn(const ProvisioningUiFlowOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

void show_result(
    const ProvisioningUiFlowOps& ops,
    const char* message,
    MessageKind kind)
{
    ops.show_message(message, kind);
}

void wipe_setup_scratch(const ProvisioningUiFlowOps& ops, const char* reason)
{
    if (provisioning_flow_wipe_active() == CleanupResult::wiped) {
        log_warn(ops, reason != nullptr ? reason : "setup scratch wiped");
    }
}

bool redraw_pin_setup_panel_or_wipe(
    const ProvisioningUiFlowOps& ops,
    const char* message,
    const char* wipe_reason)
{
    if (ops.draw_pin_setup_panel(message)) {
        return true;
    }
    wipe_setup_scratch(ops, wipe_reason);
    show_result(ops, "Display error", MessageKind::error);
    return false;
}

void clear_provisioning_panel_if_needed(
    const ProvisioningUiFlowOps& ops,
    Panel panel,
    UiPanelKind panel_kind,
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
            show_result(ops, expired_message, MessageKind::timeout);
            return;
        case PanelLifetimeResult::wiped_panel_lost:
            log_warn(ops, lost_reason);
            return;
        case PanelLifetimeResult::wiped_panel_lost_timeout:
            log_warn(ops, lost_reason);
            show_result(ops, expired_message, MessageKind::timeout);
            return;
        case PanelLifetimeResult::clear_panel_preserve_timeout:
            ops.clear_panel_if_kind(panel_kind, SensitiveUiClearPolicy::preserve);
            show_result(ops, expired_message, MessageKind::timeout);
            return;
    }
}

void show_pin_setup_after_imported_entropy(const ProvisioningUiFlowOps& ops)
{
    redraw_pin_setup_panel_or_wipe(
        ops,
        nullptr,
        "local PIN setup display allocation failed after import");
}

}  // namespace

void provisioning_ui_clear_setup_choice_if_needed(const ProvisioningUiFlowOps& ops)
{
    clear_provisioning_panel_if_needed(
        ops,
        Panel::setup_choice,
        UiPanelKind::setup_choice,
        "setup choice panel lost",
        "Setup expired");
}

void provisioning_ui_clear_import_word_entry_if_needed(const ProvisioningUiFlowOps& ops)
{
    clear_provisioning_panel_if_needed(
        ops,
        Panel::import_word_entry,
        UiPanelKind::import_word_entry,
        "import word entry panel lost",
        "Import expired");
}

void provisioning_ui_clear_backup_phrase_if_needed(const ProvisioningUiFlowOps& ops)
{
    clear_provisioning_panel_if_needed(
        ops,
        Panel::backup_phrase_display,
        UiPanelKind::backup_phrase_display,
        "backup phrase display lost",
        "Phrase expired");
}

void provisioning_ui_clear_pin_setup_if_needed(const ProvisioningUiFlowOps& ops)
{
    const TickType_t now = ops.now();
    const PanelLifetimeResult result =
        provisioning_flow_handle_pin_setup_lifetime(
            ops.panel_active(UiPanelKind::pin_entry),
            now);
    switch (result) {
        case PanelLifetimeResult::unchanged:
            return;
        case PanelLifetimeResult::clear_panel_timeout:
            ops.clear_panel_if_kind(UiPanelKind::pin_entry, SensitiveUiClearPolicy::wipe);
            show_result(ops, "Setup expired", MessageKind::timeout);
            return;
        case PanelLifetimeResult::clear_panel_preserve_timeout:
            ops.clear_panel_if_kind(UiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
            show_result(ops, "Setup timed out", MessageKind::timeout);
            return;
        case PanelLifetimeResult::wiped_panel_lost:
            log_warn(ops, "local PIN setup panel lost");
            return;
        case PanelLifetimeResult::wiped_panel_lost_timeout:
            log_warn(ops, "local PIN setup panel lost");
            show_result(ops, "Setup expired", MessageKind::timeout);
            return;
    }
}

void provisioning_ui_show_setup_choice_from_touch(const ProvisioningUiFlowOps& ops)
{
    if (!ops.local_setup_start_allowed()) {
        log_warn(ops, "Local setup touch ignored because setup is unavailable");
        ops.clear_overlay();
        show_result(ops, "Setup unavailable", MessageKind::error);
        return;
    }

    if (!provisioning_flow_begin_setup_choice(
            window_from_now_ms(ops, ops.provisioning_approval_ms))) {
        log_warn(ops, "Local setup touch ignored because setup is unavailable");
        ops.clear_overlay();
        show_result(ops, "Setup unavailable", MessageKind::error);
        return;
    }
    if (!ops.draw_setup_choice_panel()) {
        wipe_setup_scratch(ops, "setup choice display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void provisioning_ui_start_generate_from_setup_choice(const ProvisioningUiFlowOps& ops)
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
            show_result(ops, "Display error", MessageKind::error);
        }
        return;
    }

    if (generation_result == GenerateResult::rng_error) {
        log_warn(ops, "Local setup RNG failed");
        show_result(ops, "RNG error", MessageKind::error);
        return;
    }

    log_warn(ops, "Local setup phrase generation failed");
    show_result(ops, "Generation error", MessageKind::error);
}

void provisioning_ui_start_import_from_setup_choice(const ProvisioningUiFlowOps& ops)
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
        show_result(ops, "Setup unavailable", MessageKind::error);
        return;
    }

    if (!ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void provisioning_ui_cancel_from_local_ui(const ProvisioningUiFlowOps& ops)
{
    if (provisioning_flow_cancel_local_setup() != CancelResult::canceled) {
        log_warn(ops, "Stale local setup cancel ignored");
        return;
    }

    ops.clear_panel_if_kind(UiPanelKind::setup_choice, SensitiveUiClearPolicy::preserve);
    ops.clear_panel_if_kind(UiPanelKind::backup_phrase_display, SensitiveUiClearPolicy::preserve);
    ops.clear_panel_if_kind(UiPanelKind::import_word_entry, SensitiveUiClearPolicy::preserve);
    ops.clear_panel_if_kind(UiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
    wipe_setup_scratch(ops, "provisioning scratch wipe");
    log_info(ops, "Local setup canceled from backup phrase UI");
    show_result(ops, "Setup canceled", MessageKind::rejected);
}

void provisioning_ui_return_to_setup_choice(const ProvisioningUiFlowOps& ops)
{
    const ReturnToChoiceResult result =
        provisioning_flow_return_to_setup_choice(
            window_from_now_ms(ops, ops.provisioning_approval_ms));
    if (result == ReturnToChoiceResult::stale) {
        log_warn(ops, "Stale local back-to-choice ignored");
        return;
    }

    ops.clear_panel_if_kind(UiPanelKind::backup_phrase_display, SensitiveUiClearPolicy::preserve);
    ops.clear_panel_if_kind(UiPanelKind::import_word_entry, SensitiveUiClearPolicy::preserve);

    if (result == ReturnToChoiceResult::failed) {
        log_warn(ops, "Local back-to-choice could not restart setup choice");
        show_result(ops, "Setup unavailable", MessageKind::error);
        return;
    }

    log_info(ops, "Returned to setup choice from generate/import UI");

    if (!ops.draw_setup_choice_panel()) {
        wipe_setup_scratch(ops, "setup choice display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void provisioning_ui_confirm_backup_phrase(const ProvisioningUiFlowOps& ops)
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
        show_result(ops, "Display error", MessageKind::error);
        return;
    }

    log_info(ops, "Local backup confirmed; setup PIN entry started");
}

void provisioning_ui_handle_import_slot(uint8_t slot, const ProvisioningUiFlowOps& ops)
{
    if (!provisioning_flow_import_select_slot(
            slot,
            window_from_now_ms(ops, ops.provisioning_approval_ms))) {
        return;
    }
    if (!ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void provisioning_ui_handle_import_letter(char letter, const ProvisioningUiFlowOps& ops)
{
    if (!provisioning_flow_import_add_letter(
            letter,
            window_from_now_ms(ops, ops.provisioning_approval_ms))) {
        return;
    }
    if (!ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void provisioning_ui_handle_import_clear(const ProvisioningUiFlowOps& ops)
{
    if (provisioning_flow_import_clear_active(
            window_from_now_ms(ops, ops.provisioning_approval_ms)) &&
        !ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void provisioning_ui_handle_import_candidate(
    uint16_t word_index,
    const ProvisioningUiFlowOps& ops)
{
    if (provisioning_flow_import_select_candidate(
            word_index,
            window_from_now_ms(ops, ops.provisioning_approval_ms)) &&
        !ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void provisioning_ui_handle_import_previous(const ProvisioningUiFlowOps& ops)
{
    if (provisioning_flow_import_previous_page(
            window_from_now_ms(ops, ops.provisioning_approval_ms)) &&
        !ops.draw_import_word_entry_panel(nullptr)) {
        wipe_setup_scratch(ops, "import word entry display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void provisioning_ui_handle_import_next(const ProvisioningUiFlowOps& ops)
{
    const TimeoutWindow import_window =
        window_from_now_ms(ops, ops.provisioning_approval_ms);
    const TimeoutWindow pin_window =
        window_from_now_ms(ops, ops.local_pin_setup_ms);
    const ImportNextResult result =
        provisioning_flow_handle_import_next(import_window, pin_window);
    if (result == ImportNextResult::ignored || result == ImportNextResult::incomplete) {
        return;
    }

    if (result == ImportNextResult::page_advanced) {
        if (!ops.draw_import_word_entry_panel(nullptr)) {
            wipe_setup_scratch(ops, "import word entry display allocation failed");
            show_result(ops, "Display error", MessageKind::error);
        }
        return;
    }

    if (result == ImportNextResult::checksum_failed) {
        if (!ops.draw_import_word_entry_panel("Checksum failed. Recheck words.")) {
            wipe_setup_scratch(ops, "import checksum failure display allocation failed");
            show_result(ops, "Import error", MessageKind::error);
        }
        return;
    }

    if (result == ImportNextResult::pin_setup_failed) {
        log_warn(ops, "Imported phrase could not enter setup PIN state");
        show_result(ops, "Setup unavailable", MessageKind::error);
        return;
    }

    show_pin_setup_after_imported_entropy(ops);
}

void provisioning_ui_handle_pin_digit(char digit, const ProvisioningUiFlowOps& ops)
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

void provisioning_ui_handle_pin_clear(const ProvisioningUiFlowOps& ops)
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

void provisioning_ui_handle_pin_backspace(const ProvisioningUiFlowOps& ops)
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

void provisioning_ui_handle_pin_submit(const ProvisioningUiFlowOps& ops)
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
        show_result(ops, "Display error", MessageKind::error);
    }
}

void provisioning_ui_handle_setup_auth_worker_result(
    LocalAuthWorkerResult& worker_result,
    const ProvisioningUiFlowOps& ops)
{
    const ProvisioningFlowCommitFinishResult finish_result =
        provisioning_flow_finish_commit_worker_result(
            worker_result,
            ops.commit_setup_with_prepared_auth);
    if (finish_result.status == CommitFinishStatus::stale) {
        return;
    }

    if (finish_result.status == CommitFinishStatus::failed) {
        log_warn(ops, "local setup PIN verifier preparation failed");
        ops.clear_panel_if_kind(UiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
        show_result(ops, "Storage error", MessageKind::error);
        return;
    }

    ops.clear_panel_if_kind(UiPanelKind::pin_entry, SensitiveUiClearPolicy::preserve);
    switch (finish_result.commit_result) {
        case CommitResult::ok:
            log_info(ops, "Local setup PIN confirmed and provisioned");
            show_result(ops, "Provisioned", MessageKind::success);
            break;
        case CommitResult::missing_input:
            log_warn(ops, "Local PIN confirmation missing scratch");
            show_result(ops, "Setup unavailable", MessageKind::error);
            break;
        case CommitResult::storage_error:
            log_warn(ops, "Local PIN confirmation storage error");
            show_result(ops, "Storage error", MessageKind::error);
            break;
    }
}

}  // namespace signing
