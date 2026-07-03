#include "ui_panel_cleanup.h"

namespace signing {

namespace {

bool provisioning_panel_for_kind(
    UiPanelKind kind,
    ProvisioningFlowPanel* panel)
{
    if (panel == nullptr) {
        return false;
    }
    switch (kind) {
        case UiPanelKind::setup_choice:
            *panel = ProvisioningFlowPanel::setup_choice;
            return true;
        case UiPanelKind::backup_phrase_display:
            *panel = ProvisioningFlowPanel::backup_phrase_display;
            return true;
        case UiPanelKind::import_word_entry:
            *panel = ProvisioningFlowPanel::import_word_entry;
            return true;
        case UiPanelKind::pin_entry:
            *panel = ProvisioningFlowPanel::pin_entry;
            return true;
        case UiPanelKind::none:
        case UiPanelKind::connect_review:
        case UiPanelKind::settings_menu:
        case UiPanelKind::chain_settings_menu:
        case UiPanelKind::sui_settings:
        case UiPanelKind::action_pin_entry:
        case UiPanelKind::error_recovery:
        case UiPanelKind::local_pin_auth:
        case UiPanelKind::policy_update_review:
        case UiPanelKind::sui_zklogin_review:
        case UiPanelKind::user_signing_review:
            return false;
    }
    return false;
}

}  // namespace

UiPanelCleanupPlan ui_panel_cleanup_plan(const UiPanelCleanupInput& input)
{
    UiPanelCleanupPlan plan{
        false,
        ProvisioningFlowPanel::setup_choice,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    };

    ProvisioningFlowPanel provisioning_panel =
        ProvisioningFlowPanel::setup_choice;
    if (provisioning_panel_for_kind(input.panel_kind, &provisioning_panel)) {
        plan.route_provisioning_panel_deleted = true;
        plan.provisioning_panel = provisioning_panel;
        plan.wipe_setup_if_unhandled =
            input.event == UiPanelCleanupEvent::explicit_clear;
        return plan;
    }

    if (input.storage_maintenance_stage_matches) {
        plan.clear_storage_maintenance = true;
        return plan;
    }

    if (input.panel_kind == UiPanelKind::local_pin_auth) {
        if (input.event == UiPanelCleanupEvent::external_delete) {
            plan.recover_local_pin_auth_panel = true;
        } else if (input.local_pin_auth_stage_matches) {
            plan.clear_local_pin_auth = true;
        }
    }

    if (input.panel_kind == UiPanelKind::user_signing_review) {
        if (input.event == UiPanelCleanupEvent::external_delete) {
            plan.recover_user_signing_review_panel = true;
        } else if (input.user_signing_review_stage_matches) {
            plan.wipe_user_signing = true;
        }
    }

    if (input.panel_kind == UiPanelKind::policy_update_review) {
        if (input.event == UiPanelCleanupEvent::external_delete) {
            plan.recover_policy_update_review_panel = true;
        }
    }

    if (input.panel_kind == UiPanelKind::sui_zklogin_review) {
        if (input.event == UiPanelCleanupEvent::external_delete) {
            plan.recover_sui_zklogin_review_panel = true;
        }
    }

    return plan;
}

}  // namespace signing
