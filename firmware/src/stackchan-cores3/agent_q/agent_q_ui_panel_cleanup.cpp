#include "agent_q_ui_panel_cleanup.h"

namespace agent_q {

namespace {

bool provisioning_panel_for_kind(
    AgentQUiPanelKind kind,
    AgentQProvisioningFlowPanel* panel)
{
    if (panel == nullptr) {
        return false;
    }
    switch (kind) {
        case AgentQUiPanelKind::setup_choice:
            *panel = AgentQProvisioningFlowPanel::setup_choice;
            return true;
        case AgentQUiPanelKind::backup_phrase_display:
            *panel = AgentQProvisioningFlowPanel::backup_phrase_display;
            return true;
        case AgentQUiPanelKind::import_word_entry:
            *panel = AgentQProvisioningFlowPanel::import_word_entry;
            return true;
        case AgentQUiPanelKind::pin_entry:
            *panel = AgentQProvisioningFlowPanel::pin_entry;
            return true;
        case AgentQUiPanelKind::none:
        case AgentQUiPanelKind::connect_review:
        case AgentQUiPanelKind::settings_menu:
        case AgentQUiPanelKind::reset_pin_entry:
        case AgentQUiPanelKind::error_recovery:
        case AgentQUiPanelKind::local_pin_auth:
        case AgentQUiPanelKind::policy_update_review:
        case AgentQUiPanelKind::sui_zklogin_review:
        case AgentQUiPanelKind::user_signing_review:
            return false;
    }
    return false;
}

}  // namespace

AgentQUiPanelCleanupPlan ui_panel_cleanup_plan(const AgentQUiPanelCleanupInput& input)
{
    AgentQUiPanelCleanupPlan plan{
        false,
        AgentQProvisioningFlowPanel::setup_choice,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    };

    AgentQProvisioningFlowPanel provisioning_panel =
        AgentQProvisioningFlowPanel::setup_choice;
    if (provisioning_panel_for_kind(input.panel_kind, &provisioning_panel)) {
        plan.route_provisioning_panel_deleted = true;
        plan.provisioning_panel = provisioning_panel;
        plan.wipe_setup_if_unhandled =
            input.event == AgentQUiPanelCleanupEvent::explicit_clear;
        return plan;
    }

    if (input.local_reset_stage_matches) {
        plan.wipe_local_reset = true;
        return plan;
    }

    if (input.panel_kind == AgentQUiPanelKind::local_pin_auth) {
        if (input.event == AgentQUiPanelCleanupEvent::external_delete) {
            plan.recover_local_pin_auth_panel = true;
        } else if (input.local_pin_auth_stage_matches) {
            plan.wipe_local_pin_auth = true;
        }
    }

    if (input.panel_kind == AgentQUiPanelKind::user_signing_review) {
        if (input.event == AgentQUiPanelCleanupEvent::external_delete) {
            plan.recover_user_signing_review_panel = true;
        } else if (input.user_signing_review_stage_matches) {
            plan.wipe_user_signing = true;
        }
    }

    if (input.panel_kind == AgentQUiPanelKind::policy_update_review) {
        if (input.event == AgentQUiPanelCleanupEvent::external_delete) {
            plan.recover_policy_update_review_panel = true;
        }
    }

    if (input.panel_kind == AgentQUiPanelKind::sui_zklogin_review) {
        if (input.event == AgentQUiPanelCleanupEvent::external_delete) {
            plan.recover_sui_zklogin_review_panel = true;
        }
    }

    return plan;
}

}  // namespace agent_q
