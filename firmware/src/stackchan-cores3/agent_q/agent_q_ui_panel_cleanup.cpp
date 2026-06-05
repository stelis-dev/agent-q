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
        case AgentQUiPanelKind::recovery_phrase_display:
            *panel = AgentQProvisioningFlowPanel::recovery_phrase_display;
            return true;
        case AgentQUiPanelKind::recovery_word_entry:
            *panel = AgentQProvisioningFlowPanel::recovery_word_entry;
            return true;
        case AgentQUiPanelKind::pin_entry:
            *panel = AgentQProvisioningFlowPanel::pin_entry;
            return true;
        case AgentQUiPanelKind::none:
        case AgentQUiPanelKind::decision_strip:
        case AgentQUiPanelKind::settings_menu:
        case AgentQUiPanelKind::reset_pin_entry:
        case AgentQUiPanelKind::error_recovery:
        case AgentQUiPanelKind::local_pin_auth:
        case AgentQUiPanelKind::sign_transaction_user_review:
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

    if (input.panel_kind == AgentQUiPanelKind::sign_transaction_user_review) {
        if (input.event == AgentQUiPanelCleanupEvent::external_delete) {
            plan.recover_sign_transaction_user_review_panel = true;
        } else if (input.sign_transaction_user_review_stage_matches) {
            plan.wipe_sign_transaction_user = true;
        }
    }

    return plan;
}

}  // namespace agent_q
