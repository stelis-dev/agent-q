#pragma once

#include "agent_q_drawing_surface.h"
#include "agent_q_provisioning_flow.h"

namespace agent_q {

enum class AgentQUiPanelCleanupEvent {
    explicit_clear,
    external_delete,
};

struct AgentQUiPanelCleanupInput {
    AgentQUiPanelKind panel_kind;
    AgentQUiPanelCleanupEvent event;
    bool local_reset_stage_matches;
    bool local_pin_auth_stage_matches;
    bool policy_update_review_stage_matches;
    bool user_signing_review_stage_matches;
};

struct AgentQUiPanelCleanupPlan {
    bool route_provisioning_panel_deleted;
    AgentQProvisioningFlowPanel provisioning_panel;
    bool wipe_setup_if_unhandled;
    bool wipe_local_reset;
    bool wipe_local_pin_auth;
    bool recover_local_pin_auth_panel;
    bool recover_policy_update_review_panel;
    bool wipe_user_signing;
    bool recover_user_signing_review_panel;
};

AgentQUiPanelCleanupPlan ui_panel_cleanup_plan(const AgentQUiPanelCleanupInput& input);

}  // namespace agent_q
