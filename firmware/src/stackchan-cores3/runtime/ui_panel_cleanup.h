#pragma once

#include "drawing_surface.h"
#include "provisioning_flow.h"

namespace signing {

enum class UiPanelCleanupEvent {
    explicit_clear,
    external_delete,
};

struct UiPanelCleanupInput {
    UiPanelKind panel_kind;
    UiPanelCleanupEvent event;
    bool local_reset_stage_matches;
    bool local_pin_auth_stage_matches;
    bool policy_update_review_stage_matches;
    bool sui_zklogin_review_stage_matches;
    bool user_signing_review_stage_matches;
};

struct UiPanelCleanupPlan {
    bool route_provisioning_panel_deleted;
    ProvisioningFlowPanel provisioning_panel;
    bool wipe_setup_if_unhandled;
    bool wipe_local_reset;
    bool wipe_local_pin_auth;
    bool recover_local_pin_auth_panel;
    bool recover_policy_update_review_panel;
    bool recover_sui_zklogin_review_panel;
    bool wipe_user_signing;
    bool recover_user_signing_review_panel;
};

UiPanelCleanupPlan ui_panel_cleanup_plan(const UiPanelCleanupInput& input);

}  // namespace signing
