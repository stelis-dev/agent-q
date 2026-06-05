#pragma once

#include "lvgl.h"

namespace agent_q {

enum class AgentQUiPanelKind {
    none,
    decision_strip,
    setup_choice,
    recovery_phrase_display,
    recovery_word_entry,
    pin_entry,
    settings_menu,
    reset_pin_entry,
    error_recovery,
    local_pin_auth,
    sign_transaction_user_review,
};

enum class SensitiveUiClearPolicy {
    wipe,
    preserve,
};

using AgentQUiPanelDeletedCallback = void (*)(AgentQUiPanelKind kind);

void drawing_surface_set_panel_deleted_callback(AgentQUiPanelDeletedCallback callback);
void drawing_surface_mark_ready();
bool drawing_surface_ready();
bool drawing_surface_panel_active(AgentQUiPanelKind kind);
bool drawing_surface_get_panel_coords(AgentQUiPanelKind kind, lv_area_t* area);

lv_obj_t* drawing_surface_panel_locked();
AgentQUiPanelKind drawing_surface_panel_kind_locked();
lv_obj_t* drawing_surface_create_panel_locked(AgentQUiPanelKind kind);
void drawing_surface_register_panel_locked(lv_obj_t* panel, AgentQUiPanelKind kind);
AgentQUiPanelKind drawing_surface_clear_panel_locked();
void drawing_surface_move_panel_foreground_locked();

}  // namespace agent_q
