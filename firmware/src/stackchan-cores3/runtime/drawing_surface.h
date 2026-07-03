#pragma once

#include "lvgl.h"

namespace signing {

enum class UiPanelKind {
    none,
    connect_review,
    setup_choice,
    backup_phrase_display,
    import_word_entry,
    pin_entry,
    settings_menu,
    chain_settings_menu,
    sui_settings,
    action_pin_entry,
    error_recovery,
    local_pin_auth,
    policy_update_review,
    sui_zklogin_review,
    user_signing_review,
};

enum class SensitiveUiClearPolicy {
    wipe,
    preserve,
};

using UiPanelDeletedCallback = void (*)(UiPanelKind kind);

void drawing_surface_set_panel_deleted_callback(UiPanelDeletedCallback callback);
void drawing_surface_mark_ready();
bool drawing_surface_ready();
bool drawing_surface_panel_active(UiPanelKind kind);
bool drawing_surface_get_panel_coords(UiPanelKind kind, lv_area_t* area);

lv_obj_t* drawing_surface_panel_locked();
UiPanelKind drawing_surface_panel_kind_locked();
lv_obj_t* drawing_surface_create_panel_locked(UiPanelKind kind);
void drawing_surface_register_panel_locked(lv_obj_t* panel, UiPanelKind kind);
UiPanelKind drawing_surface_clear_panel_locked();
void drawing_surface_move_panel_foreground_locked();

}  // namespace signing
