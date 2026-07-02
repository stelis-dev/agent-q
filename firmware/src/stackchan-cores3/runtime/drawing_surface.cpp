#include "drawing_surface.h"

#include "esp_log.h"

namespace signing {

namespace {

constexpr const char* kTag = "DrawingSurface";

struct DrawingSurfaceState {
    lv_obj_t* panel = nullptr;
    UiPanelKind panel_kind = UiPanelKind::none;
    bool surface_ready = false;
    UiPanelDeletedCallback panel_deleted_callback = nullptr;
};

DrawingSurfaceState g_surface;

void on_panel_deleted(lv_event_t* event)
{
    lv_obj_t* target = static_cast<lv_obj_t*>(lv_event_get_target(event));
    if (g_surface.panel != target) {
        return;
    }

    const UiPanelKind deleted_kind = g_surface.panel_kind;
    ESP_LOGW(kTag, "Agent-Q panel was deleted by external UI state");
    g_surface.panel = nullptr;
    g_surface.panel_kind = UiPanelKind::none;
    if (g_surface.panel_deleted_callback != nullptr) {
        g_surface.panel_deleted_callback(deleted_kind);
    }
}

}  // namespace

void drawing_surface_set_panel_deleted_callback(UiPanelDeletedCallback callback)
{
    g_surface.panel_deleted_callback = callback;
}

void drawing_surface_mark_ready()
{
    g_surface.surface_ready = true;
}

bool drawing_surface_ready()
{
    return g_surface.surface_ready;
}

bool drawing_surface_panel_active(UiPanelKind kind)
{
    return g_surface.panel != nullptr &&
           g_surface.panel_kind == kind;
}

bool drawing_surface_get_panel_coords(UiPanelKind kind, lv_area_t* area)
{
    if (area == nullptr ||
        g_surface.panel == nullptr ||
        g_surface.panel_kind != kind) {
        return false;
    }
    lv_obj_get_coords(g_surface.panel, area);
    return true;
}

lv_obj_t* drawing_surface_panel_locked()
{
    return g_surface.panel;
}

UiPanelKind drawing_surface_panel_kind_locked()
{
    return g_surface.panel_kind;
}

lv_obj_t* drawing_surface_create_panel_locked(UiPanelKind kind)
{
    lv_obj_t* panel = lv_obj_create(lv_screen_active());
    if (panel == nullptr) {
        return nullptr;
    }
    // Strip the default LVGL theme's "card" styling from the panel so the modal alone
    // controls its appearance (bg, radius, border, padding) — like the modal's
    // sub-elements, which call remove_style_all before applying their own styling.
    lv_obj_remove_style_all(panel);
    drawing_surface_register_panel_locked(panel, kind);
    return panel;
}

void drawing_surface_register_panel_locked(lv_obj_t* panel, UiPanelKind kind)
{
    g_surface.panel = panel;
    g_surface.panel_kind = kind;
    lv_obj_add_flag(panel, LV_OBJ_FLAG_FLOATING);
    lv_obj_add_event_cb(panel, on_panel_deleted, LV_EVENT_DELETE, nullptr);
}

UiPanelKind drawing_surface_clear_panel_locked()
{
    if (g_surface.panel == nullptr) {
        g_surface.panel_kind = UiPanelKind::none;
        return UiPanelKind::none;
    }

    lv_obj_t* panel = g_surface.panel;
    const UiPanelKind panel_kind = g_surface.panel_kind;
    g_surface.panel = nullptr;
    g_surface.panel_kind = UiPanelKind::none;
    lv_obj_delete(panel);
    return panel_kind;
}

void drawing_surface_move_panel_foreground_locked()
{
    if (g_surface.panel != nullptr) {
        lv_obj_move_foreground(g_surface.panel);
    }
}

}  // namespace signing
