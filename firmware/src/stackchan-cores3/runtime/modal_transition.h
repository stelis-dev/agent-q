#pragma once

#include "drawing_surface.h"

namespace signing {

struct ModalTransitionOps {
    bool (*clear_panel_if_kind)(UiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*draw_processing_overlay_on_current_panel)(UiPanelKind kind);
    void (*log_warn)(const char* message);
};

using ModalTransitionAction = void (*)(void* context);
using ModalTransitionDraw = bool (*)(void* context);

bool modal_transition_show_processing_or_redraw_panel(
    const ModalTransitionOps& ops,
    UiPanelKind current_panel,
    ModalTransitionDraw redraw_panel,
    void* context);
bool modal_transition_complete_to_next_panel(
    const ModalTransitionOps& ops,
    UiPanelKind current_panel,
    ModalTransitionDraw draw_next,
    void* context);
void modal_transition_complete_to_result(
    const ModalTransitionOps& ops,
    UiPanelKind current_panel,
    ModalTransitionAction finish_result,
    void* context);
void modal_transition_complete_processing_to_result(
    const ModalTransitionOps& ops,
    UiPanelKind processing_panel,
    ModalTransitionAction finish_result,
    void* context);
void modal_transition_run_work_then_clear_panel(
    const ModalTransitionOps& ops,
    UiPanelKind retained_panel,
    ModalTransitionAction work,
    void* context);
bool modal_transition_clear_panel_after_work(
    const ModalTransitionOps& ops,
    UiPanelKind panel);

}  // namespace signing
