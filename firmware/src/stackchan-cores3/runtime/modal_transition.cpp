#include "modal_transition.h"

namespace signing {
namespace {

void log_warn(const ModalTransitionOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

}  // namespace

bool modal_transition_show_processing_or_redraw_panel(
    const ModalTransitionOps& ops,
    UiPanelKind current_panel,
    ModalTransitionDraw redraw_panel,
    void* context)
{
    if (ops.draw_processing_overlay_on_current_panel != nullptr &&
        ops.draw_processing_overlay_on_current_panel(current_panel)) {
        return true;
    }
    return redraw_panel != nullptr && redraw_panel(context);
}

bool modal_transition_complete_to_next_panel(
    const ModalTransitionOps& ops,
    UiPanelKind current_panel,
    ModalTransitionDraw draw_next,
    void* context)
{
    if (draw_next == nullptr || !draw_next(context)) {
        return false;
    }
    return modal_transition_clear_panel_after_work(ops, current_panel);
}

bool modal_transition_clear_panel_after_work(
    const ModalTransitionOps& ops,
    UiPanelKind panel)
{
    if (ops.clear_panel_if_kind == nullptr) {
        log_warn(ops, "Modal transition could not clear completed processing panel");
        return false;
    }
    return ops.clear_panel_if_kind(panel, SensitiveUiClearPolicy::preserve);
}

void modal_transition_complete_to_result(
    const ModalTransitionOps& ops,
    UiPanelKind current_panel,
    ModalTransitionAction finish_result,
    void* context)
{
    if (finish_result != nullptr) {
        finish_result(context);
    }
    modal_transition_clear_panel_after_work(ops, current_panel);
}

void modal_transition_complete_processing_to_result(
    const ModalTransitionOps& ops,
    UiPanelKind processing_panel,
    ModalTransitionAction finish_result,
    void* context)
{
    modal_transition_complete_to_result(
        ops,
        processing_panel,
        finish_result,
        context);
}

void modal_transition_run_work_then_clear_panel(
    const ModalTransitionOps& ops,
    UiPanelKind retained_panel,
    ModalTransitionAction work,
    void* context)
{
    if (work != nullptr) {
        work(context);
    }
    modal_transition_clear_panel_after_work(ops, retained_panel);
}

}  // namespace signing
