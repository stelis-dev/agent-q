#pragma once

#include "agent_q_drawing_surface.h"

namespace agent_q {

struct AgentQModalTransitionOps {
    bool (*clear_panel_if_kind)(AgentQUiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*draw_processing_overlay_on_current_panel)(AgentQUiPanelKind kind);
    void (*log_warn)(const char* message);
};

using AgentQModalTransitionAction = void (*)(void* context);
using AgentQModalTransitionDraw = bool (*)(void* context);

bool modal_transition_show_processing_or_redraw_panel(
    const AgentQModalTransitionOps& ops,
    AgentQUiPanelKind current_panel,
    AgentQModalTransitionDraw redraw_panel,
    void* context);
void modal_transition_complete_processing_to_next_panel(
    const AgentQModalTransitionOps& ops,
    AgentQUiPanelKind processing_panel,
    AgentQModalTransitionAction draw_next,
    void* context);
void modal_transition_complete_processing_to_result(
    const AgentQModalTransitionOps& ops,
    AgentQUiPanelKind processing_panel,
    AgentQModalTransitionAction finish_result,
    void* context);
void modal_transition_run_work_then_clear_panel(
    const AgentQModalTransitionOps& ops,
    AgentQUiPanelKind retained_panel,
    AgentQModalTransitionAction work,
    void* context);
bool modal_transition_clear_panel_after_work(
    const AgentQModalTransitionOps& ops,
    AgentQUiPanelKind panel);

}  // namespace agent_q
