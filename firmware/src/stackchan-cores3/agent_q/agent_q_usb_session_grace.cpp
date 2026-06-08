#include "agent_q_usb_session_grace.h"

namespace agent_q {

AgentQUsbGraceAction usb_session_grace_step(
    AgentQUsbLinkEvent event,
    TickType_t now,
    TickType_t grace_ticks,
    AgentQUsbGraceState& state)
{
    switch (event) {
        case AgentQUsbLinkEvent::disconnected:
            // Edge from connected to disconnected: hold the session instead of tearing
            // it down, and remember when the window opened.
            state.pending = true;
            state.pending_since = now;
            return AgentQUsbGraceAction::suspend;
        case AgentQUsbLinkEvent::unchanged_disconnected:
            // Still down. Confirm the loss once the window has elapsed. TickType_t is
            // unsigned, so the subtraction is wrap-safe for the short grace window.
            if (state.pending && (now - state.pending_since) >= grace_ticks) {
                state.pending = false;
                return AgentQUsbGraceAction::confirm;
            }
            return AgentQUsbGraceAction::none;
        case AgentQUsbLinkEvent::connected:
            // Reconnected; if a window was open the session survived it.
            if (state.pending) {
                state.pending = false;
                return AgentQUsbGraceAction::resume;
            }
            return AgentQUsbGraceAction::none;
        case AgentQUsbLinkEvent::not_due:
        case AgentQUsbLinkEvent::initial_observed:
        case AgentQUsbLinkEvent::unchanged_connected:
            return AgentQUsbGraceAction::none;
    }
    return AgentQUsbGraceAction::none;
}

}  // namespace agent_q
