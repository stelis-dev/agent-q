#include "usb_session_grace.h"

namespace signing {

UsbGraceAction usb_session_grace_step(
    UsbLinkEvent event,
    TickType_t now,
    TickType_t grace_ticks,
    UsbGraceState& state)
{
    switch (event) {
        case UsbLinkEvent::disconnected:
            // Edge from connected to disconnected: hold the session instead of tearing
            // it down, and remember when the window opened.
            state.pending = true;
            state.pending_since = now;
            return UsbGraceAction::suspend;
        case UsbLinkEvent::unchanged_disconnected:
            // Still down. Confirm the loss once the window has elapsed. TickType_t is
            // unsigned, so the subtraction is wrap-safe for the short grace window.
            if (state.pending && (now - state.pending_since) >= grace_ticks) {
                state.pending = false;
                return UsbGraceAction::confirm;
            }
            return UsbGraceAction::none;
        case UsbLinkEvent::connected:
            // Reconnected; if a window was open the session survived it.
            if (state.pending) {
                state.pending = false;
                return UsbGraceAction::resume;
            }
            return UsbGraceAction::none;
        case UsbLinkEvent::not_due:
        case UsbLinkEvent::initial_observed:
        case UsbLinkEvent::unchanged_connected:
            return UsbGraceAction::none;
    }
    return UsbGraceAction::none;
}

}  // namespace signing
