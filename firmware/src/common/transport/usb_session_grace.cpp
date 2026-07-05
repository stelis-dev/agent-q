#include "transport/usb_session_grace.h"

namespace signing {

UsbGraceAction usb_session_grace_step(
    UsbLinkEvent event,
    TickType_t now,
    TickType_t grace_ticks,
    UsbGraceState& state)
{
    switch (event) {
        case UsbLinkEvent::disconnected:
            state.pending = true;
            state.pending_since = now;
            return UsbGraceAction::suspend;
        case UsbLinkEvent::unchanged_disconnected:
            if (state.pending && (now - state.pending_since) >= grace_ticks) {
                state.pending = false;
                return UsbGraceAction::confirm;
            }
            return UsbGraceAction::none;
        case UsbLinkEvent::connected:
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
