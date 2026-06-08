#pragma once

#include "freertos/FreeRTOS.h"

#include "agent_q_usb_link_state.h"

namespace agent_q {

// Debounce for USB host-link loss. A transient drop (USB selective-suspend resume
// window, a brief cable wobble) should not immediately tear the session down: holding
// it through a short grace window lets a quick reconnect resume and recover the
// buffered signing result. A sustained disconnect past the window confirms the loss.
//
// Pure decision logic (no globals, no hardware) so it is exhaustively host-tested. The
// link stays physically down for the whole grace window, so no host request can run
// during it; the session id still gates every operation, so a different host that
// reconnects cannot act on the held session without knowing it. The grace only buys
// the original host time to fetch its buffered result before a fresh connect replaces
// the session.

enum class AgentQUsbGraceAction {
    none,     // nothing to do (still connected, or the window has not elapsed)
    suspend,  // disconnect edge: begin holding the session through the grace window
    confirm,  // grace elapsed while still disconnected: tear the session down now
    resume,   // reconnected within the grace window: keep the session
};

struct AgentQUsbGraceState {
    bool pending = false;
    TickType_t pending_since = 0;
};

AgentQUsbGraceAction usb_session_grace_step(
    AgentQUsbLinkEvent event,
    TickType_t now,
    TickType_t grace_ticks,
    AgentQUsbGraceState& state);

}  // namespace agent_q
