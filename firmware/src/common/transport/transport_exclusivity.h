#pragma once

namespace signing {

struct TransportExclusivityState {
    bool primary_transport_connected = false;
    bool secondary_transport_active = false;
};

enum class TransportExclusivityAction {
    none,
    close_secondary_transport,
};

inline bool secondary_transport_entry_allowed(
    const TransportExclusivityState& state)
{
    return !state.primary_transport_connected &&
           !state.secondary_transport_active;
}

inline TransportExclusivityAction transport_exclusivity_action(
    const TransportExclusivityState& state)
{
    return state.primary_transport_connected && state.secondary_transport_active
        ? TransportExclusivityAction::close_secondary_transport
        : TransportExclusivityAction::none;
}

}  // namespace signing
