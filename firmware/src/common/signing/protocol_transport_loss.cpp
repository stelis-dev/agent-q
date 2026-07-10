#include "protocol_transport_loss.h"

namespace signing {

namespace {

bool owned_by_lost_transport(
    const ProtocolTransportOwnedActivity& activity,
    ProtocolTransport lost_transport)
{
    return lost_transport != ProtocolTransport::none &&
           activity.active &&
           activity.transport == lost_transport;
}

}  // namespace

ProtocolTransportLossPlan protocol_transport_loss_plan(
    const ProtocolTransportLossState& state)
{
    const bool session_active =
        owned_by_lost_transport(state.session, state.lost_transport);
    const bool connect_approval_active =
        owned_by_lost_transport(state.connect_approval, state.lost_transport);
    const ProtocolPinLossPurpose protocol_pin =
        state.lost_transport != ProtocolTransport::none &&
                state.protocol_pin_transport == state.lost_transport
            ? state.protocol_pin
            : ProtocolPinLossPurpose::none;
    const LocalPinLossPurpose local_pin =
        state.lost_transport != ProtocolTransport::none &&
                state.local_pin_transport == state.lost_transport
            ? state.local_pin
            : LocalPinLossPurpose::none;
    const bool policy_update_active =
        owned_by_lost_transport(state.policy_update, state.lost_transport);
    const bool credential_preparation_active =
        owned_by_lost_transport(
            state.credential_preparation,
            state.lost_transport);
    const bool credential_proposal_active =
        owned_by_lost_transport(state.credential_proposal, state.lost_transport);
    const bool user_signing_active =
        owned_by_lost_transport(state.user_signing, state.lost_transport);
    const bool protocol_connect =
        protocol_pin == ProtocolPinLossPurpose::connect;
    const bool protocol_policy_update =
        protocol_pin == ProtocolPinLossPurpose::policy_update;
    const bool protocol_credential_proposal =
        protocol_pin == ProtocolPinLossPurpose::credential_proposal;
    const bool local_connect =
        local_pin == LocalPinLossPurpose::connect;
    const bool local_policy_update =
        local_pin == LocalPinLossPurpose::policy_update;
    const bool local_credential_proposal =
        local_pin == LocalPinLossPurpose::credential_proposal;
    const bool local_user_signing =
        local_pin == LocalPinLossPurpose::user_signing;
    const bool local_session_bound =
        local_connect || local_policy_update || local_credential_proposal || local_user_signing;
    const bool protocol_session_bound =
        protocol_connect || protocol_policy_update || protocol_credential_proposal;
    const bool cancel_user_signing =
        user_signing_active && !state.user_signing_critical;

    return ProtocolTransportLossPlan{
        session_active ||
            connect_approval_active ||
            protocol_session_bound ||
            local_session_bound ||
            policy_update_active ||
            credential_preparation_active ||
            credential_proposal_active ||
            user_signing_active,
        session_active,
        connect_approval_active,
        protocol_session_bound,
        local_session_bound,
        policy_update_active || protocol_policy_update || local_policy_update,
        credential_preparation_active,
        credential_proposal_active ||
            protocol_credential_proposal ||
            local_credential_proposal,
        cancel_user_signing,
        connect_approval_active,
        local_session_bound,
        policy_update_active && !local_policy_update,
        credential_proposal_active && !local_credential_proposal,
        cancel_user_signing,
    };
}

}  // namespace signing
