#pragma once

#include "protocol/protocol_transport_kind.h"

namespace signing {

enum class ProtocolPinLossPurpose {
    none,
    connect,
    policy_update,
    credential_proposal,
    other,
};

enum class LocalPinLossPurpose {
    none,
    connect,
    policy_update,
    credential_proposal,
    user_signing,
    other,
};

struct ProtocolTransportOwnedActivity {
    bool active = false;
    ProtocolTransport transport = ProtocolTransport::none;
};

struct ProtocolTransportLossState {
    ProtocolTransport lost_transport = ProtocolTransport::none;
    ProtocolTransportOwnedActivity session = {};
    ProtocolTransportOwnedActivity connect_approval = {};
    ProtocolPinLossPurpose protocol_pin = ProtocolPinLossPurpose::none;
    ProtocolTransport protocol_pin_transport = ProtocolTransport::none;
    LocalPinLossPurpose local_pin = LocalPinLossPurpose::none;
    ProtocolTransport local_pin_transport = ProtocolTransport::none;
    ProtocolTransportOwnedActivity policy_update = {};
    ProtocolTransportOwnedActivity credential_preparation = {};
    ProtocolTransportOwnedActivity credential_proposal = {};
    ProtocolTransportOwnedActivity user_signing = {};
    bool user_signing_critical = false;
};

struct ProtocolTransportLossPlan {
    bool relevant;
    bool clear_session;
    bool clear_connect_approval;
    bool clear_protocol_pin;
    bool clear_local_pin_auth;
    bool clear_policy_update_flow;
    bool clear_credential_preparation;
    bool clear_credential_proposal_flow;
    bool cancel_user_signing;
    bool clear_connect_review_panel;
    bool clear_local_pin_panel;
    bool clear_policy_update_review_panel;
    bool clear_credential_review_panel;
    bool clear_user_signing_review_panel;
};

ProtocolTransportLossPlan protocol_transport_loss_plan(
    const ProtocolTransportLossState& state);

}  // namespace signing
