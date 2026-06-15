#pragma once

namespace agent_q {

enum class AgentQUsbSessionLossProtocolPinPurpose {
    none,
    connect,
    policy_update,
    sui_zklogin_proposal,
    other,
};

enum class AgentQUsbSessionLossLocalPinPurpose {
    none,
    connect,
    policy_update,
    sui_zklogin_proposal,
    user_signing,
    other,
};

struct AgentQUsbSessionLossInput {
    bool session_active;
    bool connect_approval_active;
    AgentQUsbSessionLossProtocolPinPurpose protocol_pin;
    AgentQUsbSessionLossLocalPinPurpose local_pin;
    bool policy_update_active;
    bool sui_zklogin_proposal_active;
    bool user_signing_active;
    bool user_signing_critical;
};

struct AgentQUsbSessionLossPlan {
    bool relevant;
    bool clear_session;
    bool clear_connect_approval;
    bool clear_protocol_pin;
    bool wipe_local_pin_auth;
    bool clear_policy_update_flow;
    bool clear_sui_zklogin_proposal_flow;
    bool cancel_user_signing;
    bool clear_connect_review_panel;
    bool clear_local_pin_panel;
    bool clear_policy_update_review_panel;
    bool clear_sui_zklogin_review_panel;
    bool clear_user_signing_review_panel;
};

AgentQUsbSessionLossPlan usb_session_loss_plan(const AgentQUsbSessionLossInput& input);

}  // namespace agent_q
