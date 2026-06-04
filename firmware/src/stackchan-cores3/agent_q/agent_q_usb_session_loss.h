#pragma once

namespace agent_q {

enum class AgentQUsbSessionLossProtocolPinPurpose {
    none,
    connect,
    policy_update,
    other,
};

enum class AgentQUsbSessionLossLocalPinPurpose {
    none,
    connect,
    policy_update,
    sign_by_user,
    other,
};

struct AgentQUsbSessionLossInput {
    bool session_active;
    bool connect_approval_active;
    AgentQUsbSessionLossProtocolPinPurpose protocol_pin;
    AgentQUsbSessionLossLocalPinPurpose local_pin;
    bool sign_by_user_active;
    bool sign_by_user_critical;
};

struct AgentQUsbSessionLossPlan {
    bool relevant;
    bool clear_session;
    bool clear_connect_approval;
    bool clear_protocol_pin;
    bool wipe_local_pin_auth;
    bool clear_policy_update_flow;
    bool cancel_sign_by_user;
    bool clear_decision_panel;
    bool clear_local_pin_panel;
    bool clear_sign_by_user_review_panel;
};

AgentQUsbSessionLossPlan usb_session_loss_plan(const AgentQUsbSessionLossInput& input);

}  // namespace agent_q
