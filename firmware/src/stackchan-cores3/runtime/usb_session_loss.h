#pragma once

namespace signing {

enum class UsbSessionLossProtocolPinPurpose {
    none,
    connect,
    policy_update,
    sui_zklogin_proposal,
    other,
};

enum class UsbSessionLossLocalPinPurpose {
    none,
    connect,
    policy_update,
    sui_zklogin_proposal,
    user_signing,
    other,
};

struct UsbSessionLossInput {
    bool session_active;
    bool connect_approval_active;
    UsbSessionLossProtocolPinPurpose protocol_pin;
    UsbSessionLossLocalPinPurpose local_pin;
    bool policy_update_active;
    bool sui_zklogin_proposal_active;
    bool user_signing_active;
    bool user_signing_critical;
};

struct UsbSessionLossPlan {
    bool relevant;
    bool clear_session;
    bool clear_connect_approval;
    bool clear_protocol_pin;
    bool clear_local_pin_auth;
    bool clear_policy_update_flow;
    bool clear_sui_zklogin_proposal_flow;
    bool cancel_user_signing;
    bool clear_connect_review_panel;
    bool clear_local_pin_panel;
    bool clear_policy_update_review_panel;
    bool clear_sui_zklogin_review_panel;
    bool clear_user_signing_review_panel;
};

UsbSessionLossPlan usb_session_loss_plan(const UsbSessionLossInput& input);

}  // namespace signing
