#include "agent_q_usb_session_loss.h"

namespace agent_q {

AgentQUsbSessionLossPlan usb_session_loss_plan(const AgentQUsbSessionLossInput& input)
{
    const bool protocol_connect =
        input.protocol_pin == AgentQUsbSessionLossProtocolPinPurpose::connect;
    const bool protocol_policy_update =
        input.protocol_pin == AgentQUsbSessionLossProtocolPinPurpose::policy_update;
    const bool local_connect =
        input.local_pin == AgentQUsbSessionLossLocalPinPurpose::connect;
    const bool local_policy_update =
        input.local_pin == AgentQUsbSessionLossLocalPinPurpose::policy_update;
    const bool local_session_bound =
        local_connect || local_policy_update;
    const bool protocol_session_bound = protocol_connect || protocol_policy_update;

    return AgentQUsbSessionLossPlan{
        input.session_active ||
            input.connect_approval_active ||
            protocol_session_bound ||
            local_session_bound,
        input.session_active,
        input.connect_approval_active,
        protocol_session_bound,
        local_session_bound,
        protocol_policy_update || local_policy_update,
        input.connect_approval_active,
        local_session_bound,
    };
}

}  // namespace agent_q
