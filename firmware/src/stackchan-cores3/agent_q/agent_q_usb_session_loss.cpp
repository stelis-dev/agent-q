#include "agent_q_usb_session_loss.h"

namespace agent_q {

AgentQUsbSessionLossPlan usb_session_loss_plan(const AgentQUsbSessionLossInput& input)
{
    const bool protocol_connect =
        input.protocol_pin == AgentQUsbSessionLossProtocolPinPurpose::connect;
    const bool protocol_policy_update =
        input.protocol_pin == AgentQUsbSessionLossProtocolPinPurpose::policy_update;
    const bool protocol_sui_zklogin_proposal =
        input.protocol_pin == AgentQUsbSessionLossProtocolPinPurpose::sui_zklogin_proposal;
    const bool local_connect =
        input.local_pin == AgentQUsbSessionLossLocalPinPurpose::connect;
    const bool local_policy_update =
        input.local_pin == AgentQUsbSessionLossLocalPinPurpose::policy_update;
    const bool local_sui_zklogin_proposal =
        input.local_pin == AgentQUsbSessionLossLocalPinPurpose::sui_zklogin_proposal;
    const bool local_user_signing =
        input.local_pin == AgentQUsbSessionLossLocalPinPurpose::user_signing;
    const bool local_session_bound =
        local_connect || local_policy_update || local_sui_zklogin_proposal || local_user_signing;
    const bool protocol_session_bound =
        protocol_connect || protocol_policy_update || protocol_sui_zklogin_proposal;
    const bool cancel_user_signing =
        input.user_signing_active && !input.user_signing_critical;

	    return AgentQUsbSessionLossPlan{
	        input.session_active ||
	            input.connect_approval_active ||
	            protocol_session_bound ||
	            local_session_bound ||
	            input.policy_update_active ||
	            input.sui_zklogin_proposal_active ||
	            input.user_signing_active,
	        input.session_active,
	        input.connect_approval_active,
	        protocol_session_bound,
	        local_session_bound,
	        input.policy_update_active || protocol_policy_update || local_policy_update,
	        input.sui_zklogin_proposal_active ||
	            protocol_sui_zklogin_proposal ||
	            local_sui_zklogin_proposal,
	        cancel_user_signing,
	        input.connect_approval_active,
	        local_session_bound,
	        input.policy_update_active && !local_policy_update,
	        input.sui_zklogin_proposal_active && !local_sui_zklogin_proposal,
	        cancel_user_signing,
	    };
}

}  // namespace agent_q
